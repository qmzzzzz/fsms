/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
// 超大时间范围阈值（天）
const AUDIT_LOG_RANGE_WARN_DAYS = 365;
const warnLargeAuditRange = ({ startDate, endDate }, res) => {
  if (!startDate || !endDate) return;
  const deltaDays =
    (new Date(endDate).getTime() - new Date(startDate).getTime()) / (24 * 60 * 60 * 1000);
  if (deltaDays > AUDIT_LOG_RANGE_WARN_DAYS) {
    logger.warn(`审计日志查询时间范围过大（${Math.round(deltaDays)}天），可能影响性能`);
    res.setHeader('X-Performance-Warning', 'query_range_too_large');
  }
};

const buildAuditSummary = (summaryAgg) => {
  const summaryMap = new Map(summaryAgg.map((summary) => [summary._id, summary.count]));
  return {
    critical: summaryMap.get('critical') || 0,
    high: summaryMap.get('high') || 0,
    medium: summaryMap.get('medium') || 0,
    low: summaryMap.get('low') || 0,
  };
};

// 评价报告 #22/#13：数据范围过滤（all/self/department 翻译 + 部门成员缓存）
// 已拆分至 auditScopeFilter.js（体积棘轮），此处 re-export 保持既有调用面不变。
const applyAuditDataScope = require('./auditScopeFilter').applyAuditDataScope;

const fetchAuditCursorPage = (cursorQuery, query, limitNum) =>
  Promise.all([
    AuditLog.find(cursorQuery)
      .populate('userId', 'username realName')
      .sort({ timestamp: -1 })
      .limit(limitNum + 1)
      .select(AuditLog.RESPONSE_EXCLUDE),
    AuditLog.aggregate([{ $match: query }, { $group: { _id: '$riskLevel', count: { $sum: 1 } } }]),
  ]);

const fetchAuditOffsetPage = (query, skip, limitNum) =>
  Promise.all([
    AuditLog.find(query)
      .populate('userId', 'username realName')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limitNum)
      .select(AuditLog.RESPONSE_EXCLUDE),
    AuditLog.aggregate([{ $match: query }, { $group: { _id: '$riskLevel', count: { $sum: 1 } } }]),
  ]);

// E-05 整改：本文件此前内联维护了第二份 buildAuditQuery（与 utils/auditQuery.js
// 逐行近似但不相同），两份实现已经漂移——本地副本的 date-only 边界仍走
// `new Date(`${d}T00:00:00`)`（服务器本地时区），而共享实现早已改为
// parseDateBoundary（业务时区，评价报告 #12）。后果是 UTC 容器下
// 查询接口与导出接口对同一天的筛选边界相差 8 小时：
//   UTC 容器 + startDate=2026-09-15
//     查询（本地副本）→ 2026-09-15T00:00:00Z
//     导出（共享实现）→ 2026-09-14T16:00:00Z（业务时区当天 0 点）
//   即导出比查询多算 8 小时，而东八区当天 0-8 点的记录在查询侧被漏掉。
// 现删除本地副本，统一引用 utils/auditQuery.js——重复块与口径漂移一并消除。
const { buildAuditQuery } = require('../utils/auditQuery');
/**
 * 查询审计日志（支持多维度筛选）
 * GET /api/security/audit-logs
 *
 * L-13 修复：原实现为「同步 try/catch 包裹 async IIFE」——
 *   try { return (async () => { await ... })(); } catch (e) { ... }
 * 同步 catch 拦不住 IIFE 内部的 reject，故失败时这里专门的
 * logger.error('审计日志查询失败') 与 codeError 都不会执行，错误会逃逸到
 * asyncHandler → 全局 errorHandler，日志变成泛化的 UnhandledError，丢失操作上下文。
 * （不会挂死：调用方在 asyncHandler 内 return 了该 promise，故仍返回 500。）
 * 现改为 async 函数 + await，让 try/catch 真正生效。
 */
const queryAuditCursorPage = async (req, res, query, { limitNum, decodedCursor }) => {
  try {
    const cursorQuery = applyCursorCondition(query, {
      sortField: 'timestamp',
      sortDir: -1,
      cursor: decodedCursor,
      valueType: 'date',
    });
    const [docs, summaryAgg] = await fetchAuditCursorPage(cursorQuery, query, limitNum);
    const { items, hasMore, nextCursor } = buildCursorResult(docs, limitNum, 'timestamp');
    return ApiResponse.success(
      res,
      {
        data: items,
        meta: {
          page: null,
          limit: limitNum,
          total: null,
          totalPages: null,
          hasNext: hasMore,
          hasPrev: true,
          nextCursor,
          lastUpdated: new Date().toISOString(),
          count: items.length,
          summary: buildAuditSummary(summaryAgg),
        },
      },
      '获取成功'
    );
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
};

// L-13 修复：同上，改为 async 函数 + await，使 try/catch 能真正接管异步失败
const queryAuditOffsetPage = async (req, res, query, { pageNum, limitNum }) => {
  try {
    const total = await AuditLog.countDocuments(query);
    if (total === 0) {
      return ApiResponse.success(
        res,
        {
          data: [],
          meta: {
            page: pageNum,
            limit: limitNum,
            total: 0,
            totalPages: 0,
            hasNext: false,
            hasPrev: false,
            lastUpdated: new Date().toISOString(),
            count: 0,
            summary: { critical: 0, high: 0, medium: 0, low: 0 },
          },
        },
        '获取成功'
      );
    }

    const [logs, summaryAgg] = await fetchAuditOffsetPage(
      query,
      (pageNum - 1) * limitNum,
      limitNum
    );
    const hasNext = pageNum * limitNum < total;
    const lastLog = logs[logs.length - 1];
    return ApiResponse.success(
      res,
      {
        data: logs,
        meta: {
          page: pageNum,
          limit: limitNum,
          total,
          totalPages: Math.ceil(total / limitNum),
          hasNext,
          hasPrev: pageNum > 1,
          nextCursor:
            hasNext && lastLog
              ? encodeCursor({ v: lastLog.timestamp, id: String(lastLog._id) })
              : null,
          lastUpdated: new Date().toISOString(),
          count: logs.length,
          summary: buildAuditSummary(summaryAgg),
        },
      },
      '获取成功'
    );
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'AUDIT_QUERY_FAILED');
  }
};

const queryAuditLogs = asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, cursor } = req.query;
  let query;
  let startDate;
  let endDate;
  try {
    ({ query, startDate, endDate } = buildAuditQuery(req));
  } catch (err) {
    return ApiResponse.error(res, err.message, 400);
  }

  warnLargeAuditRange({ startDate, endDate }, res);
  if (!req.user || !req.user.userId) {
    return ApiResponse.codeError(res, 'UNAUTHORIZED_ACCESS');
  }

  ({ query } = await applyAuditDataScope(query, req.user.userId));

  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 1000);
  let decodedCursor = null;
  if (cursor) {
    try {
      decodedCursor = decodeCursor(cursor);
    } catch (err) {
      return ApiResponse.error(res, err.message || '分页游标无效', err.statusCode || 400);
    }
  }

  if (decodedCursor) {
    return queryAuditCursorPage(req, res, query, { limitNum, decodedCursor });
  }
  return queryAuditOffsetPage(req, res, query, { pageNum, limitNum });
});

module.exports = { queryAuditLogs, applyAuditDataScope };
