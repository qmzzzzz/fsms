/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { validateEnum, normalizePagination, escapeRegExp } = require('../utils/helpers');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { normalizeIP } = require('../utils/ipUtils');
const { AUDIT_CATEGORIES, AUDIT_LOG_ACTIONS } = require('../constants/audit');

const AUDIT_LOG_CATEGORIES = AUDIT_CATEGORIES; // 单一事实来源：constants/audit.js
const AUDIT_LOG_RISK_LEVELS = ['low', 'medium', 'high', 'critical'];
const AUDIT_LOG_LEVELS = ['info', 'warning', 'error'];
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

const buildAuditQuery = (req) => {
  const { startDate, endDate, userId, username, action, category, ip, riskLevel, success, level } =
    req.query;

  // 日期格式校验前置，避免无效日期进入查询导致数据库异常
  if (startDate && isNaN(new Date(startDate).getTime())) {
    throw new Error('开始日期格式错误');
  }
  if (endDate && isNaN(new Date(endDate).getTime())) {
    throw new Error('结束日期格式错误');
  }

  // 枚举参数白名单强校验：非法值抛错，避免静默忽略
  // category 同样纳入校验——否则传入非法分类时该条件被静默丢弃并返回全量数据
  validateEnum(action, AUDIT_LOG_ACTIONS, 'action');
  validateEnum(category, AUDIT_LOG_CATEGORIES, 'category');
  validateEnum(riskLevel, AUDIT_LOG_RISK_LEVELS, 'riskLevel');
  validateEnum(level, AUDIT_LOG_LEVELS, 'level');

  // userId 必须是合法 ObjectId
  if (userId && !mongoose.Types.ObjectId.isValid(userId)) {
    throw new Error('参数 userId 必须是合法的用户 ID');
  }

  // ip 归一化与合法性校验
  let normalizedQueryIP = null;
  if (ip) {
    normalizedQueryIP = normalizeIP(ip);
    if (!normalizedQueryIP) {
      throw new Error('参数 ip 必须是合法的 IPv4/IPv6 地址');
    }
  }

  const query = {};

  if (startDate || endDate) {
    query.timestamp = {};
    if (startDate) {
      // 纯日期串（YYYY-MM-DD）按本地时区当天 00:00:00 起算，
      // 避免 new Date() 按 UTC 解析导致东八区丢失当天 0-8 点记录
      query.timestamp.$gte = /^\d{4}-\d{2}-\d{2}$/.test(startDate)
        ? new Date(`${startDate}T00:00:00`)
        : new Date(startDate);
    }
    if (endDate) {
      // 结束日期补全为当天 23:59:59.999，保证"含当天"语义
      query.timestamp.$lte = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
        ? new Date(`${endDate}T23:59:59.999`)
        : new Date(endDate);
    }
  }
  if (userId) query.userId = userId;
  // 使用 escapeRegExp 防止 ReDoS 正则拒绝服务攻击
  if (username) query.username = { $regex: escapeRegExp(username), $options: 'i' };
  // action 为枚举值（如 login_success），使用精确匹配，避免子串误命中
  if (action) query.action = action;
  if (category) query.category = category;
  // IP 用归一化值 + 原始值同时匹配：存量记录可能以 ::ffff:1.2.3.4 形式落库，
  // 而管理员通常输入纯 IPv4，只按单一形式查会漏记录
  if (normalizedQueryIP) {
    const ipVariants = [...new Set([normalizedQueryIP, String(ip).trim()])];
    query.ip = ipVariants.length > 1 ? { $in: ipVariants } : ipVariants[0];
  }
  if (riskLevel) query.riskLevel = riskLevel;
  if (success !== undefined && success !== '') {
    query.success = success === 'true' || success === true;
  }

  // 日志等级筛选（派生自 success + riskLevel，口径与前端展示一致）：
  // error   = 操作失败 或 高危/严重风险
  // warning = 操作成功 且 中等风险
  // info    = 操作成功 且 非中高以上风险
  // 注意：用 $and 叠加而非直接覆盖 query 字段——直接赋值会静默丢弃
  // 用户已选的 success/riskLevel 筛选，导致"选了日志等级其他筛选失效"
  if (level && ['info', 'warning', 'error'].includes(level)) {
    let levelCond;
    if (level === 'error') {
      levelCond = { $or: [{ success: false }, { riskLevel: { $in: ['high', 'critical'] } }] };
    } else if (level === 'warning') {
      levelCond = { success: true, riskLevel: 'medium' };
    } else {
      levelCond = { success: true, riskLevel: { $nin: ['medium', 'high', 'critical'] } };
    }
    query.$and = [...(query.$and || []), levelCond];
  }

  return { query, startDate, endDate };
};
/**
 * 查询审计日志（支持多维度筛选）
 * GET /api/security/audit-logs
 */
const queryAuditCursorPage = (req, res, query, { limitNum, decodedCursor }) => {
  try {
    const cursorQuery = applyCursorCondition(query, {
      sortField: 'timestamp',
      sortDir: -1,
      cursor: decodedCursor,
      valueType: 'date',
    });
    return (async () => {
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
    })();
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.serverError(res, '审计日志查询失败');
  }
};

const queryAuditOffsetPage = (req, res, query, { pageNum, limitNum }) => {
  try {
    return (async () => {
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
    })();
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.serverError(res, '审计日志查询失败');
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
    return ApiResponse.unauthorized(res, '未授权访问');
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
