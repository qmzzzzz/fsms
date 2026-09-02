/**
 * 审计日志控制器（D-1 自 securityController 拆出）
 *
 * 审计日志的查询、流式导出（CSV + 签名 manifest）与哈希链完整性校验。
 * action 白名单枚举以 constants/audit.js 为单一事实来源。
 */

const crypto = require('crypto');
const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const {
  validateEnum,
  normalizePagination,
  escapeRegExp,
  sanitizeSpreadsheetCell,
} = require('../utils/helpers');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { normalizeIP } = require('../utils/ipUtils');
const { auditPath } = require('../utils/auditMeta');
const { AUDIT_CATEGORIES, AUDIT_LOG_ACTIONS } = require('../constants/audit');

const AUDIT_LOG_CATEGORIES = AUDIT_CATEGORIES; // 单一事实来源：constants/audit.js
const AUDIT_LOG_RISK_LEVELS = ['low', 'medium', 'high', 'critical'];
const AUDIT_LOG_LEVELS = ['info', 'warning', 'error'];
// 超大时间范围阈值（天）
const AUDIT_LOG_RANGE_WARN_DAYS = 365;
// 审计日志导出硬上限（条）：达到即截断游标拉取，防止无界导出拖垮内存与带宽
const EXPORT_HARD_LIMIT = 50000;

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
const queryAuditLogs = asyncHandler(async (req, res) => {
  try {
    const { page = 1, limit = 20, cursor } = req.query;

    // 构建查询条件（参数校验 + 查询体构建统一收敛到 buildAuditQuery）
    let query, startDate, endDate;
    try {
      ({ query, startDate, endDate } = buildAuditQuery(req));
    } catch (err) {
      return ApiResponse.error(res, err.message, 400);
    }

    // 超大时间范围性能告警：跨度超过阈值时记录 warn 日志并设置响应头标记
    if (startDate && endDate) {
      const deltaDays =
        (new Date(endDate).getTime() - new Date(startDate).getTime()) / (24 * 60 * 60 * 1000);
      if (deltaDays > AUDIT_LOG_RANGE_WARN_DAYS) {
        logger.warn(`审计日志查询时间范围过大（${Math.round(deltaDays)}天），可能影响性能`);
        res.setHeader('X-Performance-Warning', 'query_range_too_large');
      }
    }

    // 添加额外的安全过滤
    if (!req.user || !req.user.userId) {
      return ApiResponse.unauthorized(res, '未授权访问');
    }

    // 规范化分页参数（统一限界，避免字符串比较漏洞）
    const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 1000);

    // E-2：审计日志是系统内量级最大的集合（所有受审计请求都会写入），
    // 深分页时 skip 与 countDocuments 双双退化。支持游标分页：
    // 传 cursor 时按 timestamp 倒序做 keyset seek，不做全量 count，
    // 以 hasMore/nextCursor 表达翻页；不传 cursor 保持原 page/limit 语义。
    let decodedCursor = null;
    if (cursor) {
      try {
        decodedCursor = decodeCursor(cursor);
      } catch (err) {
        return ApiResponse.error(res, err.message || '分页游标无效', err.statusCode || 400);
      }
    }

    const buildSummary = (summaryAgg) => {
      const summaryMap = new Map(summaryAgg.map((s) => [s._id, s.count]));
      return {
        critical: summaryMap.get('critical') || 0,
        high: summaryMap.get('high') || 0,
        medium: summaryMap.get('medium') || 0,
        low: summaryMap.get('low') || 0,
      };
    };

    if (decodedCursor) {
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'timestamp',
        sortDir: -1,
        cursor: decodedCursor,
        valueType: 'date',
      });
      try {
        const [docs, summaryAgg] = await Promise.all([
          AuditLog.find(cursorQuery)
            .populate('userId', 'username realName')
            .sort({ timestamp: -1 })
            .limit(limitNum + 1)
            .select(AuditLog.RESPONSE_EXCLUDE),
          AuditLog.aggregate([
            { $match: query },
            { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
          ]),
        ]);
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
              summary: buildSummary(summaryAgg),
            },
          },
          '获取成功'
        );
      } catch (error) {
        logger.error(`审计日志查询失败: ${error.message}`);
        return ApiResponse.serverError(res, '审计日志查询失败');
      }
    }

    // 查询总记录数
    const total = await AuditLog.countDocuments(query);

    // 如果没有记录，直接返回空数组
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
            summary: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
            },
          },
        },
        '获取成功'
      );
    }

    // P-02：分页列表查询与全局统计聚合无相互依赖，合并为一次并行往返（原串行 2 次 → 1 次）
    const [logs, summaryAgg] = await Promise.all([
      AuditLog.find(query)
        .populate('userId', 'username realName')
        .sort({ timestamp: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .select(AuditLog.RESPONSE_EXCLUDE),
      AuditLog.aggregate([
        { $match: query },
        { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
      ]),
    ]);
    const summary = buildSummary(summaryAgg);

    // 添加元数据
    // offset 模式同样下发 nextCursor：客户端可在任意页切换为游标续翻
    const hasNext = pageNum * limitNum < total;
    const lastLog = logs[logs.length - 1];
    const response = {
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
        summary,
      },
    };

    return ApiResponse.success(res, response, '获取成功');
  } catch (error) {
    logger.error(`审计日志查询失败: ${error.message}`);
    return ApiResponse.serverError(res, '审计日志查询失败');
  }
});

/**
 * 导出审计日志（CSV + 签名 manifest）
 * GET /api/security/audit-logs/export
 *
 * P3-12 流式输出：原实现自称游标流式、实则把全部行累积进 csvRows 再 join，
 * 5 万条上限时内存峰值约 2-3 倍于成品文件（行数组 + join 中间串 + 响应体三份）。
 * 现改为边拉边写：cursor 逐条 → 行字符串直接 res.write，内存占用 O(1)。
 * manifest 的 sha256 与 recordCount 在流结束后补发（X- 头 + 尾部 JSON 行），
 * 消费方按「CSV 正文 + 末行 __MANIFEST__ JSON」解析；截断语义不变。
 */

// manifest 以注释行追加在 CSV 末尾（# 前缀，Excel/WPS 打开时不产生错位行）
const MANIFEST_LINE_PREFIX = '#__MANIFEST__:';
const exportAuditLogs = asyncHandler(async (req, res) => {
  try {
    // 复用查询筛选逻辑
    let query;
    try {
      ({ query } = buildAuditQuery(req));
    } catch (err) {
      return ApiResponse.error(res, err.message, 400);
    }

    if (!req.user || !req.user.userId) {
      return ApiResponse.unauthorized(res, '未授权访问');
    }

    const CSV_COLUMNS = [
      'timestamp',
      'action',
      'category',
      'username',
      'ip',
      'path',
      'statusCode',
      'success',
      'riskLevel',
      'prevHash',
      'hash',
    ];

    // CSV 值转义：含逗号/引号/换行时用双引号包裹，内部双引号翻倍
    //
    // 公式注入防护（必需）：username 列内容攻击者完全可控——登录失败路径
    // 以原始请求体 username 调 recordLogin(null, username) 入库，
    // 而 loginValidation 只限长度不限字符集。任意人可制造
    // username = "=cmd|'/c calc'!A1" 的 login_failed 记录，安全管理员
    // 导出 CSV 双击打开即在其终端触发公式执行/DDE 钓鱼。
    // sanitizeSpreadsheetCell 给 = + - @ Tab CR 开头的值加前置单引号，
    // Excel/WPS/LibreOffice 一律按文本处理（与 reportController 同口径）。
    const csvEscape = (val) => {
      if (val === null || val === undefined) return '';
      let s;
      if (val instanceof Date) {
        s = val.toISOString();
      } else if (typeof val === 'object') {
        s = JSON.stringify(val);
      } else {
        s = String(val);
      }
      s = sanitizeSpreadsheetCell(s);
      if (/[",\n\r]/.test(s)) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };

    // 游标流式拉取，边拉边写（P3-12）：
    // 原实现把全部行累积进 csvRows 再 join，5 万条上限时内存峰值约 2-3 倍成品体积；
    // 现在每行生成后立即 res.write，配合 drain 等待处理背压，内存占用 O(1)。
    const cursor = AuditLog.find(query).sort({ _id: 1 }).lean().cursor();

    let recordCount = 0;
    let startTime = null;
    let endTime = null;
    // 硬上限截断标记：超出 EXPORT_HARD_LIMIT 的记录不包含在本次导出中
    let truncated = false;
    // 增量哈希：逐条 update hash，避免拼接超长字符串
    const hasher = crypto.createHash('sha256');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="audit-logs-export.csv"');
    res.write(`${CSV_COLUMNS.join(',')}\n`);

    /** 写一行并处理背压：write 返回 false 时等 drain，防止内核缓冲无界增长 */
    const writeLine = (line) =>
      new Promise((resolve) => {
        if (res.write(line)) return resolve();
        res.once('drain', resolve);
      });

    await cursor.eachAsync(async (doc) => {
      // 达到硬上限后关闭游标停止拉取（守卫条件保证缓冲中残余文档也被跳过）
      if (recordCount >= EXPORT_HARD_LIMIT) {
        truncated = true;
        cursor.close();
        return;
      }
      recordCount++;
      const ts = doc.timestamp instanceof Date ? doc.timestamp : new Date(doc.timestamp);
      if (!startTime || ts < startTime) startTime = ts;
      if (!endTime || ts > endTime) endTime = ts;

      // 将 hash 喂给增量哈希器（无 hash 的 legacy 记录跳过）
      if (doc.hash) {
        hasher.update(doc.hash, 'utf8');
      }

      const row = CSV_COLUMNS.map((col) => {
        if (col === 'timestamp') return csvEscape(ts);
        return csvEscape(doc[col]);
      });
      await writeLine(`${row.join(',')}\n`);
    });

    const sha256 = hasher.digest('hex');
    const manifest = {
      recordCount,
      startTime: startTime ? startTime.toISOString() : null,
      endTime: endTime ? endTime.toISOString() : null,
      generatedAt: new Date().toISOString(),
      sha256,
    };
    // 截断提示（meta）：明确告知消费方本次导出并非全量
    if (truncated) {
      manifest.truncated = true;
      manifest.notice = `导出记录数已达硬上限 ${EXPORT_HARD_LIMIT} 条并截断，请缩小筛选范围后分批导出`;
    }

    // 批量导出检测：导出记录数超过阈值时触发高危审计与告警（补齐导出审计盲区）
    const { checkBulkExport } = require('../services/securityAlert');
    await checkBulkExport(req.user.userId, req.user.username, recordCount, 'audit_logs_export');

    // manifest 以注释行追加在流末尾 + 响应头双通道：
    // 头部供程序化读取；尾部注释行让下载的文件自带签名信息（Excel 打开时 # 行不产生错位）
    res.setHeader('X-Audit-Manifest-Sha256', sha256);
    res.setHeader('X-Audit-Manifest-Records', String(recordCount));
    if (truncated) res.setHeader('X-Audit-Truncated', 'true');
    res.write(`${MANIFEST_LINE_PREFIX}${JSON.stringify(manifest)}\n`);
    res.end();
    return undefined;
  } catch (error) {
    logger.error(`审计日志导出失败: ${error.message}`);
    // 流已开始后无法再改状态码发 JSON 错误，只能尽力结束响应
    if (!res.headersSent) {
      return ApiResponse.serverError(res, '审计日志导出失败');
    }
    res.end();
    return undefined;
  }
});

/**
 * 校验审计日志哈希链完整性
 * GET /api/security/audit-logs/verify?limit=20000&from=latest|earliest
 *
 * 运行时可调用的完整性校验（此前只有离线脚本，链有效性从未被在线验证，
 * 「日志防篡改」属被动装饰性控制）。校验逻辑集中在 services/auditChainVerify.js，
 * 与运维脚本共用同一实现，避免两处口径漂移。
 */
const verifyAuditChainIntegrity = asyncHandler(async (req, res) => {
  const { verifyAuditChain, DEFAULT_MAX_RECORDS } = require('../services/auditChainVerify');

  const rawLimit = req.query.limit;
  if (rawLimit !== undefined && !/^\d+$/.test(String(rawLimit))) {
    return ApiResponse.error(res, 'limit 必须是正整数', 400);
  }
  const from = req.query.from;
  if (from !== undefined && !['latest', 'earliest'].includes(from)) {
    return ApiResponse.error(res, 'from 只能是 latest 或 earliest', 400);
  }

  const report = await verifyAuditChain(AuditLog, {
    maxRecords: rawLimit ? parseInt(rawLimit, 10) : DEFAULT_MAX_RECORDS,
    fromLatest: from !== 'earliest',
  });

  // 断裂即安全事件：必须留痕并告警，不能只作为一次普通查询响应
  if (!report.intact) {
    logger.error(
      `审计链完整性校验发现 ${report.breaks} 处断裂（` +
        `hash_mismatch=${report.byType.hash_mismatch} ` +
        `hmac_missing=${report.byType.hmac_missing} ` +
        `hmac_mismatch=${report.byType.hmac_mismatch} ` +
        `chain_break=${report.byType.chain_break}），` +
        `扫描 ${report.total} 条 by ${req.user.username}`
    );
  }

  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'audit_chain_verify',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    // 只记结论摘要，不记 samples（含 hash 明文，无需二次落库）
    body: { total: report.total, breaks: report.breaks, byType: report.byType },
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: report.intact ? 'low' : 'high',
  }).catch(() => {});

  return ApiResponse.success(res, report, report.intact ? '审计链完整' : '审计链存在断裂');
});

module.exports = {
  buildAuditQuery,
  queryAuditLogs,
  exportAuditLogs,
  verifyAuditChainIntegrity,
};
