// 取证溯源控制器（T5/T6）：溯源查询、IP 池聚类、CIDR 封禁编排、签名导出。读溯源走 security:audit，改封禁走 security:config；封段默认人工确认（请求拿票 → 持票落库），跳过任何一步都不封。

const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
// 取证集合的读写一律经 services/forensicCapture（分层纪律 D-1a）：控制器不 require 模型
const forensicTrace = require('../services/forensicTrace');
const ipPoolCluster = require('../services/ipPoolCluster');
const ipPoolBan = require('../services/ipPoolBan');
const forensicExport = require('../services/forensicExport');
const forensicCapture = require('../services/forensicCapture');
const forensicManifest = require('../services/forensicManifest');
const ipListService = require('../services/ipListService');
const {
  clientIpForSecurityDecision,
  normalizeIP,
  auditClientAddress,
} = require('../utils/ipUtils');
const { auditPath } = require('../utils/auditMeta');
const { CODES: REFUSAL } = require('../constants/banRefusalReason');

const MAX_WINDOW_HOURS = 720;

/** 三个查询维度 + 时间窗；一个维度都不给时由 service 判 no_criteria（控制器不自己放宽） */
const criteriaOf = (src) => ({
  ip: src.ip,
  fingerprint: src.fingerprint,
  deviceKey: src.deviceKey,
  ipSegment: src.ipSegment,
  since: src.since ? new Date(src.since) : undefined,
  until: src.until ? new Date(src.until) : undefined,
  limit: src.limit,
});

/** 聚类窗口上限 720 小时（30 天）：不限的话一次请求能把整库聚合出来 */
/** query 值转数字：非数字返回 undefined，让服务层用它自己的默认值（不要把字符串塞进聚合管道） */
const numberOrUndefined = (raw) => {
  const n = Number.parseInt(String(raw ?? ''), 10);
  return Number.isFinite(n) ? n : undefined;
};

const windowOf = (src) => {
  const hours = Number.parseInt(src.windowHours, 10);
  const h = Number.isFinite(hours) && hours > 0 ? Math.min(hours, MAX_WINDOW_HOURS) : 24;
  return h * 60 * 60 * 1000;
};

/** 导出物绑定当天清单锚点：只签记录的话，把清单删了再重签就自洽了。清单读不到就退化成不绑定（如实报 null） */
const manifestRefOf = () => {
  try {
    const read = forensicManifest.readManifest();
    const entries = (read && read.entries) || [];
    if (!entries.length) return null;
    const last = entries[entries.length - 1];
    return {
      dateKey: last.dateKey || null,
      chainHash: last.chainHash || null,
      lastSeq: last.lastSeq || null,
    };
  } catch (e) {
    logger.warn('取证导出未能绑定清单锚点（不影响导出本身）：' + String((e && e.message) || e));
    return null;
  }
};

const getTrace = asyncHandler(async (req, res) => {
  try {
    const result = await forensicTrace.traceActor({
      model: forensicCapture.captureModel(),
      ...criteriaOf(req.query),
    });
    if (!result.ok) return ApiResponse.codeError(res, 'FORENSIC_NO_CRITERIA');
    return ApiResponse.success(res, result, '获取成功');
  } catch (e) {
    logger.error('取证溯源查询失败：' + String((e && e.stack) || e));
    return ApiResponse.codeError(res, 'FORENSIC_QUERY_FAILED');
  }
});

const getClusters = asyncHandler(async (req, res) => {
  try {
    const result = await ipPoolCluster.clusterIpPools({
      model: forensicCapture.captureModel(),
      windowMs: windowOf(req.query),
      // query 参数恒为字符串：直接进 $match/$limit 时，'20' 走 BSON 类型括号后恒不匹配（段数恒 0），
      // '50' 直接让 $limit 抛 MongoServerError ⇒ 500。路由的 isInt 只保证"看起来是数字"，不改变类型。
      minHits: numberOrUndefined(req.query.minHits),
      minIps: numberOrUndefined(req.query.minIps),
      limit: numberOrUndefined(req.query.limit),
    });
    return ApiResponse.success(res, result, '获取成功');
  } catch (e) {
    logger.error('IP 池聚类失败：' + String((e && e.stack) || e));
    return ApiResponse.codeError(res, 'FORENSIC_QUERY_FAILED');
  }
});

/** 第一步：拿确认票据。被拒时把**具体原因**放进 errors.reason（前端按原因给文案，不是一个笼统的失败） */
const requestPoolBan = asyncHandler(async (req, res) => {
  const result = await ipPoolBan.requestBan({
    cidr: req.body.cidr,
    reason: req.body.reason,
    operator: (req.user && req.user.userId) || null,
    // B1：票据同时带 username——确认落库的审计行才不必拿 ObjectId 串冒充操作者名
    operatorUsername: (req.user && req.user.username) || null,
    operatorIp: normalizeIP(clientIpForSecurityDecision(req)),
  });
  if (!result.ok) {
    return ApiResponse.codeError(res, 'FORENSIC_POOL_BAN_REFUSED', {
      params: { reason: result.reason },
    });
  }
  return ApiResponse.success(res, result, '待确认');
});

// 并集复核有两个时刻：写入前先判（rolledBack=0）与"写完才发现并发补齐"（rolledBack>0）。
// 两者都要留痕、不能只留 logger.warn；函数与档位跟同型护栏 enforceConcurrentUnionGuard 一致。
const tracePoolBanUnionRollback = async (req, result) => {
  if (result.reason !== REFUSAL.union_covers_family) return;
  const rolledBack = result.rolledBack || 0;
  await ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    body: {
      cidr: result.cidr,
      rolledBack,
      rolledBackIds: result.rolledBackIds || [],
      skippedExisting: result.skippedExisting || 0,
    },
    success: false,
    riskLevel: 'critical',
    riskFactors: [
      rolledBack || result.skippedExisting
        ? 'full_range_cidr_pool_ban_union_rollback'
        : 'full_range_cidr_pool_ban_union_prewrite',
    ],
    reason: `确认 ${result.cidr} 时黑名单并集覆盖地址族（${rolledBack ? '已回滚本次写入' : result.skippedExisting ? '未删他人既有条目' : '写入前拦下'}）`,
  });
};

/** 第二步：持票落库。票据一次性，重放同一张票不生效 */
const confirmPoolBan = asyncHandler(async (req, res) => {
  const raw = req.body.durationHours;
  const hours = Number.parseFloat(raw);
  const durationMs = Number.isFinite(hours) && hours > 0 ? Math.round(hours * 3600000) : 0;
  // "永久"只认 **0 / '0' 两种显式字面**（审计 2026-11-02 F-2）。路由校验对 falsy 值整体放行
  // （optional({ values: 'falsy' })），''、null、false 都会原样到达——旧折算「解析不出正数且字段传了
  // ⇒ 永久」会把空输入折成永久封段（恰好复活 ADR-018 ④ 否定过的「漏填即最重」）。非显式永久的
  // 一切取值都落 durationMs=0 + permanent=false，由 ipPoolBan.applyBan 兜底 DEFAULT_BAN_MS（24h），// 退化方向永远是「更短」而非「更重」。
  const permanent = raw === 0 || raw === '0';
  const result = await ipPoolBan.applyBan({
    token: req.body.token,
    typedConfirm: req.body.typedConfirm,
    durationMs,
    permanent,
    // B3：审计归因需要请求上下文（method/path/auditClientAddress/UA/sessionId/fingerprint）
    req,
    // 落库时刻的操作者位置：由与拦截中间件同一把尺取（不读 req.ip —— 开着 trust proxy 时它由请求头决定）
    operatorIp: normalizeIP(clientIpForSecurityDecision(req)),
  });
  if (!result.ok) {
    await tracePoolBanUnionRollback(req, result);
    return ApiResponse.codeError(res, 'FORENSIC_POOL_BAN_REFUSED', {
      params: { reason: result.reason },
    });
  }
  return ApiResponse.success(res, result, '封禁已提交');
});

const exportForensic = asyncHandler(async (req, res) => {
  const secret = forensicExport.secretOf();
  if (!secret) return ApiResponse.codeError(res, 'FORENSIC_EXPORT_NO_SECRET');
  try {
    const found = await forensicTrace.traceTimeline({
      model: forensicCapture.captureModel(),
      ...criteriaOf(req.body),
    });
    if (!found.ok) return ApiResponse.codeError(res, 'FORENSIC_NO_CRITERIA');
    const built = forensicExport.buildExport({
      records: found.records,
      manifestRef: manifestRefOf(),
      secret,
      operator: (req.user && (req.user.username || req.user.userId)) || 'unknown',
    });
    if (!built.ok) {
      if (built.reason === 'no_secret')
        return ApiResponse.codeError(res, 'FORENSIC_EXPORT_NO_SECRET');
      return ApiResponse.codeError(res, 'FORENSIC_QUERY_FAILED', {
        params: { reason: built.reason },
      });
    }
    return ApiResponse.success(res, built, '导出成功');
  } catch (e) {
    logger.error('取证导出失败：' + String((e && e.stack) || e));
    return ApiResponse.codeError(res, 'FORENSIC_QUERY_FAILED');
  }
});

module.exports = { getTrace, getClusters, requestPoolBan, confirmPoolBan, exportForensic };
