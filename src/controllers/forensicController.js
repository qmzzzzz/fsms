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
const { clientIpForSecurityDecision, normalizeIP } = require('../utils/ipUtils');

const MAX_WINDOW_HOURS = 720;

/** 三个查询维度 + 时间窗；一个维度都不给时由 service 判 no_criteria（控制器不自己放宽） */
const criteriaOf = (src) => ({
  ip: src.ip,
  fingerprint: src.fingerprint,
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
    operatorIp: normalizeIP(clientIpForSecurityDecision(req)),
  });
  if (!result.ok) {
    return ApiResponse.codeError(res, 'FORENSIC_POOL_BAN_REFUSED', {
      params: { reason: result.reason },
    });
  }
  return ApiResponse.success(res, result, '待确认');
});

/** 第二步：持票落库。票据一次性，重放同一张票不生效 */
const confirmPoolBan = asyncHandler(async (req, res) => {
  const hours = Number.parseFloat(req.body.durationHours);
  const durationMs = Number.isFinite(hours) && hours > 0 ? Math.round(hours * 3600000) : 0;
  // "永久"必须由调用方**显式**要求（durationHours===0 且字段确实传了）：把"没填"与"选了永久"
  // 折成同一个 0，会让漏填的请求落成永久封禁——库里 expiresAt=null，DEFAULT_BAN_MS 永不生效。
  const permanent = durationMs === 0 && req.body.durationHours !== undefined;
  const result = await ipPoolBan.applyBan({
    token: req.body.token,
    typedConfirm: req.body.typedConfirm,
    durationMs,
    permanent,
  });
  if (!result.ok) {
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
