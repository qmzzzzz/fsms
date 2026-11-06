/**
 * 注入尝试检测器 ——「静默剥离」的检测留痕面（攻击检测面 2026-11-05）。
 *
 * sanitizeMongo/materializeQuery 把 NoSQL 操作符键剥离后请求照常放行，此前只有一行
 * logger.warn——AuditLog 零留痕、指标零记录，攻击者可**无痕探测**。本模块把剥离事件
 * 升级为结构化检测信号：incSecurityAlert 指标 + AuditLog 直写行（attackEvents 注册表
 * `injection` 分类的事件源，攻击告警查询面自动可见）。三条纪律：
 *  1) fire-and-forget：剥离是既有防线（行为零变更），检测写失败绝不影响剥离与放行
 *     （guardDetection 包壳，直写不走 auditBuffer，与 recordEarlyRejection 同形）；
 *  2) 不冒充：只记「尝试被剥离」。statusCode 刻意省略——剥离发生在请求早期，最终
 *     HTTP 走向此刻不可知，记了就是猜；success:false =「剥离即未得手」；
 *  3) 去重有界：同 IP+同面+同键形态 60s 只落一行，审计刷量压到「指纹数」量级。
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { guardDetection } = require('../utils/auditWriteFailure');
const { computeFingerprint } = require('../utils/fingerprint');
const { stripControlChars } = require('../utils/helpers');
const { auditPath } = require('../utils/auditMeta');
const { auditClientAddress } = require('../utils/ipUtils');
const { incSecurityAlert } = require('../utils/metrics');

// 键样本上界：证据只承担定性（哪种操作符被探过），全量载荷由全局 auditLog 的快照承担
const MAX_KEY_SAMPLES = 5;
const KEY_SAMPLE_MAX_LENGTH = 64;
const DEDUP_WINDOW_MS = 60 * 1000;
const DEDUP_MAX_ENTRIES = 4096;

/** 键 = `${ip}|${surface}|${key}`，值 = 窗口过期时间；写前清扫，绝不整体清空 */
const recentByFingerprint = new Map();

const pruneDedup = (now) => {
  if (recentByFingerprint.size < DEDUP_MAX_ENTRIES) return;
  for (const [key, expiresAt] of recentByFingerprint.entries()) {
    if (expiresAt <= now) recentByFingerprint.delete(key);
  }
  while (recentByFingerprint.size >= DEDUP_MAX_ENTRIES) {
    recentByFingerprint.delete(recentByFingerprint.keys().next().value);
  }
};

/** 同 IP+面+键形态 60s 内只落一行；返回 true 表示本次应写审计 */
const shouldRecord = (fingerprint, now) => {
  pruneDedup(now);
  if (recentByFingerprint.get(fingerprint) > now) return false;
  recentByFingerprint.set(fingerprint, now + DEDUP_WINDOW_MS);
  return true;
};

const sampleKeys = (keys) =>
  (Array.isArray(keys) ? keys : [])
    .slice(0, MAX_KEY_SAMPLES)
    .map((key) => stripControlChars(String(key), KEY_SAMPLE_MAX_LENGTH))
    .filter(Boolean);

/**
 * 记录一次「NoSQL 操作符键被剥离」的注入尝试。
 *
 * @param {object} params
 * @param {string[]} params.keys 本次剥离的键名（操作符键或原型链键，如 $ne、$gt）
 * @param {'body'|'params'|'query'} params.surface 剥离发生的请求面
 * @param {import('express').Request} params.req 当前请求（取 path/ip/userAgent/fingerprint）
 * @returns {void} 永不抛：内部 guardDetection 兜底，调用方（sanitize 热路径）零负担
 */
const recordNosqlStripAttempt = ({ keys, surface, req }) => {
  // 同步段整体 try：调用方是剥离热路径，req 形态不可控（单测桩/畸形请求），
  // 任何异常都不得上抛——检测失败只留 error 日志
  try {
    const samples = sampleKeys(keys);
    if (samples.length === 0 || !req) return;
    const ip = auditClientAddress(req).ip;
    const fingerprints = samples.map((key) => `${ip}|${surface}|${key}`);
    const now = Date.now();
    // 同一请求剥离多个键：按指纹逐个判重，首次探测必留痕，重复探测被窗口吸收
    const freshKeys = samples.filter((key, i) => shouldRecord(fingerprints[i], now));
    if (freshKeys.length === 0) return;
    // setImmediate：剥离热路径上只做入队，审计写入挪到本轮之后
    setImmediate(() => guardedRecord({ keys: freshKeys, surface, req }));
  } catch (error) {
    logger.error(`注入尝试留痕同步段失败（已跳过本轮）: ${error.message}`);
  }
};

const guardedRecord = guardDetection('注入尝试留痕', async ({ keys, surface, req }) => {
  incSecurityAlert('nosql_injection_attempt', 'medium');
  AuditLog.record({
    action: 'nosql_injection_attempt',
    category: 'security',
    userId: req.user?.userId,
    username: req.user?.username || 'anonymous',
    sessionId: req.user?.sessionId || null,
    fingerprint: computeFingerprint(req),
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: stripControlChars(req.get('user-agent'), 512),
    success: false,
    riskLevel: 'medium',
    riskFactors: ['mongo_operator_strip'],
    // 键样本进 reason（有界已清洗）：全文载荷由全局 auditLog 的 body/query 快照承担，
    // 这里只承担"哪种操作符被探过"的定性
    reason: stripControlChars(`NoSQL 操作符剥离（surface=${surface}）：${keys.join(', ')}`, 512),
  });
  logger.warn(`NoSQL 注入尝试已留痕（surface=${surface}）：${keys.join(', ')}`);
});

/** 测试与运维自检：当前去重表规模（有界可见） */
const getInjectionDetectorStats = () => ({
  tracked: recentByFingerprint.size,
  windowMs: DEDUP_WINDOW_MS,
  maxEntries: DEDUP_MAX_ENTRIES,
});

/** 测试钩子：清空去重表（jest 用例间隔离；生产进程内无需调用） */
const resetInjectionDetector = () => {
  recentByFingerprint.clear();
};

module.exports = { recordNosqlStripAttempt, getInjectionDetectorStats, resetInjectionDetector };
