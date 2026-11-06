/**
 * SQL/NoSQL 注入特征串边缘检测（攻击检测面 2026-11-05，W1）。
 *
 * 职责：请求路径与 query 里出现注入特征（UNION SELECT / ' or 1 / sleep( / 路径穿越 /
 * <script / jndi 等）时**留痕不阻断**——fsms 用 Mongoose 无 SQL、搜索词走 escapeRegExp
 * 与范围比较，特征串在本仓没有可注入的消费点；但「尝试」本身是攻击画像的关键信号，
 * 此前只有读侧画像扫审计行 path（attackProfileClassify），body/query 形态与
 * 非 /api 早拒绝段全部无痕。
 *
 * 判据单源：INJECTION_PATH_RE 从 constants/attackProfile.js 导入（读侧画像与请求侧
 * 检测共用同一把尺，复制一份就是漂移点）。
 *
 * 三条纪律（与 injectionDetector 同族）：
 *  1) fire-and-forget：检测失败不影响放行（guardDetection 包壳）；
 *  2) 不冒充：detect-only，statusCode 省略（最终走向此刻不可知）；
 *  3) 去重有界：同 IP+同命中样本 60s 一行（有界 Map）。
 *
 * 挂载：**全站**（app.js 的 app.use 不带 '/api/' 前缀）——注入探测最常打的恰恰是 /api 之外
 * 的面（SPA 路由 query、静态路径、登录页），只挂 /api/ 会让声称的补盲面大半落在盲区。
 * 位置在 queryScalarGuard 之后（query 已物化、非标量已 400）、auditLog 之前
 * （全局审计的 query 快照是清洗后形态，本检测补的是"尝试"信号）。
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { guardDetection } = require('../utils/auditWriteFailure');
const { computeFingerprint } = require('../utils/fingerprint');
const { stripControlChars } = require('../utils/helpers');
const { auditPath } = require('../utils/auditMeta');
const { auditClientAddress } = require('../utils/ipUtils');
const { incSecurityAlert } = require('../utils/metrics');
const { INJECTION_PATH_RE } = require('../constants/attackProfile');
const { markForensicTarget } = require('../services/forensicTrigger');

// 单请求最多送检的候选值数量与单值长度：query 值已被 queryLengthLimit 钳到 200，
// 这里只兜防御性上界（originalUrl 理论上可达 16KB，截断后扫描）
const MAX_CANDIDATES = 8;
const CANDIDATE_MAX_LENGTH = 512;

// 去重窗口：与 injectionDetector 同参数（60s / 4096），独立指纹空间
const DEDUP_WINDOW_MS = 60 * 1000;
const DEDUP_MAX_ENTRIES = 4096;
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

/** 收集送检候选：原始 URL（含编码形态与查询串）+ 解码后 path + query 标量值 */
const collectCandidates = (req) => {
  const candidates = [];
  if (req.originalUrl) candidates.push(String(req.originalUrl).slice(0, CANDIDATE_MAX_LENGTH));
  if (req.path) candidates.push(String(req.path).slice(0, CANDIDATE_MAX_LENGTH));
  const query = req.query;
  if (query && typeof query === 'object') {
    for (const value of Object.values(query)) {
      if (candidates.length >= MAX_CANDIDATES) break;
      // 非标量已被 queryScalarGuard 拒在前面；这里的 typeof 守卫只是防御性
      if (typeof value === 'string' && value) candidates.push(value.slice(0, CANDIDATE_MAX_LENGTH));
    }
  }
  return candidates;
};

const findSignature = (req) => {
  for (const candidate of collectCandidates(req)) {
    if (INJECTION_PATH_RE.test(candidate)) {
      return stripControlChars(candidate, 128);
    }
  }
  return null;
};

const guardedRecord = guardDetection('SQLi 特征留痕', async ({ req, sample }) => {
  incSecurityAlert('sql_injection_attempt', 'medium');
  AuditLog.record({
    action: 'sql_injection_attempt',
    category: 'security',
    userId: req.user?.userId,
    username: req.user?.username || 'anonymous',
    sessionId: req.user?.sessionId || null,
    fingerprint: computeFingerprint(req),
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: stripControlChars(req.get('user-agent'), 512),
    success: false, // detect-only：服务端已转义/白名单校验，尝试未得手
    riskLevel: 'medium',
    riskFactors: ['injection_signature'],
    reason: stripControlChars(`注入特征命中：${sample}`, 512),
  });
  // 命中即标记取证：后续请求全量捕获（与扫描探测同族联动；标记内部吞错计数）
  markForensicTarget(auditClientAddress(req).ip, {
    reason: 'injection_signature',
    source: 'injectionSignature',
    evidence: { sample },
  });
  logger.warn(`注入特征已留痕：${sample}`);
});

/**
 * 注入特征检测中间件：命中即留痕 + 取证标记，**放行不阻断**。
 * @returns {import('express').RequestHandler}
 */
const injectionSignature = () => {
  return (req, res, next) => {
    const sample = findSignature(req);
    if (!sample) return next();
    const ip = auditClientAddress(req).ip;
    const fingerprint = `${ip}|${sample}`;
    const now = Date.now();
    pruneDedup(now);
    if (recentByFingerprint.get(fingerprint) > now) return next();
    recentByFingerprint.set(fingerprint, now + DEDUP_WINDOW_MS);
    setImmediate(() => guardedRecord({ req, sample }));
    return next();
  };
};

module.exports = { injectionSignature };
