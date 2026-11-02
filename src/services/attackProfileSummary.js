'use strict';

/**
 * IP 行为画像的纯派生层：输入已限窗、已限数据范围的审计行，输出分类/评分/证据。
 * 刻意不碰数据库：两次查询之间不共享累加状态；分类判据可脱离 Mongo 单测。取数与名单状态在 services/attackProfile.js。
 */

const {
  ATTACK_CATEGORIES: C,
  SUCCESS_LOGIN_SET,
  MAX_EVIDENCE_PER_CATEGORY,
  MAX_TOP_ITEMS,
  MAX_TIMELINE_BUCKETS,
  STUFFING_MIN_ACCOUNTS,
  SUSPICIOUS_SUCCESS_MIN_FAILURES,
} = require('../constants/attackProfile');
const { matchHoneypotName } = require('../constants/honeypotAccounts');
const {
  accountOf,
  isBlockedRow,
  timeOf,
  projectionOf,
  categoryOf,
  severityOf,
} = require('./attackProfileClassify');
const { scoreOf, verdictOf, riskLevelOf, suggestionsOf } = require('./attackProfileVerdict');

// 账号维度只认这两类"输了口令但没进去"的行；MFA 失败/临时锁定是同一攻击的后续阶段，
// 计失败次数仍用 CREDENTIAL_SET，但"试过哪些账号"只从这两类取，避免系统事件重复计入。
const ACCOUNT_FAILURE_ACTIONS = new Set(['login_failed', 'auth_failed']);

const increment = (map, key) => {
  if (!key) return;
  map.set(key, (map.get(key) || 0) + 1);
};

const topOf = (map, limit = MAX_TOP_ITEMS) =>
  [...map.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));

const pushEvidence = (stats, evidence) => {
  if (stats.evidence.length < MAX_EVIDENCE_PER_CATEGORY / 2) {
    stats.evidence.push(evidence);
    return;
  }
  stats.tail.push(evidence);
  if (stats.tail.length > MAX_EVIDENCE_PER_CATEGORY / 2) stats.tail.shift();
};

const createContext = (bucketMs, credentialCategory) => ({
  bucketMs,
  credentialCategory,
  categories: new Map(),
  pathCounts: new Map(),
  actionCounts: new Map(),
  accountCounts: new Map(),
  userAgentCounts: new Map(),
  timeline: new Map(),
  bucketCategories: new Map(),
  // 未分类行不进分类卡但仍是画像证据：黑名单命中这类「处置结果」被排除在分类外，丢掉会让已拦截事实消失。
  uncategorized: { count: 0, evidence: [], tail: [] },
  failedRequests: 0,
  failedLogins: 0,
  successfulLogins: 0,
  firstFailedLoginAt: null,
  lastFailedLoginAt: null,
  realSuccessAfterFailure: null,
  criticalRows: 0,
  firstSeen: null,
  lastSeen: null,
});

const trackSeen = (ctx, at) => {
  if (!ctx.firstSeen || at < ctx.firstSeen) ctx.firstSeen = at;
  if (!ctx.lastSeen || at > ctx.lastSeen) ctx.lastSeen = at;
};

const trackLogin = (ctx, row, at) => {
  const action = String(row.action || '');
  if (ACCOUNT_FAILURE_ACTIONS.has(action) && row.success !== true) {
    ctx.failedLogins += 1;
    increment(ctx.accountCounts, accountOf(row.username));
    if (!ctx.firstFailedLoginAt || at < ctx.firstFailedLoginAt) ctx.firstFailedLoginAt = at;
    if (!ctx.lastFailedLoginAt || at > ctx.lastFailedLoginAt) ctx.lastFailedLoginAt = at;
  }
  if (!SUCCESS_LOGIN_SET.has(action) || row.success !== true) return;
  ctx.successfulLogins += 1;
  // 蜜罐会话也会落 login_success：它不是真实突破，不参与"失败后成功"的升级判据
  if (matchHoneypotName(row.username) || !ctx.firstFailedLoginAt || at <= ctx.firstFailedLoginAt) {
    return;
  }
  if (!ctx.realSuccessAfterFailure || at < ctx.realSuccessAfterFailure) {
    ctx.realSuccessAfterFailure = at;
  }
};

const trackCategory = (ctx, row, at, code, blocked) => {
  if (!code) {
    ctx.uncategorized.count += 1;
    pushEvidence(ctx.uncategorized, projectionOf(row));
    return;
  }
  const stats =
    ctx.categories.get(code) ||
    ctx.categories
      .set(code, {
        code,
        count: 0,
        blockedCount: 0,
        successCount: 0,
        firstAt: at,
        lastAt: at,
        evidence: [],
        tail: [],
      })
      .get(code);
  stats.count += 1;
  if (blocked) stats.blockedCount += 1;
  else stats.successCount += 1;
  if (at < stats.firstAt) stats.firstAt = at;
  if (at > stats.lastAt) stats.lastAt = at;
  pushEvidence(stats, projectionOf(row));
};

const trackTimeline = (ctx, at, code, blocked) => {
  const bucketMs = ctx.bucketMs;
  const bucketStart = new Date(Math.floor(at.getTime() / bucketMs) * bucketMs).toISOString();
  const bucket = ctx.timeline.get(bucketStart) || { total: 0, blocked: 0 };
  bucket.total += 1;
  if (blocked) bucket.blocked += 1;
  ctx.timeline.set(bucketStart, bucket);

  if (!code) return;
  const set = ctx.bucketCategories.get(bucketStart) || new Set();
  set.add(code);
  ctx.bucketCategories.set(bucketStart, set);
};

const applyRow = (ctx, row) => {
  const at = timeOf(row);
  if (!at) return;
  // 分类含多条正则，逐行只算一次；时间线复用同一结果
  const blocked = isBlockedRow(row);
  const code = categoryOf(row, ctx.credentialCategory);
  trackSeen(ctx, at);
  if (blocked) ctx.failedRequests += 1;
  if (row.riskLevel === 'critical') ctx.criticalRows += 1;
  increment(ctx.pathCounts, row.path ? String(row.path).slice(0, 512) : '');
  increment(ctx.actionCounts, String(row.action || ''));
  increment(ctx.userAgentCounts, row.userAgent ? String(row.userAgent).slice(0, 180) : '');
  trackLogin(ctx, row, at);
  trackCategory(ctx, row, at, code, blocked);
  trackTimeline(ctx, at, code, blocked);
};

const finalizeCategories = (categories, failedLogins) => {
  for (const stats of categories.values()) {
    stats.evidence = [...stats.evidence, ...stats.tail];
    delete stats.tail;
    stats.severity = severityOf(stats.code, stats, failedLogins);
  }
  return [...categories.values()].sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
};

const buildTimeline = (ctx) => {
  const buckets = [...ctx.timeline.entries()]
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
    .slice(-MAX_TIMELINE_BUCKETS)
    .map(([bucketStart, counts]) => ({
      bucketStart,
      total: counts.total,
      blocked: counts.blocked,
      categories: [...(ctx.bucketCategories.get(bucketStart) || [])].slice(0, 10),
    }));
  return { unit: ctx.bucketMs === 60 * 60 * 1000 ? 'hour' : 'day', buckets };
};

/**
 * @param {object} args
 * @param {string} args.ip 已归一化的 IP
 * @param {Array<object>} args.rows 时间正序的审计行（已限窗、已限数据范围）
 * @param {number} args.total 库内命中总数（可大于 rows.length）
 * @param {boolean} args.truncated 是否只分析了最近 MAX_PROFILE_ROWS 条
 * @param {{hours:number,since:string,until:string}} args.window
 * @param {object} [args.containment] 名单状态（services/attackProfile 提供）
 * @param {boolean} [args.scopeLimited] 当前账号是否只看到部分数据范围
 */
const summarizeRows = ({ ip, rows, total, truncated, window, containment, scopeLimited }) => {
  const distinctAccounts = new Set(
    rows
      .filter(
        (row) => ACCOUNT_FAILURE_ACTIONS.has(String(row.action || '')) && row.success !== true
      )
      .map((row) => accountOf(row.username))
      .filter(Boolean)
  );
  const credentialCategory =
    distinctAccounts.size >= STUFFING_MIN_ACCOUNTS ? C.CREDENTIAL_STUFFING : C.BRUTE_FORCE;
  const bucketMs = window.hours <= 48 ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  const ctx = createContext(bucketMs, credentialCategory);
  for (const row of rows) applyRow(ctx, row);

  // 失败次数可能不足以叫"疑似突破"：3 次以内更像正常输错密码，只作为风险加分项
  const compromised =
    Boolean(ctx.realSuccessAfterFailure) && ctx.failedLogins >= SUSPICIOUS_SUCCESS_MIN_FAILURES;
  const categoryList = finalizeCategories(ctx.categories, ctx.failedLogins);
  const score = scoreOf(categoryList, compromised, ctx.criticalRows);
  const verdict = verdictOf({
    total,
    score,
    categories: categoryList,
    // 只有达到"疑似突破"门槛才参与 verdict；3-9 次失败后的成功仍按攻击/可疑计
    successAfterFailure: compromised,
  });
  const timeline = buildTimeline(ctx);
  // 峰值回答"这个 IP 最密集时有多猛"：按当前桶宽（小时/天）取请求数最多的桶
  const peakBucket = timeline.buckets.reduce(
    (peak, bucket) => (!peak || bucket.total > peak.total ? bucket : peak),
    null
  );

  const result = {
    ip,
    window,
    total,
    analyzed: rows.length,
    truncated,
    firstSeen: ctx.firstSeen,
    lastSeen: ctx.lastSeen,
    score,
    verdict,
    riskLevel: riskLevelOf(verdict),
    scopeLimited: Boolean(scopeLimited),
    stats: {
      failedRequests: ctx.failedRequests,
      successfulRequests: rows.length - ctx.failedRequests,
      failedLogins: ctx.failedLogins,
      successfulLogins: ctx.successfulLogins,
      distinctAccountsTried: distinctAccounts.size,
      distinctUserAgents: ctx.userAgentCounts.size,
      criticalRows: ctx.criticalRows,
      peakBucketRequests: peakBucket ? peakBucket.total : 0,
      peakBucketStart: peakBucket ? peakBucket.bucketStart : null,
      successAfterFailure: Boolean(ctx.realSuccessAfterFailure),
      suspiciousSuccessAt: compromised ? ctx.realSuccessAfterFailure : null,
      firstFailedLoginAt: ctx.firstFailedLoginAt,
      lastFailedLoginAt: ctx.lastFailedLoginAt,
      firstSeen: ctx.firstSeen,
      lastSeen: ctx.lastSeen,
    },
    categories: categoryList,
    uncategorized: {
      count: ctx.uncategorized.count,
      evidence: [...ctx.uncategorized.evidence, ...ctx.uncategorized.tail],
    },
    topPaths: topOf(ctx.pathCounts),
    topActions: topOf(ctx.actionCounts),
    topTargetAccounts: topOf(ctx.accountCounts),
    topUserAgents: topOf(ctx.userAgentCounts, 5),
    timeline,
    containment: containment || {
      degraded: true,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    },
  };
  result.suggestions = suggestionsOf({
    verdict,
    categories: categoryList,
    containment: result.containment,
    scopeLimited,
  });
  return result;
};

module.exports = { summarizeRows, categoryOf, severityOf, verdictOf };
