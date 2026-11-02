'use strict';

/**
 * IP 攻击行为画像的取数层。
 *
 * 输入只有一个 IP + 时间窗；输出是「这个地址在窗口内做过什么、被拦了多少、现在是
 * 什么处置状态」。数据源是 append-only 的 AuditLog——攻击行为分类的证据必须与
 * 审计留存同源，不能另建一套可以绕开的统计表。
 * 数据范围由调用方（控制器）用 applyAuditDataScope 先翻译成 scopeFilter 传入：
 * 画像接口比审计列表多做了一层聚合，但可见范围不得因此放宽。
 */

const AuditLog = require('../models/AuditLog');
const ipListService = require('./ipListService');
const { normalizeIP, ipQueryCondition, isPrivateOrLoopback } = require('../utils/ipUtils');
const { summarizeRows } = require('./attackProfileSummary');
const {
  DEFAULT_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
  MAX_PROFILE_ROWS,
} = require('../constants/attackProfile');

// 画像只取判定所需的最小列：不碰 body / 头袋 / 响应正文；证据链原始载荷走单条详情，
// 不复制可被批量拉取的敏感通道。`_id` 只作证据行定位键，不是新增的可读字段。
const PROFILE_FIELDS = [
  '_id',
  'timestamp',
  'action',
  'category',
  'success',
  'statusCode',
  'refusalReason',
  'riskLevel',
  'riskFactors',
  'method',
  'path',
  'username',
  'userAgent',
  'reason',
].join(' ');

const resolveWindow = (hours, now) => {
  const parsed = Number.parseInt(String(hours ?? ''), 10);
  const resolved = Number.isFinite(parsed)
    ? Math.min(MAX_WINDOW_HOURS, Math.max(1, parsed))
    : DEFAULT_WINDOW_HOURS;
  const until = now instanceof Date ? now : new Date(now);
  const since = new Date(until.getTime() - resolved * 60 * 60 * 1000);
  return { hours: resolved, since, until };
};

const projectEntry = (entry, listType) => ({
  listType,
  ip: entry.ip,
  reason: entry.reason || null,
  source: entry.source || null,
  targetUsername: entry.targetUsername || null,
  expiresAt: entry.expiresAt || null,
  createdAt: entry.createdAt || null,
});

/**
 * 名单状态是画像的"现在是否已被处置"，不是分类证据。
 * 名单查询失败只降级这一块：画像本身仍然可用，页面必须能区分"未封禁"与"没查到"。
 */
async function loadContainment(ip) {
  const { blackMatches, whiteMatches } = await ipListService.matchEntries(ip);
  const black = (blackMatches || []).map((entry) => projectEntry(entry, 'black'));
  const white = (whiteMatches || []).map((entry) => projectEntry(entry, 'white'));
  return {
    degraded: false,
    blacklisted: black.length > 0,
    whitelisted: white.length > 0,
    entries: [...black, ...white].slice(0, 10),
  };
}

/**
 * @param {object} args
 * @param {string} args.ip 用户输入的 IP（支持 IPv4/IPv6 单地址）
 * @param {number|string} [args.hours] 时间窗小时数（1-720，越界按默认 7 天）
 * @param {object} [args.scopeFilter] applyAuditDataScope 产出的 Mongo 条件
 * @param {boolean} [args.scopeLimited] 调用者是否只拥有部分数据范围
 * @param {Date} [args.now] 测试注入的当前时间
 */
async function buildAttackProfile({
  ip,
  hours,
  scopeFilter = {},
  scopeLimited = false,
  now = new Date(),
} = {}) {
  const normalized = normalizeIP(ip);
  if (!normalized) return { ok: false, reason: 'invalid_ip' };
  const ipCondition = ipQueryCondition(normalized);
  if (!ipCondition) return { ok: false, reason: 'invalid_ip' };

  const window = resolveWindow(hours, now);
  const condition = {
    ...scopeFilter,
    ip: ipCondition,
    timestamp: { $gte: window.since, $lte: window.until },
  };

  const [rows, containment] = await Promise.all([
    AuditLog.find(condition)
      .select(PROFILE_FIELDS)
      .sort({ timestamp: -1, _id: -1 })
      .limit(MAX_PROFILE_ROWS)
      .lean(),
    loadContainment(normalized).catch(() => ({
      degraded: true,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    })),
  ]);

  // 没打满行数上限时，取回条数就是命中总数：省掉一次 count 扫描
  const total =
    rows.length < MAX_PROFILE_ROWS ? rows.length : await AuditLog.countDocuments(condition);

  const chronological = rows.reverse();
  const summary = summarizeRows({
    ip: normalized,
    rows: chronological,
    total,
    truncated: total > chronological.length,
    window: {
      hours: window.hours,
      since: window.since.toISOString(),
      until: window.until.toISOString(),
    },
    containment,
    scopeLimited,
  });

  return {
    ok: true,
    ...summary,
    isPrivate: isPrivateOrLoopback(normalized),
  };
}

module.exports = { buildAttackProfile, PROFILE_FIELDS, resolveWindow, loadContainment };
