/** 取证溯源查询（T5-1，只读）：按 IP / 指纹 / 网段把「这个人做了什么、从哪些 IP 来的、触发过什么」拼出来。IP 过滤一律走 ipUtils.ipQueryCondition（查询侧与导出侧同一把尺子），不自己拼 ::ffff: 变体。返回摘要视图；请求/响应体只在被取证标记过的那几条里才有，这是设计而非缺失。 */
const { ipQueryCondition, normalizeIP } = require('../utils/ipUtils');

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;
const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

const SUMMARY_FIELDS = [
  'createdAt',
  'ip',
  'ipSegment',
  'method',
  'path',
  'action',
  'category',
  'userId',
  'username',
  'sessionId',
  'fingerprint',
  'trigger',
  'reason',
  'markedAt',
  'status',
  'device',
  'recordHash',
  'seq',
];

const state = { queries: 0, lastError: null };

const clampLimit = (n) => {
  const v = Number.parseInt(n, 10);
  if (!Number.isFinite(v) || v <= 0) return DEFAULT_LIMIT;
  return Math.min(v, MAX_LIMIT);
};

/** 查询条件：三个维度可任意组合；一个都不给直接返回 null（拒绝全表扫描当溯源用） */
const conditionOf = ({ ip, fingerprint, ipSegment, since, until }) => {
  const cond = {};
  if (ip) {
    // 解析不出的地址必须**明确拒绝**，不能让它退化成"匹配不到"的空结果： 运维看到"0 条"会以为这个 IP 干净，而真相是地址打错了。宁可报判据不可用。
    if (!normalizeIP(ip)) return null;
    const c = ipQueryCondition(ip);
    if (!c) return null;
    cond.ip = c;
  }
  if (fingerprint) cond.fingerprint = String(fingerprint).slice(0, 128);
  if (ipSegment) cond.ipSegment = String(ipSegment).slice(0, 64);
  if (!Object.keys(cond).length) return null;
  // 倒序区间（since > until）与"地址打错"同类：Mongo 会老实返回 0 条，而 0 条在运维眼里就是"这段时间没有异常"，所以也算判据不可用。
  const sinceMs = since ? new Date(since).getTime() : null;
  const untilMs = until ? new Date(until).getTime() : null;
  if (sinceMs !== null && untilMs !== null && sinceMs > untilMs) return null;
  cond.createdAt = {};
  if (since) cond.createdAt.$gte = new Date(since);
  if (until) cond.createdAt.$lte = new Date(until);
  return cond;
};

/** 时间线：按时间正序，只出摘要字段 */
async function traceTimeline({
  model,
  limit,
  now = new Date(),
  windowMs = DEFAULT_WINDOW_MS,
  ...keys
} = {}) {
  const since = keys.since || new Date(now.getTime() - windowMs);
  const until = keys.until || now;
  const cond = conditionOf({ ...keys, since, until });
  if (!cond) return { ok: false, reason: 'no_criteria', records: [] };
  state.queries += 1;
  const records = await model
    .find(cond)
    .select(SUMMARY_FIELDS.join(' '))
    .sort({ createdAt: 1 })
    .limit(clampLimit(limit))
    .lean();
  return { ok: true, since, until, count: records.length, records };
}

/** 同一指纹落到过哪些网段 —— 这正是「他的 ip 池」的答案 */
async function actorPools({ model, fingerprint, since, until, limit, now = new Date() } = {}) {
  if (!fingerprint) return { ok: false, reason: 'no_fingerprint', pools: [] };
  const cond = conditionOf({ fingerprint, since, until: until || now });
  if (!cond) return { ok: false, reason: 'no_criteria', pools: [] }; // $match:null 会匹配全表：判据不可用时必须在这里收手，聚合没有"0 条"那么无害
  state.queries += 1;
  const pools = await model.aggregate([
    { $match: cond },
    {
      $group: {
        _id: '$ipSegment',
        hits: { $sum: 1 },
        ips: { $addToSet: '$ip' },
        firstSeen: { $min: '$createdAt' },
        lastSeen: { $max: '$createdAt' },
      },
    },
    { $sort: { hits: -1 } },
    { $limit: clampLimit(limit || 50) },
  ]);
  return {
    ok: true,
    fingerprint,
    pools: pools.map((p) => ({
      segment: p._id,
      hits: p.hits,
      distinctIps: p.ips.length,
      firstSeen: p.firstSeen,
      lastSeen: p.lastSeen,
    })),
  };
}

/** 触发的分布键：子文档取 reason，旧数据若直接存了字符串则原样用；两者都没有返回 null（不参与分布） */
const reasonKeyOf = (trigger) => {
  if (typeof trigger === 'string') return trigger || null;
  if (trigger && typeof trigger.reason === 'string') return trigger.reason || null;
  return null;
};

/** 汇总视图：时间线要点 + 触发原因分布一起给出，避免为看清一件事打十次接口 */
async function traceActor(opts = {}) {
  const timeline = await traceTimeline(opts);
  if (!timeline.ok)
    return { ok: false, reason: timeline.reason, timeline: [], triggers: [], segments: [] };
  const triggers = {};
  const segments = {};
  for (const r of timeline.records) {
    // trigger 在模型里是**子文档** { reason, markedAt }（models/ForensicCapture.js），不是字符串。
    // 直接拿它当对象键会被 ToPropertyKey 折成 '[object Object]' ⇒ 分布恒为一条、界面还照渲。
    // 取 reason；reason 缺失的归到显式的 unknownReasonOf 桶，不静默丢弃。
    const key = reasonKeyOf(r.trigger);
    if (key) triggers[key] = (triggers[key] || 0) + 1;
    if (r.ipSegment) segments[r.ipSegment] = (segments[r.ipSegment] || 0) + 1;
  }
  const extra = opts.fingerprint ? await actorPools(opts) : { pools: [] };
  return {
    ok: true,
    since: timeline.since,
    until: timeline.until,
    count: timeline.count,
    truncated: timeline.count >= clampLimit(opts.limit),
    timeline: timeline.records,
    triggers,
    segments,
    pools: extra.pools,
  };
}

const getTraceStats = () => ({ ...state });
const resetTraceState = () => {
  state.queries = 0;
  state.lastError = null;
};

module.exports = {
  DEFAULT_LIMIT,
  MAX_LIMIT,
  DEFAULT_WINDOW_MS,
  SUMMARY_FIELDS,
  clampLimit,
  conditionOf,
  traceTimeline,
  actorPools,
  traceActor,
  getTraceStats,
  resetTraceState,
};
