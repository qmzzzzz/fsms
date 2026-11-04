/** 取证溯源查询（T5-1，只读）：按 IP / 指纹 / 网段把「这个人做了什么、从哪些 IP 来的、触发过什么」拼出来。IP 过滤一律走 ipUtils.ipQueryCondition（查询侧与导出侧同一把尺子），不自己拼 ::ffff: 变体。返回摘要视图（行顶层带 status/reason，由 response.status / trigger.reason 提升）；请求/响应体只在被取证标记过的那几条里才有，这是设计而非缺失。「他的 ip 池」双路径：判据带指纹走 actorPools（全窗口完整池），按 IP/网段溯源走 derivedPools（从库内观测到的指纹派生）——换 IP 不换机器的直接证据在最常用的按 IP 入口上也要可见。 */
const { ipQueryCondition, normalizeIP } = require('../utils/ipUtils');

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;
const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// 摘要投影。这里只许写 ForensicCapture 真实存在的路径：状态码在 response.status、
// 触发原因在 trigger.reason 子文档里，模型没有顶层 status/reason/markedAt——
// 曾投影过这三个幽灵字段，读侧拿到的恒 undefined，界面「触发说明/状态码」两列永远渲染 '-'。
// 防复发闸在 tests/services/forensicTraceExport.test.js：逐条 path 对着 schema 验存在。
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
  'response.status',
  'device',
  'recordHash',
  'seq',
];

// 派生池的上限：$group 先按组命中截断再进 JS 归桶，防病态来源（上万指纹）把聚合拉爆
const DERIVED_GROUP_CAP = 400;
// 池只答 top N 指纹：溯源要的是「这几台机器从哪来」，不是全量报表
const MAX_DERIVED_FINGERPRINTS = 5;

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

/** 行摘要提升：模型把响应码与触发原因分别藏在 response.status / trigger.reason 子文档里，
 * 读侧（界面两列、签名导出）的行契约是顶层 status / reason——在这里一次性提升并拆掉
 * response 残壳（投影只带 status，不会丢正文；正文本来就不在摘要投影里）。 */
const liftSummaryRow = (row) => {
  row.status = (row.response && row.response.status) ?? null;
  delete row.response;
  // reasonKeyOf 兼容 trigger 为字符串的旧数据，与分布键同一把尺
  row.reason = reasonKeyOf(row.trigger);
  return row;
};

/** 时间线：按时间正序返回，只出摘要字段。limit 截断时取**最近** N 条（界面与导出都承诺「最近」而不是「最早」），再翻回正序供按时间线阅读 */
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
    .sort({ createdAt: -1 })
    .limit(clampLimit(limit))
    .lean();
  records.reverse();
  for (const r of records) liftSummaryRow(r);
  return { ok: true, since, until, count: records.length, records };
}

/** 同一指纹落到过哪些网段 —— 这正是「他的 ip 池」的答案（以判据身份为锚，全窗口完整）。
 * since 缺省补 7 天窗：不补的话 conditionOf 只挂 $lte，API 不传 since 就是无界聚合。 */
async function actorPools({ model, fingerprint, since, until, limit, now = new Date() } = {}) {
  if (!fingerprint) return { ok: false, reason: 'no_fingerprint', pools: [] };
  const cond = conditionOf({
    fingerprint,
    since: since || new Date(now.getTime() - DEFAULT_WINDOW_MS),
    until: until || now,
  });
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

/**
 * 非 指纹 判据（按 IP / 网段溯源）的「他的 ip 池」。
 *
 * actorPools 以判据身份为锚；本函数反过来以**库内观测到的指纹**为锚：把判据命中的
 * 记录按 {指纹, 网段} 分一次组，再归桶出 top N 指纹各自的网段池。按 IP 溯源是告警页
 * 最常见的入口，「同一设备指纹出现过的网段、按命中次数排序——换 IP 不换机器的直接
 * 证据」必须在这条路径上直接可见，而不是让运维从时间线里抄指纹再手动重查。
 * 明细在命中前 DERIVED_GROUP_CAP 组内取：极碎指纹（每段 1 次）可能漏段——这是取证
 * 辅助视图不是计量报表，页头 hint 已言明。无指纹的行归不了池，跳过（不造 unknown 桶
 * 冒充证据）。必须传 timeline 已解析的 since/until（traceActor 负责对齐），否则会退化
 * 成无上界聚合。
 */
async function derivedPools({ model, since, until, ...keys } = {}) {
  const cond = conditionOf({ ...keys, since, until });
  if (!cond) return { ok: false, reason: 'no_criteria', pools: [] };
  // 维度守卫（纵深防御）：conditionOf 认识的判据键一个都没有时（只剩时间窗），
  // 聚合等于拿全窗口当「池」答出去——判据不可用必须在这里收手，与 actorPools 同口径。
  // 当前 conditionOf 认 ip/ipSegment/指纹，这行在判据面收窄时也兜底。
  if (!cond.ip && !cond.ipSegment && !cond.fingerprint && !cond.deviceKey) {
    return { ok: false, reason: 'no_criteria', pools: [] };
  }
  state.queries += 1;
  const groups = await model.aggregate([
    { $match: cond },
    {
      $group: {
        _id: { fingerprint: '$fingerprint', segment: '$ipSegment' },
        hits: { $sum: 1 },
        ips: { $addToSet: '$ip' },
        firstSeen: { $min: '$createdAt' },
        lastSeen: { $max: '$createdAt' },
      },
    },
    { $sort: { hits: -1 } },
    { $limit: DERIVED_GROUP_CAP },
  ]);
  const byFingerprint = new Map();
  for (const g of groups) {
    const fp = g._id && g._id.fingerprint ? g._id.fingerprint : null;
    if (!fp) continue;
    if (!byFingerprint.has(fp)) byFingerprint.set(fp, { total: 0, rows: [] });
    const bucket = byFingerprint.get(fp);
    bucket.total += g.hits;
    bucket.rows.push({
      fingerprint: fp,
      segment: (g._id && g._id.segment) || null,
      hits: g.hits,
      distinctIps: g.ips.length,
      firstSeen: g.firstSeen,
      lastSeen: g.lastSeen,
    });
  }
  const top = [...byFingerprint.values()]
    .sort((a, b) => b.total - a.total)
    .slice(0, MAX_DERIVED_FINGERPRINTS);
  const pools = [];
  for (const bucket of top) {
    bucket.rows.sort((a, b) => b.hits - a.hits);
    pools.push(...bucket.rows);
  }
  return { ok: true, pools };
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
  // 池双路径：判据带指纹 ⇒ actorPools 给全窗口完整池；否则 derivedPools 从库内观测到的
  // 指纹派生。窗口必须用 timeline 已解析的 since/until，不能拿 opts 原始值重解析——
  // 缺省 since 时会退化成无上界聚合（与 timeline 的 7 天默认窗不一致）。
  const extra = opts.fingerprint
    ? await actorPools(opts)
    : await derivedPools({ ...opts, since: timeline.since, until: timeline.until });
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
  DERIVED_GROUP_CAP,
  MAX_DERIVED_FINGERPRINTS,
  SUMMARY_FIELDS,
  clampLimit,
  conditionOf,
  traceTimeline,
  actorPools,
  derivedPools,
  traceActor,
  getTraceStats,
  resetTraceState,
};
