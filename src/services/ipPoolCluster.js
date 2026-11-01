/** 取证数据里的 IP 池聚类（T6-1，只读）。判据是「同一网段内大量 IP 只有极少数指纹 ⇒ 一台机器在换 IP（代理池/肉鸡轮换），可以封段」；而「大量 IP + 大量指纹 ⇒ 更像办公 NAT/共享出口」，封段等于一次误伤整栋楼，所以只报不建议。段取自 ForensicCapture.ipSegment（utils/fingerprint 已定 IPv4 前三段 / IPv6 前四组），这里只把它转成 CIDR，不另起一套网段算法。 */
const { normalizeCIDR } = require('../utils/ipUtils');

const DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MIN_HITS = 20;
const DEFAULT_MIN_IPS = 4;
const DEFAULT_LIMIT = 50;

const state = { runs: 0, lastError: null };

/** 网段键转 CIDR：IPv4 前三段补 .0/24，IPv6 前四组补 ::/64。非法段返回 null（宁可漏报，不产出假 CIDR 去封） */
const cidrOf = (segment) => {
  if (typeof segment !== 'string' || !segment) return null;
  const raw = segment.includes(':') ? `${segment}::/64` : `${segment}.0/24`;
  return normalizeCIDR(raw);
};

/** 判定：IP 数够多、但指纹数远少于 IP 数 ⇒ 轮换池；指纹数与 IP 数同量级 ⇒ 共享出口 */
const verdictOf = ({ distinctIps, distinctFingerprints, minIps }) => {
  if (distinctIps < minIps) return 'too_few_ips';
  return distinctFingerprints <= Math.max(1, Math.floor(distinctIps / 4))
    ? 'rotate_pool'
    : 'shared_egress';
};

async function clusterIpPools({
  model,
  now = new Date(),
  windowMs = DEFAULT_WINDOW_MS,
  minHits = DEFAULT_MIN_HITS,
  minIps = DEFAULT_MIN_IPS,
  limit = DEFAULT_LIMIT,
} = {}) {
  const since = new Date(now.getTime() - windowMs);
  const rows = await model.aggregate([
    { $match: { createdAt: { $gte: since }, ipSegment: { $ne: '' } } },
    {
      $group: {
        _id: '$ipSegment',
        hits: { $sum: 1 },
        ips: { $addToSet: '$ip' },
        fps: { $addToSet: '$fingerprint' },
        firstSeen: { $min: '$createdAt' },
        lastSeen: { $max: '$createdAt' },
      },
    },
    { $match: { hits: { $gte: minHits } } },
    { $sort: { hits: -1 } },
    { $limit: limit },
  ]);
  state.runs += 1;
  const segments = rows.map((r) => {
    const cidr = cidrOf(r._id);
    const verdict = cidr
      ? verdictOf({ distinctIps: r.ips.length, distinctFingerprints: r.fps.length, minIps })
      : 'unparsable_segment';
    return {
      segment: r._id,
      cidr,
      hits: r.hits,
      distinctIps: r.ips.length,
      distinctFingerprints: r.fps.length,
      firstSeen: r.firstSeen,
      lastSeen: r.lastSeen,
      verdict,
      recommendBan: verdict === 'rotate_pool',
    };
  });
  return {
    since,
    until: now,
    segments,
    recommended: segments.filter((s) => s.recommendBan),
  };
}

const getClusterStats = () => ({ ...state });
const resetClusterState = () => {
  state.runs = 0;
  state.lastError = null;
};

module.exports = {
  DEFAULT_WINDOW_MS,
  DEFAULT_MIN_HITS,
  DEFAULT_MIN_IPS,
  DEFAULT_LIMIT,
  cidrOf,
  verdictOf,
  clusterIpPools,
  getClusterStats,
  resetClusterState,
};
