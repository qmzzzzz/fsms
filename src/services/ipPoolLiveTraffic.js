/** 封段前的业务活跃度护栏（T6-3）：该网段内若仍有真实业务请求，拒绝封段。通用安全产品没有这条判据——它只属于本系统：封掉一栋楼的后果是消防报警报不上来，不是几个访客看到 403。 */
const logger = require('../utils/logger');
const AuditLog = require('../models/AuditLog');
const { ipMatchesEntry } = require('../utils/ipUtils');
const { cidrOf } = require('./ipPoolCluster');

/** 只看「人真的在用系统」的方法：GET 是浏览/查看（审计中间件默认全量记），写操作更是铁证。HEAD/OPTIONS 不算——探测脚本也会发。 */
const ACTIVITY_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

/** 默认 15 分钟：足够长到能看见「刚才还有人在这栋楼里干活」，又短到不会因为一台三天前在线过的设备永久挡住封禁 */
const DEFAULT_LOOKBACK_MS = 15 * 60 * 1000;

/** 候选上限：捞满即视为还有没看到的行，只能保守说有活动（见 segmentHasLiveTraffic） */
const CANDIDATE_LIMIT = 200;

const state = { checks: 0, refused: 0, lastError: null };

/** 把 IP 收敛到网段键：与聚类同一口径（复用 cidrOf，不另立一套切分算法） */
const segmentOfIp = (ip) => {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.split('.');
  if (parts.length === 4) return cidrOf(parts.slice(0, 3).join('.'));
  const groups = ip.split(':');
  if (groups.length >= 4) return cidrOf(groups.slice(0, 4).join(':'));
  return null;
};

// 取行漏斗只管「别把整张表捞进来」，判据由 ipMatchesEntry 出（本仓库唯一的 CIDR 包含判断）。
// 唯一硬要求是**超集**：窄一格就漏行，答 live:false 放行封禁（fail-open）；宽了只是多挡封禁。
const decGroup = (lo, hi) => {
  const out = [];
  const t1 = Math.floor(lo / 10);
  const t2 = Math.floor(hi / 10);
  for (let t = t1; t <= t2; t += 1) {
    const a = t === t1 ? lo % 10 : 0;
    const b = t === t2 ? hi % 10 : 9;
    out.push(String(t) + (a === b ? String(a) : '[' + a + '-' + b + ']'));
  }
  return out.length === 1 ? out[0] : '(?:' + out.join('|') + ')';
};

const hundredsAlt = (lo, hi) => {
  const h1 = Math.floor(lo / 100);
  const h2 = Math.floor(hi / 100);
  const out = [];
  for (let h = h1; h <= h2; h += 1) {
    const a = h === h1 ? lo % 100 : 0;
    const b = h === h2 ? hi % 100 : 99;
    out.push(String(h) + decGroup(a, b));
  }
  return out.length === 1 ? out[0] : '(?:' + out.join('|') + ')';
};

/** 0–255 的取值区间 → 正则：区间是掩码对齐的 2^k 连续段，故可用十进制位压缩 */
const octetAlt = (lo, hi) => {
  if (lo <= 0 && hi >= 255) return '[0-9]{1,3}';
  const out = [];
  const one = Math.min(hi, 9);
  if (lo <= one) out.push(lo === one ? String(lo) : '[' + lo + '-' + one + ']');
  const twoLo = Math.max(lo, 10);
  const twoHi = Math.min(hi, 99);
  if (twoLo <= twoHi) out.push(decGroup(twoLo, twoHi));
  const threeLo = Math.max(lo, 100);
  const threeHi = Math.min(hi, 255);
  if (threeLo <= threeHi) out.push(hundredsAlt(threeLo, threeHi));
  if (out.length === 1) return out[0];
  return '(?:' + out.join('|') + ')';
};

/** v4 取行：整段照抄、半段按对齐区间展开、余下每段任意；允许映射写法（::ffff:10.9.8.9）与点转义，少认一种写法就是漏行 */
const v4Funnel = (bits, base) => {
  const width = Number.isFinite(bits) ? Math.min(32, Math.max(0, bits)) : 24;
  const octets = base.split('.');
  const whole = Math.floor(width / 8);
  const rest = width % 8;
  const parts = [];
  for (let i = 0; i < whole && i < 4; i += 1) parts.push(String(Number(octets[i]) & 255));
  if (rest > 0 && whole < 4) {
    const size = 2 ** (8 - rest);
    const lo = Number(octets[whole]) & ~(size - 1);
    parts.push(octetAlt(lo, lo + size - 1));
  }
  while (parts.length < 4) parts.push('[0-9]{1,3}');
  return '^(?:[0-9a-fA-F:]*:)?' + parts.join('\\.') + '$';
};

/** v6 取行：只到第一个零组为止——零组在文本里的位置不固定（:: 会吞掉连续零组，2001:db8:0:0:1:: 可写成 2001:db8::1:2:3:4），字面写零组即漏行；非零组只额外允许前导零 */
const v6Funnel = (bits, base) => {
  const width = Number.isFinite(bits) ? Math.min(128, Math.max(0, bits)) : 64;
  const head = [];
  for (const g of base.split(':').slice(0, Math.floor(width / 16))) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g) || Number.parseInt(g, 16) === 0) break;
    head.push('0{0,3}' + g);
  }
  if (head.length === 0) return '^[0-9a-fA-F:]*$';
  return '^' + head.join(':') + '[0-9a-fA-F:]*$';
};

/** 该网段最近是否有真实业务请求。查不到（异常）时**保守返回有活动**：宁可挡下一次封禁，也不让一个可能封错的段放行 */
async function segmentHasLiveTraffic({
  cidr,
  model,
  lookbackMs = DEFAULT_LOOKBACK_MS,
  now = new Date(),
} = {}) {
  state.checks += 1;
  if (!cidr) return { live: false, scanned: 0, reason: null };
  const since = new Date(now.getTime() - lookbackMs);
  const bits = Number.parseInt(String(cidr).split('/')[1], 10);
  const base = cidr.split('/')[0];
  const isV6 = base.includes(':');
  const funnel = new RegExp(isV6 ? v6Funnel(bits, base) : v4Funnel(bits, base), isV6 ? 'i' : '');
  try {
    const found = await (model || AuditLog)
      .find({ createdAt: { $gte: since }, ip: funnel, method: { $in: ACTIVITY_METHODS } })
      .select({ ip: 1, method: 1, createdAt: 1, action: 1 })
      .sort({ createdAt: -1 })
      .limit(CANDIDATE_LIMIT)
      .lean();
    const rows = Array.isArray(found) ? found : [];
    const inSegment = rows.filter((r) => ipMatchesEntry(r.ip, cidr));
    const truncated = rows.length >= CANDIDATE_LIMIT;
    if (truncated && inSegment.length === 0) {
      state.refused += 1;
      return { live: true, scanned: rows.length, sample: [], reason: 'candidates_truncated' };
    }
    if (inSegment.length > 0) state.refused += 1;
    return {
      live: inSegment.length > 0,
      scanned: rows.length,
      sample: inSegment
        .slice(0, 5)
        .map((r) => ({ ip: r.ip, method: r.method, at: r.createdAt, action: r.action })),
      reason: null,
    };
  } catch (e) {
    state.refused += 1;
    state.lastError = String((e && e.message) || e).slice(0, 200);
    logger.warn('封段前的活跃度检查失败，按「有活动」保守处理：' + state.lastError);
    return { live: true, scanned: 0, sample: [], reason: 'check_failed' };
  }
}

const getLiveTrafficStats = () => ({ ...state });
const resetLiveTrafficState = () => {
  state.checks = 0;
  state.refused = 0;
  state.lastError = null;
};

module.exports = {
  ACTIVITY_METHODS,
  CANDIDATE_LIMIT,
  DEFAULT_LOOKBACK_MS,
  segmentOfIp,
  segmentHasLiveTraffic,
  getLiveTrafficStats,
  resetLiveTrafficState,
};
