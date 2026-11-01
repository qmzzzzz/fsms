/** 封段前的业务活跃度护栏（T6-3）：该网段内若仍有真实业务请求，拒绝封段。通用安全产品没有这条判据——它只属于本系统：封掉一栋楼的后果是消防报警报不上来，不是几个访客看到 403。 */
const logger = require('../utils/logger');
const AuditLog = require('../models/AuditLog');
const { cidrOf } = require('./ipPoolCluster');

/** 只看「人真的在用系统」的方法：GET 是浏览/查看（审计中间件默认全量记），写操作更是铁证。HEAD/OPTIONS 不算——探测脚本也会发。 */
const ACTIVITY_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

/** 默认 15 分钟：足够长到能看见「刚才还有人在这栋楼里干活」，又短到不会因为一台三天前在线过的设备永久挡住封禁 */
const DEFAULT_LOOKBACK_MS = 15 * 60 * 1000;

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
  // 前缀只取掩码对齐的段：带"0."或 ceil(bits/8) 会让 /25–/32 恒 live:false 且静默（多算活动是有意的）。
  const v4PrefixOf = () => {
    const width = Number.isFinite(bits) ? Math.min(32, Math.max(0, bits)) : 24;
    // 完整落在网段里的段数：/24→3、/25–/32→3、/16→2、/20→2
    const whole = Math.floor(width / 8);
    const octets = base.split('.');
    const kept = Math.min(4, Math.max(1, whole));
    // /32 是单主机：整段照抄，否则会把同 /24 的其他主机算进来
    return octets.slice(0, width >= 32 ? 4 : kept).join('.');
  };
  // 前缀里必须转义正则元字符，否则 . 会变成通配符，把 203x0 也匹配进来
  const prefix = (isV6 ? base : v4PrefixOf()).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // /32（单主机）是**精确匹配**：再拼一个尾随点会变成"该地址加任意后缀"，恒不命中任何行；
  // 其余档位的点分前缀后面必须跟点，否则 /^10\.9\.8/ 会把 10.9.80.x 也算进来。
  const exactHost = !isV6 && Number.isFinite(bits) && bits >= 32;
  const ipRe = new RegExp('^' + prefix + (isV6 ? '(?:[0-9a-fA-F:]*)?$' : exactHost ? '$' : '\\.'));
  try {
    const found = await (model || AuditLog)
      .find({ createdAt: { $gte: since }, ip: ipRe, method: { $in: ACTIVITY_METHODS } })
      .select({ ip: 1, method: 1, createdAt: 1, action: 1 })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    const rows = Array.isArray(found) ? found : [];
    return {
      live: rows.length > 0,
      scanned: rows.length,
      sample: rows
        .slice(0, 5)
        .map((r) => ({ ip: r.ip, method: r.method, at: r.createdAt, action: r.action })),
      reason: null,
    };
  } catch (e) {
    state.lastError = String((e && e.message) || e).slice(0, 200);
    logger.warn(`封段前的活跃度检查失败，按「有活动」保守处理：${state.lastError}`);
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
  DEFAULT_LOOKBACK_MS,
  segmentOfIp,
  segmentHasLiveTraffic,
  getLiveTrafficStats,
  resetLiveTrafficState,
};
