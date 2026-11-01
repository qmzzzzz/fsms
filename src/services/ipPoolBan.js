/** IP 池的 CIDR 封禁（T6-2）。**永远人工**：网段封禁不做自动化，`IP_POOL_BAN_ALLOW_AUTO` 已移除（留着「默认关但能开」等于给未来留一个可以误开的开关，而误开的代价是封掉一栋楼的消防上报）。自动封禁的正确形态是单 IP 递进式（见 rateLimitEscalationBan.escalateIp：1h→4h→24h→7d），误伤半径只有一个人且可逆。 */
const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const { isFullRangeCIDR, entryCovers, normalizeCIDR } = require('../utils/ipUtils');
const { CODES } = require('../constants/banRefusalReason');
const ipListService = require('./ipListService');
const { cidrUnionCoversAll } = require('../utils/cidrCoverage');
const liveTraffic = require('./ipPoolLiveTraffic');

const DEFAULT_BAN_MS = 24 * 60 * 60 * 1000;
const MAX_BATCH = 20;
const CONFIRM_TTL_MS = 10 * 60 * 1000;
/** 网段规模超过这个值即视为高危：/24 = 256 个地址，再大就很容易罩住整栋楼或整个园区 */
const HIGH_IMPACT_HOSTS = 256;

/** 高危网段要做打字确认（GitHub 删仓库那套）：点两下按钮挡不住手滑，逐字敲网段才挡得住 */
function hostCountOf(cidr) {
  const base = String(cidr || '').split('/')[0];
  if (base.includes(':')) return Infinity;
  const bits = Number.parseInt(String(cidr).split('/')[1], 10);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return Infinity;
  return 2 ** (32 - bits);
}

/** 需要打字确认的段：主机数 ≥ 256 或解析不出规模（解析不出就按最危险处理） */
const needsTypedConfirmation = (cidr) => hostCountOf(cidr) >= HIGH_IMPACT_HOSTS;

const state = { requests: 0, applied: 0, refused: 0, failedEntries: 0, lastError: null };
const pending = new Map();

/** 拒绝原因必须点名：运维要知道是「被白名单挡住」还是「是全网段」 */
async function refusalOf(cidr, { operatorIp, reason, now = new Date() }) {
  if (!cidr) return CODES.unparsable_cidr;
  if (isFullRangeCIDR(cidr)) return CODES.full_range_cidr;
  const whites = await ipListService.findCoveringEntries(cidr, 'white');
  if (whites.length) return CODES.whitelist_covers;
  // 并集判据：单条 /1 不是全网段，但 0.0.0.0/1 + 128.0.0.0/1 的并集等价 /0（全 IPv4 拒服、
  // 管理员自锁）。只判单条 /0 会漏掉这种分片绕过；任一地址族铺满即拒（ADR-018 ①）。
  const coverage = cidrUnionCoversAll([...(await ipListService.listActiveEntryIps('black')), cidr]);
  if (coverage.ipv4 || coverage.ipv6) return CODES.union_covers_family;
  if (operatorIp && entryCovers(cidr, operatorIp)) return CODES.operator_inside;
  // 业务活跃度护栏：封段会切断该网段全部业务流量，只要最近还有人正常用系统就不许封
  // ——消防系统「报不上来」不可逆（ADR-018 ②）。查不到时保守返回「有活动」。
  const live = await liveTraffic.segmentHasLiveTraffic({ cidr, now });
  if (live.live) {
    state.refused += 1;
    return CODES.live_traffic_inside;
  }
  if (!reason) return CODES.reason_required;
  return null;
}

/** 惰性清扫：TTL 只约束"能不能用"，不约束"占不占内存"（申请 5 张、11 分钟后确认 1 张，pending 从 5 只掉到 4）。
 *  每次出票前按 TTL 清一次再对总量封顶（超出按最早出票者丢）：被丢的票只让用户重申请。 */
const PENDING_MAX = 500;
const sweepPending = (nowMs) => {
  for (const [key, ticket] of pending) {
    if (nowMs > ticket.expiresAt) pending.delete(key);
  }
};
/** 上限只在**插入之后**执行：先削后插会稳定多留一张（削到 500 再插变 501） */
const trimPending = () => {
  while (pending.size > PENDING_MAX) {
    const oldest = pending.keys().next().value;
    if (oldest === undefined) break;
    pending.delete(oldest);
  }
};

/** 生成待确认请求：只有确认过的那张票能封，票与 cidr 绑死、有时效、只能用一次 */
async function requestBan({ cidr, reason, operator, operatorIp, now = new Date() } = {}) {
  state.requests += 1;
  sweepPending(now.getTime());
  const normalized = normalizeCIDR(cidr);
  const refused = await refusalOf(normalized, { operatorIp, reason, now });
  if (refused) {
    state.refused += 1;
    return { ok: false, reason: refused, cidr: normalized || cidr };
  }
  const ticket = {
    token: crypto.randomBytes(16).toString('hex'),
    cidr: normalized,
    reason,
    operator,
    expiresAt: now.getTime() + CONFIRM_TTL_MS,
  };
  pending.set(ticket.token, ticket);
  trimPending();
  return {
    ok: true,
    token: ticket.token,
    cidr: normalized,
    expiresAt: new Date(ticket.expiresAt),
    needTypedConfirm: needsTypedConfirmation(normalized),
    hostCount: hostCountOf(normalized),
  };
}

/** 落库并审计。每条如实上报 banned 与否——addToBlacklist 从不抛错，按「没抛异常」记成功会谎报 */
async function applyBan({
  token,
  typedConfirm,
  now = new Date(),
  durationMs = DEFAULT_BAN_MS,
  permanent,
  model,
} = {}) {
  const ticket = pending.get(token);
  if (!ticket) return { ok: false, reason: CODES.unknown_token };
  if (now.getTime() > ticket.expiresAt) {
    pending.delete(token);
    state.refused += 1;
    return { ok: false, reason: CODES.token_expired, cidr: ticket.cidr };
  }
  // 打字确认必须在**消耗票据之前**判定：打错字只是没确认，不是用掉了票（ADR-018 ③）
  if (needsTypedConfirmation(ticket.cidr)) {
    const typed = typeof typedConfirm === 'string' ? typedConfirm.trim() : '';
    if (typed !== ticket.cidr) {
      state.refused += 1;
      return { ok: false, reason: CODES.typed_confirmation_required, cidr: ticket.cidr };
    }
  }
  pending.delete(token);
  // durationMs=0 在 blockIP 里表示 expiresAt=null（永久）。缺省即永久是「漏填即最重」，
  // 方向反了：只有调用方显式声明 permanent 才走永久，缺省走 DEFAULT_BAN_MS（ADR-018 ④）。
  const effectiveMs = permanent === true ? 0 : durationMs > 0 ? durationMs : DEFAULT_BAN_MS;
  const targets = ticket.cidr.split(',').slice(0, MAX_BATCH);
  const results = await Promise.all(
    targets.map(async (one) => {
      const r = await ipListService.blockIP(one, {
        reason: ticket.reason,
        durationMs: effectiveMs,
        source: 'manual',
      });
      // blockIP 返回**落库文档**（findOneAndUpdate 结果），不是 {banned:true}；按 r.banned 判
      // 生效会让 bannedCount 恒 0、审计恒 success:false，而条目其实已落库（ADR-018 踩坑）。
      const banned = Boolean(r && (r.ip || r._id));
      if (!banned) state.failedEntries += 1;
      return { cidr: one, banned, reason: (r && r.reason) || null };
    })
  );
  const bannedCount = results.filter((r) => r.banned).length;
  if (bannedCount) state.applied += 1;
  const body = {
    cidr: ticket.cidr,
    reason: ticket.reason,
    operator: ticket.operator,
    results,
    bannedCount,
  };
  try {
    await (model || AuditLog).create({
      action: 'ip_blacklist_added',
      category: 'security',
      username: ticket.operator || 'system',
      body,
      success: bannedCount === results.length,
      riskLevel: 'high',
    });
  } catch (e) {
    state.lastError = errText(e).slice(0, 200);
    logger.warn(`IP 池封禁审计写入失败（封禁本身已生效，追溯性受损）：${state.lastError}`);
  }
  return { ok: true, cidr: ticket.cidr, bannedCount, results };
}

/** 一键封禁的编排入口：自动模式必须显式开启，且只对 rotate_pool 生效 */
async function banRecommended({ clusters, operator, operatorIp, reason, now = new Date() } = {}) {
  // 只对 recommendBan 且 verdict=rotate_pool 的段出票；**没有自动分支**，无参数可传即无
  // 开关可误开。只认 recommendBan 时，verdict=shared_egress 的簇照样拿票（会误伤整栋楼）。
  const targets = (clusters || []).filter((c) => c.recommendBan && c.verdict === 'rotate_pool');
  if (!targets.length) return { ok: false, reason: 'no_candidates' };
  const requested = [];
  for (const c of targets.slice(0, MAX_BATCH)) {
    const r = await requestBan({
      cidr: c.cidr,
      reason: reason || `ip_pool:${c.verdict}`,
      operator,
      operatorIp,
      now,
    });
    requested.push({ segment: c.segment, ...r });
  }
  return { ok: true, requested };
}

const getPoolBanStats = () => ({ ...state, pending: pending.size });
const resetPoolBanState = () => {
  state.requests = 0;
  state.applied = 0;
  state.refused = 0;
  state.failedEntries = 0;
  state.lastError = null;
  pending.clear();
};

/** 封段判据（不含票据/批量语义），供**所有**同权限位的写入入口共用（各用一把尺子等于没有护栏）。
 *  只补 ip-list 侧缺失的三条：全网段/并集由 guardFullRangeCIDR 处理，原因必填由 ip-list 服务端默认值承担。
 *  @returns {Promise<string|null>} 拒绝原因，null=可以封 */
async function segmentWriteRefusal({ cidr, operatorIp, typedConfirm, now = new Date() } = {}) {
  if (operatorIp && entryCovers(cidr, operatorIp)) return CODES.operator_inside;
  const live = await liveTraffic.segmentHasLiveTraffic({ cidr, now });
  if (live.live) return CODES.live_traffic_inside;
  if (needsTypedConfirmation(cidr)) {
    const typed = typeof typedConfirm === 'string' ? typedConfirm.trim() : '';
    if (typed !== cidr) return CODES.typed_confirmation_required;
  }
  return null;
}

module.exports = {
  DEFAULT_BAN_MS,
  MAX_BATCH,
  CONFIRM_TTL_MS,
  PENDING_MAX,
  HIGH_IMPACT_HOSTS,
  hostCountOf,
  needsTypedConfirmation,
  segmentWriteRefusal,
  refusalOf,
  requestBan,
  applyBan,
  banRecommended,
  getPoolBanStats,
  liveTrafficGuard: liveTraffic.segmentHasLiveTraffic,
  resetPoolBanState,
};
