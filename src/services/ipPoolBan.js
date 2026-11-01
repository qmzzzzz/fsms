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

/** 打字确认（GitHub 删仓库那套）：点两下挡不住手滑，逐字敲网段才挡得住 */
function hostCountOf(cidr) {
  const base = String(cidr || '').split('/')[0];
  if (base.includes(':')) return Infinity;
  const bits = Number.parseInt(String(cidr).split('/')[1], 10);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return Infinity;
  return 2 ** (32 - bits);
}

/** 需要打字确认的段：主机数 ≥ 256 或解析不出规模（解析不出就按最危险处理）；确认串的比对只在下方 typedConfirmMatches 里有一份（各写一次 trim 就是两把尺子） */
const needsTypedConfirmation = (cidr) => hostCountOf(cidr) >= HIGH_IMPACT_HOSTS;

const typedConfirmMatches = (typedConfirm, cidr) =>
  typeof typedConfirm === 'string' && typedConfirm.trim() === cidr;

const state = { requests: 0, applied: 0, refused: 0, failedEntries: 0, lastError: null };
const pending = new Map();

/** 拒绝出口只此一处：计数与返回同行（两处分记会让 live_traffic 记 2 次） */
const refuse = (reason, extra = {}) => {
  state.refused += 1;
  return { ok: false, reason, ...extra };
};

/** 拒绝原因必须点名：运维要知道是「被白名单挡住」还是「是全网段」 */
async function refusalOf(cidr, { operatorIp, reason, now = new Date() }) {
  if (!cidr) return CODES.unparsable_cidr;
  if (isFullRangeCIDR(cidr)) return CODES.full_range_cidr;
  const whites = await ipListService.findCoveringEntries(cidr, 'white');
  if (whites.length) return CODES.whitelist_covers;
  // 并集判据：两条 /1 的并集等价 /0（全族拒服 + 管理员自锁），只判单条会漏掉分片绕过；任一地址族铺满即拒（ADR-018 ①）
  const coverage = cidrUnionCoversAll([...(await ipListService.listActiveEntryIps('black')), cidr]);
  if (coverage.ipv4 || coverage.ipv6) return CODES.union_covers_family;
  if (operatorIp && entryCovers(cidr, operatorIp)) return CODES.operator_inside;
  // 业务活跃度护栏：封段会切断该网段全部业务流量，只要最近还有人正常用系统就不许封
  // ——消防系统「报不上来」不可逆（ADR-018 ②）。查不到时保守返回「有活动」。
  const live = await liveTraffic.segmentHasLiveTraffic({ cidr, now });
  if (live.live) return CODES.live_traffic_inside;
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
/** 上限只在插入之后执行：先削后插会稳定多留一张（削到 500 再插变 501） */
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
  if (refused) return refuse(refused, { cidr: normalized || cidr });
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
  operatorIp,
  now = new Date(),
  durationMs = DEFAULT_BAN_MS,
  permanent,
  model,
} = {}) {
  const ticket = pending.get(token);
  if (!ticket) return refuse(CODES.unknown_token);
  if (now.getTime() > ticket.expiresAt) {
    pending.delete(token);
    return refuse(CODES.token_expired, { cidr: ticket.cidr });
  }
  const targets = ticket.cidr.split(',').slice(0, MAX_BATCH);
  const judged = await ticketJudgementRefusal({ ticket, typedConfirm, targets, operatorIp });
  if (judged) return judged;
  pending.delete(token);
  // durationMs=0 ⇒ expiresAt=null（永久）。只有显式 permanent 才走永久，缺省走 DEFAULT_BAN_MS：缺省即永久是「漏填即最重」，方向反了（ADR-018 ④）
  const effectiveMs = permanent === true ? 0 : durationMs > 0 ? durationMs : DEFAULT_BAN_MS;
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
      // created 来自 blockIP 的驱动元数据（$locals，非持久化）：未知/缺省一律按「非本次新建」，回滚侧才敢保守不删
      const created = Boolean(r && r.$locals && r.$locals.created === true);
      return {
        cidr: one,
        banned,
        created,
        reason: (r && r.reason) || null,
        _id: (r && r._id) || null,
      };
    })
  );
  const bannedCount = results.filter((r) => r.banned).length;
  const rollback = await rollbackIfUnionCoversFamily(results, bannedCount);
  if (rollback) return refuse(CODES.union_covers_family, { cidr: ticket.cidr, ...rollback });
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

/** 消耗票据之前的三条判据（都不消耗票：打错字只是没确认，环境变了还能重试）。后两条必须在落库时刻重跑——取票与落库是两个时刻（ip-list 侧就在写入时刻现取，此处同尺） */
async function ticketJudgementRefusal({ ticket, typedConfirm, targets, operatorIp }) {
  if (needsTypedConfirmation(ticket.cidr) && !typedConfirmMatches(typedConfirm, ticket.cidr)) {
    return refuse(CODES.typed_confirmation_required, { cidr: ticket.cidr });
  }
  // 写入之前先看一次并集（与 requestBan 顺序一致）：名单可能在取票后被改成整族；先判就不会写完再删、也就不会删到别人的条目
  const prospective = cidrUnionCoversAll([
    ...(await ipListService.listActiveEntryIps('black')),
    ...targets,
  ]);
  if (prospective.ipv4 || prospective.ipv6) {
    return refuse(CODES.union_covers_family, {
      cidr: ticket.cidr,
      rolledBack: 0,
      rolledBackIds: [],
      skippedExisting: 0,
    });
  }
  if (operatorIp && targets.some((one) => entryCovers(one, operatorIp))) {
    return refuse(CODES.operator_inside, { cidr: ticket.cidr });
  }
  return null;
}

async function banRecommended({ clusters, operator, operatorIp, reason, now = new Date() } = {}) {
  // 只认 recommendBan + rotate_pool：verdict=shared_egress 的簇照样拿票会误伤整栋楼
  const targets = (clusters || []).filter((c) => c.recommendBan && c.verdict === 'rotate_pool');
  if (!targets.length) return { ok: false, reason: null, empty: true };
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

/** 落库后按数据库现状复检并集：申请与确认是两个时刻，名单在两者之间会变（可能正是另一张票造成的）。
 *  只回滚**本次新建**的条目：命中他人在写前已有的同值条目时那条不是我们写的，删掉等于被拒的操作静默移除一个既有封禁（F-25-8） */
async function rollbackIfUnionCoversFamily(results, bannedCount) {
  if (!bannedCount) return null;
  const coverage = cidrUnionCoversAll(await ipListService.listActiveEntryIps('black'));
  if (!coverage.ipv4 && !coverage.ipv6) return null;
  logger.warn('确认时并集铺满地址族，回滚本次写入', { cidrs: results.map((r) => r.cidr) });
  // 计数必须是**实际删掉的**而不是「打算删的」（bannedCount）：删除可能命中 0 条、抛错或无 _id，记「打算删 N 条」等于把一次没发生的回滚记成发生过。
  const rolledBackIds = [];
  const skippedIds = [];
  for (const r of results) {
    if (!r._id) continue;
    if (!r.created) {
      skippedIds.push(String(r._id));
      continue;
    }
    const removed = await ipListService.removeEntry(r._id, 'black').catch(() => null);
    if (removed && removed.deletedCount === 1) rolledBackIds.push(String(r._id));
  }
  return { rolledBack: rolledBackIds.length, rolledBackIds, skippedExisting: skippedIds.length };
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

/** 封段判据（不含票据/批量语义），供所有同权限位的写入入口共用；全网段/并集不在这里判。
 *  @returns {Promise<string|null>} 拒绝原因，null=可以封 */
async function segmentWriteRefusal({ cidr, operatorIp, typedConfirm, now = new Date() } = {}) {
  if (operatorIp && entryCovers(cidr, operatorIp)) return CODES.operator_inside;
  const live = await liveTraffic.segmentHasLiveTraffic({ cidr, now });
  if (live.live) return CODES.live_traffic_inside;
  if (needsTypedConfirmation(cidr) && !typedConfirmMatches(typedConfirm, cidr)) {
    return CODES.typed_confirmation_required;
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
  typedConfirmMatches,
  segmentWriteRefusal,
  refusalOf,
  requestBan,
  applyBan,
  banRecommended,
  getPoolBanStats,
  liveTrafficGuard: liveTraffic.segmentHasLiveTraffic,
  resetPoolBanState,
};
