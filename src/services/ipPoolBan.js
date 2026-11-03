// IP 池 CIDR 封禁（T6-2）：永远人工、票据 sharedCache 外置语义、fail-closed 与审计口径见 docs/ip-pool-ban.md
const crypto = require('crypto');
const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const { isFullRangeCIDR, entryCovers, normalizeCIDR } = require('../utils/ipUtils');
const { CODES } = require('../constants/banRefusalReason');
const ipListService = require('./ipListService');
const { cidrUnionCoversAll } = require('../utils/cidrCoverage');
const liveTraffic = require('./ipPoolLiveTraffic');
const sharedCache = require('./sharedCache');
const { recordDurably } = require('./auditOutbox');
const { buildAuditEntry } = require('./ipPoolBanAudit');

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

const state = { requests: 0, applied: 0, refused: 0, failedEntries: 0, lastErrors: [] };
const LAST_ERRORS_LIMIT = 5;
const recordAuditError = (action, err) => {
  state.lastErrors.push({
    action,
    timestamp: new Date().toISOString(),
    error: String(errText(err)).slice(0, 200),
  });
  if (state.lastErrors.length > LAST_ERRORS_LIMIT) {
    state.lastErrors.splice(0, state.lastErrors.length - LAST_ERRORS_LIMIT);
  }
};

/** 待确认票据的共享存储键前缀（B2 外置；键语义/TTL/fail-closed 方向登记见 docs/adr/ADR-005 的切换点清单） */
const TICKET_KEY_PREFIX = 'ip_pool_ban:ticket:';
const ticketKey = (token) => TICKET_KEY_PREFIX + token;

/** 判据失败后票据**原样写回**（「敲错不消耗」，ADR-018 ③）：剩余 TTL 随票走（存进票对象），写回与下次取删共用同一份时效。 */
async function writeBackTicket(ticket) {
  const remainingMs = ticket.expiresAt - Date.now();
  if (remainingMs <= 0) return; // 已自然过期：不写回（下次尝试按 unknown_token 拒，与过期同结局）
  ticket.ttlMs = remainingMs;
  const landed = await sharedCache.set(ticketKey(ticket.token), ticket, remainingMs);
  if (!landed) {
    // landed=false ⇒ 共享层没收到：立即抹掉本地副本，否则 getDel 的内存回退会把它当共享层真值读回来（一次性消费被架空）
    sharedCache.dropLocalCopy(ticketKey(ticket.token));
  }
}

const refuse = (reason, extra = {}) => {
  state.refused += 1;
  return { ok: false, reason, ...extra };
};

async function refusalOf(cidr, { operatorIp, reason, now = new Date() }) {
  if (!cidr) return CODES.unparsable_cidr;
  if (isFullRangeCIDR(cidr)) return CODES.full_range_cidr;
  const whites = await ipListService.findCoveringEntries(cidr, 'white');
  if (whites.length) return CODES.whitelist_covers;
  // 并集判据：两条 /1 的并集等价 /0（全族拒服 + 管理员自锁），只判单条会漏掉分片绕过；任一地址族铺满即拒（ADR-018 ①）
  const coverage = cidrUnionCoversAll([...(await ipListService.listActiveEntryIps('black')), cidr]);
  if (coverage.ipv4 || coverage.ipv6) return CODES.union_covers_family;
  if (operatorIp && entryCovers(cidr, operatorIp)) return CODES.operator_inside;
  // 业务活跃度护栏：封段切断全部业务流量，消防「报不上来」不可逆（ADR-018 ②）；查不到时保守按「有活动」
  const live = await liveTraffic.segmentHasLiveTraffic({ cidr, now });
  if (live.live) return CODES.live_traffic_inside;
  if (!reason) return CODES.reason_required;
  return null;
}

/** 生成待确认请求：只有确认过的那张票能封，票与 cidr 绑死、有时效、只能用一次 */
async function requestBan({
  cidr,
  reason,
  operator,
  operatorUsername,
  operatorIp,
  now = new Date(),
} = {}) {
  state.requests += 1;
  const normalized = normalizeCIDR(cidr);
  const refused = await refusalOf(normalized, { operatorIp, reason, now });
  if (refused) return refuse(refused, { cidr: normalized || cidr });
  const ticket = {
    token: crypto.randomBytes(16).toString('hex'),
    cidr: normalized,
    reason,
    operator,
    // B1：票据同时带 userId 与用户名——确认时刻的审计才不必拿 ObjectId 冒充 username
    operatorUsername: operatorUsername || null,
    expiresAt: now.getTime() + CONFIRM_TTL_MS,
  };
  // setIfAbsent 原子占位：false 只可能是共享层不可用（按重复处理返回 false），此时拒绝出票（fail-closed，拒绝码借用 unknown_token）
  const issued = await sharedCache.setIfAbsent(ticketKey(ticket.token), ticket, CONFIRM_TTL_MS);
  if (!issued) return refuse(CODES.unknown_token, { cidr: normalized });
  return {
    ok: true,
    token: ticket.token,
    cidr: normalized,
    expiresAt: new Date(ticket.expiresAt),
    needTypedConfirm: needsTypedConfirmation(normalized),
    hostCount: hostCountOf(normalized),
  };
}

// B3：可靠 outbox 写入（先落 DB、失败转审计 WAL；WAL 未启用时重抛由 asyncHandler 转 500）；条目构造在 ipPoolBanAudit.js
const writeAuditDurably = async (entry, req) => {
  try {
    const persisted = await recordDurably(entry, {
      auditAction: 'ip_list_change',
      req,
    });
    if (persisted === null) {
      recordAuditError('ip_blacklist_added', '审计未直写 DB（已转审计 WAL 待重放）');
    }
  } catch (e) {
    recordAuditError('ip_blacklist_added', e);
    throw e;
  }
};

/** 落库并审计。每条如实上报 banned 与否——addToBlacklist 从不抛错，按「没抛异常」记成功会谎报 */
async function applyBan({
  token,
  typedConfirm,
  operatorIp,
  req,
  now = new Date(),
  durationMs = DEFAULT_BAN_MS,
  permanent,
} = {}) {
  // 第一步就是原子取删（getDel）：并发双击确认只有一方拿得到票，取代旧两步形态的双花窗口
  const ticket = token ? await sharedCache.getDel(ticketKey(String(token))) : null;
  if (!ticket) return refuse(CODES.unknown_token);
  if (now.getTime() > ticket.expiresAt) {
    // 已消费不写回：过期票本就该作废（下次尝试按 unknown_token 拒）
    return refuse(CODES.token_expired, { cidr: ticket.cidr });
  }
  const targets = ticket.cidr.split(',').slice(0, MAX_BATCH);
  const judged = await ticketJudgementRefusal({ ticket, typedConfirm, targets, operatorIp });
  if (judged) {
    await writeBackTicket(ticket); // 敲错不消耗（ADR-018 ③）：票据原样写回剩余 TTL
    return judged;
  }
  // durationMs=0 ⇒ expiresAt=null（永久）。只有显式 permanent 才走永久，缺省走 DEFAULT_BAN_MS：缺省即永久是「漏填即最重」，方向反了（ADR-018 ④）
  const effectiveMs = permanent === true ? 0 : durationMs > 0 ? durationMs : DEFAULT_BAN_MS;
  const results = await Promise.all(
    targets.map(async (one) => {
      const r = await ipListService.blockIP(one, {
        reason: ticket.reason,
        durationMs: effectiveMs,
        source: 'manual',
      });
      // blockIP 返回落库文档（findOneAndUpdate 结果），不是 {banned:true}；按 r.banned 判生效会让计数恒 0
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
  const entry = buildAuditEntry({
    ticket,
    req,
    results,
    bannedCount,
    success: bannedCount === results.length,
  });
  await writeAuditDurably(entry, req);
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

async function banRecommended({
  clusters,
  operator,
  operatorUsername,
  operatorIp,
  reason,
  now = new Date(),
} = {}) {
  // 只认 recommendBan + rotate_pool：verdict=shared_egress 的簇照样拿票会误伤整栋楼
  const targets = (clusters || []).filter((c) => c.recommendBan && c.verdict === 'rotate_pool');
  if (!targets.length) return { ok: false, reason: null, empty: true };
  const requested = [];
  for (const c of targets.slice(0, MAX_BATCH)) {
    const r = await requestBan({
      cidr: c.cidr,
      reason: reason || `ip_pool:${c.verdict}`,
      operator,
      operatorUsername,
      operatorIp,
      now,
    });
    requested.push({ segment: c.segment, ...r });
  }
  return { ok: true, requested };
}

// 落库后按数据库现状复检并集（申请与确认是两个时刻）；只回滚**本次新建**的条目，删他人既有同值条目等于静默移除既有封禁（F-25-8）
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

const getPoolBanStats = () => ({
  ...state,
  // B2：票据外置 sharedCache，进程内无从计数，多实例下本进程数字也代表不了全局——宁可空缺不给假数
  pending: null,
});
const resetPoolBanState = () => {
  state.requests = 0;
  state.applied = 0;
  state.refused = 0;
  state.failedEntries = 0;
  state.lastErrors = [];
};

/** 封段判据（不含票据/批量语义），供所有同权限位写入入口共用；全网段/并集不在这里判。@returns {Promise<string|null>} 拒绝原因，null=可以封 */
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
  HIGH_IMPACT_HOSTS,
  TICKET_KEY_PREFIX,
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
