'use strict';

/**
 * IP 名单写入的两道前置护栏（自 ipListController 抽出：控制器已贴 max-lines 与 complexity 棘轮）。
 * 两者都以「写入后的并集/调用者位置/活跃流量」为判据，与控制器自身的校验/冲突检测分开。
 */

const ApiResponse = require('../utils/apiResponse');
const ApiError = require('../utils/ApiError');
const logger = require('../utils/logger');
const ipListService = require('../services/ipListService');
const { isFullRangeCIDR, normalizeIP, ipMatchesEntry } = require('../utils/ipUtils');
const { cidrUnionCoversAll } = require('../utils/cidrCoverage');
const { auditPath } = require('../utils/auditMeta');
const { auditClientAddress } = require('../utils/ipUtils');
const { clientIpForSecurityDecision } = require('../utils/ipUtils');
const {
  segmentWriteRefusal,
  needsTypedConfirmation,
  typedConfirmMatches,
} = require('../services/ipPoolBan');
const { CODES: REFUSAL } = require('../constants/banRefusalReason');

/** 加入后同类型名单的并集是否铺满某个地址族（调用方还要用它判"是否属于全网段口径"） */
const coveredFamiliesOf = async (normalizedIP, type) => {
  if (isFullRangeCIDR(normalizedIP)) return [normalizedIP.includes(':') ? 'IPv6' : 'IPv4'];
  const existing = await ipListService.listActiveEntryIps(type);
  const coverage = cidrUnionCoversAll([...existing, normalizedIP]);
  return [coverage.ipv4 && 'IPv4', coverage.ipv6 && 'IPv6'].filter(Boolean);
};

/**
 * 操作者是否已有**可用的救援路径**：来源 IP 被一条**永不过期**的白名单条目覆盖。三条不可放宽：
 *  - 取值用 clientIpForSecurityDecision（与拦截中间件同一把尺，否则带一个 XFF 就能造出假救援）；
 *  - 必须 !expiresAt（临时白 1h + 永久 /0 = 一小时后二次自锁，那时已无人能登录修）；
 *  - 覆盖按 CIDR 语义（运维的白名单通常是 /8 这类段，逼他加 /32 只会让白名单更碎）。
 */
const hasRescuePath = async (req) => {
  const operatorIp = normalizeIP(clientIpForSecurityDecision(req));
  if (!operatorIp) return false;
  const permanentWhite = await ipListService.listPermanentEntryIps('white');
  return permanentWhite.some((entry) => ipMatchesEntry(operatorIp, entry));
};

/**
 * 全网段写入**成功落库后**才调用：写一条 success:true 的 critical 越权痕迹。
 * 与拒绝侧同族（riskFactors 后缀区分 granted/attempt），SIEM 据此区分「加防线」与「未遂」。
 * 必须在 blockIP 与并发回滚复检都通过之后调——这两步任一失败都不存在「已加入」这件事。
 */
const recordFullRangeGrantIfGranted = (req) => {
  const pending = req.fullRangeGrant;
  if (!pending) return;
  req.fullRangeGrant = null;
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    body: { ip: pending.ip, type: pending.type },
    success: true,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_super_admin_grant'],
    reason: `超级管理员将 ${pending.ip} 加入${pending.type === 'black' ? '黑' : '白'}名单：该条目覆盖全部 ${pending.scope} 地址`,
  });
};

/**
 * 删除侧守护救援路径：删掉这条永久白之后，若仍有黑名单铺满某地址族，则操作者（以及任何人）
 * 将再也无法自救——连列表都读不到，拿不到 _id 去恢复。判据只在「删除会带走救援路径」时为真。
 * 与添加侧同一把尺（clientIpForSecurityDecision），否则一个 XFF 就能让两侧看到不同的地址。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardRescueRemoval = async (req, res, { entry, activeBlackIps }) => {
  if (entry.type !== 'white' || entry.expiresAt) return false;
  const covered = cidrUnionCoversAll(activeBlackIps);
  if (!covered.ipv4 && !covered.ipv6) return false;
  const remainingWhite = (await ipListService.listPermanentEntryIps('white')).filter(
    (ip) => ip !== entry.ip
  );
  const operatorIp = normalizeIP(clientIpForSecurityDecision(req));
  if (remainingWhite.some((ip) => ipMatchesEntry(operatorIp, ip))) return false;
  logger.warn('删除永久白名单会拆掉全网段黑名单的唯一救援路径', {
    ip: entry.ip,
    operator: req.user.username,
  });
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    body: { ip: entry.ip, type: entry.type },
    success: false,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_rescue_removal_attempt'],
    reason: `尝试删除 ${entry.ip}（覆盖 ${operatorIp} 的永久白名单）：黑名单已铺满地址族，删除后无人能自行解除封锁，已拒绝`,
  });
  ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
    message: '该条是全网段黑名单的唯一救援路径，删除后无人能自行解除封锁',
    params: { ip: entry.ip },
  });
  return true;
};

/** 缺救援路径的拒绝留痕：与放行/越权同族，后缀区分结局 */
const refuseNoRescuePath = (req, normalizedIP, scope) => {
  logger.warn('全网段黑名单写入被拒：操作者没有可用的救援路径', {
    ip: normalizedIP,
    operator: req.user.username,
  });
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    body: { ip: normalizedIP, type: 'black' },
    success: false,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_no_rescue_path'],
    reason: `尝试将 ${normalizedIP} 加入黑名单（覆盖全部 ${scope} 地址），但操作者来源 IP 未被永久白名单覆盖，写入后将无法自行解除，已拒绝`,
  });
};

/**
 * 全网段（/0）与"分片铺满"收口：这类条目一次性命中所有客户端——加黑即全站拒服且管理员
 * 自己也无法登录解除，加白使黑名单与限流整体失效。故仅内置超管可配置，两种结局都留高危痕迹
 * （成败都记 privilege_escalation；操作者判定只认生效角色）。超管放行也要逐字确认：确认门槛
 * 只问「影响面多大」，不问「是不是超管」——挡手滑不挡权限。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardFullRangeCIDR = async (
  req,
  res,
  { normalizedIP, type, coveredFamilies: pre = null }
) => {
  const coveredFamilies = pre || (await coveredFamiliesOf(normalizedIP, type));
  if (coveredFamilies.length === 0) return false;

  const scope = coveredFamilies.join('/');
  if (await ipListService.operatorIsSuperAdmin(req.user.userId)) {
    // 确认先于留痕：写成「已加入」的痕迹不能出现在一个其实没写进去的请求上（/0 恒需确认）
    const typedOk = typedConfirmMatches(req.body.typedConfirm, normalizedIP);
    if (needsTypedConfirmation(normalizedIP) && !typedOk) {
      ApiResponse.codeError(res, 'IP_SEGMENT_WRITE_REFUSED', {
        // expected 是**归一化后**的值：确认串比对的就是它，不回带的话
        // 用户敲 2001:DB8::/64 / 10.0.0.0/08 / ::ffff:10.0.0.0/104 一律 400 且无从得知该敲什么
        params: { reason: REFUSAL.typed_confirmation_required, expected: normalizedIP },
      });
      return true;
    }
    // 加黑 /0 = 全站拒服**且操作者自己也被拒**：此刻若没有一条覆盖操作者来源 IP 的永久白名单，
    // 写下去就再也解不开（连列表都读不到，拿不到 _id 去删）。故先验救援路径，再放行。
    if (type === 'black' && !(await hasRescuePath(req))) {
      refuseNoRescuePath(req, normalizedIP, scope);
      ApiResponse.codeError(res, 'IP_SEGMENT_WRITE_REFUSED', {
        params: { reason: REFUSAL.no_rescue_path, expected: normalizedIP },
      });
      return true;
    }
    logger.warn('超级管理员正在添加全网段名单', {
      ip: normalizedIP,
      type,
      coveredFamilies,
      operator: req.user.username,
    });
    // 允许侧留痕**推迟到落库成功后**（recordFullRangeGrantIfGranted）：留在这里的话，护栏之后的
    // 任何拒绝（白名单已覆盖/段护栏/并发回滚）都会留下一句「已将 /0 加入黑名单」的 success:true 痕迹，
    // 事后复盘会以为防线已经架上了。没有条目，就没有「已加入」。判据与拒绝侧同一 riskFactors 家族。
    req.fullRangeGrant = { ip: normalizedIP, type, scope };
    return false;
  }
  logger.warn('非超级管理员尝试添加全网段名单', {
    ip: normalizedIP,
    type,
    coveredFamilies,
    operator: req.user.username,
  });
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    userAgent: req.get('user-agent'),
    body: { ip: normalizedIP, type },
    success: false,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_attempt'],
    reason: `尝试将 ${normalizedIP} 加入${type === 'black' ? '黑' : '白'}名单（加入后覆盖全部 ${scope} 地址），权限不足`,
  });
  ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
    message: `该条目加入后，名单中的网段组合将覆盖全部 ${scope} 地址，会命中所有 IP；仅超级管理员可配置。如需限制特定范围请使用更精确的网段`,
    params: { ip: normalizedIP },
  });
  return true;
};

/**
 * 段写入护栏：加黑网段与 pool-ban 同一套判据（自伤/活跃流量/打字确认）。加白不走（只放行、
 * 不切业务，拦了没法解误封）；单地址不走（无"封段"语义）。
 *
 * **豁免只认「这一条本身是 /0」**，不认「并集铺满」：两者是不同判据。并集铺满说明"这条
 * 写下去会让名单覆盖整个地址族"——那正是更需要看活跃流量的场合，不是豁免理由。两者混用
 * 的实测后果：已有 128.0.0.0/1 时写 0.0.0.0/1（罩住一半 IPv4、含调用者自己）一路 200，
 * 而同样的 0.0.0.0/1 在名单为空时会被拒——**是否被拦取决于名单里已有什么**，判据自相矛盾。
 *
 * 而 /0 本身确实必须豁免：自伤与活跃流量两条对 /0 恒为真（任何请求都在 /0 里），照查等于
 * 永久拒绝，把"仅超管可配全网段"变成死代码。这类条目由 guardFullRangeCIDR 收口
 * （超管判定 + 逐字确认 + critical 审计）。**豁免的只是那两条判据，不是确认**：/0 影响面最大，
 * 恰恰是唯一无条件需要逐字敲的段。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardSegmentWrite = async (req, res, { normalizedIP, type, typedConfirm }) => {
  if (type !== 'black' || !normalizedIP.includes('/') || isFullRangeCIDR(normalizedIP))
    return false;
  const refusal = await segmentWriteRefusal({
    cidr: normalizedIP,
    operatorIp: normalizeIP(clientIpForSecurityDecision(req)),
    typedConfirm,
  });
  if (!refusal) return false;
  // expected 与全网段分支同口径：确认串比对的是归一化值，不回带它用户就不知道该敲什么
  ApiResponse.codeError(res, 'IP_SEGMENT_WRITE_REFUSED', {
    params: { reason: refusal, expected: normalizedIP },
  });
  return true;
};

/**
 * 并发并集复检（回滚式，round22 B2）：写入前的并集判据在**并发**下会双双放行。
 *
 * 缺陷形态（实测三轮全中）：两次并发 POST 分别写 ::/1 与 8000::/1，各自读快照时对方都还没落库，
 * 于是两条都通过 guardFullRangeCIDR 并都落库，事后并集铺满整个 IPv6 —— 与 /0 等价（全站拒服 +
 * 管理员自锁），而非内置超管本不该有这个能力。顺序提交时第二条会被正确拒绝，所以串行测试看不见它。
 *
 * 这里在**写入之后**再算一次并集：若此刻覆盖整族且操作者不是内置超管，就把**本次写入**回滚掉并回 403。
 * 「本次写入」按 blockIP 的 created 判据（`$locals.created === true`，与 pool-ban 侧 F-25-8 同一口径）：命中
 * 他人既有条目的重复写不是本次写入，删它＝被拒的操作静默解除既有封禁 ⇒ 只留痕 403、不动他人条目。
 *
 * 残留窗口（如实记录）：从本次 blockIP 落库到 removeEntry 落库之间（毫秒级，且要求两个请求恰好落在
 * 同一窗口），期间该族对新请求表现为全覆盖；进程若在两步之间崩溃，条目会残留（需靠人工/对账收敛）。
 * 比纯进程内互斥可靠的地方：判据落在数据库状态上，多实例部署同样成立。
 * 违规时抛 ApiError(403, FULL_RANGE_FORBIDDEN)；无违规时正常返回（调用方一条 await 即可，不需要分支）
 */
const enforceConcurrentUnionGuard = async (req, { normalizedIP, type, entry }) => {
  const coveredFamilies = await coveredFamiliesOf(normalizedIP, type);
  if (coveredFamilies.length === 0) return;
  if (await ipListService.operatorIsSuperAdmin(req.user.userId)) return;

  const created = Boolean(entry && entry.$locals && entry.$locals.created === true); // 只有本次新建的条目才归本次回滚（blockIP 的 $locals.created，口径同 pool-ban 侧 F-25-8）
  const skippedExisting = entry && entry._id && !created ? 1 : 0; // 命中他人既有条目时不动它：删它=被拒的操作静默解除既有封禁
  if (created) await ipListService.removeEntry(entry._id, type);
  const outcome = created ? '已回滚本次写入' : '本次未新建条目，未回滚（既有条目原样保留）';
  const scope = coveredFamilies.join('/');
  logger.warn(`并发写入铺满地址族，${outcome}`, {
    ip: normalizedIP,
    type,
    coveredFamilies,
    operator: req.user.username,
    skippedExisting,
  });
  ipListService.recordPrivilegeEscalation({
    action: 'privilege_escalation',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    ...auditClientAddress(req),
    userAgent: req.get('user-agent'),
    body: { ip: normalizedIP, type, skippedExisting },
    success: false,
    riskLevel: 'critical',
    riskFactors: ['full_range_cidr_concurrent_bypass'],
    reason: `并发写入 ${normalizedIP} 后${type === 'black' ? '黑' : '白'}名单并集覆盖全部 ${scope} 地址，${outcome}；仅超级管理员可配置全网段`,
  });
  // 抛错而不是自己写响应：控制器里就能是「一条 await」，不给 addIPEntry 增加分支
  // （该函数复杂度已贴 eslint complexity=15 棘轮）。err.code ⇒ errors.errorCode 由 errorHandler 统一映射。
  throw new ApiError(
    `并发写入后，名单中的网段组合将覆盖全部 ${scope} 地址，${outcome}；仅超级管理员可配置全网段`,
    403,
    { ip: normalizedIP, skippedExisting },
    'FULL_RANGE_FORBIDDEN'
  );
};

module.exports = {
  coveredFamiliesOf,
  guardFullRangeCIDR,
  recordFullRangeGrantIfGranted,
  guardSegmentWrite,
  guardRescueRemoval,
  enforceConcurrentUnionGuard,
};
