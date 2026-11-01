/**
 * IP 黑白名单控制器（D-1 自 securityController 拆出）
 *
 * IP 名单的列表、命中查询、增删。名单读写经 models/IPBlacklist 快照机制同步到匹配层（中间件请求期判定），删除/加白后须失效降级封禁缓存。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
// 名单类型取值与 models/IPBlacklist 的 enum、securityRoutes 的 isIn 同源
const { IP_LIST_TYPES } = require('../constants/ipList');
const { rejectUnknownWriteFields } = require('./ipListWriteGuards');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
// 与 middleware/security.js 的匹配层守卫同一判据（IP 命中查询必须与请求期判定口径一致；判据住在 ipUtils）。
const {
  normalizeIP,
  normalizeCIDR,
  isAmbiguousIpText,
  lenientAddressHint,
  auditClientAddress,
} = require('../utils/ipUtils');
// 并集覆盖判定单独成文件（ipUtils 已贴 max-lines 棘轮）；分片铺满的收口见 ipListSegmentGuards
const { cidrRemovalBreaksFullCoverage } = require('../utils/cidrCoverage');
const { auditPath } = require('../utils/auditMeta');
const { invalidateIPBlockCache } = require('../middleware/security');
// 全网段收口与段写入护栏（自本文件抽出：max-lines/complexity 已贴棘轮）
const {
  coveredFamiliesOf,
  guardFullRangeCIDR,
  guardSegmentWrite,
  guardRescueRemoval,
  enforceConcurrentUnionGuard,
  recordFullRangeGrantIfGranted,
} = require('./ipListSegmentGuards');
// IP 黑白名单变更属于**安全配置**且业务状态已落库 ⇒ 审计必须先持久化（DB 或审计 WAL）才允许回成功；落库失败时转 WAL 待重放，不允许"回成功但可能零留痕"。
const { recordDurably } = require('../services/auditOutbox');
// 归属地展示增强（locate fail-soft 且带缓存；CIDR 网段条目无单一归属，返回 null）
const ipLocationService = require('../services/ipLocationService');
// A-4：名单读写与操作者超管判定下沉 service，控制器不再直连模型
const ipListService = require('../services/ipListService');

/**
 * 获取 IP 黑白名单列表 GET /api/security/ip-list?type=black|white&page=1&limit=20
 * 同时返回黑/白名单总数，前端无需再发一次不带 type 的请求做计数
 */
const getIPList = asyncHandler(async (req, res) => {
  // 路由挂了校验链却从不消费结果：?type=<script> 不命中 black/white 分支后 filter.type 根本不设置，静默退化成"全量返回"，调用方拿到两个名单的混合分页，计数也对不上。
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { type, page = 1, limit = 20 } = req.query;

  const now = new Date();
  const activeFilter = { $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] };

  const filter = { ...activeFilter };
  // 手写 `type === 'black' || type === 'white'` 是本族最坏的一种副本：给清单加一档后，路由校验（isIn 读同一份 constants）会放行新值，而这里**不认识**它就整条丢掉过滤
  // 条件 ⇒ `?type=<新档>` 返回全量名单而不是 400（口径同 F-138 的 userService）。
  if (IP_LIST_TYPES.includes(type)) filter.type = type;

  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 200);

  const { list, total, blackCount, whiteCount } = await ipListService.listEntries({
    filter,
    activeFilter,
    page: pageNum,
    limit: limitNum,
  });

  return ApiResponse.success(
    res,
    {
      // list 已是 lean()：直接浅拷贝挂归属地字段（CIDR 网段条目无单一归属，location 为 null，前端省略）
      list: list.map((entry) => ({ ...entry, location: ipLocationService.locate(entry.ip) })),
      counts: { black: blackCount, white: whiteCount },
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    },
    '获取成功'
  );
});

/**
 * IP 名单命中查询 GET /api/security/ip-list/query?ip=1.2.3.4
 * 返回该 IP 命中的全部黑/白名单记录（含 CIDR 网段与等价地址形式）；各列表按覆盖面最宽优先排序（如 /16 与 /24 同时命中时 /16 在首位），并给出最终生效判定（白名单优先）
 */
const queryIPMatch = asyncHandler(async (req, res) => {
  const rawIP = typeof req.query.ip === 'string' ? req.query.ip.trim() : '';

  // 歧义文本必须**明确拒答**，不能给 verdict。背景：早前匹配层（models/IPBlacklist.findMatchingEntries）对
  // `0177.0.0.1` / `0x7f.0.0.1` / `127.1` 这类形态一律返回空 ⇒ 请求期该客户端既不算命中黑名单也不算命中白名单。本接口若沿用同一判据却继续打印
  // `normalizedIP: '127.0.0.1'`，管理员读到的是「127.0.0.1 没被拦」——而名单里可能正封着 127.0.0.1，两者互相矛盾，且状态码 200 无任何提示。
  // 所以这里把"你问的是哪一个地址"问清楚：宽松解析出的规范地址回给对方，让其重查。
  //
  // 顺序不可颠倒：ipUtils 收紧后 normalizeIP 对歧义文本已经返回 null，若先跑下面那道 null 判断，"形态有歧义"会被误报成"请输入单地址"，
  // 管理员拿不到重查指引 ⇒ 本分支必须在 normalizeIP 之前。提示值走 lenientAddressHint（只显示宽松解释的结果，不参与任何判定）。
  if (isAmbiguousIpText(rawIP)) {
    const hint = lenientAddressHint(rawIP);
    return ApiResponse.codeError(res, 'IP_FORMAT_INVALID', {
      message:
        `"${rawIP}" 不是规范的点分十进制写法（前导零/十六进制/短写会被解释成另一个地址）。` +
        `请求期该文本按非法客户端处理，不参与名单匹配；如需查询地址 ${hint || '（无法确定）'} 的命中情况，请用规范写法重新查询。`,
      params: { ip: rawIP, normalizedIP: hint },
    });
  }

  // 仅接受单地址（IPv4/IPv6）；CIDR 网段不是合法的查询目标
  const normalizedIP = rawIP ? normalizeIP(rawIP) : null;
  if (!normalizedIP) {
    return ApiResponse.codeError(res, 'IP_SINGLE_REQUIRED');
  }

  const { blackMatches, whiteMatches } = await ipListService.matchEntries(rawIP);

  // 最终判定：白名单优先（豁免黑名单与限流）> 黑名单拦截 > 未命中放行
  const verdict =
    whiteMatches.length > 0 ? 'whitelisted' : blackMatches.length > 0 ? 'blocked' : 'allowed';

  return ApiResponse.success(
    res,
    {
      ip: rawIP,
      normalizedIP,
      verdict,
      // 各列表按覆盖面最宽优先排序，首位即主命中（如 /16 与 /24 并存时返回 /16）
      primaryBlack: blackMatches[0] || null,
      primaryWhite: whiteMatches[0] || null,
      blackMatches,
      whiteMatches,
    },
    '查询成功'
  );
});

/**
 * 名单入参校验与归一化（四道判据按原顺序，一步不增不减）：
 * ip 非空、type 枚举、IP/CIDR 强格式归一化、时长区间。
 *
 * 归一化必须发生在入库之前：以 ipaddr.js 把 IPv4 前导零与 IPv6 等价写法收敛成规范形式（`192.168.001.001 → 192.168.1.1`），入库文本才与请求期判定
 * （isBlocked / isWhitelisted）用的是同一个串——否则条目永远不命中，名单里留下一条"看着在防、其实没防"的死记录。
 * @returns {{trimmedIP: string, normalizedIP: string, hours: number}|null} null 表示已写出拒绝响应
 */
const normalizeListEntryRequest = (res, { ip, type, durationHours }) => {
  if (!ip || typeof ip !== 'string' || ip.trim().length === 0) {
    ApiResponse.codeError(res, 'IP_REQUIRED');
    return null;
  }
  if (!IP_LIST_TYPES.includes(type)) {
    ApiResponse.codeError(res, 'IP_LIST_TYPE_INVALID');
    return null;
  }
  const trimmedIP = ip.trim();
  const normalizedIP = trimmedIP.includes('/') ? normalizeCIDR(trimmedIP) : normalizeIP(trimmedIP);
  if (!normalizedIP) {
    ApiResponse.codeError(res, 'IP_FORMAT_INVALID');
    return null;
  }
  const hours = Number(durationHours) || 0;
  if (hours < 0 || hours > 24 * 365) {
    ApiResponse.codeError(res, 'IP_LIST_DURATION_OUT_OF_RANGE');
    return null;
  }
  return { trimmedIP, normalizedIP, hours };
};

/**
 * 白名单优先于黑名单：加黑时若该 IP/网段已被白名单覆盖则拒绝——信任标记不可被封禁覆盖，
 * 需先显式移出白名单。用 findCoveringEntries 而非 isWhitelisted：后者只接受单地址，
 * 传入 CIDR 会解析失败返回 false，使网段形式绕过冲突检测。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const guardWhitelistConflict = async (res, normalizedIP, type) => {
  if (type !== 'black') return false;
  const covering = await ipListService.findCoveringEntries(normalizedIP, 'white');
  if (covering.length === 0) return false;
  const coveredBy = covering.map((e) => e.ip).join('、');
  ApiResponse.codeError(res, 'IP_COVERED_BY_WHITELIST', {
    message: `该 IP 已被白名单条目（${coveredBy}）覆盖，白名单优先级高于黑名单；如需封禁请先将其移出白名单`,
    params: { coveredBy: coveredBy },
  });
  return true;
};

/**
 * 添加 IP 到黑/白名单 POST /api/security/ip-list
 * body: { ip, type: 'black'|'white', reason, durationHours }
 */
const addIPEntry = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  // 未知字段闸门排在取值之前：先确认"调用方说的字段我们都认识"再谈值是否合法，否则拼错字段名会被当成"没传"而落到永久默认值（判据见 ipListWriteGuards）
  if (rejectUnknownWriteFields(res, req.body)) return;

  const { ip, type = 'black', reason = 'manual_configuration', durationHours = 0 } = req.body;

  const parsed = normalizeListEntryRequest(res, { ip, type, durationHours });
  if (!parsed) return;
  const { trimmedIP, normalizedIP, hours } = parsed;

  const coveredFamilies = await coveredFamiliesOf(normalizedIP, type);
  if (await guardFullRangeCIDR(req, res, { normalizedIP, type, coveredFamilies })) return;
  if (
    await guardSegmentWrite(req, res, { normalizedIP, type, typedConfirm: req.body.typedConfirm })
  )
    return;

  const durationMs = hours > 0 ? hours * 60 * 60 * 1000 : 0;

  if (await guardWhitelistConflict(res, normalizedIP, type)) return;

  const entry = await ipListService.blockIP(normalizedIP, {
    type,
    reason: String(reason).slice(0, 200),
    durationMs,
    source: 'manual',
  });
  // 写入前那次并集判据在并发下会双双放行（两条互补 /1 = 整族覆盖），落库后按数据库状态复检并回滚；违规时抛 403
  await enforceConcurrentUnionGuard(req, { normalizedIP, type, entry });
  // 到这里条目已确实落库且未触发回滚 ⇒ 全网段的允许侧痕迹在此刻才写（写在护栏里会留下未写入的假痕迹）
  recordFullRangeGrantIfGranted(req);

  // L-14：先落白名单、再解除黑名单。反序（先解黑再写白）在写白失败时会留下一个「已解除封禁」的 IP——失败方向是放行（fail-open）。
  // 本序在解除失败时白名单已经生效，运行期白名单优先，重试也是幂等的。
  if (type === 'white') {
    await ipListService.unblockIP(normalizedIP, 'black');
    // 加白后立即失效降级封禁缓存，避免 DB 故障期沿用陈旧封禁判定误拦可信 IP
    invalidateIPBlockCache(normalizedIP);
  }

  // 审计日志
  await recordDurably(
    {
      action: type === 'black' ? 'ip_blacklist_added' : 'ip_whitelist_added',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      method: req.method,
      path: auditPath(req),
      body: { ip: normalizedIP, type, reason, durationHours: hours },
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: type === 'black' ? 'medium' : 'high',
    },
    { auditAction: 'ip_list_change', req }
  );
  // 置位必须晚于审计：审计重抛时这次 500 由全局审计接手记录（先置位 ⇒ 状态已变、审计为零）
  res.locals.skipGlobalAudit = true;

  logger.info('IP 已加入名单', {
    ip: normalizedIP,
    requestedIp: trimmedIP,
    type,
    operator: req.user.username,
  });

  return ApiResponse.success(res, entry, `已加入${type === 'black' ? '黑' : '白'}名单`);
});

/**
 * 从名单中移除 IP 记录 DELETE /api/security/ip-list/:id
 */
const removeIPEntry = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { id } = req.params;

  const entry = await ipListService.findEntryById(id);
  if (!entry) {
    return ApiResponse.codeError(res, 'IP_LIST_ENTRY_NOT_FOUND');
  }

  // ===== 修复：删除侧的对称约束 =====addIPEntry 对全网段（0.0.0.0/0 等）做了「仅内置超管可添加」的收口，
  // 删除侧却完全没有对等约束——持 security:config 的低阶管理员可先拆掉超管配置的全网段白名单（该白名单是限流豁免/信任标记的前提），
  // 再塞入恶意黑名单，等效于绕过整个 IP 管控体系。保护的不变量：谁能添加，才能删除。
  //
  // 判据必须是**并集**而不是单条 bits===0：两条互补的 /1 合起来等价于 /0，逐个删除时每一条都只是半张网，单条判据全都放行。这里只拦「删掉之后
  // 覆盖率下降」的那一步——全覆盖名单里一条冗余 /24 被删掉不会触发，避免误伤。覆盖判定与添加侧共用 cidrCoverage，读的也是同一份生效名单快照。
  // 删除侧的第二道判据：这条永久白是不是全网段黑名单的唯一救援路径（拆掉它 = 谁都解不开）
  if (
    await guardRescueRemoval(req, res, {
      entry,
      activeBlackIps: await ipListService.listActiveEntryIps('black'),
    })
  )
    return;

  const activeIps = await ipListService.listActiveEntryIps(entry.type);
  const broken = cidrRemovalBreaksFullCoverage(activeIps, entry.ip);
  const coveredFamilies = [broken.ipv4 && 'IPv4', broken.ipv6 && 'IPv6'].filter(Boolean);

  if (coveredFamilies.length > 0) {
    const scope = coveredFamilies.join('/');
    const isSuperAdmin = await ipListService.operatorIsSuperAdmin(req.user.userId);

    if (!isSuperAdmin) {
      logger.warn('非超级管理员尝试删除全网段名单', {
        ip: entry.ip,
        type: entry.type,
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
        ...auditClientAddress(req),
        userAgent: req.get('user-agent'),
        body: { ip: entry.ip, type: entry.type },
        success: false,
        riskLevel: 'critical',
        riskFactors: ['full_range_cidr_removal_attempt'],
        reason: `尝试移除铺满 ${scope} 地址的名单条目 ${entry.ip}（该条目是全覆盖的组成部分），权限不足`,
      });
      return ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
        message: `该条目是当前${entry.type === 'black' ? '黑' : '白'}名单覆盖全部 ${scope} 地址的组成部分，移除后覆盖将不再完整；仅超级管理员可移除`,
        params: { ip: entry.ip },
      });
    }

    logger.warn('超级管理员正在移除全网段名单', {
      ip: entry.ip,
      type: entry.type,
      coveredFamilies,
      operator: req.user.username,
    });
  }

  // removeById 内含名单快照失效，保证下一次匹配立即读到删除结果
  await ipListService.removeEntry(id, entry.type);

  // 解除黑名单后必须同步失效降级封禁缓存，否则 DB 故障期该 IP 仍会被陈旧缓存拦截（表现为「界面已解封但依然 403」）
  if (entry.type === 'black') {
    invalidateIPBlockCache(entry.ip);
  }

  // 审计日志
  await recordDurably(
    {
      action: entry.type === 'black' ? 'ip_blacklist_removed' : 'ip_whitelist_removed',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      method: req.method,
      path: auditPath(req),
      body: { ip: entry.ip, type: entry.type },
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
    },
    { auditAction: 'ip_list_change', req }
  );
  // 置位必须晚于审计：审计重抛时这次 500 由全局审计接手记录（先置位 ⇒ 状态已变、审计为零）
  res.locals.skipGlobalAudit = true;

  logger.info('IP 已从名单移除', { ip: entry.ip, type: entry.type, operator: req.user.username });

  return ApiResponse.success(res, { id, ip: entry.ip }, '已移除');
});

module.exports = {
  getIPList,
  queryIPMatch,
  addIPEntry,
  removeIPEntry,
};
