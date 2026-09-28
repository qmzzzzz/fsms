/**
 * IP 黑白名单控制器（D-1 自 securityController 拆出）
 *
 * IP 名单的列表、命中查询、增删。名单读写经 models/IPBlacklist 快照机制
 * 同步到匹配层（中间件请求期判定），删除/加白后须失效降级封禁缓存。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const ApiResponse = require('../utils/apiResponse');
// 名单类型取值与 models/IPBlacklist 的 enum、securityRoutes 的 isIn 同源
const { IP_LIST_TYPES } = require('../constants/ipList');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
// 与 middleware/security.js 的匹配层守卫同一判据（IP 命中查询必须与请求期判定口径一致）。
// 判据此前已住在 ipUtils（四个解析漏斗共用），本文件直接复用，不再有中间模块。
const {
  normalizeIP,
  normalizeCIDR,
  isFullRangeCIDR,
  isAmbiguousIpText,
  lenientAddressHint,
} = require('../utils/ipUtils');
const { auditPath } = require('../utils/auditMeta');
const { isSuperAdminRole } = require('../utils/superAdmin');
const { invalidateIPBlockCache } = require('../middleware/security');
const { onAuditWriteFailure } = require('../utils/auditWriteFailure');

/**
 * 获取 IP 黑白名单列表
 * GET /api/security/ip-list?type=black|white&page=1&limit=20
 * 同时返回黑/白名单总数，前端无需再发一次不带 type 的请求做计数
 */
const getIPList = asyncHandler(async (req, res) => {
  // P3-5：路由挂了校验链却从不消费结果——?type=<script> 不命中
  // black/white 分支后 filter.type 根本不设置，静默退化成"全量返回"，
  // 调用方以为在查某个名单实际拿到两个名单的混合分页，计数也对不上。
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { type, page = 1, limit = 20 } = req.query;
  const IPBlacklistModel = require('../models/IPBlacklist');

  const now = new Date();
  const activeFilter = { $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] };

  const filter = { ...activeFilter };
  // 手写 `type === 'black' || type === 'white'` 是本族最坏的一种副本：给清单加一档后，
  // 路由校验（isIn 读同一份 constants）会放行新值，而这里**不认识**它就整条丢掉过滤
  // 条件 ⇒ `?type=<新档>` 返回全量名单而不是 400（口径同 F-138 的 userService）。
  if (IP_LIST_TYPES.includes(type)) filter.type = type;

  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit, 200);

  const [list, total, blackCount, whiteCount] = await Promise.all([
    IPBlacklistModel.find(filter)
      .sort({ createdAt: -1 })
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .lean(),
    IPBlacklistModel.countDocuments(filter),
    IPBlacklistModel.countDocuments({ ...activeFilter, type: 'black' }),
    IPBlacklistModel.countDocuments({ ...activeFilter, type: 'white' }),
  ]);

  return ApiResponse.success(
    res,
    {
      list,
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
 * IP 名单命中查询
 * GET /api/security/ip-list/query?ip=1.2.3.4
 * 返回该 IP 命中的全部黑/白名单记录（含 CIDR 网段与等价地址形式）；
 * 各列表按覆盖面最宽优先排序（如 /16 与 /24 同时命中时 /16 在首位），并给出最终生效判定（白名单优先）
 */
const queryIPMatch = asyncHandler(async (req, res) => {
  const rawIP = typeof req.query.ip === 'string' ? req.query.ip.trim() : '';

  // 歧义文本必须**明确拒答**，不能给 verdict。
  // 背景：早前匹配层（models/IPBlacklist.findMatchingEntries）对
  // `0177.0.0.1` / `0x7f.0.0.1` / `127.1` 这类形态一律返回空 ⇒ 请求期该客户端
  // 既不算命中黑名单也不算命中白名单。本接口若沿用同一判据却继续打印
  // `normalizedIP: '127.0.0.1'`，管理员读到的是「127.0.0.1 没被拦」——
  // 而名单里可能正封着 127.0.0.1，两者互相矛盾，且状态码 200 无任何提示。
  // 所以这里把"你问的是哪一个地址"问清楚：宽松解析出的规范地址回给对方，让其重查。
  //
  // 顺序不可颠倒：ipUtils 收紧后 normalizeIP 对歧义文本已经返回 null，
  // 若先跑下面那道 null 判断，"形态有歧义"会被误报成"请输入单地址"，
  // 管理员拿不到重查指引 ⇒ 本分支必须在 normalizeIP 之前。
  // 提示值走 lenientAddressHint（只显示宽松解释的结果，不参与任何判定）。
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

  const IPBlacklistModel = require('../models/IPBlacklist');

  const [blackMatches, whiteMatches] = await Promise.all([
    IPBlacklistModel.matchIP(rawIP, 'black'),
    IPBlacklistModel.matchIP(rawIP, 'white'),
  ]);

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
 * 归一化必须发生在入库之前：以 ipaddr.js 把 IPv4 前导零与 IPv6 等价写法收敛成
 * 规范形式（`192.168.001.001 → 192.168.1.1`），入库文本才与请求期判定
 * （isBlocked / isWhitelisted）用的是同一个串——否则条目永远不命中，
 * 名单里留下一条"看着在防、其实没防"的死记录。
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
 * 操作者是否为内置超级管理员——添加侧与删除侧共用同一判据。
 *
 * 只认生效角色，口径与 auth.js buildAuthContext、rbac.js 的回退查询一致。
 * 字符串形式的 populate 无法携带 match，故必须写成对象形式：
 * 否则「直连数据库把 SUPER_ADMIN 置为 inactive」之后，其持有者仍被判定为超管，
 * 依然可以加白 0.0.0.0/0 让黑名单与限流整体失效——正是本文件守卫要防的结局。
 * 接口侧改内置角色 status 已被 roleGuards.js 的 BUILTIN_ROLE_STATUS_LOCKED 挡住，
 * 因此这条属纵深防御；注释保留原因，免得后人把它当冗余删掉。
 * 防御性说明：实测 mongoose 8.24.1 对 populate+match 未命中的引用是**丢弃元素**（不留 null），
 * 故 isSuperAdminRole 的 !!role 判空今天是冗余；保留它以防未来版本改为留 null 洞
 * （形状由 src/tests/populateMatchShape.test.js 钉住，升级会先红）。
 */
const operatorIsSuperAdmin = async (userId) => {
  const operator = await User.findById(userId)
    .populate({ path: 'roles', select: 'code isBuiltIn', match: { status: 'active' } })
    .lean();
  return (operator?.roles || []).some(isSuperAdminRole);
};

/**
 * 全网段（0.0.0.0/0、::/0）收口：此类条目一次性命中所有客户端——
 * 加黑导致全站拒服且管理员自己也无法登录解除；加白使黑名单与限流整体失效。
 * 故仅允许内置超级管理员配置，且两种结局都留高危痕迹（拒绝侧记 privilege_escalation）。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应，调用方应立即 return
 */
const guardFullRangeCIDR = async (req, res, { normalizedIP, type }) => {
  if (!isFullRangeCIDR(normalizedIP)) return false;

  const isSuperAdmin = await operatorIsSuperAdmin(req.user.userId);

  if (!isSuperAdmin) {
    logger.warn('非超级管理员尝试添加全网段名单', {
      ip: normalizedIP,
      operator: req.user.username,
    });
    AuditLog.record({
      action: 'privilege_escalation',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      method: req.method,
      path: auditPath(req),
      ip: req.ip,
      userAgent: req.get('user-agent'),
      body: { ip: normalizedIP, type },
      success: false,
      riskLevel: 'critical',
      riskFactors: ['full_range_cidr_attempt'],
      reason: `尝试将全网段 ${normalizedIP} 加入${type === 'black' ? '黑' : '白'}名单，权限不足`,
    });
    ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
      message: `全网段（${normalizedIP}）会命中所有 IP，仅超级管理员可配置；如需限制特定范围请使用更精确的网段`,
      params: { ip: normalizedIP },
    });
    return true;
  }

  logger.warn('超级管理员正在添加全网段名单', {
    ip: normalizedIP,
    type,
    operator: req.user.username,
  });
  return false;
};

/**
 * 添加 IP 到黑/白名单
 * POST /api/security/ip-list
 * body: { ip, type: 'black'|'white', reason, durationHours }
 */
const addIPEntry = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { ip, type = 'black', reason = 'manual_configuration', durationHours = 0 } = req.body;

  const parsed = normalizeListEntryRequest(res, { ip, type, durationHours });
  if (!parsed) return;
  const { trimmedIP, normalizedIP, hours } = parsed;

  if (await guardFullRangeCIDR(req, res, { normalizedIP, type })) return;

  const IPBlacklistModel = require('../models/IPBlacklist');
  const durationMs = hours > 0 ? hours * 60 * 60 * 1000 : 0;

  // 白名单优先于黑名单：
  // - 加入黑名单时，若该 IP/网段已被白名单覆盖则拒绝（信任标记不可被封禁覆盖，需先显式移出白名单）
  //   用 findCoveringEntries 而非 isWhitelisted：后者只接受单地址，
  //   传入 CIDR 时会解析失败返回 false，使网段形式绕过冲突检测
  // - 加入白名单时，自动解除同 IP 的黑名单记录（信任优先，保持名单语义无矛盾）
  if (type === 'black') {
    const covering = await IPBlacklistModel.findCoveringEntries(normalizedIP, 'white');
    if (covering.length > 0) {
      const coveredBy = covering.map((e) => e.ip).join('、');
      return ApiResponse.codeError(res, 'IP_COVERED_BY_WHITELIST', {
        message: `该 IP 已被白名单条目（${coveredBy}）覆盖，白名单优先级高于黑名单；如需封禁请先将其移出白名单`,
        params: { coveredBy: coveredBy },
      });
    }
  } else if (type === 'white') {
    await IPBlacklistModel.unblockIP(normalizedIP, 'black');
    // 加白后立即失效降级封禁缓存，避免 DB 故障期沿用陈旧封禁判定误拦可信 IP
    invalidateIPBlockCache(normalizedIP);
  }

  const entry = await IPBlacklistModel.blockIP(normalizedIP, {
    type,
    reason: String(reason).slice(0, 200),
    durationMs,
    source: 'manual',
  });

  // 审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: type === 'black' ? 'ip_blacklist_added' : 'ip_whitelist_added',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    body: { ip: normalizedIP, type, reason, durationHours: hours },
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: type === 'black' ? 'medium' : 'high',
  }).catch(onAuditWriteFailure('ip_list_change', req));

  logger.info('IP 已加入名单', {
    ip: normalizedIP,
    requestedIp: trimmedIP,
    type,
    operator: req.user.username,
  });

  return ApiResponse.success(res, entry, `已加入${type === 'black' ? '黑' : '白'}名单`);
});

/**
 * 从名单中移除 IP 记录
 * DELETE /api/security/ip-list/:id
 */
const removeIPEntry = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { id } = req.params;
  const IPBlacklistModel = require('../models/IPBlacklist');

  const entry = await IPBlacklistModel.findById(id);
  if (!entry) {
    return ApiResponse.codeError(res, 'IP_LIST_ENTRY_NOT_FOUND');
  }

  // ===== P2-13 修复：删除侧的对称约束 =====
  // addIPEntry 对全网段（0.0.0.0/0 等）做了「仅内置超管可添加」的收口，
  // 删除侧却完全没有对等约束——持 security:config 的低阶管理员可先拆掉
  // 超管配置的全网段白名单（该白名单是限流豁免/信任标记的前提），
  // 再塞入恶意黑名单，等效于绕过整个 IP 管控体系。
  // 保护的不变量：谁能添加，才能删除。
  if (isFullRangeCIDR(entry.ip)) {
    const isSuperAdmin = await operatorIsSuperAdmin(req.user.userId);

    if (!isSuperAdmin) {
      logger.warn('非超级管理员尝试删除全网段名单', { ip: entry.ip, operator: req.user.username });
      AuditLog.record({
        action: 'privilege_escalation',
        category: 'security',
        userId: req.user.userId,
        username: req.user.username,
        method: req.method,
        path: auditPath(req),
        ip: req.ip,
        userAgent: req.get('user-agent'),
        body: { ip: entry.ip, type: entry.type },
        success: false,
        riskLevel: 'critical',
        riskFactors: ['full_range_cidr_removal_attempt'],
        reason: `尝试移除全网段 ${entry.ip} 的${entry.type === 'black' ? '黑' : '白'}名单，权限不足`,
      });
      return ApiResponse.codeError(res, 'FULL_RANGE_FORBIDDEN', {
        message: `全网段（${entry.ip}）名单仅超级管理员可移除：它是限流豁免与信任标记的前提，移除会影响全部 IP 的访问控制`,
        params: { ip: entry.ip },
      });
    }

    logger.warn('超级管理员正在移除全网段名单', {
      ip: entry.ip,
      type: entry.type,
      operator: req.user.username,
    });
  }

  // removeById 内含名单快照失效，保证下一次匹配立即读到删除结果
  await IPBlacklistModel.removeById(id, entry.type);

  // 解除黑名单后必须同步失效降级封禁缓存，
  // 否则 DB 故障期该 IP 仍会被陈旧缓存拦截（表现为「界面已解封但依然 403」）
  if (entry.type === 'black') {
    invalidateIPBlockCache(entry.ip);
  }

  // 审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: entry.type === 'black' ? 'ip_blacklist_removed' : 'ip_whitelist_removed',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    method: req.method,
    path: auditPath(req),
    body: { ip: entry.ip, type: entry.type },
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
  }).catch(onAuditWriteFailure('ip_list_change', req));

  logger.info('IP 已从名单移除', { ip: entry.ip, type: entry.type, operator: req.user.username });

  return ApiResponse.success(res, { id, ip: entry.ip }, '已移除');
});

module.exports = {
  getIPList,
  queryIPMatch,
  addIPEntry,
  removeIPEntry,
};
