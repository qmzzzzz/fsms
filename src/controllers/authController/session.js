/**
 * 认证控制器 · 会话域（2026-10-19 自 `controllers/authController.js` 拆分）
 *
 * 覆盖：当前用户信息（getMe）/ 登出 / 轻量会话探测 / 设备级会话列表与吊销。
 * 函数体与注释自原文件原样迁出，相对 require 路径加深一级。
 *
 * 审计持久化（F-03）：本文件两处会话吊销走 services/auditOutbox.js 的
 * `recordSensitiveActionDurably`（先持久化再回成功）；档位语义说明见 profile.js 头部
 * 与 utils/auditWriteFailure.js。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
// 令牌提取的唯一实现（authenticate 用的就是它）；登出必须与认证同源，见 logout 注释
const { extractAccessToken } = require('../../middleware/auth');
const {
  clearAuthCookies,
  getCookies,
  REFRESH_COOKIE_NAME,
  ACCESS_COOKIE_NAME,
} = require('../../utils/cookie');
const sessionService = require('../../services/sessionService');
const authService = require('../../services/authService');
const { recordSensitiveActionDurably } = require('../../services/auditOutbox');
const { isAccessTokenValid, isRefreshTokenValid } = require('../../services/tokenService');
const { getUserPermissions, getMenuTree } = require('../../utils/permissionHelper');

/**
 * 获取当前用户信息
 * GET /api/auth/me
 */
const getMe = asyncHandler(async (req, res) => {
  const userId = req.user.userId;

  // 使用权限辅助工具获取完整的用户权限信息
  const permInfo = await getUserPermissions(userId);

  if (!permInfo) {
    return ApiResponse.codeError(res, 'AUTH_USER_NOT_FOUND');
  }

  // 获取动态菜单树
  const menuTree = await getMenuTree(userId);

  // 获取数据范围
  const { getDataScope } = require('../../middleware/rbac');
  const dataScope = await getDataScope(userId);

  return ApiResponse.success(
    res,
    {
      user: permInfo.user,
      permissions: permInfo.permissions,
      menuPermissions: permInfo.menuPermissions,
      buttonPermissions: permInfo.buttonPermissions,
      apiPermissions: permInfo.apiPermissions,
      menus: menuTree,
      buttons: permInfo.buttonPermissions.map((b) => b.code),
      dataScope,
    },
    '获取成功'
  );
});

/**
 * 登出
 * POST /api/auth/logout
 *
 * fail-closed：令牌吊销未能落库时返回 503 而非「登出成功」
 * （判定在 authService.revokeTokensOnLogout，语义注释见该处）。
 */
const logout = asyncHandler(async (req, res) => {
  // 登出用户名提到函数头算一次：下方三个分支（foreign / revokeFailed / 成功日志）都要用。
  // 重复书写 req.user?.username || 'unknown' 每处在 eslint complexity 里算 2 点
  // （可选链 + 逻辑或），而 logout 的复杂度贴着 max 15 的棘轮上限——2026-10-10
  // 实测三处合并后 17 → 13。值在同一请求内不变，提出去不改变语义。
  const username = req.user?.username || 'unknown';

  // G3：请求体 refreshToken 的类型/长度校验结果
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  // 将当前 access token 和 refresh token 同时加入黑名单（保留既有黑名单逻辑）
  // I-01：令牌来源兼容 Authorization Bearer 头与 httpOnly cookie 双路径。
  //
  // 必须复用 middleware/auth 的 extractAccessToken，不能在控制器里再抄一份分支：
  // 手写版是 `if (Bearer) token = split(' ')[1]; else if (cookie) ...`，
  // 而 `Authorization: Bearer  <token>`（**双空格**；实测 Node 会修剪尾随空格但保留
  // 中间空格，所以 'Bearer ' 这种形态到不了服务端，'Bearer  x' 能到）下
  // split(' ')[1] 得到空串 ⇒ 走不进 else-if ⇒ token 停在空值。
  // 同一请求在 authenticate 那侧却是另一套：extractAccessToken 对空串**回退 cookie**并放行，
  // 于是"认证用的令牌"与"登出要吊销的令牌"不是同一个东西——登出回 200「已登出」，
  // 而那个仍然有效的访问令牌没进黑名单，一路活到自己的 TTL。
  // 这正是用 LOGOUT_REVOKE_FAILED 要堵的 fail-open，被一条复制粘贴的分叉绕开。
  const token = extractAccessToken(req);
  const cookies = getCookies(req);
  // 两个来源**都要**吊销。旧写法 `req.body?.refreshToken || cookies[...]` 是二选一：
  // 客户端（或中间层）只要出示一条**已轮换掉的旧串**，浏览器里那条仍在有效期的
  // refresh 令牌就永远进不了登出请求 ⇒ 接口回 200「已登出」，服务端那条线还活着，
  // 而用户已经认为会话终止、不会再补救（要堵的正是这类假成功）。
  const presentedRefresh = typeof req.body?.refreshToken === 'string' ? req.body.refreshToken : '';
  const cookieValue = cookies[REFRESH_COOKIE_NAME];
  const cookieRefresh = typeof cookieValue === 'string' ? cookieValue : '';
  const [primaryRefresh, ...extraRefresh] = [...new Set([presentedRefresh, cookieRefresh])].filter(
    Boolean
  );

  const { revokeFailed, foreignRefresh } = await authService.revokeTokensOnLogout({
    accessToken: token,
    refreshToken: primaryRefresh || null,
    extraRefreshTokens: extraRefresh,
    // 属主判据：被出示的 refresh 串必须是当前操作者的（authenticate 已保证 req.user 存在）
    userId: req.user?.userId,
  });

  if (foreignRefresh) {
    // 整次失败：不清 cookie（清了浏览器侧看起来已登出，用户不会重试，而那串
    // 令牌仍然有效）、不动会话表。保留 cookie 与下方 revokeFailed 分支同旨——
    // 让客户端能原样重试。判据与理由见 errorCodes.LOGOUT_REFRESH_FOREIGN。
    logger.warn('登出时出示了非本人的 refresh 令牌，整次拒绝', { username });
    return ApiResponse.codeError(res, 'LOGOUT_REFRESH_FOREIGN');
  }

  if (revokeFailed) {
    // 不清 cookie：清掉会让浏览器侧看起来已登出，用户不会重试，
    // 而服务端令牌仍然有效 —— 那正是 fail-open 的危害本身。
    // 保留 cookie 让前端可以原样重试登出。
    logger.error('登出失败（令牌吊销未落库）', { username });
    return ApiResponse.codeError(res, 'LOGOUT_REVOKE_FAILED');
  }

  // I-01：按各自 path 清除两个令牌 cookie，浏览器侧会话同步结束
  clearAuthCookies(res);

  // 会话表收敛：把本设备的会话置为 revoked。
  //
  // 为什么必须做：黑名单只作用于「这一个 access token」，而会话记录是
  // 「登录会话」界面的数据源。若不置位，用户登出后再登录，列表里会同时
  // 出现新旧两条记录，且旧的显示为在线——用户会误判为账号被盗。
  //
  // 放在 clearAuthCookies 之后且失败不阻断登出：cookie 已清、令牌已入黑名单，
  // 安全结论已经达成；残留一条 active 记录是展示层瑕疵，会话在 refresh
  // 有效期后自然过期。为此让用户登出失败是本末倒置。
  if (req.user?.sid) {
    await sessionService.revokeSessionSafe({
      sid: req.user.sid,
      userId: req.user.userId,
      reason: 'logout',
    });
  }

  logger.info('用户登出', { username });

  return ApiResponse.success(res, null, '登出成功');
});

/**
 * 轻量会话探测（不触发 token 刷新链）
 * GET /api/auth/session
 *
 * 目的：给 login/register 等无需认证的路由一个「是否已登录」判断端点。
 * 始终返回 200 { authenticated: boolean }，绝不返回 401/403——
 * 否则会触发前端拦截器的「401 → doRefreshToken → refresh 400」连锁请求，
 * 产生浏览器控制台无意义的 Failed to load resource 日志。
 *
 * 判定：access token 有效，或 access token 无效但 refresh token 有效，
 * 都视为「已登录」（后者前端随后 getMe 会自动触发刷新救回会话）。
 * 本端点仅做预筛，不签发/轮换/吊销任何令牌，安全结论以 getMe 为准。
 */
const getSessionStatus = asyncHandler(async (req, res) => {
  const cookies = getCookies(req);
  const accessToken = cookies[ACCESS_COOKIE_NAME];
  const refreshTokenRaw = cookies[REFRESH_COOKIE_NAME];

  let authenticated = false;
  if (accessToken && (await isAccessTokenValid(accessToken))) {
    authenticated = true;
  } else if (refreshTokenRaw && (await isRefreshTokenValid(refreshTokenRaw))) {
    // access token 已失效但 refresh token 仍有效：视为已登录，
    // 前端后续 getMe 触发刷新即可恢复完整会话
    authenticated = true;
  }

  return ApiResponse.success(res, { authenticated });
});

/**
 * 列出当前用户的活跃登录会话
 * GET /api/auth/sessions
 *
 * 只返回本人的会话：userId 取自 req.user（令牌），不接受任何请求参数指定用户 ——
 * 若开放 ?userId= 之类的入参，就等于给「查看他人在哪些设备登录」开了口子。
 * 管理员强制下线属于用户管理范畴，不复用本端点。
 */
const listSessions = asyncHandler(async (req, res) => {
  const sessions = await sessionService.listSessions({
    userId: req.user.userId,
    currentSid: req.user.sid || null,
  });

  return ApiResponse.success(
    res,
    {
      sessions,
      total: sessions.length,
      // 当前令牌是否带 sid：不带时（功能上线前签发的旧令牌）列表里不会有
      // 任何一条标记为「本设备」，前端据此提示用户重新登录以获得完整管理能力，
      // 否则用户会以为自己这台设备没在列表里、怀疑功能坏了
      currentSidPresent: !!req.user.sid,
    },
    '获取成功'
  );
});

/**
 * 吊销指定会话（踢除单台设备）
 * DELETE /api/auth/sessions/:sid
 *
 * 越权防护由 sessionService.revokeSession 的 userId 查询条件承担：
 * sid 是 UUID 不可枚举，但「不可猜」不是授权机制，必须在查询层限定归属。
 */
const revokeSession = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { sid } = req.params;

  // 禁止踢除自己所在的会话：语义上那是「登出」，而登出还需要吊销令牌、
  // 清 cookie。若允许从这里踢自己，用户会停留在一个 cookie 尚在、
  // 但每个请求都返回 401 的页面上，只能手动刷新才恢复正常。
  if (req.user.sid && String(sid) === String(req.user.sid)) {
    return ApiResponse.codeError(res, 'CANNOT_REVOKE_CURRENT_SESSION');
  }

  const revoked = await sessionService.revokeSession({
    sid,
    userId: req.user.userId,
    reason: 'user_revoked',
  });

  if (!revoked) {
    // 不区分「不存在」与「不属于你」：两者返回同一个 404，否则响应差异
    // 会变成 sid 存在性的探测通道
    return ApiResponse.codeError(res, 'SESSION_NOT_FOUND');
  }

  // F-03：会话已吊销 ⇒ 审计先持久化再回成功（同改密口径）
  await recordSensitiveActionDurably({
    userId: req.user.userId,
    username: req.user.username,
    action: 'session_revoked',
    category: 'auth',
    req,
    res,
    auditAction: 'session_revoked',
  });

  return ApiResponse.success(res, { sid }, '该设备的登录已终止');
});

/**
 * 吊销除当前会话外的全部会话（退出其他所有设备）
 * DELETE /api/auth/sessions/others
 *
 * 与改密的差别：不递增 tokenVersion，因此当前设备不受影响，用户无需重新登录。
 * 这正是设备级吊销存在的意义——此前想清掉其他设备只能改密码把自己也踢掉。
 */
const revokeOtherSessions = asyncHandler(async (req, res) => {
  const count = await sessionService.revokeOtherSessions({
    userId: req.user.userId,
    exceptSid: req.user.sid || null,
    reason: 'user_revoked',
  });

  // F-03：批量吊销已完成 ⇒ 审计先持久化再回成功（同改密口径）
  await recordSensitiveActionDurably({
    userId: req.user.userId,
    username: req.user.username,
    action: 'session_revoked_others',
    category: 'auth',
    req,
    res,
    auditAction: 'session_revoked_others',
  });

  return ApiResponse.success(res, { revokedCount: count }, `已终止 ${count} 台其他设备的登录`);
});

module.exports = {
  getMe,
  logout,
  getSessionStatus,
  listSessions,
  revokeSession,
  revokeOtherSessions,
};
