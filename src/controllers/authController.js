/**
 * 认证控制器
 * 处理用户登录、注册、Token 刷新等认证相关操作
 *
 * D-1：业务规则已下沉到 services 层，本文件只做
 * 入参校验（express-validator）→ service 调用 → HTTP 响应编排：
 * - services/authService.js   注册/登录（含 MFA 二期）/刷新/改密/资料/登出
 * - services/tokenService.js  令牌签发与轻量会话探测
 * - services/sessionService.js 设备级会话
 * - services/mfaService.js    MFA 防爆破与恢复码原语
 */

const { validationResult } = require('express-validator');
const config = require('../config');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { auditPath } = require('../utils/auditMeta');
const captchaService = require('../services/captchaService');
const {
  setAuthCookies,
  clearAuthCookies,
  getCookies,
  REFRESH_COOKIE_NAME,
  ACCESS_COOKIE_NAME,
} = require('../utils/cookie');
const { getPublicKeyInfo } = require('../utils/loginCipher');
const { computeFingerprint } = require('../utils/fingerprint');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');
const { isAccessTokenValid, isRefreshTokenValid } = require('../services/tokenService');
const { getUserPermissions, getMenuTree } = require('../utils/permissionHelper');
const AuditLog = require('../models/AuditLog');
const metrics = require('../utils/metrics');

/**
 * 用户注册
 * POST /api/auth/register
 */
const register = asyncHandler(async (req, res) => {
  // 验证输入
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const result = await authService.registerUser(req.body);
  switch (result.outcome) {
    case 'CAPTCHA_INVALID':
      return ApiResponse.codeError(res, 'CAPTCHA_INVALID');
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'DUPLICATE':
      // 统一返回模糊提示，防止枚举探测有效用户名/邮箱
      return ApiResponse.error(res, '注册信息无效或已被使用', 400);
    default:
      break;
  }

  // 注册成功即建立会话：下发 httpOnly 令牌 cookie（I-01），注册后立即登录无需再次输密码；
  // 响应体保持原有结构（不新增 tokens 字段，避免改变既有 API 契约）
  setAuthCookies(res, result.token, result.refreshToken);

  return ApiResponse.success(
    res,
    {
      userId: result.userId,
      username: result.username,
      email: result.email,
    },
    '注册成功',
    201
  );
});

/**
 * 获取图形验证码
 * GET /api/auth/captcha
 */
const getCaptcha = asyncHandler(async (req, res) => {
  // R-3 迁移后 generate 为异步 API（共享存储读取必须异步）
  const captcha = await captchaService.generate();
  if (!captcha) {
    return ApiResponse.codeError(res, 'CAPTCHA_SERVICE_UNAVAILABLE');
  }
  return ApiResponse.success(res, captcha, '获取成功');
});

/**
 * 查询登录验证码开关状态（公开接口，登录页据此决定是否渲染验证码）
 * GET /api/auth/captcha-status
 */
const getCaptchaStatus = asyncHandler(async (req, res) => {
  const { SystemConfig } = require('../models');
  let loginEnabled;
  let registerEnabled;
  try {
    [loginEnabled, registerEnabled] = await Promise.all([
      SystemConfig.isLoginCaptchaEnabled(),
      SystemConfig.isRegisterCaptchaEnabled(),
    ]);
  } catch (_) {
    // 数据库故障时降级到静态配置
    loginEnabled = config.loginCaptchaEnabled;
    registerEnabled = config.registerCaptchaEnabled;
  }
  return ApiResponse.success(
    res,
    {
      loginCaptchaEnabled: loginEnabled,
      registerCaptchaEnabled: registerEnabled,
    },
    '获取成功'
  );
});

/**
 * 下发登录口令加密公钥
 * GET /api/auth/login-public-key
 * 公钥本身是公开信息，无需认证；限流防滥用即可（见路由挂载）
 */
const getLoginPublicKey = asyncHandler(async (req, res) => {
  return ApiResponse.success(res, getPublicKeyInfo(), '获取成功');
});

/**
 * 用户登录
 * POST /api/auth/login
 */
const login = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const result = await authService.loginUser(
    {
      username: req.body.username,
      password: req.body.password,
      encPassword: req.body.encPassword,
      mfaCode: req.body.mfaCode,
      captchaId: req.body.captchaId,
      captchaText: req.body.captchaText,
    },
    {
      req,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      method: req.method,
      path: auditPath(req),
      fingerprint: computeFingerprint(req),
    }
  );

  // 业务指标（P3）：登录尝试按结果枚举计数，供「登录成功率」面板与告警使用。
  // MFA_REQUIRED 是二段验证的中间态，单列 mfa_challenge，不计入成败
  metrics.incLoginAttempt(
    result.outcome === 'OK'
      ? 'success'
      : result.outcome === 'MFA_REQUIRED'
        ? 'mfa_challenge'
        : 'failure'
  );

  switch (result.outcome) {
    case 'CAPTCHA_INVALID':
      return ApiResponse.codeError(res, 'CAPTCHA_INVALID');
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'INVALID_CREDENTIALS':
      return ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS');
    case 'MFA_REQUIRED':
      return ApiResponse.success(res, { mfaRequired: true }, '请输入两步验证码');
    case 'MFA_ATTEMPTS_EXCEEDED':
      return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
    case 'MFA_CODE_INVALID':
      return ApiResponse.codeError(res, 'MFA_CODE_INVALID');
    default:
      break;
  }

  // I-01：登录成功同时通过 httpOnly cookie 下发两个令牌；
  // 响应体保留 token/refreshToken 字段以兼容现有测试与 API 消费者
  setAuthCookies(res, result.token, result.refreshToken);

  return ApiResponse.success(
    res,
    {
      token: result.token,
      refreshToken: result.refreshToken,
      expires: config.jwt.expire,
      user: result.user,
    },
    '登录成功'
  );
});

/**
 * 刷新 Token
 * POST /api/auth/refresh
 */
const refreshToken = asyncHandler(async (req, res) => {
  // G3：请求体 refreshToken 的类型/长度校验结果（校验器见 authRoutes.refreshTokenBodyValidation）
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  // 刷新令牌来源：请求体 refreshToken 优先，回退读取 refresh_token cookie（I-01 httpOnly 方案）
  const cookies = getCookies(req);
  const refreshTokenRaw = req.body?.refreshToken || cookies[REFRESH_COOKIE_NAME];

  let result;
  try {
    result = await authService.refreshSession(refreshTokenRaw, { ip: req.ip });
  } catch (error) {
    // 与拆分前口径一致：刷新链路上的任何未预期异常（含数据库故障）
    // 一律按「无效的刷新令牌」拒绝，不把内部错误细节暴露给客户端
    return ApiResponse.unauthorized(res, '无效的刷新令牌');
  }

  switch (result.outcome) {
    case 'MISSING':
      return ApiResponse.error(res, '缺少刷新令牌', 400);
    case 'INVALID':
      return ApiResponse.unauthorized(res, '无效的刷新令牌');
    case 'IP_DENIED':
    case 'REPLAYED':
      return ApiResponse.unauthorized(res, '刷新令牌已失效，请重新登录');
    case 'PASSWORD_CHANGED':
      return ApiResponse.unauthorized(res, '密码已修改，请重新登录');
    case 'VERSION_MISMATCH':
      return ApiResponse.unauthorized(res, '会话已失效，请重新登录');
    case 'BLACKLIST_UNAVAILABLE':
    case 'SESSION_UNAVAILABLE':
    case 'REVOKE_UNAVAILABLE':
      return ApiResponse.error(res, '安全服务暂不可用，请稍后重试', 503);
    case 'SESSION_REVOKED':
      return ApiResponse.unauthorized(res, '该设备的登录已被终止，请重新登录');
    case 'EXPIRED':
      return ApiResponse.unauthorized(res, '刷新令牌已过期，请重新登录');
    default:
      break;
  }

  // 轮换时同步轮换两个 cookie（I-01）；响应体保留 tokens 字段兼容既有消费者
  setAuthCookies(res, result.token, result.refreshToken);

  return ApiResponse.success(
    res,
    {
      token: result.token,
      refreshToken: result.refreshToken,
      expires: config.jwt.expire,
    },
    'Token 刷新成功'
  );
});

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
  const { getDataScope } = require('../middleware/rbac');
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
 * 修改密码
 * PUT /api/auth/password
 */
const changePassword = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const result = await authService.changeUserPassword(req.user.userId, req.body, {
    username: req.user?.username,
  });

  switch (result.outcome) {
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'MISSING':
      return ApiResponse.error(res, '请提供当前密码和新密码', 400);
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'USER_NOT_FOUND':
      return ApiResponse.unauthorized(res, '用户不存在或已被删除');
    case 'CURRENT_WRONG':
      return ApiResponse.error(res, '当前密码错误', 400);
    case 'SAME_PASSWORD':
      return ApiResponse.error(res, '新密码不能与旧密码相同', 400);
    case 'REVOKE_FAILED': {
      // 密码已经改成功——审计必须落库，且先把状态码置为 503，
      // 让 recordSensitiveAction 按 res.statusCode 如实记录失败与风险因子
      res.status(503);
      AuditLog.recordSensitiveAction(
        req.user.userId,
        result.username,
        'change_password',
        'auth',
        req,
        res
      ).catch((e) => logger.warn(`改密吊销失败审计落库失败：${e.message}`));
      return ApiResponse.error(
        res,
        '密码已修改，但会话吊销服务暂不可用，旧登录状态可能仍然有效，请重新登录',
        503
      );
    }
    default:
      break;
  }

  AuditLog.recordSensitiveAction(
    req.user.userId,
    result.username,
    'change_password',
    'auth',
    req,
    res
  ).catch((e) => logger.warn(`改密审计落库失败：${e.message}`));

  return ApiResponse.success(res, null, '密码修改成功');
});

/**
 * 更新个人资料
 * PUT /api/auth/profile
 */
const updateProfile = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const result = await authService.updateUserProfile(req.user.userId, req.body);

  switch (result.outcome) {
    case 'NOT_FOUND':
      return ApiResponse.notFound(res, '用户不存在');
    case 'INVALID_PHONE':
      return ApiResponse.error(res, '请输入有效的手机号码', 400);
    case 'INVALID_EMAIL':
      return ApiResponse.error(res, '请输入有效的邮箱地址', 400);
    case 'EMAIL_TAKEN':
      return ApiResponse.error(res, '该邮箱已被其他用户使用', 400);
    case 'INVALID_AVATAR':
      return ApiResponse.error(res, '头像必须是有效的图片 URL 或图片数据', 400);
    default:
      break;
  }

  return ApiResponse.success(res, result.profile, '资料更新成功');
});

/**
 * 登出
 * POST /api/auth/logout
 *
 * P2-26 fail-closed：令牌吊销未能落库时返回 503 而非「登出成功」
 * （判定在 authService.revokeTokensOnLogout，语义注释见该处）。
 */
const logout = asyncHandler(async (req, res) => {
  // G3：请求体 refreshToken 的类型/长度校验结果
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  // 将当前 access token 和 refresh token 同时加入黑名单（保留既有黑名单逻辑）
  // I-01：令牌来源兼容 Authorization Bearer 头与 httpOnly cookie 双路径
  const cookies = getCookies(req);
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (cookies[ACCESS_COOKIE_NAME]) {
    token = cookies[ACCESS_COOKIE_NAME];
  }
  const refreshTokenRaw = req.body?.refreshToken || cookies[REFRESH_COOKIE_NAME];

  const { revokeFailed } = await authService.revokeTokensOnLogout({
    accessToken: token,
    refreshToken: refreshTokenRaw,
  });

  if (revokeFailed) {
    // 不清 cookie：清掉会让浏览器侧看起来已登出，用户不会重试，
    // 而服务端令牌仍然有效 —— 那正是 fail-open 的危害本身。
    // 保留 cookie 让前端可以原样重试登出。
    logger.error('登出失败（令牌吊销未落库）', { username: req.user?.username || 'unknown' });
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

  logger.info('用户登出', { username: req.user?.username || 'unknown' });

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
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { sid } = req.params;

  // 禁止踢除自己所在的会话：语义上那是「登出」，而登出还需要吊销令牌、
  // 清 cookie。若允许从这里踢自己，用户会停留在一个 cookie 尚在、
  // 但每个请求都返回 401 的页面上，只能手动刷新才恢复正常。
  if (req.user.sid && String(sid) === String(req.user.sid)) {
    return ApiResponse.error(res, '不能从会话列表中终止当前设备，请使用退出登录', 400);
  }

  const revoked = await sessionService.revokeSession({
    sid,
    userId: req.user.userId,
    reason: 'user_revoked',
  });

  if (!revoked) {
    // 不区分「不存在」与「不属于你」：两者返回同一个 404，否则响应差异
    // 会变成 sid 存在性的探测通道
    return ApiResponse.notFound(res, '会话不存在或已失效');
  }

  AuditLog.recordSensitiveAction(
    req.user.userId,
    req.user.username,
    'session_revoked',
    'auth',
    req,
    res
  ).catch((e) => logger.warn(`会话吊销审计落库失败：${e.message}`));

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

  AuditLog.recordSensitiveAction(
    req.user.userId,
    req.user.username,
    'session_revoked_others',
    'auth',
    req,
    res
  ).catch((e) => logger.warn(`批量会话吊销审计落库失败：${e.message}`));

  return ApiResponse.success(res, { revokedCount: count }, `已终止 ${count} 台其他设备的登录`);
});

module.exports = {
  register,
  login,
  getCaptcha,
  getCaptchaStatus,
  getLoginPublicKey,
  refreshToken,
  getMe,
  changePassword,
  updateProfile,
  logout,
  getSessionStatus,
  listSessions,
  revokeSession,
  revokeOtherSessions,
};
