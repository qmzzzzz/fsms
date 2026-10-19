/**
 * 安全管理控制器 · 配置开关（注册 / 登录验证码 / 注册验证码）
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出，纯搬家不改语义）
 */

const { SystemConfig } = require('./shared');
const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
// F-03（2026-10-17）：业务状态已改变的成功路径改走可靠 outbox（落库失败 ⇒ 转审计 WAL
// 待重放），因此"返回成功"不再等于"审计可能没写上"。仍用 onAuditWriteFailure 的两处
// （PII 查看、安全举报）是刻意的 fail-closed：它们必须"记账后重抛"，不许把结果交出去。
const { recordDurably } = require('../../services/auditOutbox');

/**
 * 获取注册开关状态
 * GET /api/security/config/allowPublicRegistration
 */
const getRegistrationConfig = asyncHandler(async (req, res) => {
  const allowed = await SystemConfig.isRegistrationAllowed();
  return ApiResponse.success(
    res,
    {
      allowPublicRegistration: allowed,
      description: '是否允许公开注册（false 时仅管理员可创建用户）',
    },
    '获取成功'
  );
});

/**
 * 设置注册开关
 * PUT /api/security/config/allowPublicRegistration
 * body: { allowPublicRegistration: boolean }
 */
const setRegistrationConfig = asyncHandler(async (req, res) => {
  const { allowPublicRegistration } = req.body;

  if (typeof allowPublicRegistration !== 'boolean') {
    return ApiResponse.codeError(res, 'CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN');
  }

  await SystemConfig.set('allowPublicRegistration', allowPublicRegistration, req.user.userId);
  SystemConfig.invalidateRegistrationCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  // F-03：注册开关已落库并失效缓存 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: allowPublicRegistration ? 'registration_enabled' : 'registration_disabled',
      category: 'system',
      userId: req.user.userId,
      username: req.user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
      body: { allowPublicRegistration },
    },
    { auditAction: 'security_config_change', req }
  );

  logger.info('注册开关已变更', { allowPublicRegistration, operator: req.user.username });

  return ApiResponse.success(
    res,
    {
      allowPublicRegistration,
    },
    `已${allowPublicRegistration ? '开启' : '关闭'}公开注册`
  );
});

/**
 * 获取登录验证码开关状态
 * GET /api/security/config/loginCaptchaEnabled
 */
const getLoginCaptchaConfig = asyncHandler(async (req, res) => {
  const enabled = await SystemConfig.isLoginCaptchaEnabled();
  return ApiResponse.success(
    res,
    {
      loginCaptchaEnabled: enabled,
      description: '是否要求登录时输入图形验证码（默认关闭）',
    },
    '获取成功'
  );
});

/**
 * 设置登录验证码开关
 * PUT /api/security/config/loginCaptchaEnabled
 * body: { loginCaptchaEnabled: boolean }
 */
const setLoginCaptchaConfig = asyncHandler(async (req, res) => {
  const { loginCaptchaEnabled } = req.body;

  if (typeof loginCaptchaEnabled !== 'boolean') {
    return ApiResponse.codeError(res, 'CONFIG_LOGIN_CAPTCHA_MUST_BE_BOOLEAN');
  }

  await SystemConfig.set('loginCaptchaEnabled', loginCaptchaEnabled, req.user.userId);
  SystemConfig.invalidateLoginCaptchaCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  // F-03：登录验证码开关已落库并失效缓存 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: loginCaptchaEnabled ? 'login_captcha_enabled' : 'login_captcha_disabled',
      category: 'system',
      userId: req.user.userId,
      username: req.user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
      body: { loginCaptchaEnabled },
    },
    { auditAction: 'security_config_change', req }
  );

  logger.info('登录验证码开关已变更', { loginCaptchaEnabled, operator: req.user.username });

  return ApiResponse.success(
    res,
    {
      loginCaptchaEnabled,
    },
    `已${loginCaptchaEnabled ? '开启' : '关闭'}登录验证码`
  );
});

/**
 * 获取注册验证码开关状态
 * GET /api/security/config/registerCaptchaEnabled
 */
const getRegisterCaptchaConfig = asyncHandler(async (req, res) => {
  const enabled = await SystemConfig.isRegisterCaptchaEnabled();
  return ApiResponse.success(
    res,
    {
      registerCaptchaEnabled: enabled,
      description: '是否要求注册时输入图形验证码（默认开启）',
    },
    '获取成功'
  );
});

/**
 * 设置注册验证码开关
 * PUT /api/security/config/registerCaptchaEnabled
 * body: { registerCaptchaEnabled: boolean }
 */
const setRegisterCaptchaConfig = asyncHandler(async (req, res) => {
  const { registerCaptchaEnabled } = req.body;

  if (typeof registerCaptchaEnabled !== 'boolean') {
    return ApiResponse.codeError(res, 'CONFIG_REGISTER_CAPTCHA_MUST_BE_BOOLEAN');
  }

  await SystemConfig.set('registerCaptchaEnabled', registerCaptchaEnabled, req.user.userId);
  SystemConfig.invalidateRegisterCaptchaCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  // F-03：注册验证码开关已落库并失效缓存 ⇒ 审计先持久化再回成功
  await recordDurably(
    {
      action: registerCaptchaEnabled ? 'register_captcha_enabled' : 'register_captcha_disabled',
      category: 'system',
      userId: req.user.userId,
      username: req.user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'medium',
      body: { registerCaptchaEnabled },
    },
    { auditAction: 'security_config_change', req }
  );

  logger.info('注册验证码开关已变更', { registerCaptchaEnabled, operator: req.user.username });

  return ApiResponse.success(
    res,
    {
      registerCaptchaEnabled,
    },
    `已${registerCaptchaEnabled ? '开启' : '关闭'}注册验证码`
  );
});

module.exports = {
  getRegistrationConfig,
  setRegistrationConfig,
  getLoginCaptchaConfig,
  setLoginCaptchaConfig,
  getRegisterCaptchaConfig,
  setRegisterCaptchaConfig,
};
