/**
 * 认证控制器 · 凭证域（2026-10-19 自 `controllers/authController.js` 拆分）
 *
 * 覆盖：注册 / 登录（含 MFA 中间态与 fail-closed 未知 outcome）/ 图形验证码 /
 * 登录公钥下发 / 刷新令牌。函数体与注释自原文件原样迁出，相对 require 路径加深一级。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const config = require('../../config');
const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { auditPath } = require('../../utils/auditMeta');
const captchaService = require('../../services/captchaService');
const { setAuthCookies, getCookies, REFRESH_COOKIE_NAME } = require('../../utils/cookie');
const { getPublicKeyInfo } = require('../../utils/loginCipher');
const { computeFingerprint } = require('../../utils/fingerprint');
const authService = require('../../services/authService');
const metrics = require('../../utils/metrics');
const { rejectUnknownOutcome } = require('./shared');

/**
 * 用户注册
 * POST /api/auth/register
 */
const register = asyncHandler(async (req, res) => {
  // 验证输入
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const result = await authService.registerUser(req.body, { req });
  switch (result.outcome) {
    case 'CAPTCHA_INVALID':
      return ApiResponse.codeError(res, 'CAPTCHA_INVALID');
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'DUPLICATE':
      // 统一返回模糊提示，防止枚举探测有效用户名/邮箱
      return ApiResponse.codeError(res, 'REGISTER_INFO_INVALID');
    case 'OK':
      break;
    default:
      // 未知 outcome 一律 fail-closed（全仓 outcome switch 普查口径），绝不落到成功分支
      return rejectUnknownOutcome(res, 'register', result.outcome);
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
  const { SystemConfig } = require('../../models');
  // 两个开关各自带静态默认兜底 + 降级信号（见 SystemConfig.captchaSwitch）。
  // 原先这里是一段 Promise.all + 单个 catch：任一失败则两个一起退回静态默认，
  // 且**没有任何信号**。改成逐键读取后，降级只影响真正失败的那一个键，
  // 且 DB 读取失败会在 captchaSwitch 内部发 captcha_switch_db_fallback。
  //
  // 外层 try/catch 是**最后一道网**，与上面那个降级不是同一回事：captchaSwitch
  // 自身不抛（有专门的用例钉住这一点），所以走到这里的只可能是「意外」——
  // models 聚合入口加载失败、或 SystemConfig 上根本没有 captchaSwitch（例如
  // 测试里的部分 mock、或将来重构漏改调用方）。这种情况**绝不能静默**：
  // 它同样会把两个开关换成静态默认（captcha 关掉时等于放宽登录），但原因不是
  // 「DB 故障」，所以**刻意不复用** captcha_switch_db_fallback——那个 type 的语义
  // 是「库读失败」，把意外错误混进去会让告警的处置方向指错。这里按 error 留痕，
  // 让「本该不可达却到了」这件事在日志里可见。
  // （注：本行原写作字面量 `require('…/models')`，被 architecture/layeringRatchet 的
  //  正则当成第 3 处 controller→models 直连而判红——该门禁扫**原文**、不剥注释。
  //  代码形状的文本别写进注释。）
  let loginEnabled;
  let registerEnabled;
  try {
    [loginEnabled, registerEnabled] = await Promise.all([
      SystemConfig.captchaSwitch('login'),
      SystemConfig.captchaSwitch('register'),
    ]);
  } catch (err) {
    logger.error(`[captcha-status] 开关读取走到兜底网（应为不可达）：${err && err.message}`);
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
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
      // 2026-10-10：与 INVALID_CREDENTIALS 合并为同一对客 401。解密失败曾独占
      // AUTH_ENCRYPTED_CREDENTIAL_INVALID（400），攻击者可借此区分「信封不可
      // 解密 / nonce 已消费 / 超出时间窗」与「口令错误」——即 nonce 消费预言机，
      // 与 utils/loginCipher.js「失败原因不回传客户端做区分」的设计意图相悖。
      // 真实原因只进服务端日志与审计（authService 已按 err.code 落 reason）。
      // 前端自愈（服务端轮换密钥后公钥缓存失效）改由 api.js 在登录失败时清缓存，
      // 见 web-admin/src/utils/api.js FE-M1 段，不再依赖本错误码的区分度。
      return ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS');
    case 'INVALID_CREDENTIALS':
      return ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS');
    case 'MFA_REQUIRED':
      return ApiResponse.success(res, { mfaRequired: true }, '请输入两步验证码');
    case 'MFA_ATTEMPTS_EXCEEDED':
      return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
    case 'MFA_CODE_INVALID':
      return ApiResponse.codeError(res, 'MFA_CODE_INVALID');
    case 'OK':
      break;
    default:
      // 未知 outcome 一律 fail-closed（全仓 outcome switch 普查口径），绝不落到成功分支
      return rejectUnknownOutcome(res, 'login', result.outcome);
  }

  // I-01：登录成功只通过 httpOnly cookie 下发两个令牌。
  // 响应体刻意不回传令牌——JS 可读的副本会让 XSS 绕过 httpOnly 直接窃取 refresh token，
  // 而前端自 I-01 起只从 cookie 取身份（web-admin store/auth.js），回传没有任何消费方。
  setAuthCookies(res, result.token, result.refreshToken);

  return ApiResponse.success(
    res,
    {
      expires: config.jwt.expire,
      user: result.user,
    },
    '登录成功'
  );
});

/**
 * 刷新失败 outcome → 响应函数。
 *
 * 顺序无关（查表，不是 switch 链）；**'OK' 刻意不在表内**——不在表内即视为
 * 「未知 outcome」，落到 fail-closed 的 rejectUnknownOutcome，绝不落到成功分支
 * （全仓 outcome switch 普查口径）。
 * 用 Map 而不是普通对象：普通对象会把 'constructor'/'__proto__' 这类原型键读成真值。
 *
 * 值写成「直接调 codeError 的箭头函数」而不是「错误码字符串」是有意的：
 * 码字面量必须留在 codeError 调用的**第二个实参**位置上（写成字符串字面量），否则
 * `src/tests/emittedErrorCodeCoverage.test.js` 的提取器看不见它们，
 * 这些码会被判成"注册了却没人发"的死码——而它们其实还在发。
 */
const REFRESH_OUTCOME_RESPONSES = new Map([
  ['MISSING', (res) => ApiResponse.codeError(res, 'REFRESH_TOKEN_MISSING')],
  ['INVALID', (res) => ApiResponse.codeError(res, 'REFRESH_TOKEN_INVALID')],
  ['IP_DENIED', (res) => ApiResponse.codeError(res, 'REFRESH_TOKEN_REVOKED')],
  ['REPLAYED', (res) => ApiResponse.codeError(res, 'REFRESH_TOKEN_REVOKED')],
  ['PASSWORD_CHANGED', (res) => ApiResponse.codeError(res, 'PASSWORD_CHANGED_RELOGIN')],
  ['VERSION_MISMATCH', (res) => ApiResponse.codeError(res, 'SESSION_EXPIRED')],
  ['BLACKLIST_UNAVAILABLE', (res) => ApiResponse.codeError(res, 'SECURITY_SERVICE_UNAVAILABLE')],
  ['SESSION_UNAVAILABLE', (res) => ApiResponse.codeError(res, 'SECURITY_SERVICE_UNAVAILABLE')],
  ['REVOKE_UNAVAILABLE', (res) => ApiResponse.codeError(res, 'SECURITY_SERVICE_UNAVAILABLE')],
  ['SESSION_REVOKED', (res) => ApiResponse.codeError(res, 'DEVICE_SESSION_REVOKED')],
  ['EXPIRED', (res) => ApiResponse.codeError(res, 'REFRESH_TOKEN_EXPIRED')],
]);

/**
 * 刷新 Token
 * POST /api/auth/refresh
 */
const refreshToken = asyncHandler(async (req, res) => {
  // G3：请求体 refreshToken 的类型/长度校验结果（校验器见 authRoutes.refreshTokenBodyValidation）
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  // 刷新令牌来源：请求体 refreshToken 优先，回退读取 refresh_token cookie（I-01 httpOnly 方案）
  const cookies = getCookies(req);
  const refreshTokenRaw = req.body?.refreshToken || cookies[REFRESH_COOKIE_NAME];

  let result;
  try {
    result = await authService.refreshSession(refreshTokenRaw, { ip: req.ip });
  } catch (error) {
    // 刷新链路上的任何未预期异常（含数据库故障）
    // 一律按「无效的刷新令牌」拒绝，不把内部错误细节暴露给客户端
    return ApiResponse.codeError(res, 'REFRESH_TOKEN_INVALID');
  }

  if (result.outcome !== 'OK') {
    const respond = REFRESH_OUTCOME_RESPONSES.get(result.outcome);
    return respond ? respond(res) : rejectUnknownOutcome(res, 'refreshToken', result.outcome);
  }

  // 轮换时同步轮换两个 cookie（I-01）；令牌同样不进响应体（见 login 的成功分支）
  setAuthCookies(res, result.token, result.refreshToken);

  return ApiResponse.success(res, { expires: config.jwt.expire }, 'Token 刷新成功');
});

module.exports = {
  register,
  getCaptcha,
  getCaptchaStatus,
  getLoginPublicKey,
  login,
  refreshToken,
};
