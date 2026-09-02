/**
 * 认证相关路由
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
// D-1：MFA 生命周期端点自 authController 拆出
const mfaController = require('../controllers/mfaController');
const { authenticate } = require('../middleware/auth');
const {
  loginLimiter,
  loginIpLimiter,
  loginUserLimiter,
  strictLimiter,
  captchaLimiter,
  registerIpLimiter,
  passwordChangeLimiter,
} = require('../middleware/rateLimit');
const { body, param } = require('express-validator');
const { validatePasswordStrength } = require('../utils/helpers');
const config = require('../config');
const ApiResponse = require('../utils/apiResponse');

// ===== 登录口令加密传输（密文轨/明文轨双轨）=====
// 明文轨守卫：LOGIN_ENCRYPT_STRICT=true 后所有明文口令字段直接拒绝
// （前端全量切换后开启；仅 HTTPS/localhost 部署可开——非 secure context
//  浏览器无 WebCrypto，前端只能走明文降级轨，开 strict 会把用户锁在门外）
const rejectPlaintextInStrict = () => {
  if (config.loginEncryptStrict) {
    throw new Error('服务端已启用口令加密传输，请刷新页面后重试');
  }
  return true;
};

// 口令密文字段的统一格式约束（ECDH 信封 base64，实际约 600 字符，
// 上限与 utils/loginCipher.js 的 ENVELOPE_MAX_B64_LEN 一致）
const encPasswordField = (field) =>
  body(field)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('口令密文格式无效')
    .isLength({ max: 1024 })
    .withMessage('口令密文长度异常');

// 密码强度校验（企业级统一策略）
const passwordStrengthCheck = (value) => {
  const err = validatePasswordStrength(value);
  if (err) throw new Error(err);
  return true;
};

// 验证规则
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('用户名长度应为 3-30 个字符')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('用户名只能包含字母、数字和下划线'),
  body('email').trim().isEmail().withMessage('请输入有效的邮箱地址').normalizeEmail(),
  // 密文轨：ECDH 信封（优先）；强度校验在控制器解密后补做
  encPasswordField('encPassword'),
  // 明文轨：仅未携带 encPassword 时校验强度（灰度兼容）
  body('password')
    .if((value, { req }) => !req.body.encPassword)
    .custom(passwordStrengthCheck)
    .custom(rejectPlaintextInStrict),
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('phone')
    .optional()
    .trim()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
];

const loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('请输入用户名')
    .isLength({ max: 128 })
    .withMessage('用户名长度异常'),
  // 密文轨：ECDH 信封（优先）
  encPasswordField('encPassword'),
  // 明文轨：仅未携带 encPassword 时必填（灰度兼容）；strict 模式下直接拒绝
  body('password')
    .if((value, { req }) => !req.body.encPassword)
    .notEmpty()
    .withMessage('请输入密码')
    .isLength({ max: 128 })
    .withMessage('密码长度异常')
    .custom(rejectPlaintextInStrict),
  // MFA 二期动态口令（I-06）：未开启 MFA 的用户不传，已开启的必须 6 位数字
  body('mfaCode')
    .optional({ values: 'falsy' })
    .trim()
    // 兼容两类因子：6 位 TOTP 或备用恢复码 XXXX-XXXX（字母表排除易混字符）
    .matches(/^(\d{6}|[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4})$/i)
    .withMessage('请输入 6 位动态验证码或备用恢复码'),
];

// 修改密码校验：新密码走统一企业级强度策略并限制上限，防 bcrypt 超长
// isString() 必不可少：express-validator 会把对象/数组强制转字符串再跑
// notEmpty/isLength，`{}` 转成 `[object Object]` 能通过全部校验，
// 随后原值（对象）直达 bcrypt.compare 触发 TypeError → 500
const changePasswordValidation = [
  // 密文轨：ECDH 信封（优先，两个字段各自独立信封）
  encPasswordField('encCurrentPassword'),
  encPasswordField('encNewPassword'),
  // 明文轨：仅未携带对应密文字段时生效（灰度兼容）
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .isString()
    .withMessage('当前密码格式无效')
    .notEmpty()
    .withMessage('请提供当前密码')
    .isLength({ max: 64 })
    .withMessage('当前密码长度异常')
    .custom(rejectPlaintextInStrict),
  body('newPassword')
    .if((value, { req }) => !req.body.encNewPassword)
    .isString()
    .withMessage('新密码格式无效')
    .custom(passwordStrengthCheck)
    .isLength({ max: 64 })
    .withMessage('新密码长度不能超过 64 个字符')
    .custom(rejectPlaintextInStrict),
];

// 刷新令牌校验（G3）：令牌可来自请求体或 httpOnly cookie，故请求体字段为可选；
// 但一旦提交就必须是有界字符串——jwt.verify 前先卡长度，避免超长串进入
// 签名校验（base64 解码 + HMAC 计算）造成无谓 CPU 开销
const refreshTokenBodyValidation = [
  body('refreshToken')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('刷新令牌格式无效')
    .isLength({ max: 2048 })
    .withMessage('刷新令牌长度异常'),
];

// 关闭 MFA 校验（G3）：两条验证路径二选一，均为可选字段（控制器判定哪条生效），
// 此处只做类型与长度收敛。currentPassword 上限与改密接口一致，
// 防超长串进入 bcrypt.compare
const mfaDisableValidation = [
  body('mfaCode')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('两步验证码格式无效')
    .isLength({ max: 16 })
    .withMessage('两步验证码长度异常'),
  // 密文轨：ECDH 信封（优先）
  encPasswordField('encCurrentPassword'),
  // 明文轨：仅未携带密文字段时生效（灰度兼容）
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('密码格式无效')
    .isLength({ max: 64 })
    .withMessage('密码长度异常')
    .custom(rejectPlaintextInStrict),
];

// 更新个人资料：长度上限与模型/注册接口保持一致，防超长文本入库
const updateProfileValidation = [
  body('realName').optional().trim().isLength({ max: 50 }).withMessage('姓名不能超过 50 个字符'),
  body('email')
    .optional()
    .trim()
    .isLength({ max: 254 })
    .withMessage('邮箱不能超过 254 个字符')
    .isEmail()
    .withMessage('请输入有效的邮箱地址'),
  body('phone')
    .optional()
    .isLength({ max: 20 })
    .withMessage('手机号不能超过 20 个字符')
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('请输入有效的手机号'),
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('部门不能超过 100 个字符'),
  body('avatar')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('头像地址不能超过 500 个字符'),
];

// 路由定义
/**
 * @route   POST /api/auth/register
 * @desc    用户注册
 * @access  Public
 */
// 注册开关：支持运行时动态切换（数据库持久化 + 30 秒缓存）
// 启动时先使用静态配置，运行时通过 SystemConfig 动态覆盖
router.post(
  '/register',
  strictLimiter,
  registerIpLimiter,
  registerValidation,
  async (req, res, next) => {
    try {
      const { SystemConfig } = require('../models');
      const allowed = await SystemConfig.isRegistrationAllowed();
      if (!allowed) {
        return ApiResponse.error(res, '当前系统已关闭公开注册，请联系管理员创建账户', 403);
      }
      return authController.register(req, res, next);
    } catch (err) {
      // 数据库故障时无法确认注册开关，fail-closed 直接拒绝：
      // 原「降级到静态配置放行」并不成立——register 本身依赖数据库，
      // 放行只会把失败推迟为 500，不如在此明确返回 503
      return ApiResponse.error(res, '注册服务暂不可用，请稍后重试', 503);
    }
  }
);

/**
 * @route   GET /api/auth/captcha
 * @desc    获取图形验证码（登录前置人机校验）
 * @access  Public
 */
router.get('/captcha', captchaLimiter, authController.getCaptcha);

/**
 * @route   GET /api/auth/captcha-status
 * @desc    查询登录验证码开关状态（登录页据此决定是否渲染验证码）
 * @access  Public
 */
router.get('/captcha-status', authController.getCaptchaStatus);

/**
 * @route   GET /api/auth/login-public-key
 * @desc    下发登录口令加密公钥（ECDH 公开信息，前端据此加密口令上行）
 * @access  Public
 */
router.get('/login-public-key', captchaLimiter, authController.getLoginPublicKey);

/**
 * @route   POST /api/auth/login
 * @desc    用户登录
 * @access  Public
 */
router.post(
  '/login',
  loginIpLimiter,
  loginLimiter,
  loginUserLimiter,
  loginValidation,
  authController.login
);

/**
 * @route   POST /api/auth/refresh
 * @desc    刷新 Token
 * @access  Public
 */
router.post('/refresh', strictLimiter, refreshTokenBodyValidation, authController.refreshToken);

/**
 * @route   GET /api/auth/session
 * @desc    轻量会话探测（返回是否已登录，始终 200，不触发 token 刷新链）
 * @access  Public
 */
router.get('/session', authController.getSessionStatus);

/**
 * @route   GET /api/auth/me
 * @desc    获取当前用户信息
 * @access  Private
 */
router.get('/me', authenticate, authController.getMe);

/**
 * @route   PUT /api/auth/password
 * @desc    修改密码
 * @access  Private
 */
router.put(
  '/password',
  authenticate,
  // 凭据型限流（5 次/15 分钟，userId+IP 组合键，白名单不豁免）：
  // 改密是账户接管的关键动作，此前误挂资源型 strictLimiter（30 次且豁免白名单）
  passwordChangeLimiter,
  changePasswordValidation,
  authController.changePassword
);

/**
 * @route   PUT /api/auth/profile
 * @desc    更新个人资料（姓名、电话、部门）
 * @access  Private
 */
router.put('/profile', authenticate, updateProfileValidation, authController.updateProfile);

/**
 * @route   POST /api/auth/logout
 * @desc    用户登出
 * @access  Private
 */
router.post('/logout', authenticate, refreshTokenBodyValidation, authController.logout);

// ================= MFA 两步验证（I-06，TOTP） =================

/**
 * @route   GET /api/auth/mfa/status
 * @desc    查询当前用户 MFA 开启状态
 * @access  Private
 */
router.get('/mfa/status', authenticate, mfaController.getMfaStatus);

/**
 * @route   POST /api/auth/mfa/enroll
 * @desc    生成 MFA 密钥（开启第一步，返回 secret 与 otpauth URI）
 * @access  Private
 *
 * G3 复核结论：该接口不读取任何请求体/查询/路径参数（控制器仅用 req.user.userId），
 * 无外部可控输入面，故无需 express-validator。此注释用于说明「无校验器」是
 * 有意为之而非遗漏。
 */
router.post('/mfa/enroll', authenticate, strictLimiter, mfaController.mfaEnroll);

/**
 * @route   POST /api/auth/mfa/enable
 * @desc    确认开启 MFA（校验一次动态口令）
 * @access  Private
 */
router.post(
  '/mfa/enable',
  authenticate,
  body('mfaCode')
    .trim()
    .matches(/^\d{6}$/)
    .withMessage('两步验证码应为 6 位数字'),
  mfaController.mfaEnable
);

/**
 * @route   POST /api/auth/mfa/disable
 * @desc    关闭 MFA（需动态口令或登录密码二次验证）
 * @access  Private
 */
router.post(
  '/mfa/disable',
  authenticate,
  strictLimiter,
  mfaDisableValidation,
  mfaController.mfaDisable
);

/**
 * @route   POST /api/auth/mfa/recovery-codes
 * @desc    重新生成备用恢复码（旧码全部作废；需当前动态口令）
 * @access  Private
 */
router.post(
  '/mfa/recovery-codes',
  authenticate,
  strictLimiter,
  body('mfaCode')
    .trim()
    .matches(/^\d{6}$/)
    .withMessage('两步验证码应为 6 位数字'),
  mfaController.regenerateRecoveryCodes
);

// ================= 设备级会话管理（登录会话） =================

// sid 形状校验：sessionService.newSid 用 crypto.randomUUID()，因此必须是 UUID。
// 为什么要卡形状而不是直接丢给查询：sid 会进 Mongo 查询条件与审计记录，
// 提前收敛可以挡掉超长/畸形串（$ 开头的对象注入尝试在这里就被拒）。
const sessionSidValidation = [
  param('sid')
    .isString()
    .withMessage('会话标识格式无效')
    .matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
    .withMessage('会话标识格式无效'),
];

/**
 * @route   GET /api/auth/sessions
 * @desc    列出本人当前的活跃登录会话（设备列表）
 * @access  Private
 *
 * 不加 strictLimiter：会话界面进入即拉取、踢除后还要刷新，
 * 把只读列表纳入严格限流会让正常操作触发 429。用户级限流已在
 * authenticate 内生效，足以约束滥用。
 */
router.get('/sessions', authenticate, authController.listSessions);

/**
 * @route   DELETE /api/auth/sessions/others
 * @desc    退出其他所有设备（保留当前设备）
 * @access  Private
 *
 * 必须声明在 /sessions/:sid 之前：Express 按注册顺序匹配，
 * 若顺序颠倒，'others' 会被当作 sid 传入并被 UUID 校验拒为 400。
 */
router.delete('/sessions/others', authenticate, strictLimiter, authController.revokeOtherSessions);

/**
 * @route   DELETE /api/auth/sessions/:sid
 * @desc    终止指定设备的登录（设备级吊销，不影响其他设备）
 * @access  Private
 */
router.delete(
  '/sessions/:sid',
  authenticate,
  strictLimiter,
  sessionSidValidation,
  authController.revokeSession
);

module.exports = router;
