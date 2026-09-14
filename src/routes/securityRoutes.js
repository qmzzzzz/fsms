/**
 * 安全管理路由
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
// D-1：审计日志与 IP 名单端点自 securityController 拆出
const auditController = require('../controllers/auditController');
const ipListController = require('../controllers/ipListController');
const {
  authenticate,
  checkPermission,
  checkViewSensitivePermission,
  requireReAuthentication,
} = require('../middleware');
const { body, param, query } = require('express-validator');
// 改密专用限流器 + 严格限流器（导出等重资源操作）
// 注意：change-password 此前误用 loginLimiter——其组键读取 body.username 且
// skipSuccessfulRequests 语义面向登录成功，均不适用于改密场景，现替换为专用限流器
const { passwordChangeLimiter, strictLimiter } = require('../middleware/rateLimit');
const { consumeValidation } = require('../middleware/validateQuery');
const { validatePasswordStrength } = require('../utils/helpers');
const config = require('../config');

// ===== 登录口令加密传输（密文轨/明文轨双轨，与 authRoutes 同口径）=====
// 明文轨守卫：LOGIN_ENCRYPT_STRICT=true 后所有明文口令字段直接拒绝
const rejectPlaintextInStrict = () => {
  if (config.loginEncryptStrict) {
    throw new Error('服务端已启用口令加密传输，请刷新页面后重试');
  }
  return true;
};

// 口令密文字段的统一格式约束（ECDH 信封 base64，上限与 loginCipher 一致）
const encPasswordField = (field) =>
  body(field)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('口令密文格式无效')
    .isLength({ max: 1024 })
    .withMessage('口令密文长度异常');

// 验证规则
// isString() 前置：express-validator 会把对象/数组先强转字符串再跑后续校验，
// `{}` → `[object Object]` 可通过 notEmpty/matches，原值随后进入
// bcrypt.compare 触发 TypeError → 500（与 authRoutes 同口径修复）
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
    .custom(rejectPlaintextInStrict),
  body('newPassword')
    .if((value, { req }) => !req.body.encNewPassword)
    .isString()
    .withMessage('新密码格式无效')
    .custom((value) => {
      // P3-29：统一委托 helpers 单一强度实现（覆盖长度上限与泄露口令黑名单）
      const err = validatePasswordStrength(value);
      if (err) throw new Error(err);
      return true;
    })
    .custom(rejectPlaintextInStrict),
  body('confirmPassword').custom((value, { req }) => {
    // 密文轨下 newPassword 明文在信封内，一致性比对由控制器解密后执行
    if (!req.body.encNewPassword && value !== req.body.newPassword) {
      throw new Error('两次输入的密码不一致');
    }
    return true;
  }),
];

const reportValidation = [
  body('targetType').isIn(['user', 'device', 'alarm', 'system']).withMessage('无效的目标类型'),
  body('reason').trim().isLength({ min: 1, max: 200 }).withMessage('原因长度应为 1-200 个字符'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('描述不能超过 500 个字符'),
];

// 路由定义
/**
 * @route   GET /api/security/my-info
 * @desc    获取当前用户的安全信息
 * @access  Private
 */
router.get('/my-info', authenticate, securityController.getMySecurityInfo);

/**
 * @route   PUT /api/security/change-password
 * @desc    修改密码（强化版）
 * @access  Private
 */
router.put(
  '/change-password',
  authenticate,
  passwordChangeLimiter,
  changePasswordValidation,
  securityController.changePasswordSecure
  // PERMISSION-EXEMPT: 本人资源：authenticate 已确定身份（#15 收敛后业务在 authService）
);

/**
 * @route   GET /api/security/bindings
 * @desc    获取账户绑定信息
 * @access  Private
 */
router.get('/bindings', authenticate, securityController.getAccountBindings);

/**
 * @route   POST /api/security/view-sensitive
 * @desc    查看敏感数据（需要二次验证）
 * @access  Private
 */
router.post(
  '/view-sensitive',
  authenticate,
  // #9：本人查看免鉴权；查看他人需 system:read（原来一律要求 system:read，
  // 导致普通角色连查看本人手机号/邮箱都被 403，见 rbac.checkViewSensitivePermission）
  checkViewSensitivePermission,
  requireReAuthentication(),
  // G3：dataType 白名单前置校验（控制器 default 分支已兜底，此处提前拦截
  // 非法/缺失值，避免无效请求进入二次验证后的敏感数据分支）
  body('dataType').isIn(['phone', 'email']).withMessage('不支持的数据类型'),
  securityController.viewSensitiveData
);

/**
 * @route   GET /api/security/stats
 * @desc    获取系统安全统计（管理员）
 * @access  Private [security:stats]
 */
router.get(
  '/stats',
  authenticate,
  checkPermission('security:stats'),
  securityController.getSecurityStats
);

/**
 * @route   POST /api/security/report
 * @desc    举报异常行为
 * @access  Private
 */
router.post('/report', authenticate, reportValidation, securityController.reportSuspiciousActivity);
// PERMISSION-EXEMPT: 本人资源：可疑行为上报的内容来自调用者自身，无越权面

/**
 * @route   GET /api/security/my-logs
 * @desc    获取个人操作日志
 * @access  Private
 */
router.get('/my-logs', authenticate, securityController.getMyLogs);

/**
 * @route   PUT /api/security/users/:userId/lock
 * @desc    锁定/解锁用户账户（管理员）
 * @access  Private [user:lock]
 */
router.put(
  '/users/:userId/lock',
  authenticate,
  checkPermission('user:lock'),
  param('userId').isMongoId().withMessage('用户 ID 格式无效'),
  body('locked')
    .isBoolean()
    .withMessage('locked 必须为布尔值')
    .notEmpty()
    .withMessage('请提供 locked 参数'),
  securityController.toggleUserLock
);

/**
 * @route   PUT /api/security/users/:userId/mfa/reset
 * @desc    管理员重置用户两步验证（清除 TOTP 密钥/恢复码并强制下线）
 *          场景：用户丢失认证器且恢复码用尽，无法自行关闭 MFA
 * @access  Private [user:reset_password]（与重置密码同级敏感的账户救济操作）
 */
router.put(
  '/users/:userId/mfa/reset',
  authenticate,
  checkPermission('user:reset_password'),
  strictLimiter,
  param('userId').isMongoId().withMessage('用户 ID 格式无效'),
  securityController.resetUserMfa
);

/**
 * @route   GET /api/security/overview
 * @desc    获取安全概览（管理员）
 * @access  Private [security:audit]
 */
router.get(
  '/overview',
  authenticate,
  // 权限码与 initData.js 播种的 security:audit 对齐，避免授权用户被误判 403
  checkPermission('security:audit'),
  securityController.getSecurityOverview
);

/**
 * @route   GET /api/security/alerts
 * @desc    获取最近安全告警
 * @access  Private [security:audit]
 */
router.get(
  '/alerts',
  authenticate,
  checkPermission('security:audit'),
  securityController.getRecentAlerts
);

/**
 * @route   GET /api/security/audit-logs/verify
 * @desc    校验审计日志哈希链完整性（hash 重算 + hmac 签名 + 链接性）
 * @access  Private [security:audit]
 * 注意：必须在 /audit-logs 之前注册，避免被 /audit-logs 吞掉。
 * 挂 strictLimiter：全量重算是重 CPU 操作（每条记录一次 SHA-256 + 一次 HMAC）。
 */
router.get(
  '/audit-logs/verify',
  authenticate,
  checkPermission('security:audit'),
  strictLimiter,
  auditController.verifyAuditChainIntegrity
);

/**
 * @route   GET /api/security/audit-logs/export
 * @desc    导出审计日志（CSV + 签名 manifest）
 * @access  Private [security:audit]
 * 注意：必须在 /audit-logs 路由之前注册，避免被 /audit-logs 吞掉
 */
router.get(
  '/audit-logs/export',
  authenticate,
  checkPermission('security:audit'),
  strictLimiter,
  auditController.exportAuditLogs
);

/**
 * @route   GET /api/security/audit-logs
 * @desc    查询审计日志（支持多维度筛选）
 * @access  Private [security:audit]
 */
router.get(
  '/audit-logs',
  authenticate,
  checkPermission('security:audit'),
  auditController.queryAuditLogs
);

/**
 * @route   GET /api/security/config/allowPublicRegistration
 * @desc    获取注册开关状态
 * @access  Private [security:config]
 */
router.get(
  '/config/allowPublicRegistration',
  authenticate,
  checkPermission('security:config'),
  securityController.getRegistrationConfig
);

/**
 * @route   PUT /api/security/config/allowPublicRegistration
 * @desc    设置注册开关（true=允许公开注册，false=仅管理员创建）
 * @access  Private [security:config]
 */
router.put(
  '/config/allowPublicRegistration',
  authenticate,
  checkPermission('security:config'),
  body('allowPublicRegistration').isBoolean().withMessage('必须为布尔值'),
  securityController.setRegistrationConfig
);

/**
 * @route   GET /api/security/config/loginCaptchaEnabled
 * @desc    获取登录验证码开关状态
 * @access  Private [security:config]
 */
router.get(
  '/config/loginCaptchaEnabled',
  authenticate,
  checkPermission('security:config'),
  securityController.getLoginCaptchaConfig
);

/**
 * @route   PUT /api/security/config/loginCaptchaEnabled
 * @desc    设置登录验证码开关（true=登录需图形验证码，false=关闭）
 * @access  Private [security:config]
 */
router.put(
  '/config/loginCaptchaEnabled',
  authenticate,
  checkPermission('security:config'),
  body('loginCaptchaEnabled').isBoolean().withMessage('必须为布尔值'),
  securityController.setLoginCaptchaConfig
);

/**
 * @route   GET /api/security/config/registerCaptchaEnabled
 * @desc    获取注册验证码开关状态（true=注册需图形验证码，false=关闭）
 * @access  Private [security:config]
 */
router.get(
  '/config/registerCaptchaEnabled',
  authenticate,
  checkPermission('security:config'),
  securityController.getRegisterCaptchaConfig
);

/**
 * @route   PUT /api/security/config/registerCaptchaEnabled
 * @desc    设置注册验证码开关（true=注册需图形验证码，false=关闭）
 * @access  Private [security:config]
 */
router.put(
  '/config/registerCaptchaEnabled',
  authenticate,
  checkPermission('security:config'),
  body('registerCaptchaEnabled').isBoolean().withMessage('必须为布尔值'),
  securityController.setRegisterCaptchaConfig
);

/**
 * @route   GET /api/security/ip-list
 * @desc    获取 IP 黑白名单列表（?type=black|white）
 * @access  Private [security:config]
 */
router.get(
  '/ip-list',
  authenticate,
  checkPermission('security:config'),
  query('type').optional({ values: 'falsy' }).isIn(['black', 'white']).withMessage('名单类型无效'),
  query('page').optional().isInt({ min: 1 }).withMessage('页码无效'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('每页数量应在 1-200'),
  consumeValidation(),
  ipListController.getIPList
);

/**
 * @route   GET /api/security/ip-list/query
 * @desc    查询 IP 命中的黑/白名单记录（含 CIDR 网段；多条命中按覆盖面最宽优先）
 * @access  Private [security:config]
 */
router.get(
  '/ip-list/query',
  authenticate,
  checkPermission('security:config'),
  query('ip').isString().trim().notEmpty().withMessage('请提供 IP 地址'),
  ipListController.queryIPMatch
);

/**
 * @route   POST /api/security/ip-list
 * @desc    添加 IP 到黑/白名单
 * @access  Private [security:config]
 */
router.post(
  '/ip-list',
  authenticate,
  checkPermission('security:config'),
  body('ip')
    .isString()
    .trim()
    .notEmpty()
    .withMessage('请提供 IP 地址')
    .isLength({ max: 200 })
    .withMessage('IP 地址不能超过 200 个字符'),
  body('type').optional().isIn(['black', 'white']).withMessage('名单类型无效'),
  body('reason')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 200 })
    .withMessage('原因不超过 200 字符'),
  body('durationHours')
    .optional()
    .isFloat({ min: 0, max: 8760 })
    .withMessage('生效时长应在 0-8760 小时'),
  ipListController.addIPEntry
);

/**
 * @route   DELETE /api/security/ip-list/:id
 * @desc    从名单中移除 IP 记录
 * @access  Private [security:config]
 */
router.delete(
  '/ip-list/:id',
  authenticate,
  checkPermission('security:config'),
  // G3：非法 ObjectId 会在 findById 抛 CastError（走全局 errorHandler 转 400），
  // 前置 isMongoId 校验使错误响应口径统一且不产生无谓的 DB 往返
  param('id').isMongoId().withMessage('名单记录 ID 格式无效'),
  ipListController.removeIPEntry
);

module.exports = router;
