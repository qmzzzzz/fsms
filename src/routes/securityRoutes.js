/**
 * 安全管理路由
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
// D-1：审计日志与 IP 名单端点自 securityController 拆出
const auditController = require('../controllers/auditController');
const ipListController = require('../controllers/ipListController');
// 名单类型取值与 models/IPBlacklist 的 enum、ipListController 的守卫同源
const { IP_LIST_TYPES } = require('../constants/ipList');
const {
  authenticate,
  checkPermission,
  checkViewSensitivePermission,
  requireReAuthentication,
} = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString } = require('../utils/validationRules');
// 改密专用限流器 + 严格限流器（导出等重资源操作）
// 注意：change-password 此前误用 loginLimiter——其组键读取 body.username 且
// skipSuccessfulRequests 语义面向登录成功，均不适用于改密场景，现替换为专用限流器
const {
  passwordChangeLimiter,
  passwordChangeUserLimiter,
  reauthLimiter,
  reauthUserLimiter,
  strictLimiter,
} = require('../middleware/rateLimit');
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
  // targetId 只有 schema 的 maxlength:100 兜底：超长/非字符串会走到 Mongoose 校验，
  // 而 errorHandler 对 ValidationError 在生产环境**不返回字段明细**（避免泄露 schema），
  // 于是同一个 400 里 targetType/reason 有 fieldErrors、targetId 只有一句通用文案。
  // 在路由层补齐：isString 前置（express-validator 会先把对象强转成字符串再跑后续校验）。
  body('targetId')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('目标 ID 必须为字符串')
    .isLength({ max: 100 })
    .withMessage('目标 ID 最长 100 个字符'),
  mustBeString('reason', '原因'),
  body('reason').trim().isLength({ min: 1, max: 200 }).withMessage('原因长度应为 1-200 个字符'),
  mustBeString('description', '描述'),
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
  // 与 /auth/password 同口径：组合键含可伪造的 req.ip，补一个纯 userId 桶
  passwordChangeUserLimiter,
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
  // 本端点做**凭据校验**（当前密码或 TOTP），必须与其余四个凭据端点
  // （/auth/login、/auth/password、/security/change-password、/auth/mfa/disable）
  // 同级挂上凭据型限流。此前只有全局 generalLimiter 兜着，而 6 位 TOTP 空间只有 10^6，
  // 且二次验证分支原先既不记失败计数也不锁定（见 middleware/security.js requireReAuthentication），
  // 等于允许以请求速率硬猜步进验证口令。限流放在 requireReAuthentication **之前**，
  // 避免把 DB 查询与口令比对留在限流判定前面。
  // 但**必须用独立的桶**：与 /change-password 共用 passwordChangeLimiter 时，
  // 正常的连续查看（本人手机号/邮箱）会把用户的改密配额吃光——429 的文案还写着
  // "密码修改操作过于频繁"，用户与运维都看不出根因；反向同理（刷改密耗尽二次验证配额）。
  reauthLimiter,
  // 并列的纯 userId 桶：上面那个组合键含 req.ip，而 TRUST_PROXY_HOPS>0 时 req.ip 取自
  // X-Forwarded-For ⇒ 每换一个假 IP 就多一份 5 次配额，硬猜 TOTP（空间仅 10^6）的
  // 速率上限就此被架空。本桶只认 userId，不放宽任何一侧。
  reauthUserLimiter,
  // #9：本人查看免鉴权；查看他人需 system:read（原来一律要求 system:read，
  // 导致普通角色连查看本人手机号/邮箱都被 403，见 rbac.checkViewSensitivePermission）
  checkViewSensitivePermission,
  // G3：dataType 白名单。原顺序是这条挂在 requireReAuthentication() **之后**、
  // 且只由控制器在链尾读 validationResult ⇒ 填错 dataType 的请求会先把步进验证走完：
  // 口令错则本人 mfaFailCount +1（阈值 5，计数器与登录共用），口令对则烧掉这个时间窗
  // （同一个码随后连登录都不能再用），密码分支还白做一次 bcrypt 比对。
  // "注定 400"的请求不得产生凭据侧副作用 ⇒ 就地 consumeValidation() 收口。
  // 对外错误码不变：仍是控制器那句 VALIDATION_FAILED。
  body('dataType').isIn(['phone', 'email']).withMessage('不支持的数据类型'),
  // 同一口径的第二条：targetUserId 原先零校验，坏格式一路漏到控制器的
  // `User.findById(targetUserId)`，得到 CastError ⇒ 400 只有一句"资源 ID 格式无效"、
  // errors 里没有任何字段明细；而更先发生的是步进验证已被走完（口令错则计数、
  // 口令对则烧掉这个时间窗的码）。挂在 consumeValidation() 之前，让"注定 400"的
  // 请求在凭据侧什么都没发生就被拒掉。
  // `{ values: 'falsy' }`：本人查看按契约不传该字段，空串也按未传处理（与控制器
  // `isSelf = !targetUserId || ...` 的取值口径一致）。
  body('targetUserId')
    .optional({ values: 'falsy' })
    .isMongoId()
    .withMessage('目标用户 ID 格式无效'),
  consumeValidation(),
  requireReAuthentication(),
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
  // 必须在边界把字符串收成真布尔：validator 的 isBoolean 放行 'false'/'0'，
  // 而服务层按 truthy 判定（locked ? 'locked' : 'active'），不转换的话
  // 一条 {"locked":"false"} 的**解锁**请求会把账户锁上。
  body('locked')
    .isBoolean()
    .withMessage('locked 必须为布尔值')
    .notEmpty()
    .withMessage('请提供 locked 参数')
    .toBoolean(),
  // reason 会写进两处：`user.remark`（锁定方向）与 `AuditLog.reason`。
  // 上限取自 models/User.js remark 的 maxlength(500)——路由比 schema 松就等于
  // 把校验推给 user.save()：超长得到的是 Mongoose ValidationError，经 errorHandler
  // 在非 development 下把 fieldErrors 抹成 undefined，客户端只看到一个和自己提交的
  // 字段不同名的 VALIDATION_FAILED；非字符串得到 CastError，被映射成"资源 ID 格式无效"。
  // 解锁方向 schema 根本不跑（remark 只在锁定时写），AuditLog.reason 也没有上限，
  // ⇒ 这条路由闸是解锁路径上唯一的收口点，双向都要拦。
  body('reason')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('reason 必须为字符串')
    .trim()
    .isLength({ max: 500 })
    .withMessage('锁定原因最多 500 个字符'),
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
/**
 * 三个开关的 PUT 都不挂 body 校验：布尔契约由控制器用 `typeof x !== 'boolean'`
 * 收死，并返回**字段专属**错误码（前端 api.js 有 i18n 映射）。
 * 这里若再挂一层 `isBoolean()` + consumeValidation()，非法值会先被拦成通用的
 * VALIDATION_FAILED，反而把专属码吃掉；且不消费时它是纯装饰（P3-17 治的那个病）。
 * 由 src/tests/security/systemConfigBooleanContract.test.js 钉住这条契约。
 */
router.put(
  '/config/allowPublicRegistration',
  authenticate,
  checkPermission('security:config'),
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
  query('type').optional({ values: 'falsy' }).isIn(IP_LIST_TYPES).withMessage('名单类型无效'),
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
// 本链**故意不挂 consumeValidation()**：错误契约由 ipListController.queryIPMatch 拥有——
// 它对歧义文本/非法地址返回**字段专属**的 IP_FORMAT_INVALID / IP_SINGLE_REQUIRED
// （前端 web-admin/src/utils/api.js:63 有 i18n 映射）。补 consumeValidation() 会先被
// 拦成通用 VALIDATION_FAILED、把专属码吃掉，并打红
// ipListValidationAndConflictGuards / zzqoder_ipQueryAmbiguousRefusal 两组断言。
// （同下方三开关的既定口径；`trim()` 是净化器仍会执行，故本链并非纯装饰。）
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
  body('type').optional().isIn(IP_LIST_TYPES).withMessage('名单类型无效'),
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
