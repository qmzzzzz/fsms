/**
 * 安全管理路由
 */

const express = require('express');
const router = express.Router();
const securityController = require('../controllers/securityController');
// D-1：审计日志与 IP 名单端点自 securityController 拆出
const auditController = require('../controllers/auditController');
const ipListController = require('../controllers/ipListController');
// 取证溯源（T5/T6）：本文件有效行已超 300（棘轮 max-lines），故路由独立成文件，在此按 /forensic 子路径并入，避免继续堆大本文件。
const forensicRoutes = require('./forensicRoutes');
// 名单类型取值与 models/IPBlacklist 的 enum、ipListController 的守卫同源
const { IP_LIST_TYPES } = require('../constants/ipList');
const {
  authenticate,
  checkPermission,
  checkViewSensitivePermission,
  requireReAuthentication,
  requireReauthTicket,
} = require('../middleware');
const { body, param, query } = require('express-validator');
const { mustBeString } = require('../utils/validationRules');
// 改密专用限流器 + 严格限流器（导出等重资源操作）注意：change-password 此前误用 loginLimiter——其组键读取 body.username 且 skipSuccessfulRequests 语义面向登录成功，均不适用于改密场景，现替换为专用限流器
const {
  passwordChangeLimiter,
  passwordChangeUserLimiter,
  reauthLimiter,
  reauthUserLimiter,
  securityReportUserLimiter,
  strictLimiter,
} = require('../middleware/rateLimit');
const { consumeValidation } = require('../middleware/validateQuery');
const { validatePasswordStrength } = require('../utils/helpers');
const {
  rejectPlaintextInStrict,
  encPasswordField,
  rejectEncPlaintextCoexistence,
  reauthCredentialValidation, // /reauth 与管理员写操作（含升级）共用的凭据契约
} = require('../middleware/security/reauthCredentialRules');

// 验证规则 isString() 前置：express-validator 会把对象/数组先强转字符串再跑后续校验，
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
      // 统一委托 helpers 单一强度实现（覆盖长度上限与泄露口令黑名单）
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

/**
 * 举报目标类型（单一声明，下面两条链共用）：
 * `system` 表示"没有具体对象的系统级异常"，其余三类都指向一条真实记录。
 */
const REPORT_TARGET_TYPES = ['user', 'device', 'alarm', 'system'];
const REPORT_RECORD_TYPES = REPORT_TARGET_TYPES.filter((t) => t !== 'system');

/** 记录型举报：targetType 已过 isIn，取不到时按非记录型处理（那种请求整体 400） */
const isReportRecordType = (value, { req }) => REPORT_RECORD_TYPES.includes(req.body?.targetType);
const isReportSystemType = (value, { req }) => req.body?.targetType === 'system';

const reportValidation = [
  body('targetType').isIn(REPORT_TARGET_TYPES).withMessage('无效的目标类型'),
  // targetId 的形态由 targetType 决定（2026-10-01 拍板：校 ID + 存在性 + 限流）：
  //  · 记录型 ⇒ 必填、必须是 ObjectId。存在性与数据范围在控制器判（路由层不查库：
  //    校验阶段查库会让每一个坏格式请求都吃一次 DB 往返，而此时 targetType 自己
  //    可能还没过 isIn）；
  //  · system ⇒ 不得携带。反向禁止不是洁癖：否则只要把 targetType 改成 'system'
  //    就绕过整条核验，而"任何登录用户可向审计写入任意 targetId 字符串 +
  //    riskLevel:high"正是本次要收口的投毒面本身。
  // 自由文本（reason/description）仍按原样放行：它本来就不参与结构化判定，
  // 范围外的对象可以用文字描述，被约束的是**结构化字段**必须是真记录。
  //
  // isString 前置（express-validator 的标准校验器拿到的是 String(value) 之后的值，
  // 对象会先变成 '[object Object]'；判据见 tests/routes/bodyTypeGate.test.js 文件头）。
  // .bail()：字段缺失时不再叠加"格式无效"，否则同一个空字段报出两条互相矛盾的错。
  // .exists({ values: 'falsy' }) 承担的是**文案**而不是**拒绝**：缺字段/空串即使删掉
  // 这一环，后面的 isString/isMongoId 也会给出同一个 400 + 同一个 path（变异实证见
  // reportTargetScopeAndLimiter.test.js 的 msg 断言）。留着它，是为了让漏传 ID 的客户端
  // 收到「请提供被举报对象的 ID」，而不是把"你漏了字段"误导成"你格式写错了"。
  body('targetId')
    .if(isReportRecordType)
    .exists({ values: 'falsy' })
    .withMessage('请提供被举报对象的 ID')
    .bail()
    .isString()
    .withMessage('目标 ID 必须为字符串')
    .bail()
    .isMongoId()
    .withMessage('目标 ID 格式无效'),
  body('targetId')
    .if(isReportSystemType)
    .custom((value) => {
      if (value !== undefined && value !== null && value !== '') {
        throw new Error('系统级举报不指向具体对象，请勿提交目标 ID');
      }
      return true;
    }),
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
/** GET /api/security/my-info：本人安全信息（Private，本人资源）。 */
// 挂在所有具体路由之前：/forensic/* 是独立前缀，先注册避免被后续同前缀规则抢占
router.use('/forensic', forensicRoutes);

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

/** GET /api/security/bindings：本人账户绑定状态（Private，本人资源）。 */
router.get('/bindings', authenticate, securityController.getAccountBindings);

/**
 * @route   POST /api/security/reauth
 * @desc    完成一次二次验证并换取短时审计读取票据（5 分钟，绑定账号与会话）
 * @access  Private
 *
 * 为什么需要票据：GET 类审计端点无法携带口令（会出现在 URL/日志里），
 * 而每次翻页/筛选都弹一次密码框也不可用。票据是无状态 HMAC 签名串，
 * 服务端不落库；退出登录/切换账号时前端丢弃即可，过期由 exp 兜底。
 */
router.post(
  '/reauth',
  authenticate,
  reauthLimiter,
  reauthUserLimiter,
  reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
  // PERMISSION-EXEMPT: 本人资源：票据只由 authenticate 判定的 req.user 签发，
  // 且前置 requireReAuthentication 已完成凭据步进，无任何目标用户入参。
  securityController.issueReauthTicket
);

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
  // step-up 口令密文轨：前端用 PASSWORD_CURRENT 用途加密当前口令，服务端在
  // requireReAuthentication 中解密；密文无效一律 fail-closed，不回落明文。
  encPasswordField('encCurrentPassword'),
  rejectEncPlaintextCoexistence('encCurrentPassword', 'currentPassword'),
  body('currentPassword')
    .if((value, { req }) => !req.body.encCurrentPassword)
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('密码格式无效')
    .isLength({ max: 128 })
    .withMessage('密码长度异常')
    .custom(rejectPlaintextInStrict),
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
 * @route   GET /api/security/report-targets
 * @desc    列出"我数据范围内的可举报对象"（举报对话框的对象选择器取数）
 * @access  Private
 *
 * 为什么要这个端点：举报对话框原先把「对象 ID」摆给用户填 24 位 ObjectId，
 * 而一线人员拿不到该值 —— 记录型举报实际不可用。
 *
 * 为什么不复用 /users、/devices、/alarms：那三个列表分别要求
 * `user:read` / `device:read` / `alarm:read`，而举报入口刻意对全员开放；
 * 复用会让没有读权限的人打开下拉就吃 403，比"填不出 ID"更糟。
 *
 * 候选集与提交核验**同判据**（控制器用 buildRecordScopeFilter，与
 * resolveReportTargetViolation 的 isRecordInScope 逐臂同值），因此不存在
 * "选得到却提交 403"或"能通过却选不到"。type 白名单不在这里重复声明：
 * 控制器对未知 type 已 fail-closed 返回 400（listReportTargets 的 !kind 分支），
 * 而记录型清单的单一来源是本文件的 REPORT_RECORD_TYPES（reportTargetRegistryParity 盯着）。
 * 限流由 authenticate 内的账号级 userLimiter 承担（200/15min），与举报提交的
 * 独立 20 次写配额分开——搜索不会吃掉提交配额。
 */
router.get('/report-targets', authenticate, securityController.listReportTargets);
// PERMISSION-EXEMPT: 与 POST /report 同源——它是举报的前置步骤，挂权限码
// 会让一线人员根本选不到对象。约束由"候选集 = 举报人数据范围"（与提交核验
// 同一判据）+ 最小投影（不含 phone/email、报警描述、上报人姓名）+ 账号级
// userLimiter 承担，而不是把入口藏起来。

/**
 * @route   POST /api/security/report
 * @desc    举报异常行为
 * @access  Private
 */
router.post(
  '/report',
  authenticate,
  securityReportUserLimiter,
  reportValidation,
  securityController.reportSuspiciousActivity
);
// PERMISSION-EXEMPT: 举报是人人可用的入口（挂权限码会让一线人员报不了警），
// 且它不读取任何他人数据。但它会往审计写一条 riskLevel:high 的记录，所以豁免的
// 只是"权限码"而不是"约束"：targetId 必须是举报人数据范围内的真实记录（控制器判），
// 并按账号限流（见 rateLimit.js 的 securityReportUserLimiter）。
// 原注释写的是「本人资源：可疑行为上报的内容来自调用者自身，无越权面」——
// 那句是假的：上报内容由调用者撰写，但 targetId 指向的是**别人**的记录。

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
  // 清除他人 TOTP 是账户接管级操作：权限码之外再要求操作者本人当场
  // 通过一次口令/MFA 验证，避免会话被借用时直接摘掉受害者的第二因子。
  // 不叠加 reauthLimiter：该桶与 /view-sensitive 共用（5 次/15 分钟），
  // 会让"看几次本人联系方式再重置 MFA"的正常管理动作直接 429。
  // 暴力猜口令由 requireReAuthentication 内部的共享 MFA 失败锁兜底
  //（5 次失败 → 10 分钟锁定），与 /auth/mfa/disable 的口径一致。
  param('userId').isMongoId().withMessage('用户 ID 格式无效'),
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
  securityController.resetUserMfa
);

/**
 * @route   PUT /api/security/users/:userId/password/reset
 * @desc    管理员重置用户口令（生成一次性临时口令并强制首次登录改密）
 *          场景：内部系统无自助找回渠道，员工忘记口令时由管理员救济
 * @access  Private [user:reset_password]（与重置 MFA 同级敏感的账户救济操作）
 */
router.put(
  '/users/:userId/password/reset',
  authenticate,
  checkPermission('user:reset_password'),
  strictLimiter,
  // 与 MFA 重置同口径：账户接管级操作，权限码之外再要求操作者当场验证一次
  // 口令/MFA，避免会话被借用时直接改掉受害者口令。
  param('userId').isMongoId().withMessage('用户 ID 格式无效'),
  body('reason')
    .optional({ values: 'falsy' })
    .isString()
    .withMessage('reason 必须为字符串')
    .trim()
    .isLength({ max: 200 })
    .withMessage('重置原因最多 200 个字符'),
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
  securityController.resetUserPassword
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
  // 审计数据的读取需要短时票据（POST /reauth 换取），见文件顶部说明。
  // 权限码在前：无权限者得到 403，不泄露"票据是否有效"。
  requireReauthTicket(),
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
  requireReauthTicket(),
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
  requireReauthTicket(),
  strictLimiter,
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
 * 三个开关的 PUT 都不挂 bool 校验：布尔契约由控制器用 `typeof x !== 'boolean'`
 * 收死，并返回**字段专属**错误码（前端 api.js 有 i18n 映射）。
 * 这里若再挂一层 `isBoolean()` + consumeValidation()，非法值会先被拦成通用的
 * VALIDATION_FAILED，反而把专属码吃掉；且不消费时它是纯装饰（治的那个病）。
 * 由 src/tests/security/systemConfigBooleanContract.test.js 钉住这条契约。
 * 二次验证凭据（password / mfaCode）仍挂校验并消费：它不属于 bool 契约，
 * 坏格式凭据不应进入 requireReAuthentication 的比对与失败计数路径。
 * 不叠加 reauthLimiter：理由同 PUT /users/:userId/mfa/reset——失败计数与
 * 共享 MFA 失败锁已覆盖暴力猜口令，而共用 5 次桶会误伤正常管理操作。
 */
router.put(
  '/config/allowPublicRegistration',
  authenticate,
  checkPermission('security:config'),
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
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
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
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
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
  securityController.setRegisterCaptchaConfig
);

/** GET /api/security/upgrade：概览 [security:config]。GET 不挂 requireReAuthentication
 * （只读构建信息与就绪原因）；两条 GET 在 auditGetExcludePaths 豁免（3 秒轮询会灌满审计链）。 */
router.get(
  '/upgrade',
  authenticate,
  checkPermission('security:config'),
  securityController.getUpgradeOverview
);

/** GET /api/security/upgrade/jobs/:jobId：任务状态 [security:config]。参数名用 :jobId 而非
 * :id——applyObjectIdParams 会对 :id 做 ObjectId 校验，而任务 ID 是 randomUUID，用 :id 会 400。 */
router.get(
  '/upgrade/jobs/:jobId',
  authenticate,
  checkPermission('security:config'),
  securityController.getUpgradeJob
);

/** POST /api/security/upgrade/requests：入队 [security:config + 唯一超管 + 步进验证]。
 * 用 strictLimiter 而非 reauth 桶：后者与 /view-sensitive 共用 5 次/15 分钟，正常查看
 * 联系方式后不该连带失去发布能力；步进验证的暴力防护由共享 MFA 失败锁承担。 */
router.post(
  '/upgrade/requests',
  authenticate,
  checkPermission('security:config'),
  strictLimiter,
  body('image')
    .isString()
    .trim()
    .notEmpty()
    .withMessage('请提供镜像地址')
    .isLength({ max: 512 })
    .withMessage('镜像地址不能超过 512 个字符'),
  body('mode')
    .optional()
    .isIn(['registry', 'offline'])
    .withMessage('mode 只能是 registry 或 offline'),
  ...reauthCredentialValidation,
  consumeValidation(),
  requireReAuthentication(),
  securityController.triggerUpgrade
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
// ipListValidationAndConflictGuards / ipQueryAmbiguousRefusal 两组断言。
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
  body('typedConfirm')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 200 })
    .withMessage('确认串不能超过 200 个字符'),
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
