/**
 * 数据分类分级声明（审计一-7，2026-10-31）缺口：仓里对「哪些字段是个人信息 / 敏感数据」只有零散口径——piiCrypto 的加密范围、各模型的 select:false 清单、审计脱敏名单——没有任何一处能回答「User.email 属于第几级、依据是什么、静态存储是否已加密」。于是等保 2.0 与《个人信息保护法》要求的「数据分类分级」不可核对：新增一个字段时没人能判断它该不该加密、该不该进审计脱敏名单、该不该要单独同意。
 * 本文件是**唯一声明**：等级（L1 公开 / L2 内部 / L3 敏感 / L4 关键）、静态存储形态（atRest）、是否个人信息（pii）、是否属于需要单独同意的范围（consent）、以及依据（reason）。判据由 tests/ci/dataClassificationInventory.test.js 强制：模型与字段不得有僵尸条目、 select:false 与 getter 必须逐条对得上、个人信息不得悄悄降级、加密声明不得只在注释里。
 */

/** 四级分类（等保 2.0 三级口径：公开 / 内部 / 敏感 / 关键） */
const CLASSIFICATION_LEVELS = Object.freeze([
  { code: 'L1', name: '公开', basis: '可对外公开，泄露不造成影响' },
  { code: 'L2', name: '内部', basis: '仅内部可见，泄露造成轻度影响' },
  {
    code: 'L3',
    name: '敏感',
    basis: '个人信息 / 行为痕迹，泄露造成一般影响（需最小化 + 访问留痕）',
  },
  { code: 'L4', name: '关键', basis: '凭证材料 / 全量取证，泄露造成严重影响到特别严重影响' },
]);

const LEVEL_CODES = Object.freeze(CLASSIFICATION_LEVELS.map((l) => l.code));

/** 静态存储形态：gcm=字段级加密（utils/piiCrypto）、hmac=键控摘要、sha256/bcrypt=单向摘要、plain=明文 */
const AT_REST_FORMS = Object.freeze(['gcm', 'hmac', 'sha256', 'bcrypt', 'plain']);

/**
 * 加密但**没有** schema getter 的路径登记（atRest='gcm' 却查不到 getter 的唯一合法来源）。理由必须写在这里：解密发生在业务层（头像服务自行解密并校验 PNG 结构），不是 schema getter——没有这条登记，判据会把「真实存在」和「注释里声称」混为一谈。
 */
const GCM_WITHOUT_GETTER = Object.freeze({
  'UserAvatar.data':
    '解密在 services/avatarService 内完成（需校验图片结构后才可回吐），不设 schema getter',
});

/**
 * 同意/告知范围（consent scope）：`FIELD_LEVELS[].consent` 只允许取这里的键。为什么要有这张表：consent 标签是 services/consentService 派生「本次同意覆盖了哪些数据」的唯一来源。允许字段上随手写一个字符串，等于把范围清单变成散文——两边拼不起来时没有任何信号。这里同时声明每个范围是**向用户告知**（notice）还是**组织法定基础**（legalBasis）：自助注册只能覆盖前者；管理员建号属于后者，不写同意记录（见 docs/data-classification.md）。
 */
const CONSENT_SCOPES = Object.freeze({
  account: {
    label: '账号资料与凭证',
    basis: 'notice',
    notice: '账号、邮箱、手机号、姓名、部门、口令与 MFA 凭证',
  },
  avatar: { label: '头像图片', basis: 'notice', notice: '本人上传的头像原图' },
  device: { label: '登录设备信息', basis: 'notice', notice: '登录设备型号、IP、UA 与设备指纹' },
  audit: {
    label: '操作审计留痕',
    basis: 'legalBasis',
    notice: '按等保 2.0 三级与《网络安全法》第 21 条留存的审计记录',
  },
  security: {
    label: '安全事件处置',
    basis: 'legalBasis',
    notice: '封禁、二次验证与令牌吊销等安全处置记录',
  },
  grant: {
    label: '特权授予审批链',
    basis: 'legalBasis',
    notice: '临时权限的申请人/审批人姓名与理由',
  },
  alarm: {
    label: '报警上报人信息',
    basis: 'legalBasis',
    notice: '上报消防报警时填写的姓名与手机号',
  },
  forensic: { label: '取证捕获', basis: 'legalBasis', notice: '触发取证标记时的请求/响应全量快照' },
  consent: {
    label: '同意证据本身',
    basis: 'legalBasis',
    notice: '同意记录中的账号、时间、IP 与 UA（作为同意可被证明的凭据）',
  },
});

/** 模型基线：未在 FIELD_LEVELS 里逐字段提升的路径继承此等级 */
const MODEL_LEVELS = Object.freeze({
  User: { level: 'L3', basis: '账号主体：身份、联系与凭证材料' },
  UserAvatar: { level: 'L3', basis: '头像原图属个人信息（人像）' },
  UserSession: { level: 'L3', basis: '登录设备痕迹：IP / UA / 指纹可定位到自然人' },
  AuditLog: { level: 'L3', basis: '操作审计：操作者身份 + IP + 请求体快照' },
  IPBlacklist: { level: 'L3', basis: '封禁名单含 IP 与目标账号，属安全事件记录' },
  PrivilegeGrant: { level: 'L3', basis: '临时授权：申请人/审批人身份与授权理由' },
  ReauthGrant: { level: 'L3', basis: '二次验证凭据：与登录会话 sid 绑定' },
  ReauthTicketUse: { level: 'L3', basis: '一次性票据使用记录：jti 可反推账号' },
  FireAlarm: { level: 'L3', basis: '报警记录含上报人姓名/手机号（第三方个人信息）' },
  IdempotencyRecord: { level: 'L3', basis: '幂等键落库含响应体快照，可能含个人信息' },
  TokenBlacklist: { level: 'L4', basis: '令牌摘要：持有即可判定/伪造会话有效性' },
  ForensicCapture: { level: 'L4', basis: '取证级请求/响应全量，含完整凭据与业务数据' },
  FireDevice: { level: 'L2', basis: '设备台账：消防资产，非个人信息' },
  Inspection: { level: 'L2', basis: '巡检台账：履职证据，人员以 userId 引用' },
  Permission: { level: 'L2', basis: '权限点定义：配置元数据' },
  Role: { level: 'L2', basis: '角色定义：配置元数据' },
  SystemConfig: { level: 'L2', basis: '系统开关：配置元数据' },
  ConsentRecord: { level: 'L3', basis: '同意证据：账号身份 + IP/UA，属可识别自然人的记录' },
});

/** 字段级声明构造器（level, atRest, pii, reason, consent） */
const F = (level, atRest, pii, reason, consent = null) =>
  Object.freeze({ level, atRest, pii, reason, consent });

/**
 * 字段级声明：只登记**需要提升等级或需要说明静态形态**的路径，其余继承模型基线。 consent 标签 = 该字段属于需要「单独同意」告知的范围（services/consentService 据此派生范围清单）。
 */
const FIELD_LEVELS = Object.freeze({
  // ── User：凭证材料（L4）──
  'User.password': F(
    'L4',
    'bcrypt',
    false,
    '口令的 bcrypt 单向摘要，不可逆；仍属可离线爆破的凭证材料',
    'account'
  ),
  'User.passwordHistory': F(
    'L4',
    'hmac',
    false,
    '已退役口令的 HMAC 摘要：读到它等于拿到「某口令是否用过」的预言机',
    'account'
  ),
  'User.passwordRetiredHash': F(
    'L4',
    'bcrypt',
    false,
    '管理员重置时被替换掉的用户自选那一代口令的 bcrypt 摘要（只留最近一条，连续重置不覆盖；注销时抹空）：旧口令的可校验副本，可离线爆破，泄露等于把重置前那条口令交回去',
    'account'
  ),
  'User.mfaSecret': F(
    'L4',
    'plain',
    false,
    'TOTP 种子：明文存库（仅 select:false 保护，见 docs/data-classification.md 的残留）',
    'account'
  ),
  'User.mfaRecoveryCodes': F('L4', 'sha256', false, '恢复码 SHA-256 摘要，用即移除', 'account'),
  'User.mfaLastCounter': F(
    'L4',
    'plain',
    false,
    'TOTP 时间窗序号（重放防护），单独不可用',
    'account'
  ),
  'User.mfaFailCount': F(
    'L4',
    'plain',
    false,
    'MFA 防爆破计数：与 mfaLockUntil 同组，泄露可推断锁定窗口',
    'account'
  ),
  'User.mfaLockUntil': F('L4', 'plain', false, 'MFA 锁定截止时间，同上', 'account'),
  'User.username': F('L3', 'plain', true, '账号名：可关联到自然人（登录名即标识）', 'account'), // ── User：个人信息（L3）──
  'User.email': F(
    'L3',
    'gcm',
    true,
    '邮箱：AES-256-GCM 字段级加密 + v2 AAD 行绑定（utils/piiCrypto）',
    'account'
  ),
  'User.emailKey': F(
    'L3',
    'hmac',
    true,
    '邮箱精确检索键（HMAC）：随机 IV 下密文列不能判等，查重只能走它',
    'account'
  ),
  'User.emailGrams': F(
    'L3',
    'hmac',
    true,
    '邮箱子串盲索引（HMAC n-gram）：泄露可做子串枚举',
    'account'
  ),
  'User.phone': F('L3', 'gcm', true, '手机号：与 email 同轨加密', 'account'),
  'User.phoneKey': F('L3', 'hmac', true, '手机号精确检索键（HMAC）', 'account'),
  'User.realName': F(
    'L3',
    'plain',
    true,
    '姓名：**刻意保持明文**（姓名片段模糊检索是被保护的能力，见 deliverables/A5-realName加密决策记录）',
    'account'
  ),
  'User.department': F(
    'L3',
    'plain',
    true,
    '部门：同时是数据范围（dataScope）的唯一来源，与身份绑定',
    'account'
  ),
  'User.avatar': F(
    'L2',
    'plain',
    false,
    '仅头像地址（URL/版本号）；图片本体在 UserAvatar.data（L3/gcm）'
  ),
  'User.lastLoginIp': F('L3', 'plain', true, '最近登录 IP：行为痕迹，可定位自然人', 'account'),
  'User.allowedIPs': F('L2', 'plain', false, 'IP 范围规则文本（CIDR/通配符），非个人信息'),
  // ── UserAvatar ──
  'UserAvatar.data': F(
    'L3',
    'gcm',
    true,
    '头像原图 Base64：enc.v2 密文，解密在业务层完成（见 GCM_WITHOUT_GETTER）',
    'avatar'
  ),
  // ── Role：删除流程中断恢复标记 ──
  'Role.deletionPreviousStatus': F(
    'L2',
    'plain',
    false,
    '删除中断恢复标记：select:false，不下发前端'
  ),
  'Role.deletionStartedAt': F('L2', 'plain', false, '删除流程开始时间：select:false，同上'),
  'Role.name': F('L2', 'plain', false, '角色显示名，非个人信息'),
  'Permission.name': F('L2', 'plain', false, '权限点显示名，非个人信息'),
  // ── UserSession：登录设备痕迹 ──
  'UserSession.sid': F(
    'L3',
    'plain',
    true,
    '会话标识：与令牌 sid 同值，可反推账号与设备',
    'device'
  ),
  'UserSession.ip': F('L3', 'plain', true, '登录 IP', 'device'),
  'UserSession.lastIp': F('L3', 'plain', true, '最近活跃 IP', 'device'),
  'UserSession.userAgent': F('L3', 'plain', true, 'UA 原文：设备指纹原料', 'device'),
  'UserSession.fingerprint': F('L3', 'plain', true, '设备指纹：跨会话识别同一设备', 'device'),
  'AuditLog.username': F('L3', 'plain', true, '操作者账号名', 'audit'), // ── AuditLog ──
  'AuditLog.targetUsername': F('L3', 'plain', true, '被操作者账号名', 'audit'),
  'AuditLog.ip': F('L3', 'plain', true, '操作 IP', 'audit'),
  'AuditLog.userAgent': F('L3', 'plain', true, '操作 UA', 'audit'),
  'AuditLog.clientInfo.reportedIp': F(
    'L3',
    'plain',
    true,
    'XFF 声称的客户端 IP（未经验证，仅留痕）',
    'audit'
  ),
  'AuditLog.clientInfo.socketPeer': F('L3', 'plain', true, 'TCP 对端地址（可信来源）', 'audit'),
  'AuditLog.sessionId': F(
    'L3',
    'plain',
    true,
    '会话标识：与 UserSession.sid 对应，追溯断链的修复点',
    'audit'
  ),
  'AuditLog.fingerprint': F('L3', 'plain', true, '设备指纹', 'audit'),
  'IPBlacklist.ip': F('L3', 'plain', true, '封禁 IP：安全事件记录，可关联自然人', 'security'), // ── IPBlacklist ──
  'IPBlacklist.targetUsername': F('L3', 'plain', true, '被封禁尝试的账号名', 'security'),
  'PrivilegeGrant.username': F('L3', 'plain', true, '被授权账号名', 'grant'), // ── PrivilegeGrant ──
  'PrivilegeGrant.requestedByName': F('L3', 'plain', true, '申请人姓名（审批链证据）', 'grant'),
  'PrivilegeGrant.decidedByName': F('L3', 'plain', true, '审批人姓名（审批链证据）', 'grant'),
  'PrivilegeGrant.revokedByName': F('L3', 'plain', true, '撤销人姓名（审批链证据）', 'grant'),
  'ReauthGrant.sid': F('L3', 'plain', true, '二次验证凭据绑定的会话标识', 'security'), // ── 二次验证 ──
  'ReauthTicketUse.jti': F(
    'L3',
    'plain',
    true,
    '一次性票据 jti：与账号绑定，泄露可做重放探测',
    'security'
  ),
  // ── TokenBlacklist ──
  'TokenBlacklist.tokenHash': F(
    'L4',
    'sha256',
    false,
    '已吊销令牌的 SHA-256 摘要：判定吊销状态所需，不可逆',
    'security'
  ),
  // ── FireAlarm：第三方个人信息 ──
  'FireAlarm.reporter.name': F(
    'L3',
    'plain',
    true,
    '上报人自填姓名：**刻意不加密**（与 User.realName 同一取舍）',
    'alarm'
  ),
  'FireAlarm.reporter.phone': F(
    'L3',
    'gcm',
    true,
    '上报人手机号：与 User.phone 同轨加密，且任何读接口都不回传',
    'alarm'
  ),
  // ── ConsentRecord：同意证据 ──
  'ConsentRecord.username': F(
    'L3',
    'plain',
    true,
    '同意主体账号名（冗余快照，账号匿名化后仍可追溯）',
    'consent'
  ),
  'ConsentRecord.ip': F('L3', 'plain', true, '同意动作发生时的 IP', 'consent'),
  'ConsentRecord.userAgent': F('L3', 'plain', true, '同意动作发生时的 UA', 'consent'),
  'FireDevice.deviceName': F('L2', 'plain', false, '设备名称，非个人信息'), // ── FireDevice ──
  // ── ForensicCapture：取证全量 ──
  'ForensicCapture.ip': F(
    'L4',
    'plain',
    true,
    '取证 IP：只对 forensicTrigger 标记的来源落库',
    'forensic'
  ),
  'ForensicCapture.username': F('L4', 'plain', true, '取证请求的账号名', 'forensic'),
  'ForensicCapture.sessionId': F('L4', 'plain', true, '取证请求的会话标识', 'forensic'),
  'ForensicCapture.fingerprint': F('L4', 'plain', true, '取证请求的设备指纹', 'forensic'),
  'ForensicCapture.net.reportedIp': F('L4', 'plain', true, 'XFF 声称 IP', 'forensic'),
  'ForensicCapture.net.socketPeer': F('L4', 'plain', true, 'TCP 对端地址', 'forensic'),
});

/**
 * 字段分类：字段级声明优先，否则继承模型基线。未登记的模型/字段直接返回 null —— 静默给个默认等级会让「漏登记」看起来像「已分级」，调用方必须自己决定怎么处理（当前唯一调用方是门禁与 consentService，两者都 fail-closed）。
 */
const classifyField = (model, path) => {
  const modelLevel = MODEL_LEVELS[model];
  if (!modelLevel) return null;
  const declared = FIELD_LEVELS[model + '.' + path];
  if (declared) return { model, path, ...declared };
  return {
    model,
    path,
    level: modelLevel.level,
    atRest: 'plain',
    pii: false,
    reason: modelLevel.basis,
    consent: null,
  };
};

module.exports = {
  CLASSIFICATION_LEVELS,
  CONSENT_SCOPES,
  LEVEL_CODES,
  AT_REST_FORMS,
  MODEL_LEVELS,
  FIELD_LEVELS,
  GCM_WITHOUT_GETTER,
  classifyField,
};
