/**
 * 安全管理控制器
 * 处理安全相关的操作和查询
 */

const User = require('../models/User');
const { validationResult } = require('express-validator');
const AuditLog = require('../models/AuditLog');
const SystemConfig = require('../models/SystemConfig');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel } = require('../utils/permissionHelper');
const { DataMasking } = require('../utils/encryption');
const { validatePasswordStrength } = require('../utils/helpers');
const { isSuperAdminRole } = require('../utils/superAdmin');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const sessionService = require('../services/sessionService');
const { RETENTION_DAYS, wasAdjusted: retentionWasAdjusted } = require('../constants/retention');
const { businessDayBounds } = require('../constants/timezone');

/**
 * 获取当前用户的安全信息
 * GET /api/security/my-info
 */
const getMySecurityInfo = asyncHandler(async (req, res) => {
  const userId = req.user.userId;

  const user = await User.findById(userId).select(
    'username email phone lastLoginAt createdAt status'
  );

  // 获取最近登录记录
  const recentLogins = await AuditLog.find({
    userId,
    action: { $in: ['login_success', 'login_failed'] },
  })
    .sort({ timestamp: -1 })
    .limit(10)
    .select('action ip timestamp success');

  // 计算安全评分
  let securityScore = 100;
  const suggestions = [];

  // 检查最后登录时间
  const daysSinceLastLogin = user.lastLoginAt
    ? Math.floor((Date.now() - new Date(user.lastLoginAt)) / (1000 * 60 * 60 * 24))
    : 999;

  if (daysSinceLastLogin > 30) {
    securityScore -= 10;
    suggestions.push('账户长期未登录，请注意账户安全');
  }

  // 检查失败登录尝试
  const failedLogins = recentLogins.filter((l) => !l.success).length;
  if (failedLogins > 3) {
    securityScore -= 15;
    suggestions.push('检测到多次登录失败，建议修改密码');
  }

  return ApiResponse.success(
    res,
    {
      user: {
        ...user.toObject(),
        phone: DataMasking.maskPhone(user.phone),
        email: DataMasking.maskEmail(user.email),
      },
      securityScore: Math.max(0, securityScore),
      suggestions,
      recentLogins: recentLogins.map((login) => ({
        action: login.action,
        ip: DataMasking.maskIP(login.ip),
        time: login.timestamp,
        success: login.success,
      })),
    },
    '获取成功'
  );
});

/**
 * 修改密码（需要当前密码验证）
 * PUT /api/security/change-password
 */
const changePasswordSecure = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  // ===== 口令密文轨（S5：与 /api/auth/password 双轨口径一致）=====
  // LOGIN_ENCRYPT_STRICT=true 后明文轨已被校验层关闭，此端点此前只收明文，
  // 会成为「明文轨已关」不变量的缺口；现在密文字段优先，解密后走同一套校验
  const { decryptLoginCredential } = require('../utils/loginCipher');
  let currentPassword = req.body.currentPassword;
  if (typeof req.body.encCurrentPassword === 'string' && req.body.encCurrentPassword) {
    try {
      currentPassword = await decryptLoginCredential(req.body.encCurrentPassword);
    } catch (err) {
      logger.warn('改密拒绝 - 当前口令密文无效', { username: req.user?.username, code: err.code });
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    }
  }

  let newPassword = req.body.newPassword;
  if (typeof req.body.encNewPassword === 'string' && req.body.encNewPassword) {
    try {
      newPassword = await decryptLoginCredential(req.body.encNewPassword);
    } catch (err) {
      logger.warn('改密拒绝 - 新口令密文无效', { username: req.user?.username, code: err.code });
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    }
    // 密文轨下校验层无法比对 confirm（明文在信封内）：若客户端仍携带
    // 明文 confirmPassword，则在此兜底比对；未携带时以解密结果为准
    const { confirmPassword } = req.body;
    if (typeof confirmPassword === 'string' && confirmPassword && confirmPassword !== newPassword) {
      return ApiResponse.error(res, '两次输入的新密码不一致', 400);
    }
  } else if (newPassword !== req.body.confirmPassword) {
    // 明文轨：验证新密码一致性
    return ApiResponse.error(res, '两次输入的新密码不一致', 400);
  }

  // 验证新密码强度（统一企业级策略；密文轨的明文只有解密后才能评估）
  const strengthError = validatePasswordStrength(newPassword);
  if (strengthError) {
    return ApiResponse.error(res, strengthError, 400);
  }

  const user = await User.findById(req.user.userId).select('+password');
  if (!user) {
    return ApiResponse.unauthorized(res, '用户不存在或已被删除');
  }

  // 验证当前密码
  const isMatch = await user.comparePassword(currentPassword);
  if (!isMatch) {
    logger.warn('密码修改失败 - 当前密码错误', { username: user.username });
    return ApiResponse.error(res, '当前密码错误', 400);
  }

  // 检查新密码是否与旧密码相同
  if (await user.comparePassword(newPassword)) {
    return ApiResponse.error(res, '新密码不能与当前密码相同', 400);
  }

  // 更新密码
  user.password = newPassword;
  user.passwordChangedAt = new Date();
  await user.save();

  // 改密后立即吊销该用户全部会话，与 /api/auth/password 口径一致：
  // invalidateUserTokens 内部完成 tokenVersion += 1 与用户缓存失效。
  // fail-closed：密码此刻已落库，吊销失败绝不能变成笼统 500 或假装成功——
  // 必须如实告知「已改但未吊销」，引导用户重新登录以建立干净会话
  const { invalidateUserTokens } = require('../middleware/tokenBlacklist');
  try {
    await invalidateUserTokens(user._id);
  } catch (revokeErr) {
    logger.error(`改密成功但会话吊销失败：${revokeErr.message}`, { username: user.username });
    return ApiResponse.error(
      res,
      '密码已修改，但会话吊销服务暂不可用，旧登录状态可能仍然有效，请重新登录',
      503
    );
  }
  // 会话表须与 tokenVersion 同步收敛：tokenVersion 递增已让所有令牌失效，
  // 但会话记录若仍是 active，「登录会话」界面会列出一批实际已掉线的设备，
  // 用户据此判断「账号是否被别人登录着」会得到错误结论
  await sessionService.revokeAllSessionsSafe(user._id, 'password_changed');

  logger.info('用户成功修改密码', { username: user.username });

  // 记录审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'password_changed',
    category: 'auth',
    userId: user._id,
    username: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
  });

  return ApiResponse.success(res, null, '密码修改成功，请重新登录');
});

/**
 * 获取账户绑定信息
 * GET /api/security/bindings
 */
const getAccountBindings = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('email phone department status');

  return ApiResponse.success(
    res,
    {
      bindings: [
        {
          type: 'email',
          value: DataMasking.maskEmail(user.email),
          verified: !!user.email,
          required: true,
        },
        {
          type: 'phone',
          value: DataMasking.maskPhone(user.phone),
          verified: !!user.phone,
          required: false,
        },
        {
          type: 'department',
          value: user.department || '未设置',
          verified: true,
          required: false,
        },
      ],
    },
    '获取成功'
  );
});

/**
 * 查看敏感数据（需要二次验证）
 * POST /api/security/view-sensitive
 */
const viewSensitiveData = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { dataType } = req.body;

  const user = await User.findById(req.user.userId);
  if (!user) {
    return ApiResponse.unauthorized(res, '用户不存在或已被删除');
  }

  let sensitiveData = {};

  switch (dataType) {
    case 'phone':
      sensitiveData = {
        type: 'phone',
        masked: DataMasking.maskPhone(user.phone),
        full: user.phone, // 实际场景应解密后返回
      };
      break;
    case 'email':
      sensitiveData = {
        type: 'email',
        masked: DataMasking.maskEmail(user.email),
        full: user.email,
      };
      break;
    default:
      return ApiResponse.error(res, '不支持的数据类型', 400);
  }

  // 记录审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'view_sensitive_data',
    category: 'auth',
    userId: req.user.userId,
    username: user.username,
    dataType,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
  });

  return ApiResponse.success(res, sensitiveData, '获取成功');
});

/**
 * 获取系统安全统计
 * GET /api/security/stats
 */
const getSecurityStats = asyncHandler(async (req, res) => {
  // 「今日」起点统一取业务时区零点（P3-18 单一声明 businessDayBounds）：
  // 原 setHours(0,0,0,0) 依赖服务器本地时区（容器 TZ=Asia/Shanghai 时碰巧正确，
  // 但裸跑/改 TZ 即漂移），与 auditMonitor 告警频控、仪表盘/报表的「今日」
  // 存在分叉隐患。businessDayBounds().start 与全站「今日」口径同源。
  const { start: today } = businessDayBounds();

  // 今日登录统计
  const todayLogins = await AuditLog.countDocuments({
    category: 'auth',
    action: 'login_success',
    timestamp: { $gte: today },
  });

  // 今日失败登录统计
  const todayFailedLogins = await AuditLog.countDocuments({
    category: 'auth',
    action: 'login_failed',
    timestamp: { $gte: today },
  });

  // 高风险操作统计
  const highRiskOps = await AuditLog.countDocuments({
    riskLevel: { $in: ['high', 'critical'] },
    timestamp: { $gte: today },
  });

  // 异常行为检测
  const anomalies = await AuditLog.detectAnomalies({
    windowMinutes: 60,
    threshold: 5,
  });

  // 被封禁 IP 数量
  // （实际应从 Redis 或其他存储中获取）

  return ApiResponse.success(
    res,
    {
      overview: {
        todayLogins,
        todayFailedLogins,
        highRiskOperations: highRiskOps,
      },
      anomalies: {
        failedOperationUsers: anomalies.failedOperations,
        unusualTimeUsers: anomalies.unusualTimeOperations,
      },
      securityLevel: todayFailedLogins > 20 || highRiskOps > 10 ? 'high' : 'normal',
    },
    '获取成功'
  );
});

/**
 * 举报异常行为
 * POST /api/security/report
 */
const reportSuspiciousActivity = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { targetType, targetId, reason, description } = req.body;

  if (!targetType || !reason) {
    return ApiResponse.error(res, '请提供目标类型和原因', 400);
  }

  res.locals.skipGlobalAudit = true;
  const report = await AuditLog.create({
    action: 'suspicious_report',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    targetType,
    targetId,
    reason,
    description,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    riskLevel: 'high',
  });

  logger.warn('安全举报', { reporter: req.user.username, targetType, targetId, reason });

  return ApiResponse.success(
    res,
    {
      reportId: report._id,
    },
    '举报已提交，安全团队将尽快处理'
  );
});

/**
 * 获取个人操作日志
 * GET /api/security/my-logs
 */
const getMyLogs = asyncHandler(async (req, res) => {
  const { days = 7, limit = 50, category } = req.query;

  // limit 解析为整数并限界：非法输入（非数字/小于 1）回退本接口默认值 50，
  // 上限 500，避免客户端传入任意大值或 NaN 直传 Mongo limit()
  let parsedLimit = parseInt(limit, 10);
  if (!Number.isInteger(parsedLimit) || parsedLimit < 1) parsedLimit = 50;
  parsedLimit = Math.min(parsedLimit, 500);

  // days 同样解析并钳制到 [1,365]：非法输入回退默认 7 天，
  // 防止 NaN 或超大窗口直传 getUserActivity 造成无界时间范围全表扫描
  let parsedDays = parseInt(days, 10);
  if (!Number.isInteger(parsedDays) || parsedDays < 1) parsedDays = 7;
  parsedDays = Math.min(parsedDays, 365);

  const logs = await AuditLog.getUserActivity(req.user.userId, {
    days: parsedDays,
    limit: parsedLimit,
    category,
  });

  return ApiResponse.success(res, logs, '获取成功');
});

/**
 * 账户锁定/解锁（管理员功能）
 * PUT /api/security/users/:userId/lock
 */
const toggleUserLock = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { userId } = req.params;
  const { locked, reason } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // 层级校验：禁止锁定/解锁等于或高于自身层级的用户
  const Role = require('../models/Role');
  // select 必须包含 isBuiltIn，否则下方内置超管保护判断恒为 false（死代码）
  const targetUserRoles = await Role.find({ _id: { $in: user.roles } }).select(
    'level code isBuiltIn'
  );
  const targetMaxLevel =
    targetUserRoles.length > 0 ? Math.max(...targetUserRoles.map((r) => r.level || 0)) : 0;

  // 按操作者 ID 重新查询角色层级（req.user.roles 存的是角色编码字符串，
  // 直接用于 _id: {$in: ...} 会触发 CastError，导致整个接口 500）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);

  // 禁止操作同级或更高级别的用户
  if (targetMaxLevel >= operatorMaxLevel && String(user._id) !== String(req.user.userId)) {
    return ApiResponse.error(res, '无权操作同级或更高级别的用户', 403);
  }

  // 禁止锁定超级管理员（无 isSelf 例外：锁定后层级校验会拦下所有解锁尝试）
  const isBuiltInSuperAdmin = targetUserRoles.some(isSuperAdminRole);
  if (locked && isBuiltInSuperAdmin) {
    return ApiResponse.codeError(res, 'CANNOT_LOCK_SUPER_ADMIN');
  }

  // ===== 解锁/锁定状态保护 =====
  // 仅当账户当前确实处于锁定态时才允许解锁并恢复为 active；
  // 管理员禁用（inactive）的账户不允许借“解锁”复活，需先由管理员通过用户更新接口恢复启用
  if (!locked && user.status === 'inactive') {
    return ApiResponse.error(
      res,
      '该账户已被管理员禁用（inactive），不能通过解锁恢复；请先由管理员启用该账户',
      400
    );
  }
  if (!locked && user.status !== 'locked') {
    return ApiResponse.error(res, '该账户当前未处于锁定状态，无需解锁', 400);
  }
  // 锁定方向同样拒绝已禁用账户：若允许 inactive → locked，
  // 后续“锁定→解锁”链路会把禁用账户洗回 active，变相复活被禁用账户
  if (locked && user.status === 'inactive') {
    return ApiResponse.error(res, '该账户已被管理员禁用，不能重复锁定', 400);
  }

  user.status = locked ? 'locked' : 'active';

  if (locked && reason) {
    user.remark = reason;
  }

  await user.save();

  // 失效用户缓存
  const { invalidateUserCache } = require('../middleware/auth');
  invalidateUserCache(user._id);
  // 锁定/解锁影响用户统计，目标用户与操作者（统计视角）的统计缓存均需失效
  const statsCache = require('../services/statsCache');
  statsCache.invalidateByUserId(user._id);
  statsCache.invalidateByUserId(req.user.userId);

  // 注意：不再将用户级锁定关联到 IP 黑名单，避免误封 NAT 出口

  // 记录审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: locked ? 'user_locked' : 'user_unlocked',
    category: 'user',
    userId: req.user.userId,
    username: req.user.username,
    targetUserId: user._id,
    targetUsername: user.username,
    reason,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'high',
  });

  logger.info('用户锁定状态变更', { username: user.username, locked, operator: req.user.username });

  return ApiResponse.success(
    res,
    {
      userId: user._id,
      username: user.username,
      status: user.status,
    },
    `用户已${locked ? '锁定' : '解锁'}`
  );
});

/**
 * 管理员重置用户两步验证（MFA）
 * PUT /api/security/users/:userId/mfa/reset
 *
 * 场景：用户丢失认证器且备用恢复码用尽，无法自行关闭 MFA 时的账户救济通道。
 * 效果：清除 TOTP 密钥/恢复码/防爆破计数，并吊销该用户全部会话（强制重新登录）。
 * 权限：user:reset_password（与重置密码同级敏感的救济操作）。
 */
const resetUserMfa = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { userId } = req.params;
  const user = await User.findById(userId);
  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // 自身不走管理员重置：请通过个人资料页用动态口令正常关闭
  if (String(user._id) === String(req.user.userId)) {
    return ApiResponse.error(res, '不能通过管理接口重置自己的两步验证，请在个人资料页操作', 400);
  }
  if (!user.mfaEnabled) {
    return ApiResponse.error(res, '该用户未开启两步验证，无需重置', 400);
  }

  // 层级与内置超管保护（与 toggleUserLock 同口径）
  const Role = require('../models/Role');
  const targetUserRoles = await Role.find({ _id: { $in: user.roles } }).select(
    'level code isBuiltIn'
  );
  const targetMaxLevel =
    targetUserRoles.length > 0 ? Math.max(...targetUserRoles.map((r) => r.level || 0)) : 0;
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.error(res, '无权重置同级或更高级别用户的两步验证', 403);
  }
  if (targetUserRoles.some(isSuperAdminRole)) {
    return ApiResponse.codeError(res, 'CANNOT_RESET_MFA_SUPER_ADMIN', {
      message: '不能重置超级管理员的两步验证',
    });
  }

  // fail-closed 顺序：先吊销会话，再清 MFA。若先清两步验证而吊销失败，
  // 会造成「防护已拆除 + 旧会话仍在线」的复合风险；吊销失败直接 503，
  // MFA 状态原样保留，管理员可安全重试。
  // （invalidateUserTokens 内部已含缓存失效，无需再手动调用 invalidateUserCache）
  const { invalidateUserTokens } = require('../middleware/tokenBlacklist');
  try {
    await invalidateUserTokens(user._id);
  } catch (revokeErr) {
    logger.error(`重置 MFA 中止 - 会话吊销失败：${revokeErr.message}`, {
      username: user.username,
      operator: req.user.username,
    });
    return ApiResponse.error(res, '会话吊销服务暂不可用，未执行重置，请稍后重试', 503);
  }

  try {
    await User.findByIdAndUpdate(user._id, {
      mfaEnabled: false,
      mfaSecret: '',
      mfaRecoveryCodes: [],
      mfaFailCount: 0,
      mfaLockUntil: null,
    });
  } catch (clearErr) {
    // 吊销已生效（用户已强制下线），仅 MFA 清除失败——该方向仍是安全的
    // （两步验证保持开启），但响应不能假装整体成功，须告知管理员重试
    logger.error(`重置 MFA 未完成 - 清除两步验证状态失败：${clearErr.message}`, {
      username: user.username,
      operator: req.user.username,
    });
    return ApiResponse.error(res, '该用户已被强制下线，但两步验证状态清除失败，请重试', 503);
  }

  // 会话表须与 tokenVersion 同步收敛：否则被重置 MFA 的用户在「登录会话」
  // 界面仍看到一堆 active 设备，而它们实际上已经全部掉线
  await sessionService.revokeAllSessionsSafe(user._id, 'admin_revoked');

  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'admin_reset_mfa',
    category: 'security',
    userId: req.user.userId,
    username: req.user.username,
    targetUserId: user._id,
    targetUsername: user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'high',
    riskFactors: ['admin_mfa_reset'],
    reason: `管理员重置用户 ${user.username} 的两步验证并强制下线`,
  });

  logger.warn('管理员重置 MFA', { username: user.username, operator: req.user.username });

  return ApiResponse.success(
    res,
    {
      userId: user._id,
      username: user.username,
      mfaEnabled: false,
    },
    '该用户的两步验证已重置，需重新登录'
  );
});

/**
 * 获取安全概览
 * GET /api/security/overview
 */
const getSecurityOverview = asyncHandler(async (req, res) => {
  try {
    const securityAlert = require('../services/securityAlert');
    const overview = await securityAlert.getSecurityOverview(7);
    if (!overview || typeof overview !== 'object') {
      return ApiResponse.error(res, '安全概览数据格式错误', 404);
    }
    // 验证必要的字段
    if (
      typeof overview.criticalAlerts !== 'number' ||
      typeof overview.highAlerts !== 'number' ||
      typeof overview.failedLogins !== 'number'
    ) {
      return ApiResponse.error(res, '安全概览数据结构错误', 404);
    }
    // 添加默认值
    overview.period = overview.period || `${7}天`;
    // 确保所有数字字段都是非负数
    overview.criticalAlerts = Math.max(0, overview.criticalAlerts);
    overview.highAlerts = Math.max(0, overview.highAlerts);
    overview.failedLogins = Math.max(0, overview.failedLogins);
    // 添加额外的安全指标
    overview.unusualAccess =
      typeof overview.unusualAccess === 'number' ? Math.max(0, overview.unusualAccess) : 0;
    // L-03/P3-6：riskScore 以 securityAlert.getSecurityOverview 的计算为准
    // （unusualAccess 系数 5）。此前控制器用系数 3 整个重算覆盖，两处口径
    // 漂移后改哪处都会被另一处静默抵消。此处仅做边界钳位，不再重算。
    overview.riskScore = Math.min(
      100,
      Math.max(0, typeof overview.riskScore === 'number' ? overview.riskScore : 0)
    );
    // 添加时间戳（不包含服务器环境信息，防止信息泄露）
    overview.updatedAt = new Date().toISOString();
    overview.version = '1.0.0';
    // 添加安全建议
    overview.suggestions = [];
    if (overview.riskScore > 70) {
      overview.suggestions.push('高风险：建议立即审查最近的操作日志');
    }
    if (overview.failedLogins > 10) {
      overview.suggestions.push('登录失败次数过多：建议检查账户安全');
    }
    if (overview.unusualAccess > 5) {
      overview.suggestions.push('非常规时间访问：建议确认操作合法性');
    }
    // P3-6：原 summary.successRate = (四类事件总数 - 失败登录数) / 总数，
    // 分母混入了告警数——criticalAlerts=100、failedLogins=10 时显示 90.9%，
    // 这个"成功率"没有任何可解释的业务含义（概览里根本没有成功登录计数），
    // 且全仓无任何消费者。直接移除，而非补查询去圆一个伪指标。
    // 添加性能指标
    overview.performance = {
      lastQueryTime: 0, // 后续可以添加实际查询时间
      avgResponseTime: 0, // 后续可以添加平均响应时间
      maxConcurrentConnections: 0, // 后续可以添加最大并发连接数
    };
    // 合规指标（阶段5.1）：审计日志合规就绪度，供合规仪表盘展示
    try {
      const { getLatestHash } = require('../utils/auditChain');
      const auditMonitor = require('../services/auditMonitor');
      const auditBuffer = require('../services/auditBuffer');
      const AuditLogModel = require('../models/AuditLog');
      const chainTailHash = await getLatestHash(AuditLogModel);
      overview.compliance = {
        // P3-46：对外展示的必须是**实际生效值**而非原始配置值。
        // 原实现 `parseInt(...) || 180` 会把 AUDIT_RETENTION_DAYS=1 如实报成 1，
        // 而数据库 TTL 实为 90 天——合规仪表盘与真实留存不一致，两种方向都危险：
        // 报低了让人误以为不合规去调参，报高了则是对外虚假声明
        retentionDays: RETENTION_DAYS,
        // 配置被钳制/回退时一并暴露，让运维知道自己的配置未被原样采用
        retentionConfigAdjusted: retentionWasAdjusted,
        appendOnlyEnforced: true,
        monitorRunning:
          typeof auditMonitor.isRunning === 'function' ? auditMonitor.isRunning() : false,
        walEnabled:
          typeof auditBuffer.isWalEnabled === 'function' ? auditBuffer.isWalEnabled() : false,
        exportEnabled: true,
        shippingEnabled: !!process.env.LOG_SHIPPING_URL,
        chainTailHash: chainTailHash || null,
      };
    } catch (e) {
      overview.compliance = { error: '合规指标获取失败' };
    }
    return ApiResponse.success(res, overview, '获取成功');
  } catch (error) {
    logger.error(`安全概览查询失败: ${error.message}`);
    return ApiResponse.serverError(res, '安全概览查询失败');
  }
});

/**
 * 获取最近安全告警
 * GET /api/security/alerts
 */
const getRecentAlerts = asyncHandler(async (req, res) => {
  try {
    const securityAlert = require('../services/securityAlert');
    // 多取 1 条用于探测是否还有更多：固定取 50 时 hasMore 恒为 false，分页探测失效
    const ALERTS_PAGE_SIZE = 50;
    const alertsRaw = await securityAlert.getRecentAlerts(ALERTS_PAGE_SIZE + 1);
    if (!alertsRaw || !Array.isArray(alertsRaw)) {
      return ApiResponse.error(res, '最近告警数据为空', 404);
    }
    // 据实计算 hasMore 后再截断到页大小，保证返回体与元数据一致
    const hasMore = alertsRaw.length > ALERTS_PAGE_SIZE;
    const alerts = alertsRaw.slice(0, ALERTS_PAGE_SIZE);
    // M-03 修复：仅校验结构性必需字段（_id/timestamp/action）。
    // 原 15 字段全量非空强校验会把缺少任一可选字段（userAgent/statusCode/duration 等）
    // 的合法告警静默丢弃，造成安全告警漏报（监控盲区）。
    const validAlerts = alerts
      .filter(
        (alert) =>
          alert && typeof alert === 'object' && alert._id && alert.timestamp && alert.action
      )
      .map((alert) => ({
        // 先展开原始告警，再对缺失的可选字段兜底，保证前端渲染稳定
        ...alert,
        category: alert.category || 'unknown',
        username: alert.username || 'anonymous',
        riskLevel: alert.riskLevel || 'low',
        ip: alert.ip || '-',
        riskFactors: alert.riskFactors || [],
        statusCode: alert.statusCode ?? 0,
        success: alert.success !== undefined ? alert.success : true,
        duration: alert.duration ?? 0,
        userAgent: alert.userAgent || '-',
        method: alert.method || '-',
        path: alert.path || '-',
      }));
    // 按时间倒序排序
    validAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    // 限制返回数量
    const limitedAlerts = validAlerts.slice(0, ALERTS_PAGE_SIZE);
    // 计算统计摘要
    const summary = {
      critical: validAlerts.filter((a) => a.riskLevel === 'critical').length,
      high: validAlerts.filter((a) => a.riskLevel === 'high').length,
      medium: validAlerts.filter((a) => a.riskLevel === 'medium').length,
      low: validAlerts.filter((a) => a.riskLevel === 'low').length,
      total: validAlerts.length,
    };
    // 添加元数据
    const response = {
      data: limitedAlerts,
      meta: {
        total: limitedAlerts.length,
        page: 1,
        limit: ALERTS_PAGE_SIZE,
        hasMore,
        lastUpdated: new Date().toISOString(),
        count: limitedAlerts.length,
        summary,
      },
    };
    return ApiResponse.success(res, response, '获取成功');
  } catch (error) {
    logger.error(`最近告警查询失败: ${error.message}`);
    return ApiResponse.serverError(res, '最近告警查询失败');
  }
});

/**
 * ⚠ 已知不一致（本次不改，待统一）：
 * queryAuditLogs / exportAuditLogs / getRecentAlerts 返回体为 { data: {...}, meta } 结构，
 * 经 ApiResponse.success 再包一层后出现 data.data 双层信封，
 * 与其他接口的单层 data 信封不一致；属 API 契约变更，需与前端协同后统一调整。
 */

/**
 * 构建审计日志查询条件（queryAuditLogs 与 exportAuditLogs 共用筛选逻辑）
 *
 * 将参数校验与查询体构建统一收敛到此函数，避免导出接口与查询接口逻辑分叉。
 * @param {object} req Express 请求对象
 * @returns {{ query: object, startDate: string|undefined, endDate: string|undefined }}
 * @throws {Error} 参数非法时抛出带可读消息的错误（调用方应返回 400）
 */
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
    return ApiResponse.error(res, '参数 allowPublicRegistration 必须为布尔值', 400);
  }

  await SystemConfig.set('allowPublicRegistration', allowPublicRegistration, req.user.userId);
  SystemConfig.invalidateRegistrationCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: allowPublicRegistration ? 'registration_enabled' : 'registration_disabled',
    category: 'system',
    userId: req.user.userId,
    username: req.user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    body: { allowPublicRegistration },
  }).catch(() => {});

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
    return ApiResponse.error(res, '参数 loginCaptchaEnabled 必须为布尔值', 400);
  }

  await SystemConfig.set('loginCaptchaEnabled', loginCaptchaEnabled, req.user.userId);
  SystemConfig.invalidateLoginCaptchaCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: loginCaptchaEnabled ? 'login_captcha_enabled' : 'login_captcha_disabled',
    category: 'system',
    userId: req.user.userId,
    username: req.user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    body: { loginCaptchaEnabled },
  }).catch(() => {});

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
    return ApiResponse.error(res, '参数 registerCaptchaEnabled 必须为布尔值', 400);
  }

  await SystemConfig.set('registerCaptchaEnabled', registerCaptchaEnabled, req.user.userId);
  SystemConfig.invalidateRegisterCaptchaCache();

  // 审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: registerCaptchaEnabled ? 'register_captcha_enabled' : 'register_captcha_disabled',
    category: 'system',
    userId: req.user.userId,
    username: req.user.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    body: { registerCaptchaEnabled },
  }).catch(() => {});

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
  getMySecurityInfo,
  changePasswordSecure,
  getAccountBindings,
  viewSensitiveData,
  getSecurityStats,
  reportSuspiciousActivity,
  getMyLogs,
  toggleUserLock,
  resetUserMfa,
  getSecurityOverview,
  getRecentAlerts,
  getRegistrationConfig,
  setRegistrationConfig,
  getLoginCaptchaConfig,
  setLoginCaptchaConfig,
  getRegisterCaptchaConfig,
  setRegisterCaptchaConfig,
};
