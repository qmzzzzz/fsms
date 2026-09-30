/**
 * 安全管理控制器
 * 处理安全相关的操作和查询
 */

const User = require('../models/User');
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const AuditLog = require('../models/AuditLog');
const SystemConfig = require('../models/SystemConfig');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../utils/permissionHelper');
const { assertRecordInScope } = require('../middleware/rbac');
// 数据范围字段只有一份声明（constants/dataScopeFields.js）：本文件两处用户范围闸曾各抄一遍
// 'createdBy'/'department'，与 userController 引用的同一常量脱钩。
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { applyAuditDataScope } = require('../services/auditScopeFilter');
const { DataMasking } = require('../utils/encryption');
const { isSuperAdminRole } = require('../utils/superAdmin');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');
const { RETENTION_DAYS, wasAdjusted: retentionWasAdjusted } = require('../constants/retention');
const { businessDayBounds } = require('../constants/timezone');
// 高危档取自 constants/audit.js 由有序等级表切出的同一段（F-149）：概览这里的"高风险操作次数"
// 与告警取数、审计页 level=error、行为基线 highRisk 必须同进同退，各抄一份字面量就会分叉。
const { AUDIT_RISK_LEVELS, AUDIT_ERROR_RISK_LEVELS } = require('../constants/audit');
const { onAuditWriteFailure, onAuditWriteFailureRethrow } = require('../utils/auditWriteFailure');

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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  // 评价报告 #15（改密逻辑双实现收敛）：本端点与 /api/auth/password 的
  // 「解密→确认→强度→比对→落库→吊销→会话收敛」此前各写一遍，极易漂移。
  // 现在控制器只做 HTTP 语义映射，业务规则全部收敛到
  // authService.changeUserPassword 单一实现（确认密码比对在解密后于业务层完成）。
  const result = await authService.changeUserPassword(req.user.userId, req.body, {
    username: req.user?.username,
  });

  switch (result.outcome) {
    case 'ENC_INVALID':
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    case 'MISSING':
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_AND_NEW_REQUIRED');
    case 'CONFIRM_MISMATCH':
      return ApiResponse.codeError(res, 'PASSWORD_CONFIRM_MISMATCH');
    case 'WEAK':
      return ApiResponse.error(res, result.message, 400);
    case 'USER_NOT_FOUND':
      return ApiResponse.codeError(res, 'USER_NOT_FOUND_OR_DELETED');
    case 'CURRENT_WRONG':
      logger.warn('密码修改失败 - 当前密码错误', { username: req.user?.username });
      return ApiResponse.codeError(res, 'PASSWORD_CURRENT_INCORRECT');
    case 'SAME_PASSWORD':
      return ApiResponse.codeError(res, 'PASSWORD_SAME_AS_CURRENT');
    // 与 authController 同码同语义：两个端点改的是同一份口令、同一套历史，
    // 文案差异只应来自各自对"当前密码"的称呼（profile 页 vs 安全中心），复用历史没有这种差异
    case 'PASSWORD_REUSED':
      return ApiResponse.codeError(res, 'PASSWORD_REUSED_IN_HISTORY', {
        params: { historyDepth: result.historyDepth },
      });
    case 'REVOKE_FAILED':
      // fail-closed：密码已落库但吊销失败，如实告知「已改但未吊销」（与 auth 端点同文案）
      return ApiResponse.codeError(res, 'PASSWORD_CHANGED_REVOKE_FAILED');
    case 'OK':
      break;
    default:
      // fail-closed：未知 outcome 绝不落到成功分支。
      // 原为 `default: break;` —— 业务层一旦新增 outcome 而此处忘了映射，会**静默按成功处理**
      // 并写入 password_changed 审计，把「映射表漏项」变成一条假的成功留痕。
      // 取证：`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕（zzqA_changePasswordOutcomeMap 的「未知 outcome」用例
      // 此前只是被一次无关的 ValidationError 顶成绿，源码里并没有守这条不变量）。
      logger.error('改密返回未知 outcome，已按失败处理', { outcome: result.outcome });
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
  }

  logger.info('用户成功修改密码', { username: result.username });

  // 记录审计日志
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'password_changed',
    category: 'auth',
    userId: req.user.userId,
    username: result.username,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
  }).catch(onAuditWriteFailure('password_changed', req));

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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { dataType, targetUserId } = req.body;
  // #9：本人查看（未指定 targetUserId 或指向自己）免鉴权——二次验证已由
  // requireReAuthentication 兜底；查看他人需 system:read（路由层 checkViewSensitivePermission
  // 已拦），且受数据范围约束（非超管不得越级查看层级高于自己的目标）。
  const isSelf = !targetUserId || String(targetUserId) === String(req.user.userId);

  // 数据范围保护：查看他人时，操作者层级须**严格高于**目标用户层级
  // （目标层级 >= 操作者层级即拒绝，含同级——与 userController/rolePermissionController/
  // authService 等其余 23 处「>= 即拒绝」口径一致，P1-21 修复，2026-09-17）。
  // 理由：敏感数据（手机号/邮箱）的横向查看不因同级而合法，同级放行等于允许
  // 平级管理员互相读取 PII；越级（target > op）更应拒绝。超管 *:* 恒通过。
  if (!isSelf) {
    const opLevel = await getOperatorMaxLevel(req.user.userId);
    const targetUser = await User.findById(targetUserId)
      .select('roles')
      .populate({ path: 'roles', select: 'level' })
      .lean();
    if (!targetUser) {
      return ApiResponse.codeError(res, 'TARGET_USER_NOT_FOUND');
    }
    const targetRoles = (targetUser.roles || []).filter(Boolean);
    const targetLevel = maxRoleLevel(targetRoles);
    // 目标层级必须取**全部**角色（含停用）：停用角色随时可能恢复，按 status:'active' 过滤
    // 会把 targetLevel 一路拉低；更危险的是空角色集时 maxRoleLevel 返回 -Infinity，
    // 于是 `opLevel <= targetLevel` 对任何持有者恒 false → 该账号 PII 对全体 system:read 者裸奔。
    // 故：无角色（无法确认其层级）从严拒绝；否则仍要求操作者严格高于目标。两处均 fail-closed。
    if (targetRoles.length === 0 || opLevel <= targetLevel) {
      return ApiResponse.codeError(res, 'SENSITIVE_VIEW_HIGHER_LEVEL_FORBIDDEN');
    }
  }

  const user = isSelf ? await User.findById(req.user.userId) : await User.findById(targetUserId);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND_OR_DELETED');
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
      return ApiResponse.codeError(res, 'UNSUPPORTED_DATA_TYPE');
  }

  // 记录审计日志
  // L-06 修复：原实现把 userId（操作者）与 username（被查看者）写进同一条记录，
  // 一条记录里两个主体字段指向不同的人。该处已设 skipGlobalAudit，故这是该操作
  // 的唯一留痕——按 username 检索时会把"谁查看了谁"记为被查看者本人。
  // 现改为：username 为操作者，被查看者另存 targetUserId/targetUsername。
  // P0-5 修复（2026-09-17）后"唯一留痕"才成立：skipGlobalAudit 由全局审计
  // 中间件在**响应时刻**读取（security.js 的 doLog），下方赋值与随后
  // res.json 之间的顺序因此生效；修复前该标志在中间件入口即被检查，
  // 此处赋值永远晚于检查，本次操作会被双写。
  res.locals.skipGlobalAudit = true;
  await AuditLog.create({
    action: 'view_sensitive_data',
    category: 'auth',
    userId: req.user.userId,
    username: req.user.username,
    targetUserId: user._id,
    targetUsername: user.username,
    dataType,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: true,
    riskLevel: 'medium',
    // 用重抛档而不是吞错档（档位表见 utils/auditWriteFailure.js）：本操作已设
    // skipGlobalAudit，这条 create 是唯一留痕；吞掉错误会照样把明文手机号/邮箱
    // 发出去 ⇒「读了 PII 却毫无记录」，比失败更糟。
  }).catch(onAuditWriteFailureRethrow('view_sensitive_data', req));

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
    riskLevel: { $in: AUDIT_ERROR_RISK_LEVELS },
    timestamp: { $gte: today },
  });

  // 异常行为检测
  // 两路聚合都按 userId 分组，返回体里就是"哪些用户"——与 /security/alerts 的行级
  // 列表同性质，故走同一个范围翻译器（口径见 F-B12）。上方的今日登录/高危次数是
  // 全局聚合，是否随范围收窄属另一条口径，此处未动。
  const { query: anomalyScope } = await applyAuditDataScope({}, req.user.userId);
  const anomalies = await AuditLog.detectAnomalies({
    windowMinutes: 60,
    threshold: 5,
    scopeFilter: anomalyScope,
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { targetType, targetId, reason, description } = req.body;

  if (!targetType || !reason) {
    return ApiResponse.codeError(res, 'REPORT_TARGET_AND_REASON_REQUIRED');
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
    // 用重抛档而不是吞错档（档位表见 utils/auditWriteFailure.js）：`reportId` 取自
    // 这条 create 的文档，吞掉错误后它是 undefined 而响应仍写「举报已提交」。
  }).catch(onAuditWriteFailureRethrow('suspicious_report', req));

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
 *
 * O-2 重构：业务规则（层级校验/内置超管保护/inactive 状态机/缓存失效/
 * 专用审计）已整体下沉 services/authService.setUserLockStatus，
 * 此处只保留参数校验与 outcome → HTTP 响应映射。
 */
const toggleUserLock = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { userId } = req.params;
  const { locked, reason } = req.body;

  // 数据范围闸（与 userController 写路径同判据）：本控制器此前零处范围调用，
  // 部门域管理员可锁定/解锁自己根本看不到的跨部门用户。层级校验在服务层，
  // 范围校验在此先行——两个正交轴都要有。
  const lockTarget = await User.findById(userId);
  if (!lockTarget) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }
  const { allowed: lockTargetInScope } = await assertRecordInScope(
    req,
    lockTarget,
    DATA_SCOPE_FIELDS.user.ownerField,
    DATA_SCOPE_FIELDS.user.departmentField
  );
  if (!lockTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  const result = await authService.setUserLockStatus(
    userId,
    { locked, reason },
    {
      operatorId: req.user.userId,
      operatorUsername: req.user.username,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    }
  );

  switch (result.outcome) {
    case 'NOT_FOUND':
      return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
    case 'FORBIDDEN_SAME_LEVEL':
      return ApiResponse.codeError(res, 'USER_OPERATE_PEER_OR_HIGHER_FORBIDDEN');
    case 'CANNOT_LOCK_SUPER_ADMIN':
      return ApiResponse.codeError(res, 'CANNOT_LOCK_SUPER_ADMIN');
    case 'INACTIVE_UNLOCK':
      return ApiResponse.codeError(res, 'UNLOCK_INACTIVE_ACCOUNT');
    case 'INACTIVE_LOCK':
      return ApiResponse.codeError(res, 'LOCK_INACTIVE_ACCOUNT');
    case 'NOT_LOCKED':
      return ApiResponse.codeError(res, 'ACCOUNT_NOT_LOCKED');
    case 'OK':
      break;
    default:
      // 同 changePasswordSecure：未知 outcome 不得落到成功分支（fail-closed）
      logger.error('锁定/解锁返回未知 outcome，已按失败处理', { outcome: result.outcome });
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
  }

  // 成功路径才跳过全局审计（与原实现一致：专用审计已由服务层落库）
  res.locals.skipGlobalAudit = true;
  return ApiResponse.success(
    res,
    {
      userId: result.userId,
      username: result.username,
      status: result.status,
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { userId } = req.params;
  const user = await User.findById(userId);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 自身不走管理员重置：请通过个人资料页用动态口令正常关闭

  // 数据范围闸：与 toggleUserLock / userController 写路径同判据
  const { allowed: mfaResetTargetInScope } = await assertRecordInScope(
    req,
    user,
    DATA_SCOPE_FIELDS.user.ownerField,
    DATA_SCOPE_FIELDS.user.departmentField
  );
  if (!mfaResetTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  if (String(user._id) === String(req.user.userId)) {
    return ApiResponse.codeError(res, 'CANNOT_RESET_OWN_MFA_VIA_ADMIN');
  }
  if (!user.mfaEnabled) {
    return ApiResponse.codeError(res, 'TARGET_MFA_NOT_ENABLED');
  }

  // 层级与内置超管保护（与 toggleUserLock 同口径）
  const Role = require('../models/Role');
  const targetUserRoles = await Role.find({ _id: { $in: user.roles } }).select(
    'level code isBuiltIn'
  );
  const targetMaxLevel = maxRoleLevel(targetUserRoles);
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.codeError(res, 'MFA_RESET_PEER_OR_HIGHER_FORBIDDEN');
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
    return ApiResponse.codeError(res, 'SESSION_REVOKE_SERVICE_UNAVAILABLE');
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
    return ApiResponse.codeError(res, 'FORCE_LOGOUT_MFA_CLEAR_FAILED');
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
  }).catch(onAuditWriteFailure('admin_reset_mfa', req));

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
      return ApiResponse.codeError(res, 'SECURITY_OVERVIEW_FORMAT_INVALID');
    }
    // 验证必要的字段
    if (
      typeof overview.criticalAlerts !== 'number' ||
      typeof overview.highAlerts !== 'number' ||
      typeof overview.failedLogins !== 'number'
    ) {
      return ApiResponse.codeError(res, 'SECURITY_OVERVIEW_STRUCTURE_INVALID');
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
        // 原先这里写死 `appendOnlyEnforced: true`——防篡改护栏的真实状态是
        // models/auditLogHooks.js 里的闭包变量（测试环境可关），而对外合规面板
        // 把它当事实陈述。现在读实际生效值；getter 缺失时让整块落到 catch 报
        // `error`（宁可报"取不到"，也不报一个编出来的 true）。
        appendOnlyEnforced: AuditLogModel.isAppendOnlyEnforced(),
        monitorRunning:
          typeof auditMonitor.isRunning === 'function' ? auditMonitor.isRunning() : false,
        // F-125：isRunning() 只回答"定时器挂着没有"，回答不了"检测有没有在成功跑"。
        // 定时任务最常见的静默失效形态是「面板说活着、实际每轮都失败」，
        // 而 runs/failures/consecutiveFailures/skippedOverlaps 此前只有测试能读
        // ——与本块 auditLoss 修的是同一个缺陷类（有指标、无出口）。
        // 兜底走 null 而不是让它抛：这里抛 TypeError 会把整段 compliance
        // （留存天数/链尾哈希/丢失计数）一起降级成 `{error}`，代价远大于一个字段。
        monitorHealth:
          typeof auditMonitor.getHealth === 'function' ? auditMonitor.getHealth() : null,
        walEnabled:
          typeof auditBuffer.isWalEnabled === 'function' ? auditBuffer.isWalEnabled() : false,
        // 审计导出没有运行期开关（路由恒挂载），所以这个键不携带信息量；
        // 保留是为了不打破既有消费方，读它的人应当知道它恒为 true。
        exportEnabled: true,
        // F-215：原先写 `!!process.env.LOG_SHIPPING_URL`。那个表达式回答的是
        // "配过这么个变量"，不是"日志正在往 SIEM 送"：变量写成不可解析的串时
        // transport 仍会挂载成功、启动日志仍会打「日志转发已启用」，面板再说一遍
        // 同一个误判没有任何价值（三个取值实测见 utils/logger.js 的 F-215 注释）。
        // 现在读挂载态，判据与邻居 walEnabled / monitorRunning 同口径。
        shippingEnabled:
          typeof logger.isShippingEnabled === 'function' ? logger.isShippingEnabled() : false,
        chainTailHash: chainTailHash || null,
        // 「有没有永久缺失的审计」此前只有测试能读（getStats 无生产读取方）。
        // 合规面板是这些指标唯一该有的地方：任何一项 >0 都意味着有一份需要取证的
        // 完整性缺口（各键的确切含义见下方逐项注释——有的是"已丢"，有的是"会重复"）。
        auditLoss: (() => {
          const s = auditBuffer.getStats();
          return {
            droppedCount: s.droppedCount,
            walDroppedLines: s.walDroppedLines,
            walDiscardedLines: s.walDiscardedLines,
            // 解析不出文档的 WAL 行：不重放也裁不掉，每次重启原地重复出现。
            // 少了这一项，"证据在 WAL 里但永远进不了库"这条失踪路径仍是 0。
            walCorruptLines: s.walCorruptLines,
            // WAL 追加失败：这一项 >0 说的是"崩溃保护层已经失效"，不是"已经丢了"——
            // 记录仍在内存缓冲里，落库成功就无损；但落库前进程退出就是永久缺失，
            // 所以它和上面几项一样需要取证。缺了它，面板会在磁盘根本写不进去时
            // 仍然报 walEnabled: true（追加失败的证据只有一行 warn 日志）。
            walAppendFailures: s.walAppendFailures,
            // 重放补号回写失败：口径与上面几项**不同**——它不是"已经少了记录"，
            // 而是"文件里那批行仍然没有身份，下次重启会被当成新记录再落一份"
            // （重复行 + 哈希链分叉）。放在同一块里是因为运维动作同类：取 WAL 原件核查。
            walRewriteFailures: s.walRewriteFailures,
            // F-217：裁剪侧失败。口径与上面三项都不同——它既不是"少了一条记录"也不是
            // "那批行没有身份"，而是"50MB 硬上限已经越过而这一轮什么都没省下"，
            // 也就是 R-6 正在静默失效（WAL 无界增长）。缺了它，面板在
            // walEnabled:true + 三个计数全 0 时无法与"上限从未被触碰"区分。
            walTrimFailures: s.walTrimFailures,
            outageFailures: s.outageFailures,
          };
        })(),
      };
    } catch (e) {
      overview.compliance = { error: '合规指标获取失败' };
    }
    return ApiResponse.success(res, overview, '获取成功');
  } catch (error) {
    logger.error(`安全概览查询失败: ${error.message}`);
    return ApiResponse.codeError(res, 'SECURITY_OVERVIEW_QUERY_FAILED');
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
    const alertsRaw = await securityAlert.getRecentAlerts(ALERTS_PAGE_SIZE + 1, req.user.userId);
    if (!alertsRaw || !Array.isArray(alertsRaw)) {
      return ApiResponse.codeError(res, 'RECENT_ALERTS_EMPTY');
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
    // 计算统计摘要：档位键由 AUDIT_RISK_LEVELS 派生（F-149）。原先四行手写 filter，
    // 给等级表加一档就会漏计（total 里算它、四个桶里都没有 ⇒ 摘要之和 ≠ total）。
    // 键序随派生表变成 low→critical（手写版是反的）：本仓前端没有读这个 summary 的地方，
    // 对外契约仍按同名键提供，顺序不承载信息。
    const summary = {
      ...Object.fromEntries(
        AUDIT_RISK_LEVELS.map((level) => [
          level,
          validAlerts.filter((a) => a.riskLevel === level).length,
        ])
      ),
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
    return ApiResponse.codeError(res, 'RECENT_ALERTS_QUERY_FAILED');
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
    return ApiResponse.codeError(res, 'CONFIG_ALLOW_REGISTRATION_MUST_BE_BOOLEAN');
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
  }).catch(onAuditWriteFailure('security_config_change', req));

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
  }).catch(onAuditWriteFailure('security_config_change', req));

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
  }).catch(onAuditWriteFailure('security_config_change', req));

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
