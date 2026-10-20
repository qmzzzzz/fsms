/**
 * 安全管理控制器 · 管理面（账户锁定/解锁、管理员重置 MFA）
 * （2026-10-19 批 3c-3 自 controllers/securityController.js 原样迁出，纯搬家不改语义）
 */

const { User } = require('./shared');
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const { assertRecordInScope } = require('../../middleware/rbac');
// 数据范围字段只有一份声明（constants/dataScopeFields.js）：本文件两处用户范围闸曾各抄一遍
// 'createdBy'/'department'，与 userController 引用的同一常量脱钩。
const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');
const { isSuperAdminRole } = require('../../utils/superAdmin');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const sessionService = require('../../services/sessionService');
const authService = require('../../services/authService');
const roleService = require('../../services/roleService');
// F-03（2026-10-17）：业务状态已改变的成功路径改走可靠 outbox（落库失败 ⇒ 转审计 WAL
// 待重放），因此"返回成功"不再等于"审计可能没写上"。仍用 onAuditWriteFailure 的两处
// （PII 查看、安全举报）是刻意的 fail-closed：它们必须"记账后重抛"，不许把结果交出去。
const { recordDurably } = require('../../services/auditOutbox');

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
  const targetUserRoles = await roleService.findRolesByIds(user.roles);
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
  const { invalidateUserTokens } = require('../../middleware/tokenBlacklist');
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
  // F-03：管理员重置 MFA 已生效（并已强制下线）⇒ 审计先持久化再回成功
  await recordDurably(
    {
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
    },
    { auditAction: 'admin_reset_mfa', req }
  );

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

module.exports = {
  toggleUserLock,
  resetUserMfa,
};
