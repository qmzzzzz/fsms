/** 安全管理控制器 · 管理面（账户锁定/解锁、重置口令、重置 MFA）；2026-10-19 批 3c-3 自 securityController.js 迁出。 */

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
const { clientIpForSecurityDecision } = require('../../utils/ipUtils');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const sessionService = require('../../services/sessionService');
const authService = require('../../services/authService');
const roleService = require('../../services/roleService');
// 账户救济审计已抽到 services/adminAccountAudit.js（admin.js 贴 max-lines 上限；
// 临时口令/TOTP 密钥只进响应，不进审计）。两个函数内部走 recordDurably，落库失败转 WAL。
const {
  recordAdminMfaReset,
  recordAdminPasswordReset,
} = require('../../services/adminAccountAudit');
// P1-2（2026-10-30）：管理员重置口令的临时口令生成与哈希
const { generateTemporaryPassword } = require('../../utils/temporaryPassword');
const bcryptWorker = require('../../utils/bcryptWorkerPool');
const config = require('../../config');
const { invalidateUserCache } = require('../../middleware/auth');

/**
 * 账户锁定/解锁（管理员）：PUT /api/security/users/:userId/lock O-2 起业务规则整体下沉 authService.setUserLockStatus，此处只做参数校验与 outcome → HTTP 映射。
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
      ip: clientIpForSecurityDecision(req),
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
    case 'REVOKE_UNAVAILABLE':
      // 解锁前吊销旧令牌失败：fail-closed，账户仍保持锁定，可安全重试
      return ApiResponse.codeError(res, 'SESSION_REVOKE_SERVICE_UNAVAILABLE');
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

/** 审计二-2：本次重置该写进 passwordRetiredHash 的值——当前口令仍是未被消费的临时口令（mustChangePassword 未清）且已有摘要时保留它，覆盖只会抹掉真正要防的那一代（连续重置，见 ADR-016）。 */
function retiredHashForReset(user) {
  const hasUnconsumedTemp = user.mustChangePassword === true && Boolean(user.passwordRetiredHash);
  return hasUnconsumedTemp ? user.passwordRetiredHash : user.password || null;
}

/**
 * 管理员重置用户口令（P1-2 账号救济主通道）：PUT /api/security/users/:userId/password/reset 生成一次性临时口令（仅本次响应返回）→ tokenVersion++ 踢掉全部会话 → mustChangePassword=true；被替换掉的**用户自选**那一代口令的 bcrypt 摘要同时落进 passwordRetiredHash（审计二-2）——重置路径没有旧口令明文、算不出复用历史摘要，只能留可校验摘要，由改密路径比对一次；当前口令仍是未被消费的临时口令时**不覆盖**已有摘要（连续重置不得抹掉真正要防的那一代，见 ADR-016）。权限 user:reset_password + 操作者当场二次验证（与 MFA 重置同口径）。
 */
const resetUserPassword = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { userId } = req.params;
  const reason = typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
  const user = await User.findById(userId).select('+password +passwordRetiredHash'); // 退役摘要写的是旧口令的 bcrypt 摘要，两者都是 select:false；已有摘要时要判它该不该被本次覆盖
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围闸：与 toggleUserLock / resetUserMfa / userController 写路径同判据
  const { allowed: resetTargetInScope } = await assertRecordInScope(
    req,
    user,
    DATA_SCOPE_FIELDS.user.ownerField,
    DATA_SCOPE_FIELDS.user.departmentField
  );
  if (!resetTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  if (String(user._id) === String(req.user.userId)) {
    return ApiResponse.codeError(res, 'CANNOT_RESET_OWN_PASSWORD_VIA_ADMIN');
  }

  // 层级与内置超管保护（与 resetUserMfa 同口径）
  const targetUserRoles = await roleService.findRolesByIds(user.roles);
  const targetMaxLevel = maxRoleLevel(targetUserRoles);
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.codeError(res, 'PASSWORD_RESET_PEER_OR_HIGHER_FORBIDDEN');
  }
  if (targetUserRoles.some(isSuperAdminRole)) {
    return ApiResponse.codeError(res, 'CANNOT_RESET_PASSWORD_SUPER_ADMIN');
  }

  // 口令哈希放到 worker 线程池：bcrypt 12 轮是 CPU 密集操作，不能在请求线程上跑
  const temporaryPassword = generateTemporaryPassword(16);
  let passwordHash;
  try {
    passwordHash = await bcryptWorker.hash(temporaryPassword, config.bcryptRounds);
  } catch (hashErr) {
    logger.error(`口令重置失败 - 临时口令哈希失败：${hashErr.message}`, {
      username: user.username,
    });
    return ApiResponse.codeError(res, 'PASSWORD_RESET_FAILED');
  }

  const now = new Date();
  let updated;
  try {
    // 条件更新带完整范围快照（roles/department/createdBy，与删除路径同口径）：目标在范围/层级判定后被提权或换部门时不得继续重置。
    // tokenVersion、新口令与退役摘要（取值见 retiredHashForReset）在同一条原子更新里推进 —— 不存在"新口令已生效、旧令牌仍可用"的窗口。
    updated = await User.findOneAndUpdate(
      {
        _id: user._id,
        roles: user.roles || [],
        department: user.department ?? null,
        createdBy: user.createdBy ?? null,
      },
      {
        $set: {
          password: passwordHash,
          passwordRetiredHash: retiredHashForReset(user), // 审计二-2：被替换掉的那一代进退役摘要，改密时命中即拒
          passwordChangedAt: now,
          passwordSetAt: now,
          mustChangePassword: true,
        },
        $inc: { tokenVersion: 1 },
      },
      { new: true }
    );
  } catch (updateErr) {
    logger.error(`口令重置失败 - 落库异常：${updateErr.message}`, { username: user.username });
    return ApiResponse.codeError(res, 'PASSWORD_RESET_FAILED');
  }
  if (!updated) {
    logger.warn('口令重置中止 - 目标状态已变更', {
      username: user.username,
      operator: req.user.username,
    });
    return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
  }

  // tokenVersion 已递增（所有令牌失效），缓存必须同步清掉，避免 60 秒内继续用旧快照放行
  invalidateUserCache(user._id);
  // 会话表与 tokenVersion 同步收敛：否则「登录会话」页面仍显示一堆已掉线的设备
  await sessionService.revokeAllSessionsSafe(user._id, 'admin_revoked');

  await recordAdminPasswordReset(req, user, reason);
  res.locals.skipGlobalAudit = true; // 置位晚于审计：审计重抛时由全局审计接手记这次 500

  logger.warn('管理员重置用户口令（强制首次改密）', {
    username: user.username,
    operator: req.user.username,
  });
  res.set('Cache-Control', 'no-store');

  return ApiResponse.success(
    res,
    {
      userId: user._id,
      username: user.username,
      temporaryPassword,
      mustChangePassword: true,
    },
    '临时口令已生成，请通过安全通道转交；该用户首次登录必须修改密码'
  );
});

/**
 * 管理员重置用户两步验证：PUT /api/security/users/:userId/mfa/reset 清除 TOTP 密钥/恢复码/防爆破计数并吊销全部会话；权限 user:reset_password + 当场二次验证。
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
    // M-02：条件更新带上判定时的 roles 快照——若目标在层级/超管校验之后被
    // 提权，清除 MFA 就等于把一名同级/更高权限账户的防护拆掉。mfaEnabled:true
    // 同时防止并发的第二次重置把另一次已完成的救济覆盖。
    const cleared = await User.findOneAndUpdate(
      { _id: user._id, roles: user.roles || [], mfaEnabled: true },
      {
        mfaEnabled: false,
        mfaSecret: '',
        mfaRecoveryCodes: [],
        mfaFailCount: 0,
        mfaLockUntil: null,
      }
    );
    if (!cleared) {
      logger.warn('重置 MFA 中止 - 目标状态已变更', {
        username: user.username,
        operator: req.user.username,
      });
      return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
    }
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

  await recordAdminMfaReset(req, user);
  res.locals.skipGlobalAudit = true; // 置位晚于审计：审计重抛时由全局审计接手记这次 500

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
  resetUserPassword,
};
