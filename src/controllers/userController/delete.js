/** userController 删除路径：单个删除与批量删除（匿名化，见 P1-3）。 */
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { assertRecordInScope, getDataScope, isRecordInScope } = require('../../middleware/rbac');
const { uniqueIdStrings } = require('../../utils/helpers');
const { isSuperAdminRole } = require('../../utils/superAdmin');
const statsCache = require('../../services/statsCache');
const { invalidateUserCache } = require('../../middleware/auth');
const userService = require('../../services/userService');
const { USER_OWNER_FIELD, USER_DEPT_FIELD, operatorTag } = require('./shared');
// P1-3：删除改为匿名化后，审计动作从路由派生的 user_delete 收敛为专用 user_anonymized
const { recordDurably } = require('../../services/auditOutbox');
const { auditClientAddress } = require('../../utils/ipUtils');
const { auditPath } = require('../../utils/auditMeta');

/**
 * 写后置判定所依据的状态快照（M-01）：范围判据用 createdBy/department，
 * 层级与超管判据用 roles。三者都必须参与条件删除，否则判定与写入之间
 * 任一字段被改动，删除仍按旧结论落地。
 */
const stateSnapshot = (user) => {
  const snapshot = { roles: user.roles || [] };
  if (user.department !== undefined) snapshot.department = user.department;
  if (user.createdBy !== undefined) snapshot.createdBy = user.createdBy;
  return snapshot;
};

/** 删除单个用户（P1-3 起为匿名化）：DELETE /api/users/:id */
const deleteUser = asyncHandler(async (req, res) => {
  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围闸：与 updateUser/getUserById 同判据（层级之外的正交一闸）
  const { allowed: deleteTargetInScope } = await assertRecordInScope(
    req,
    user,
    USER_OWNER_FIELD,
    USER_DEPT_FIELD
  );
  if (!deleteTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  // 不允许删除自己
  if (user._id.toString() === req.user.userId) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：禁止删除等于或高于自身层级的用户（与锁定/角色分配逻辑保持一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetMaxLevel = maxRoleLevel(targetRoles);
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.codeError(res, 'USER_DELETE_PEER_OR_HIGHER_FORBIDDEN');
  }

  // 超管账户不可删除：删账户等于让超管归属归零。
  // 上面的层级校验在当前数据下已能拦住（level=10 是上限），此处是显式兜底——
  // 若 SUPER_ADMIN 的 level 被下调，层级校验会失效而本判断仍然生效
  if (targetRoles.some(isSuperAdminRole)) {
    logger.warn('删除超管账户被拒', {
      operator: operatorTag(req),
      target: user.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN');
  }

  const userId = user._id;
  // P1-3（2026-10-30）：默认行为改为匿名化——硬删除会把审计里的 userId 留成悬空指向，
  // 而删除权要求的是"不再能识别到这个人"，不是"抹掉他做过的事"。
  // deleteById 仅保留给建号失败回滚等确实需要撤销半成品记录的路径。
  const anonymized = await userService.anonymizeById(req.params.id, {
    reason: 'admin_delete',
    expected: stateSnapshot(user),
  });
  if (!anonymized) {
    return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
  }

  // 失效缓存

  invalidateUserCache(userId);
  // 统计缓存：注销改变所有查看者的聚合口径，必须全量失效（A-1）
  statsCache.invalidateAll('user-delete');

  // P1-3：业务状态已改变（实名/PII 已抹除、会话已吊销）⇒ 审计先持久化再回成功。
  // skipGlobalAudit 后由本条专用动作承担唯一留痕，避免同一操作出现两条语义不同的记录。
  await recordDurably(
    {
      action: 'user_anonymized',
      category: 'user',
      userId: req.user.userId,
      username: req.user.username,
      targetUserId: user._id,
      targetUsername: user.username,
      method: req.method,
      path: auditPath(req),
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'high',
      riskFactors: ['user_anonymized'],
      reason: '管理员注销用户并匿名化其个人身份信息',
    },
    { auditAction: 'user_anonymized', req }
  );
  res.locals.skipGlobalAudit = true; // 置位晚于审计：审计重抛时由全局审计接手记这次 500

  logger.info('用户已匿名化', { username: user.username, operator: req.user.username });

  return ApiResponse.success(
    res,
    { userId: String(userId), anonymized: true },
    '用户已注销并匿名化'
  );
});

/**
 * M-01：按判定时的状态快照做条件匿名化。
 * 快照缺失（两次读之间用户消失）与条件不匹配（判定后被改角色/部门/归属）
 * 一律返回 null，由调用方映射为 409——绝不能让 undefined 快照退化成无条件匿名化。
 */
const anonymizeBatchWithSnapshots = async (requestedIds, snapshots) => {
  const snapshotById = new Map(snapshots.map((s) => [String(s._id), stateSnapshot(s)]));
  const expectedByTarget = new Map(requestedIds.map((id) => [id, snapshotById.get(id)]));
  if (requestedIds.some((id) => !expectedByTarget.get(id))) return null;
  try {
    return await userService.anonymizeMany({ _id: { $in: requestedIds } }, expectedByTarget, {
      reason: 'admin_batch_delete',
    });
  } catch (err) {
    if (err.code === 'USER_STATE_CONFLICT') return null;
    throw err;
  }
};

/** 批量删除用户（同为匿名化）：DELETE /api/users/batch */
const batchDeleteUsers = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { ids } = req.body;
  const BATCH_DELETE_MAX = 100; // 单次批量删除上限

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return ApiResponse.codeError(res, 'USER_ID_LIST_INVALID');
  }

  if (ids.length > BATCH_DELETE_MAX) {
    return ApiResponse.codeError(res, 'BATCH_DELETE_LIMIT_EXCEEDED', {
      message: `单次批量删除最多 ${BATCH_DELETE_MAX} 个用户`,
      params: { max: BATCH_DELETE_MAX },
    });
  }

  // 校验所有 ID 是否为合法 ObjectId
  const mongoose = require('mongoose');
  const invalidIds = ids.filter((id) => !mongoose.Types.ObjectId.isValid(id));
  if (invalidIds.length > 0) {
    return ApiResponse.codeError(res, 'USER_ID_FORMAT_INVALID_IN_LIST', {
      message: `包含非法的用户 ID 格式: ${invalidIds.slice(0, 5).join(', ')}`,
      params: { invalidIds: invalidIds.slice(0, 5).join(', ') },
    });
  }

  // 归一必须在比较之前（与 assignRoles 同一条理由：$in 只回**去重后**的文档，
  // 重复 id 会被 `targets.length !== ids.length` 判成"这个用户不存在"而整批拒绝）
  const requestedIds = uniqueIdStrings(ids);

  // 检查是否包含自己（统一转为字符串比较，避免 ObjectId 类型不一致）
  if (requestedIds.includes(String(req.user.userId))) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：批量目标中包含同级或更高级别用户时整体拒绝（与单个删除口径一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const [targets, snapshots] = await Promise.all([
    userService.findBatchUsers(requestedIds),
    userService.findUserSnapshots(requestedIds),
  ]);
  if (targets.length !== requestedIds.length) {
    return ApiResponse.codeError(res, 'USER_ID_NOT_FOUND_IN_LIST');
  }
  const oversized = targets.find((t) => maxRoleLevel(t.roles) >= operatorMaxLevel);

  // 数据范围闸：任一目标越出可见域即整批拒绝（批量接口不得成为单对象保护的绕过路径）。
  // 范围只加载一次：assertRecordInScope 每次都会重新查用户/角色（N 次往返），
  // 批量上限 50 时就是 50 次重复查询，且同一请求内范围不可能变化。
  const dataScope = await getDataScope(req.user.userId);
  for (const target of targets) {
    const batchTargetInScope = isRecordInScope(dataScope, target, {
      ownerField: USER_OWNER_FIELD,
      departmentField: USER_DEPT_FIELD,
      userId: req.user.userId,
    });
    if (!batchTargetInScope) {
      return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN', {
        message: `无权操作用户：${target.username}（超出您的数据范围）`,
        params: { username: target.username },
      });
    }
  }

  if (oversized) {
    return ApiResponse.codeError(res, 'BATCH_DELETE_PEER_OR_HIGHER_FORBIDDEN', {
      message: `无权删除同级或更高级别的用户：${oversized.username}`,
      params: { username: oversized.username },
    });
  }

  // 超管账户不可删除（与单个删除口径一致）：任一目标是超管则整批拒绝，杜绝绕过路径
  const superTarget = targets.find((t) => (t.roles || []).some(isSuperAdminRole));
  if (superTarget) {
    logger.warn('批量删除含超管账户被拒', {
      operator: operatorTag(req),
      target: superTarget.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN', {
      message: `不能删除超级管理员账户：${superTarget.username}（系统必须保留唯一的最高权限账户）`,
    });
  }

  // M-01：逐个目标带快照条件匿名化；任一目标在判定后被改角色/改部门/改归属，
  // 整批以 409 中止（副本集下事务回滚），不让批量接口把单对象的保护绕过去
  const result = await anonymizeBatchWithSnapshots(requestedIds, snapshots);
  if (!result) return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');

  // 批量失效缓存

  requestedIds.forEach(invalidateUserCache);
  // 统计缓存：批量注销同样影响所有查看者，一次全量失效即可（A-1）
  statsCache.invalidateAll('user-bulk-delete');

  // P1-3：批量一条审计覆盖整批（targetIds 可逐条查）——逐目标写 N 条会让一次批量操作看起来像 N 次
  await recordDurably(
    {
      action: 'user_anonymized',
      category: 'user',
      userId: req.user.userId,
      username: req.user.username,
      method: req.method,
      path: auditPath(req),
      body: { targetIds: requestedIds, count: requestedIds.length, batch: true },
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'high',
      riskFactors: ['user_anonymized', 'batch'],
      reason: `管理员批量注销 ${requestedIds.length} 个用户并匿名化`,
    },
    { auditAction: 'user_anonymized', req }
  );
  res.locals.skipGlobalAudit = true; // 置位晚于审计：审计重抛时由全局审计接手记这次 500

  logger.info(`批量注销用户：${result.anonymizedCount} 个`);

  return ApiResponse.success(
    res,
    { anonymized: result.anonymizedCount },
    '批量注销完成（已匿名化）'
  );
});

module.exports = { deleteUser, batchDeleteUsers };
