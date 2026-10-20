/**
 * userController 删除路径：单个删除与批量删除。
 */
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { assertRecordInScope } = require('../../middleware/rbac');
const { uniqueIdStrings } = require('../../utils/helpers');
const { isSuperAdminRole } = require('../../utils/superAdmin');
const statsCache = require('../../services/statsCache');
const { invalidateUserCache } = require('../../middleware/auth');
const userService = require('../../services/userService');
const { USER_OWNER_FIELD, USER_DEPT_FIELD, operatorTag } = require('./shared');

/**
 * 删除用户
 * DELETE /api/users/:id
 */
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
  await userService.deleteById(req.params.id);

  // 失效缓存

  invalidateUserCache(userId);
  // 统计缓存：删除改变所有查看者的聚合口径，必须全量失效（A-1）
  statsCache.invalidateAll('user-delete');

  logger.info('用户已删除', { username: user.username });

  return ApiResponse.success(res, null, '用户删除成功');
});

/**
 * 批量删除用户
 * DELETE /api/users/batch
 */
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
  const targets = await userService.findBatchUsers(requestedIds);
  if (targets.length !== requestedIds.length) {
    return ApiResponse.codeError(res, 'USER_ID_NOT_FOUND_IN_LIST');
  }
  const oversized = targets.find((t) => maxRoleLevel(t.roles) >= operatorMaxLevel);

  // 数据范围闸：任一目标越出可见域即整批拒绝（批量接口不得成为单对象保护的绕过路径）
  for (const target of targets) {
    const { allowed: batchTargetInScope } = await assertRecordInScope(
      req,
      target,
      USER_OWNER_FIELD,
      USER_DEPT_FIELD
    );
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

  // 超管账户不可删除（与单个删除口径一致）：任一目标是超管则整批拒绝，
  // 避免"批量接口成为单个接口保护的绕过路径"
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

  const result = await userService.deleteMany({ _id: { $in: requestedIds } });

  // 批量失效缓存

  requestedIds.forEach(invalidateUserCache);
  // 统计缓存：批量删除同样影响所有查看者，一次全量失效即可（A-1）
  statsCache.invalidateAll('user-bulk-delete');

  logger.info(`批量删除用户：${result.deletedCount} 个`);

  return ApiResponse.success(res, { deleted: result.deletedCount }, '批量删除成功');
});

module.exports = { deleteUser, batchDeleteUsers };
