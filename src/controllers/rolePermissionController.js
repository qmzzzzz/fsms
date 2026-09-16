/**
 * 角色权限分配控制器：HTTP 编排、权限提权校验与用户缓存失效。
 * 数据访问统一经 roleService，普通 CRUD 留在 roleController。
 */

const { validationResult } = require('express-validator');
const mongoose = require('mongoose');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel, matchesPermissionCodes } = require('../utils/permissionHelper');
const { syncPermissionsToUsers } = require('../utils/permissionSync');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { invalidateUserCache } = require('../middleware/auth');
const { isSuperAdminRole } = require('../utils/superAdmin');
const roleService = require('../services/roleService');

const emitWebSocketEvent = (req, eventType, data) => {
  const wsService = req.app.get('wsService');
  if (!wsService) return;
  const payload = { ...data, type: eventType };
  if (eventType === 'permissions-updated') {
    wsService.emitPermissionUpdate(payload);
  } else {
    wsService.emitRoleUpdate(payload);
  }
};

const validateAssignmentInput = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: errors.array() });
    return null;
  }

  const { permissions, targetUserId } = req.body;
  if (!permissions || !Array.isArray(permissions)) {
    ApiResponse.codeError(res, 'PERMISSION_LIST_INVALID');
    return null;
  }
  return { permissions, targetUserId };
};

const validatePermissionTargets = async (req, res, role, permissions, targetUserId) => {
  const objectIdRegex = /^[0-9a-fA-F]{24}$/;
  const uniquePermIds = [
    ...new Set(permissions.map((item) => String(item)).filter((id) => objectIdRegex.test(id))),
  ];
  if (uniquePermIds.length === 0) {
    ApiResponse.codeError(res, 'PERMISSION_ID_REQUIRED');
    return null;
  }

  const validPerms = await roleService.findPermissionsByIds(uniquePermIds, 'code');
  if (validPerms.length !== uniquePermIds.length) {
    ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
    return null;
  }

  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes('*:*');

  if (isSuperAdmin) return { uniquePermIds, validPerms, operatorMaxLevel };

  if (role.level >= operatorMaxLevel && !targetUserId) {
    ApiResponse.codeError(res, 'ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');
    return null;
  }
  if (role.level > operatorMaxLevel && targetUserId) {
    ApiResponse.codeError(res, 'ROLE_PERM_BASE_HIGHER_LEVEL_FORBIDDEN');
    return null;
  }

  const lacking = validPerms
    .filter((perm) => !matchesPermissionCodes(operatorPermCodes, perm.code))
    .map((perm) => perm.code);
  if (lacking.length > 0) {
    ApiResponse.codeError(res, 'PERMISSION_ASSIGN_FORBIDDEN', {
      message: `无权分配以下权限：${lacking.join('、')}`,
      params: { permissions: lacking.join('、') },
    });
    return null;
  }
  return { uniquePermIds, validPerms, operatorMaxLevel };
};

const findTargetUserInScope = async (req, res, role, targetUserId, operatorMaxLevel) => {
  if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
    ApiResponse.codeError(res, 'TARGET_USER_ID_INVALID');
    return null;
  }

  const targetUser = await roleService.findUserForUpdate(targetUserId);
  if (!targetUser) {
    ApiResponse.codeError(res, 'TARGET_USER_NOT_FOUND');
    return null;
  }

  const hasRole = targetUser.roles.some((roleId) => roleId.toString() === role._id.toString());
  if (!hasRole) {
    ApiResponse.codeError(res, 'TARGET_USER_LACKS_ROLE');
    return null;
  }

  const targetRoles = await roleService.findRolesByIds(targetUser.roles);
  const targetUserMaxLevel =
    targetRoles.length > 0 ? Math.max(...targetRoles.map((item) => item.level || 0)) : 0;
  const isSelf = String(targetUser._id) === String(req.user.userId);
  if (!isSelf && targetUserMaxLevel >= operatorMaxLevel) {
    ApiResponse.codeError(res, 'USER_ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');
    return null;
  }
  return targetUser;
};

const cloneBuiltInRoleForUser = async (req, res, role, targetUser, uniquePermIds) => {
  const clonedCode = `${role.code}_${Date.now().toString(36).toUpperCase()}`;
  const clonedRole = await roleService.createRole({
    name: `${role.name}_${targetUser.username}`,
    code: clonedCode,
    description: `由内置角色 ${role.name} 克隆，仅用于用户 ${targetUser.username}`,
    level: role.level,
    isBuiltIn: false,
    permissions: uniquePermIds,
  });

  const newRoleIds = targetUser.roles.map((roleId) =>
    roleId.toString() === role._id.toString() ? clonedRole._id : roleId
  );
  await roleService.updateUserRoles(targetUser._id, newRoleIds);
  invalidateUserCache(targetUser._id);

  const updatedRole = await roleService.findPopulatedRole(clonedRole._id);
  logger.info('内置角色克隆完成', {
    roleName: role.name,
    clonedCode,
    username: targetUser.username,
  });

  emitWebSocketEvent(req, 'permissions-updated', {
    action: 'permissions-cloned',
    roleId: clonedRole._id,
    roleName: clonedRole.name,
    sourceRoleId: role._id,
    targetUserId: targetUser._id,
    permissions: uniquePermIds,
    timestamp: new Date().toISOString(),
  });

  await syncPermissionsToUsers(req, [targetUser._id], {
    action: 'permissions-cloned',
    roleId: clonedRole._id,
    roleName: clonedRole.name,
  });

  return ApiResponse.success(
    res,
    {
      clonedRole: updatedRole,
      message: `已为 ${targetUser.username} 创建自定义角色"${clonedRole.name}"，原角色"${role.name}"及其他用户不受影响`,
    },
    '权限分配成功（已克隆）'
  );
};

const assignPermissions = asyncHandler(async (req, res) => {
  const input = validateAssignmentInput(req, res);
  if (!input) return;

  const role = await roleService.findRoleForUpdate(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  const assignment = await validatePermissionTargets(
    req,
    res,
    role,
    input.permissions,
    input.targetUserId
  );
  if (!assignment) return;
  const { uniquePermIds, operatorMaxLevel } = assignment;

  if (input.targetUserId && role.isBuiltIn) {
    const targetUser = await findTargetUserInScope(
      req,
      res,
      role,
      input.targetUserId,
      operatorMaxLevel
    );
    if (!targetUser) return;

    if (isSuperAdminRole(role)) {
      logger.warn(`超管角色克隆被拒：operator=${req.user.username || req.user.userId}`);
      return ApiResponse.codeError(res, 'SUPER_ADMIN_ROLE_NOT_CLONABLE');
    }
    return cloneBuiltInRoleForUser(req, res, role, targetUser, uniquePermIds);
  }

  if (isSuperAdminRole(role)) {
    logger.warn('超管角色权限修改被拒', {
      operator: req.user.username || req.user.userId,
    });
    return ApiResponse.codeError(res, 'SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED');
  }

  role.permissions = uniquePermIds;
  await roleService.saveRole(role);
  const affectedUsers = await roleService.listUsersWithRole(role._id);
  affectedUsers.forEach((user) => invalidateUserCache(user._id));

  const updatedRole = await roleService.findPopulatedRole(role._id);
  logger.info('角色权限已更新，相关用户缓存已失效', {
    role: role.name,
    affectedUsers: affectedUsers.length,
  });

  emitWebSocketEvent(req, 'permissions-updated', {
    action: 'permissions-updated',
    roleId: role._id,
    roleName: role.name,
    permissions: uniquePermIds,
    timestamp: new Date().toISOString(),
  });

  await syncPermissionsToUsers(
    req,
    affectedUsers.map((user) => user._id),
    {
      action: 'permissions-updated',
      roleId: role._id,
      roleName: role.name,
    }
  );

  return ApiResponse.success(res, updatedRole, '权限分配成功');
});

module.exports = { assignPermissions };
