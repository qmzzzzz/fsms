/**
 * 角色权限分配控制器：HTTP 编排、权限提权校验与用户缓存失效。
 * 数据访问统一经 roleService，普通 CRUD 留在 roleController。
 */

const { validationResult } = require('express-validator');
const crypto = require('crypto');
const { safeFieldErrors } = require('../utils/validationRules');
const mongoose = require('mongoose');
const ApiResponse = require('../utils/apiResponse');
const {
  getOperatorMaxLevel,
  maxRoleLevel,
  matchesPermissionCodes,
} = require('../utils/permissionHelper');
const { syncPermissionsToUsers } = require('../utils/permissionSync');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { invalidateUserCache } = require('../middleware/auth');
const { isSuperAdminRole, RESERVED_WILDCARD_PERMISSION } = require('../utils/superAdmin');
const { assertRecordInScope } = require('../middleware/rbac');
const { uniqueIdStrings } = require('../utils/helpers');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const roleService = require('../services/roleService');
const userService = require('../services/userService');

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
    ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: safeFieldErrors(errors) });
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
  // 格式过滤留在本处（非法片段不该静默混进 $in），归一（去重 + 大小写规范化）走唯一入口
  // uniqueIdStrings，与 roleController.createRole 同一条尺——两条写路径各写一份归一，
  // 同一个 role.permissions 字段就会出现两种落库形态。
  const uniquePermIds = uniqueIdStrings(
    permissions.filter((item) => objectIdRegex.test(String(item)))
  );
  if (uniquePermIds.length === 0) {
    ApiResponse.codeError(res, 'PERMISSION_ID_REQUIRED');
    return null;
  }

  // L-05：停用权限不得被授予（恢复启用时越权会静默落地）
  const validPerms = await roleService.findPermissionsByIds(uniquePermIds, 'code', {
    activeOnly: true,
  });
  if (validPerms.length !== uniquePermIds.length) {
    ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
    return null;
  }

  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes(RESERVED_WILDCARD_PERMISSION);

  // 保留通配 `*:*` 一律不得经本接口分配。
  // 必须放在下面那句 isSuperAdmin 早返回**之前**：早返回跳过了全部提权校验，
  // 于是超管可以直接把 `*:*` 这个 permission id 分配给任意角色——
  // createRole 里"内置超管角色唯一"的不变式在这条路径上完全失效，等于铸出第二个超管角色，
  // 而"只有一个超管"正是本仓防自锁/防归属扩散的地基（utils/superAdmin.js）。
  // 这里刻意不给"内置超管角色自己"开口子：本接口后面已有
  // SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED，超管角色的权限根本不可经此改写，
  // 加一个永不成立的例外只会留下一段没人验证过的分支。
  if (validPerms.some((perm) => perm.code === RESERVED_WILDCARD_PERMISSION)) {
    ApiResponse.codeError(res, 'PERMISSION_ASSIGN_FORBIDDEN', {
      message: `保留通配权限 ${RESERVED_WILDCARD_PERMISSION} 不可经角色权限分配接口授予`,
      params: { permissions: RESERVED_WILDCARD_PERMISSION },
    });
    return null;
  }

  if (isSuperAdmin) return { uniquePermIds, validPerms, operatorMaxLevel };

  // 「同级/上级角色不可改写」的判定必须看**这次请求的实际效果**，不能只看有没有传 targetUserId：
  // 下面 assignPermissions 的克隆分支条件是 `targetUserId && role.isBuiltIn`，
  // 所以给一个**非内置**角色传任意合法 targetUserId，参数会被静默丢弃、直接落到
  // `role.permissions = [...]` 的全局改写分支 —— 原写法 `&& !targetUserId` 于是形同旁路：
  // 同级操作员只要在请求里多塞一个 targetUserId，就能全局改写同级角色的权限
  // （改完后 227 行会把该角色下所有用户的缓存失效并重同步，提权面是全组织）。
  // 正确判据：不会走克隆（即效果是全局改写）时，同级及以上一律拒绝。
  const willCloneBuiltIn = Boolean(targetUserId) && role.isBuiltIn === true;
  if (role.level >= operatorMaxLevel && !willCloneBuiltIn) {
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

  // 名字里的 InScope 现在才真正兑现：克隆分支的最后一步是
  // `updateUserRoles(targetUser._id, ...)`，即一次跨用户的 roles 数组写操作，
  // 与 userController.assignRoles 动的是同一个字段、挂的是同一个权限码（role:assign）。
  // 那条路由在写之前跑的是「数据范围闸 + 层级闸」两道正交判定，本函数此前只有后者，
  // 于是部门域操作者改**别部门**用户的角色：走"编辑用户角色"被 403，
  // 走"克隆内置角色"却 200。层级判定管能不能碰这个人，范围判定管这个人是否在可见域内。
  // 自己的记录由 rbac.isRecordInScope 统一豁免（type:'none' 除外），此处不再抄一份 isSelf 短路。
  const { allowed: targetInScope } = await assertRecordInScope(
    req,
    targetUser,
    DATA_SCOPE_FIELDS.user.ownerField,
    DATA_SCOPE_FIELDS.user.departmentField
  );
  if (!targetInScope) {
    ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
    return null;
  }

  const targetRoles = await roleService.findRolesByIds(targetUser.roles);
  // 层级判定口径只有一份（permissionHelper.maxRoleLevel）：这里曾内联展开同一式子
  const targetUserMaxLevel = maxRoleLevel(targetRoles);
  const isSelf = String(targetUser._id) === String(req.user.userId);
  if (!isSelf && targetUserMaxLevel >= operatorMaxLevel) {
    ApiResponse.codeError(res, 'USER_ROLE_PERM_PEER_OR_HIGHER_FORBIDDEN');
    return null;
  }
  return targetUser;
};

/**
 * 克隆标签：角色 name/code 都是 50 字符上限且唯一。
 * 原实现只用毫秒时间戳做后缀，同一用户重复克隆同一内置角色时 name 完全相同，
 * 第二次会撞唯一索引 500；把随机段一并编进去，并截断基名保证总长不越界。
 */
const buildCloneLabel = (base) => {
  const suffix = `${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`.toUpperCase();
  return `${base.slice(0, 50 - suffix.length - 1)}_${suffix}`;
};

const cloneBuiltInRoleForUser = async (req, res, role, targetUser, uniquePermIds) => {
  const clonedCode = buildCloneLabel(role.code);
  const clonedRole = await roleService.createRole({
    name: buildCloneLabel(`${role.name}_${targetUser.username}`),
    code: clonedCode,
    description: `由内置角色 ${role.name} 克隆，仅用于用户 ${targetUser.username}`,
    level: role.level,
    isBuiltIn: false,
    permissions: uniquePermIds,
  });

  // L-13：克隆落库后复验权限仍存在且生效（删除权限采用「先删后查引用」，
  // 本请求若在删除前通过校验、删除后才落库，这里会看到缺失）
  const activePerms = await roleService.findPermissionsByIds(uniquePermIds, '_id', {
    activeOnly: true,
  });
  if (activePerms.length !== uniquePermIds.length) {
    await roleService.deleteRole(clonedRole._id);
    return ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
  }

  const newRoleIds = targetUser.roles.map((roleId) =>
    roleId.toString() === role._id.toString() ? clonedRole._id : roleId
  );
  // L-12：克隆角色与用户角色集必须同进同退。用户角色集被并发修改时撤销本次克隆，
  // 避免留下一个无人持有的孤儿角色；CAS 过滤器用载入时的 roles 快照。
  const updated = await userService.updateRoles(targetUser._id, newRoleIds, targetUser.roles || []);
  if (!updated) {
    await roleService.deleteRole(clonedRole._id);
    return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
  }
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

  // L-04：CAS 写回。过滤器带载入时的 permissions 快照，
  // 并发授权会 miss 而不是把对方的集合整个覆盖掉。
  const previousPermissions = role.permissions;
  const saved = await roleService.updateRolePermissions(
    role._id,
    uniquePermIds,
    previousPermissions
  );
  if (!saved) {
    const stillExists = await roleService.findRoleForUpdate(role._id);
    return ApiResponse.codeError(res, stillExists ? 'ROLE_STATE_CONFLICT' : 'ROLE_NOT_FOUND');
  }
  // L-13：写后复验权限仍存在且生效。删除权限的请求采用「先删后查引用」，
  // 本请求若在删除前通过校验、删除后才落库，这里会看到缺失并回滚。
  const activePerms = await roleService.findPermissionsByIds(uniquePermIds, '_id', {
    activeOnly: true,
  });
  if (activePerms.length !== uniquePermIds.length) {
    await roleService.updateRolePermissions(role._id, previousPermissions, uniquePermIds);
    return ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
  }
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
