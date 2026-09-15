/**
 * 角色管理控制器：HTTP 编排与权限事件通知。
 * 角色数据访问与统计查询统一下沉到 roleService。
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel, matchesPermissionCodes } = require('../utils/permissionHelper');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { escapeRegExp, normalizePagination } = require('../utils/helpers');
const roleService = require('../services/roleService');
const { getDataScope } = require('../middleware/rbac');

const emitWebSocketEvent = (req, eventType, data) => {
  const wsService = req.app.get('wsService');
  if (!wsService) return;
  const payload = { ...data, type: eventType };
  wsService.emitRoleUpdate(payload);
};

const applyRoleScopeToQuery = async (query, userId) => {
  const dataScope = await getDataScope(userId);
  if (dataScope.type === 'all') return { query, dataScope };
  if (dataScope.type === 'none') {
    return { query: { ...query, _id: { $in: [] } }, dataScope };
  }

  const operatorMaxLevel = await getOperatorMaxLevel(userId);
  return {
    query: { ...query, level: { $lte: operatorMaxLevel } },
    dataScope,
  };
};

const getRoles = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, status, search } = req.query;
  const query = {};
  if (status) query.status = status;
  if (search) {
    const escapedSearch = escapeRegExp(search);
    query.$or = [
      { name: new RegExp(escapedSearch, 'i') },
      { code: new RegExp(escapedSearch, 'i') },
    ];
  }

  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);
  const { query: scopedQuery } = await applyRoleScopeToQuery(query, req.user.userId);
  const { roles, count } = await roleService.listRoles(scopedQuery, pageNum, limitNum);

  return ApiResponse.paginated(
    res,
    roles,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取角色列表成功'
  );
});

const getAllRoles = asyncHandler(async (req, res) => {
  const { query } = await applyRoleScopeToQuery({ status: 'active' }, req.user.userId);
  const roles = await roleService.listAllRoles(query);
  return ApiResponse.success(res, roles, '获取成功');
});

const getRoleById = asyncHandler(async (req, res) => {
  const role = await roleService.getRoleDetail(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  const { dataScope } = await applyRoleScopeToQuery({}, req.user.userId);
  if (dataScope.type !== 'all') {
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    if (dataScope.type === 'none' || (role.level || 0) > operatorMaxLevel) {
      return ApiResponse.codeError(res, 'ROLE_VIEW_FORBIDDEN');
    }
  }
  return ApiResponse.success(res, role, '获取成功');
});

const createRole = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: errors.array() });
  }

  const { name, code, description, level, permissions } = req.body;
  const existing = await roleService.findRoleByCode(code);
  if (existing) {
    return ApiResponse.codeError(res, 'ROLE_CODE_TAKEN');
  }

  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes('*:*');

  if (!isSuperAdmin) {
    if ((level || 1) > operatorMaxLevel) {
      return ApiResponse.codeError(res, 'ROLE_CREATE_HIGHER_LEVEL_FORBIDDEN');
    }

    if ((permissions || []).length > 0) {
      const validPerms = await roleService.findPermissionsByIds(permissions);
      if (validPerms.some((perm) => perm.code === '*:*')) {
        return ApiResponse.codeError(res, 'CANNOT_GRANT_WILDCARD_PERMISSION');
      }
      const lacking = validPerms
        .filter((perm) => !matchesPermissionCodes(operatorPermCodes, perm.code))
        .map((perm) => perm.code);
      if (lacking.length > 0) {
        return ApiResponse.codeError(res, 'PERMISSION_GRANT_FORBIDDEN', { message: `无权授予以下权限：${lacking.join('、')}`, params: { permissions: lacking.join('、') } });
      }
    }
  }

  const role = await roleService.createRole({
    name,
    code,
    description,
    level,
    permissions: permissions || [],
  });
  const createdRole = await roleService.findPopulatedRole(role._id);

  logger.info(`角色已创建：${role.name}`);
  emitWebSocketEvent(req, 'role-created', {
    action: 'created',
    roleId: role._id,
    roleName: role.name,
    timestamp: new Date().toISOString(),
  });

  return ApiResponse.success(res, createdRole, '角色创建成功', 201);
});

const updateRole = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: errors.array() });
  }

  const { name, description, level, status } = req.body;
  const role = await roleService.findRoleForUpdate(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  const { dataScope } = await applyRoleScopeToQuery({}, req.user.userId);
  if (dataScope.type === 'none') {
    return ApiResponse.codeError(res, 'ROLE_UPDATE_FORBIDDEN');
  }
  if (dataScope.type !== 'all') {
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    if ((role.level || 0) > operatorMaxLevel) {
      return ApiResponse.codeError(res, 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN');
    }
  }

  if (role.isBuiltIn && (name !== undefined || level !== undefined)) {
    return ApiResponse.codeError(res, 'BUILTIN_ROLE_NAME_LEVEL_LOCKED');
  }

  if (status !== undefined) {
    if (!['active', 'inactive'].includes(status)) {
      return ApiResponse.codeError(res, 'ROLE_STATUS_INVALID');
    }
    if (role.isBuiltIn) {
      return ApiResponse.codeError(res, 'BUILTIN_ROLE_STATUS_LOCKED');
    }
  }

  if (level !== undefined) {
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
    const isGlobalAdmin = operatorPermCodes.includes('*:*');

    if (!isGlobalAdmin && level > operatorMaxLevel) {
      return ApiResponse.codeError(res, 'ROLE_LEVEL_ABOVE_SELF_FORBIDDEN');
    }
    if (!isGlobalAdmin && (role.level || 0) > operatorMaxLevel) {
      logger.warn(
        `角色降级提权尝试被拒：operator=${req.user.username || req.user.userId}` +
          `(L${operatorMaxLevel}) role=${role.code}(L${role.level}) → L${level}`
      );
      return ApiResponse.codeError(res, 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN');
    }
  }

  if (name !== undefined) {
    const trimmed = String(name).trim();
    if (!trimmed) {
      return ApiResponse.codeError(res, 'ROLE_NAME_REQUIRED');
    }
    role.name = trimmed;
  }
  if (description !== undefined) role.description = description;
  if (level !== undefined) role.level = level;
  if (status !== undefined) role.status = status;

  await roleService.saveRole(role);
  const updatedRole = await roleService.findPopulatedRole(role._id);

  logger.info(`角色已更新：${role.name}`);
  return ApiResponse.success(res, updatedRole, '角色更新成功');
});

const deleteRole = asyncHandler(async (req, res) => {
  const role = await roleService.findRoleForUpdate(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  const { dataScope } = await applyRoleScopeToQuery({}, req.user.userId);
  if (dataScope.type === 'none') {
    return ApiResponse.codeError(res, 'ROLE_DELETE_FORBIDDEN');
  }
  if (dataScope.type !== 'all') {
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    if ((role.level || 0) > operatorMaxLevel) {
      return ApiResponse.codeError(res, 'ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN');
    }
  }

  if (role.isBuiltIn) {
    return ApiResponse.codeError(res, 'BUILTIN_ROLE_NOT_DELETABLE');
  }

  const userCount = await roleService.countUsersWithRole(role._id);
  if (userCount > 0) {
    return ApiResponse.codeError(res, 'ROLE_IN_USE', { message: `有 ${userCount} 个用户正在使用该角色，请先移除这些用户的角色`, params: { userCount: userCount } });
  }

  await roleService.deleteRole(role._id);
  logger.info(`角色已删除：${role.name}`);
  emitWebSocketEvent(req, 'role-deleted', {
    action: 'deleted',
    roleId: role._id,
    roleName: role.name,
    timestamp: new Date().toISOString(),
  });

  return ApiResponse.success(res, null, '角色删除成功');
});

const MODULE_NAMES = {
  system: '系统管理',
  user: '用户管理',
  role: '角色管理',
  permission: '权限管理',
  device: '设备管理',
  alarm: '报警管理',
  inspection: '巡检管理',
  report: '报表统计',
  security: '安全管理',
};

const buildPermissionTree = (permissions) => {
  const moduleMap = new Map();
  const idToNode = new Map();

  permissions.forEach((permission) => {
    const node = {
      _id: permission._id.toString(),
      id: permission._id.toString(),
      name: permission.name,
      code: permission.code,
      type: permission.type,
      module: permission.module,
      path: permission.path,
      method: permission.method,
      children: [],
    };
    idToNode.set(node._id, node);

    if (!moduleMap.has(permission.module)) {
      moduleMap.set(permission.module, {
        _id: `module-${permission.module}`,
        id: `module-${permission.module}`,
        name: MODULE_NAMES[permission.module] || permission.module,
        module: permission.module,
        children: [],
      });
    }
  });

  permissions.forEach((permission) => {
    const node = idToNode.get(permission._id.toString());
    const moduleNode = moduleMap.get(permission.module);
    const parentId = permission.parent?._id?.toString();
    if (parentId && idToNode.has(parentId)) {
      const parentNode = idToNode.get(parentId);
      if (!parentNode.children.some((child) => child._id === node._id)) {
        parentNode.children.push(node);
      }
    } else if (!moduleNode.children.some((child) => child._id === node._id)) {
      moduleNode.children.push(node);
    }
  });

  return Array.from(moduleMap.values());
};

const getPermissionTree = asyncHandler(async (req, res) => {
  const permissions = await roleService.listActivePermissionTree();
  return ApiResponse.success(res, buildPermissionTree(permissions), '获取权限树成功');
});

module.exports = {
  getRoles,
  getAllRoles,
  getRoleById,
  createRole,
  updateRole,
  deleteRole,
  getPermissionTree,
};
