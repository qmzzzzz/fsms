/**
 * 角色管理控制器：HTTP 编排与权限事件通知。
 * 角色数据访问与统计查询统一下沉到 roleService。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel, matchesPermissionCodes } = require('../utils/permissionHelper');
const { RESERVED_WILDCARD_PERMISSION } = require('../utils/superAdmin');
const { RESERVED_BUILTIN_ROLE_CODES } = require('../constants/permission');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination, uniqueIdStrings } = require('../utils/helpers');
const searchPatterns = require('../utils/searchPatterns');
const roleService = require('../services/roleService');
// 角色定义变更（status / permissions / 删除）会改变其持有者的权限解析
// 结果，而 userPermissionService 的进程内 TTL 缓存保存的正是解析结果。
// 不失效则被停用角色的持有者最长仍按旧权限授权 30 秒（真实越权窗口）。
const { invalidatePermissionCache } = require('../services/userPermissionService');
// 停用/启用一个角色同时改变了两份进程内缓存的内容：userPermissionService 的
// 「权限解析结果」缓存，和 auth.js 的「用户 + 其生效角色码」缓存。前者一直有失效，
// 后者此前只在 rolePermissionController 的权限变更路径失效，本文件的 status 路径漏了。
const { invalidateUserCache } = require('../middleware/auth');
const {
  createAuthorityResolver,
  applyRoleScopeToQuery,
  guardRoleWithinOperatorLevel,
  guardBuiltInNameOrLevel,
  guardRoleStatusValue,
  guardRoleLevelTarget,
  guardRoleReactivationPermissions,
  applyRoleEditableFields,
} = require('./roleGuards');

const emitWebSocketEvent = (req, eventType, data) => {
  const wsService = req.app.get('wsService');
  if (!wsService) return;
  const payload = { ...data, type: eventType };
  wsService.emitRoleUpdate(payload);
};

const getRoles = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, status, search } = req.query;
  const query = {};
  if (status) query.status = status;
  const searchTerm = searchPatterns.normalizeSearchTerm(search);
  if (searchTerm) {
    // code 入库即大写（schema uppercase:true）⇒ 搜索词同步大写并锚定前缀；
    // name 是自由文本，保持子串匹配。
    query.$or = [
      { name: searchPatterns.substringPattern(searchTerm) },
      { code: searchPatterns.upperCodePrefixPattern(searchTerm) },
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { name, code, description, level, permissions } = req.body;
  // 保留编码先于查重：ADMIN / USER 未播种，查重放行会把它们铸成
  // 不可删、名称/层级/状态冻结的内置角色（models/Role.js 的 isBuiltIn 判据）。
  if (RESERVED_BUILTIN_ROLE_CODES.includes(String(code).trim().toUpperCase())) {
    return ApiResponse.codeError(res, 'ROLE_CODE_RESERVED');
  }
  const existing = await roleService.findRoleByCode(code);
  if (existing) {
    return ApiResponse.codeError(res, 'ROLE_CODE_TAKEN');
  }

  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes(RESERVED_WILDCARD_PERMISSION);

  if (!isSuperAdmin && (level || 1) > operatorMaxLevel) {
    return ApiResponse.codeError(res, 'ROLE_CREATE_HIGHER_LEVEL_FORBIDDEN');
  }

  // 去重后比对，与 PUT /api/roles/:id/permissions 同尺（那边用 uniquePermIds，
  // 重复 ID 不算非法）；落库也用这份去重结果，避免"校验看 A、写入看 B"。
  const uniquePermIds = uniqueIdStrings(permissions);
  if (uniquePermIds.length > 0) {
    // L-05：停用权限不得被挂到新角色上
    const validPerms = await roleService.findPermissionsByIds(uniquePermIds, 'code', {
      activeOnly: true,
    });

    // 存在性校验：查到的条数必须等于提交的条数。
    //
    // 原先只把「查得到的那些」喂给后面的通配判断与越权判断，于是**格式合法但库里没有**的
    // 权限 ID 会被静默丢弃：请求方提交 N 条、角色带着 N-1 条实权 + 1 条悬空引用创建
    // 成功并回 201。这比报错更糟——授予类操作报"成功"就必须真的授到了。
    // 路由层的格式闸（body('permissions.*').isMongoId()）挡不住这一维：
    // 它是合法的 ObjectId，只是没有对应文档。同族的分配路径早就有这条判据
    // （rolePermissionController.js 的 PERMISSION_ID_INVALID），本处是缺的那一处。
    if (validPerms.length !== uniquePermIds.length) {
      return ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
    }

    // 保留通配 `*:*` 一律不得经本接口**铸造** —— 这条必须**无条件**执行，含超管。
    //
    // 原写法把它放在 `if (!isSuperAdmin)` 内，于是超管只要 POST /api/roles 建一个
    // 挂 `*:*` 的新角色，就凭空得到一个第二个通配角色：`utils/superAdmin.js` 把
    // 「内置超管角色唯一」定为**系统不变量**（防归属扩散、防自锁，见该文件头 :9-21），
    // 而这条路径上它完全失效。
    //
    // 同型缺陷已在 rolePermissionController.js:63-77（**分配**路径）修复，那处的注释
    // 写明了理由；本处是"已修的同类漏掉的那一处"。也正因如此，这里引用常量而不再写
    // 字面量——superAdmin.js:29-37 明确要求围绕通配的所有防线"都必须引用本常量"。
    if (validPerms.some((perm) => perm.code === RESERVED_WILDCARD_PERMISSION)) {
      return ApiResponse.codeError(res, 'CANNOT_GRANT_WILDCARD_PERMISSION');
    }

    if (!isSuperAdmin) {
      const lacking = validPerms
        .filter((perm) => !matchesPermissionCodes(operatorPermCodes, perm.code))
        .map((perm) => perm.code);
      if (lacking.length > 0) {
        return ApiResponse.codeError(res, 'PERMISSION_GRANT_FORBIDDEN', {
          message: `无权授予以下权限：${lacking.join('、')}`,
          params: { permissions: lacking.join('、') },
        });
      }
    }
  }

  const role = await roleService.createRole({
    name,
    code,
    description,
    level,
    permissions: uniquePermIds,
  });

  // L-13：建角色落库后复验权限仍存在且生效。删除权限的请求采用「先删后查引用」，
  // 本请求若在删除前通过校验、删除后才落库，这里会看到缺失并撤销刚建的角色，
  // 而不是留下一条指向已删权限的悬空引用。
  if (uniquePermIds.length > 0) {
    const stillActive = await roleService.findPermissionsByIds(uniquePermIds, '_id', {
      activeOnly: true,
    });
    if (stillActive.length !== uniquePermIds.length) {
      await roleService.deleteRole(role._id);
      return ApiResponse.codeError(res, 'PERMISSION_ID_INVALID');
    }
  }

  const createdRole = await roleService.findPopulatedRole(role._id);
  // 新建角色尚无持有者，逻辑上不影响任何已缓存用户；此处仍统一失效，
  // 理由见文件头——「角色写操作必失效」是一条不需要逐次推理的规则，
  // 而多失效一次的成本仅为下一次请求重新查库
  invalidatePermissionCache();

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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { name, description, level, status } = req.body;
  const role = await roleService.findRoleForUpdate(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  // 守卫按"层级范围 → 内置角色锁 → status 合法性 → 目标层级提权 → 字段写入"短路，
  // 顺序即错误优先级（同一请求同时触犯多条时，客户端看到的错误码由此顺序决定）。
  const authority = createAuthorityResolver(req.user.userId);
  const { dataScope } = await applyRoleScopeToQuery({}, req.user.userId, authority);
  if (
    await guardRoleWithinOperatorLevel({
      res,
      role,
      dataScope,
      authority,
      forbiddenCode: 'ROLE_UPDATE_FORBIDDEN',
      higherLevelCode: 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN',
    })
  ) {
    return;
  }
  if (guardBuiltInNameOrLevel({ res, role, name, level })) return;
  if (guardRoleStatusValue({ res, role, status })) return;
  if (await guardRoleLevelTarget({ req, res, role, level, authority })) return;
  // 恢复停用角色会把角色上的全部权限重新发给持有者，判据与权限分配接口同一条：
  // 不得「授予」自己没有的权限（applyRoleEditableFields 会改写 status，故在此之前）
  if (await guardRoleReactivationPermissions({ req, res, role, status })) return;
  // applyRoleEditableFields 会就地改写 role.status，故变更前的值必须在此取快照
  const previousStatus = role.status;
  if (applyRoleEditableFields({ res, role, name, description, level, status })) return;

  await roleService.saveRole(role);
  const updatedRole = await roleService.findPopulatedRole(role._id);

  // status 变更直接改变解析结果（持有者立即失去/恢复该角色权限）
  invalidatePermissionCache();

  // 权限解析缓存失效之外，还须失效 auth.js 的用户缓存：req.user.roleCodes
  // 由它提供（TTL 60s），rbac.js 的 checkRole 与 rateLimit.js 的角色配额都读它。
  // 漏掉这一步则出现自相矛盾的窗口——auth.js 缓存注释承诺「停用角色的 code
  // 不得继续进入 req.user.roleCodes」，但经本接口停用时该 code 最长留存 60 秒。
  // 口径对齐 rolePermissionController.js 的权限变更路径（同样按持有者逐个失效）。
  if (role.status !== previousStatus) {
    const affectedUsers = await roleService.listUsersWithRole(role._id);
    affectedUsers.forEach((user) => invalidateUserCache(user._id));
  }

  logger.info(`角色已更新：${role.name}`);

  // #9：另两个写路径（createRole / deleteRole）都发了广播，唯独 updateRole 只失效
  // 进程内缓存——于是「改角色名/层级/停用」这一路前端拿不到实时刷新，RoleView 要等
  // 下一次自然重拉。缓存失效口径（那两步）本身没漏，此处只补缺失的那半块，
  // 属可用性/一致性，不碰越权面。事件名与 websocketService.emitRoleUpdate 的出站名
  // 一致（复数 updated），前端 RoleView.vue:392 监听同一个。
  emitWebSocketEvent(req, 'role-updated', {
    action: 'updated',
    roleId: role._id,
    roleName: role.name,
    timestamp: new Date().toISOString(),
  });
  return ApiResponse.success(res, updatedRole, '角色更新成功');
});

const deleteRole = asyncHandler(async (req, res) => {
  const role = await roleService.findRoleForUpdate(req.params.id);
  if (!role) {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }

  const authority = createAuthorityResolver(req.user.userId);
  const { dataScope } = await applyRoleScopeToQuery({}, req.user.userId, authority);
  if (
    await guardRoleWithinOperatorLevel({
      res,
      role,
      dataScope,
      authority,
      forbiddenCode: 'ROLE_DELETE_FORBIDDEN',
      higherLevelCode: 'ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN',
    })
  ) {
    return;
  }

  if (role.isBuiltIn) {
    return ApiResponse.codeError(res, 'BUILTIN_ROLE_NOT_DELETABLE');
  }

  // L-03：先原子停用再统计，堵住「统计为 0 → 有人被授予该角色 → 删除」的窗口。
  // 编排细节见 roleService.deleteRoleIfUnused。
  const outcome = await roleService.deleteRoleIfUnused(role._id);
  if (outcome.status === 'not_found') {
    return ApiResponse.codeError(res, 'ROLE_NOT_FOUND');
  }
  if (outcome.status === 'in_use') {
    return ApiResponse.codeError(res, 'ROLE_IN_USE', {
      message: `有 ${outcome.userCount} 个用户正在使用该角色，请先移除这些用户的角色`,
      params: { userCount: outcome.userCount },
    });
  }
  if (outcome.status === 'conflict') {
    logger.warn('角色删除时状态已被并发修改，保留该角色', { role: role.name });
    return ApiResponse.codeError(res, 'ROLE_STATE_CONFLICT');
  }

  // 删除前已校验无用户持有该角色（ROLE_IN_USE 拦截），
  // 此处为防御性调用，理由同 createRole
  invalidatePermissionCache();
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
