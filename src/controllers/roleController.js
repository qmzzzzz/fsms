/**
 * 角色管理控制器
 * 处理角色的 CRUD 操作和权限分配
 */

const { validationResult } = require('express-validator');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel } = require('../utils/permissionHelper');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { escapeRegExp, normalizePagination } = require('../utils/helpers');
const { isSuperAdminRole } = require('../utils/superAdmin');

/**
 * 发送 WebSocket 事件
 *
 * 修正：原实现接收 eventType 却**从不使用**，无论传入 'role-created' /
 * 'role-deleted' / 'permissions-updated'，一律转发 emitRoleUpdate（即恒发
 * 'role-updated'）。后果是前端 RoleView 上的 'permissions-updated' 监听
 * 从未被触发过 —— 权限树与已选权限不会自动刷新，且该缺陷在界面上表现为
 * 「偶尔要手动刷新一下」，极易被当成网络抖动而不被上报。
 *
 * @param {import('express').Request} req
 * @param {'role-created'|'role-deleted'|'role-updated'|'permissions-updated'} eventType
 * @param {object} data 事件载荷
 */
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

/**
 * 向受影响用户定向推送权限同步（权限热生效）
 *
 * 与 emitWebSocketEvent 的分工：
 *  - emitWebSocketEvent 面向 role-management 房间（仅管理员），用于刷新管理界面；
 *  - 本函数面向「权限实际发生变化的那些用户」，让他们无需重登即刻生效。
 * 后者才是修复「权限调整后必须重新登录」的关键路径。
 *
 * 失败不阻断响应：权限已成功落库，推送只是加速生效；
 * 推送失败时用户退化到原有行为（下次登录或缓存过期后生效）。
 *
 * @param {import('express').Request} req
 * @param {Array<string|object>} userIds
 * @param {object} meta
 */
const syncPermissionsToUsers = async (req, userIds, meta) => {
  const wsService = req.app.get('wsService');
  if (!wsService || typeof wsService.emitPermissionSync !== 'function') return;
  try {
    await wsService.emitPermissionSync(userIds, meta);
  } catch (err) {
    logger.warn(`权限同步推送失败（不影响本次变更结果）：${err.message}`);
  }
};

/**
 * 获取角色列表
 * GET /api/roles
 */
const getRoles = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, status, search } = req.query;

  const query = {};
  if (status) {
    query.status = status;
  }
  if (search) {
    const escapedSearch = escapeRegExp(search);
    query.$or = [
      { name: new RegExp(escapedSearch, 'i') },
      { code: new RegExp(escapedSearch, 'i') },
    ];
  }

  // 规范化分页参数
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  const roles = await Role.find(query)
    .populate({
      path: 'permissions',
      select: 'name code type module',
    })
    .sort({ level: 1, createdAt: -1 })
    .limit(limitNum)
    .skip((pageNum - 1) * limitNum);

  // 获取每个角色的用户数
  const roleIds = roles.map((r) => r._id);
  const userCounts = await User.aggregate([
    { $unwind: '$roles' },
    { $match: { roles: { $in: roleIds } } },
    { $group: { _id: '$roles', count: { $sum: 1 } } },
  ]);
  const countMap = new Map(userCounts.map((uc) => [uc._id.toString(), uc.count]));

  // 将 userCount 附加到每个角色
  const rolesWithCount = roles.map((r) => ({
    ...r.toObject(),
    userCount: countMap.get(r._id.toString()) || 0,
  }));

  const count = await Role.countDocuments(query);

  return ApiResponse.paginated(
    res,
    rolesWithCount,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取角色列表成功'
  );
});

/**
 * 获取所有角色（不分页，用于下拉选择）
 * GET /api/roles/all
 */
const getAllRoles = asyncHandler(async (req, res) => {
  const roles = await Role.find({ status: 'active' })
    .select('name code description')
    .sort({ level: 1 });

  return ApiResponse.success(res, roles, '获取成功');
});

/**
 * 获取角色详情
 * GET /api/roles/:id
 */
const getRoleById = asyncHandler(async (req, res) => {
  const role = await Role.findById(req.params.id).populate({
    path: 'permissions',
    select: 'name code type module path method parent',
    populate: { path: 'parent', select: 'name code' },
  });

  if (!role) {
    return ApiResponse.notFound(res, '角色不存在');
  }

  // 过滤掉无效的权限ID（只保留有效的ObjectId）
  const objectIdRegex = /^[0-9a-fA-F]{24}$/;
  const validPermissions = role.permissions.filter(
    (perm) => perm._id && objectIdRegex.test(perm._id.toString())
  );

  // 统计该角色下的用户数
  const userCount = await User.countDocuments({ roles: role._id });

  return ApiResponse.success(
    res,
    {
      ...role.toObject(),
      permissions: validPermissions,
      userCount,
    },
    '获取成功'
  );
});

/**
 * 创建角色
 * POST /api/roles
 */
const createRole = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { name, code, description, level, permissions } = req.body;

  // 检查编码是否已存在
  const existing = await Role.findOne({ code });
  if (existing) {
    return ApiResponse.error(res, '角色编码已存在', 400);
  }

  // ===== 安全修复（H-01）：层级上限 + 权限子集双重校验 =====
  // 防止持 role:create 的中层级管理员（如 SECURITY_ADMIN）铸造携带 *:* 或
  // 高层级角色的权限容器，再借 assignRoles 自我分配完成垂直提权。
  // 校验口径与 assignPermissions 的既有防护保持一致。
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const operatorPermCodes = await User.getPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes('*:*');

  if (!isSuperAdmin) {
    // ① 层级上限：新建角色的 level 不得超过操作者自身层级
    if ((level || 1) > operatorMaxLevel) {
      return ApiResponse.forbidden(res, '无权创建高于自身层级的角色');
    }

    // ② 万能权限保护：*:* 仅允许存在于内置超管角色，任何显式授予一律拒绝
    if ((permissions || []).length > 0) {
      const validPerms = await Permission.find({ _id: { $in: permissions } }).select('code');
      if (validPerms.some((p) => p.code === '*:*')) {
        return ApiResponse.forbidden(res, '不能授予超级管理员权限（*:*）');
      }
      // ③ 权限子集：非超管授予的权限必须自身持有（精确匹配或模块通配符）
      const hasPerm = (permCode) =>
        operatorPermCodes.includes(permCode) ||
        operatorPermCodes.includes(`${permCode.split(':')[0]}:*`);
      const lacking = validPerms.filter((p) => !hasPerm(p.code)).map((p) => p.code);
      if (lacking.length > 0) {
        return ApiResponse.forbidden(res, `无权授予以下权限：${lacking.join('、')}`);
      }
    }
  }

  const role = await Role.create({
    name,
    code,
    description,
    level,
    permissions: permissions || [],
  });

  const createdRole = await Role.findById(role._id).populate({
    path: 'permissions',
    select: 'name code',
  });

  logger.info(`角色已创建：${role.name}`);

  // 发送 WebSocket 事件
  emitWebSocketEvent(req, 'role-created', {
    action: 'created',
    roleId: role._id,
    roleName: role.name,
    timestamp: new Date().toISOString(),
  });

  return ApiResponse.success(res, createdRole, '角色创建成功', 201);
});

/**
 * 更新角色
 * PUT /api/roles/:id
 */
const updateRole = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { name, description, level, status } = req.body;

  const role = await Role.findById(req.params.id);
  if (!role) {
    return ApiResponse.notFound(res, '角色不存在');
  }

  // 内置角色只能修改状态和描述（name 传空字符串同样视为尝试修改，防止绕过）
  if (role.isBuiltIn && (name !== undefined || level !== undefined)) {
    return ApiResponse.error(res, '内置角色不能修改名称和层级', 403);
  }

  // ===== 安全修复：status 白名单校验 + 内置角色状态保护 =====
  // 路由层未对 status 做枚举校验，任意字符串此前会直写 DB 破坏前端状态机；
  // 内置角色（如 SUPER_ADMIN/GUEST）的状态是系统运行前提，禁止通过本接口停用/启用
  if (status !== undefined) {
    if (!['active', 'inactive'].includes(status)) {
      return ApiResponse.error(res, 'status 必须是 active 或 inactive', 400);
    }
    if (role.isBuiltIn) {
      return ApiResponse.error(res, '内置角色不能修改状态', 403);
    }
  }

  // ===== 安全修复（H-02）：自定义角色层级变更校验 =====
  // 防止"低配角色自我分配 → 事后提级"的组合提权路径：
  // 非 *:* 操作者不得将任何角色提升到高于自身的层级。
  // 数值合法性由路由层 updateRoleValidation 的 isInt({min:1,max:10}) 保证
  //
  // ===== 安全修复（P1-1）：双向拦截，堵住"先降级再自挂"提权链 =====
  // 仅拦升方向是不够的。攻击链：超管预建了 level 9 的富权限自定义角色，
  // 中层管理员（level 5，持 role:update + role:assign）把它降到 level 5，
  // 此时 assignRoles 的 `targetMaxLevel > operatorMaxLevel` 校验读到的是
  // **降级后**的 level，校验通过 → 该角色连同全部权限被挂到自己身上，
  // 层级不变量整体击穿。因此操作者也不得触碰"当前层级已高于自身"的角色。
  if (level !== undefined) {
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    const operatorPermCodes = await User.getPermissions(req.user.userId);
    const isGlobalAdmin = operatorPermCodes.includes('*:*');

    if (!isGlobalAdmin && level > operatorMaxLevel) {
      return ApiResponse.forbidden(res, '无权将角色层级设置为高于自身层级');
    }
    // 降方向：角色现有层级高于操作者，即不属于其管辖范围，一律拒绝改动层级
    if (!isGlobalAdmin && (role.level || 0) > operatorMaxLevel) {
      logger.warn(
        `角色降级提权尝试被拒：operator=${req.user.username || req.user.userId}` +
          `(L${operatorMaxLevel}) role=${role.code}(L${role.level}) → L${level}`
      );
      return ApiResponse.forbidden(res, '无权变更高于自身层级的角色');
    }
  }

  // 通用校验：任何角色的名称不允许被置空
  if (name !== undefined) {
    const trimmed = String(name).trim();
    if (!trimmed) {
      return ApiResponse.error(res, '角色名称不能为空', 400);
    }
    role.name = trimmed;
  }
  if (description !== undefined) role.description = description;
  if (level !== undefined) role.level = level;
  if (status !== undefined) role.status = status;

  await role.save();

  const updatedRole = await Role.findById(role._id).populate({
    path: 'permissions',
    select: 'name code',
  });

  logger.info(`角色已更新：${role.name}`);

  return ApiResponse.success(res, updatedRole, '角色更新成功');
});

/**
 * 为角色分配权限
 * PUT /api/roles/:id/permissions
 *
 * 支持两种模式：
 * 1. 全局模式（默认）：直接修改该角色权限，影响所有持有该角色的用户。
 * 2. 单用户克隆模式：body 中携带 targetUserId 且角色为内置角色时，
 *    自动克隆角色 → 修改克隆体权限 → 仅将目标用户切换到克隆角色。
 *    原角色（如 GUEST）保持不变，其他用户完全不受影响。
 */
const assignPermissions = asyncHandler(async (req, res) => {
  // 路由层 assignPermissionsValidation 的校验结果必须显式消费：
  // 只声明校验器不消费 = 校验链形同虚设（与其他接口口径统一，报告 O-3）
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { permissions, targetUserId } = req.body;

  if (!permissions || !Array.isArray(permissions)) {
    return ApiResponse.error(res, '请提供有效的权限列表', 400);
  }

  const role = await Role.findById(req.params.id);
  if (!role) {
    return ApiResponse.notFound(res, '角色不存在');
  }

  // 去重并过滤掉虚拟节点 ID（如模块节点 "module-xxx"），避免触发 CastError
  // 只保留合法的 ObjectId 字符串（24 位十六进制）
  const objectIdRegex = /^[0-9a-fA-F]{24}$/;
  const uniquePermIds = [
    ...new Set(permissions.map((p) => String(p)).filter((id) => objectIdRegex.test(id))),
  ];

  // 如果过滤后为空，说明没有传入有效权限 ID
  if (uniquePermIds.length === 0) {
    return ApiResponse.error(res, '请提供至少一个有效的权限 ID', 400);
  }

  // 验证权限是否存在
  const validPerms = await Permission.find({ _id: { $in: uniquePermIds } });
  if (validPerms.length !== uniquePermIds.length) {
    return ApiResponse.error(res, '存在无效的权限 ID', 400);
  }

  // ===== 权限层级与自我提权防护 =====
  // 1) 操作者层级必须高于目标角色（全局模式）/ 不低于目标角色（克隆模式按 assignRoles 口径）
  // 2) 操作者不具备 *:* 时，只允许分配自身拥有的权限，防止借权限分配接口自我提权
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);

  const operatorPermCodes = await User.getPermissions(req.user.userId);
  const isSuperAdmin = operatorPermCodes.includes('*:*');
  if (!isSuperAdmin) {
    // 全局模式影响所有持有该角色的用户，要求严格低于自身层级
    if (role.level >= operatorMaxLevel && !targetUserId) {
      return ApiResponse.forbidden(res, '无权修改等于或高于自身层级的角色权限');
    }
    // 克隆模式等价于给目标用户分配该层级角色，与 assignRoles 保持一致：不得高于自身层级
    if (role.level > operatorMaxLevel && targetUserId) {
      return ApiResponse.forbidden(res, '无权基于高于自身层级的角色调整权限');
    }
    // 分配的权限必须是操作者自身拥有的（精确或模块通配符）
    const hasPerm = (code) =>
      operatorPermCodes.includes(code) || operatorPermCodes.includes(`${code.split(':')[0]}:*`);
    const lacking = validPerms.filter((p) => !hasPerm(p.code)).map((p) => p.code);
    if (lacking.length > 0) {
      return ApiResponse.forbidden(res, `无权分配以下权限：${lacking.join('、')}`);
    }
  }

  const { invalidateUserCache } = require('../middleware/auth');

  // 单用户克隆模式：内置角色 + 指定了目标用户 → 克隆后修改，不影响其他用户
  if (targetUserId && role.isBuiltIn) {
    const mongoose = require('mongoose');
    if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
      return ApiResponse.error(res, '目标用户 ID 格式无效', 400);
    }

    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      return ApiResponse.notFound(res, '目标用户不存在');
    }

    // 确认目标用户当前持有该角色
    const hasRole = targetUser.roles.some((r) => r.toString() === role._id.toString());
    if (!hasRole) {
      return ApiResponse.error(res, '目标用户未持有该角色，无法单独调整', 400);
    }

    // 目标用户层级保护（与 userController.assignRoles 的 M-01 口径一致）：
    // 克隆换角色等价于变更目标用户的有效角色集，此前仅校验了角色层级、
    // 未校验目标用户层级——同级管理员可借此篡改另一名同级管理员的有效角色。
    const targetRoles = await Role.find({ _id: { $in: targetUser.roles } }).select(
      'level code isBuiltIn'
    );
    const targetUserMaxLevel =
      targetRoles.length > 0 ? Math.max(...targetRoles.map((r) => r.level || 0)) : 0;
    const isSelf = String(targetUser._id) === String(req.user.userId);
    if (!isSelf && targetUserMaxLevel >= operatorMaxLevel) {
      return ApiResponse.forbidden(res, '无权变更同级或更高级别用户的角色权限');
    }
    // 超管归属不可变更（含操作者本人）：克隆模式会把目标用户从原角色切换到
    // 克隆角色（下方 newRoleIds 的 map 替换），对超管而言等价于剥离——
    // 且克隆角色 isBuiltIn=false，从此不再受任何超管保护，属绕过路径。
    // 归属只由启动期 reconcileSuperAdmin 决定，详见 utils/superAdmin.js
    if (isSuperAdminRole(role)) {
      logger.warn(
        `超管角色克隆被拒：operator=${req.user.username || req.user.userId} ` +
          `target=${targetUser.username} isSelf=${isSelf}`
      );
      return ApiResponse.codeError(res, 'SUPER_ADMIN_ROLE_NOT_CLONABLE');
    }

    // 克隆角色：生成唯一编码，避免冲突
    const timestamp = Date.now();
    const clonedCode = `${role.code}_CUSTOM_${timestamp}`;
    const clonedRole = await Role.create({
      name: `${role.name}_自定义`,
      code: clonedCode,
      description: `由 ${role.name} 克隆的自定义角色，用于单独调整用户权限`,
      level: role.level,
      isBuiltIn: false,
      permissions: uniquePermIds,
    });

    // 将目标用户从原角色切换到克隆角色（原子更新，避免读-改-save 最后写覆盖）
    const newRoleIds = targetUser.roles.map((r) =>
      r.toString() === role._id.toString() ? clonedRole._id : r
    );
    await User.findByIdAndUpdate(targetUser._id, { $set: { roles: newRoleIds } });

    // 失效目标用户缓存
    invalidateUserCache(targetUser._id);

    const updatedRole = await Role.findById(clonedRole._id).populate({
      path: 'permissions',
      select: 'name code type module',
    });

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

    // 克隆模式只影响目标用户一人：定向推送其新权限集，免去重新登录。
    // 必须在 invalidateUserCache 之后调用，否则重算命中旧缓存
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
  }

  // 全局模式：直接修改原角色，影响所有持有该角色的用户
  // 超管角色的权限集不可通过本接口修改：SUPER_ADMIN 的 `*:*` 是系统唯一的
  // 通配权限来源，一旦被替换为具体权限列表，超管即失去 `*:*` 直通授权
  // （rbac.js 与 userPermissionService 都以 `*:*` 判定超管），造成自锁死。
  // 该角色的权限由 initData.rolePermissionMap 在启动时对账收敛
  if (isSuperAdminRole(role)) {
    logger.warn('超管角色权限修改被拒', { operator: req.user.username || req.user.userId });
    return ApiResponse.codeError(res, 'SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED');
  }

  role.permissions = uniquePermIds;
  await role.save();

  // 角色权限变更后，失效所有拥有该角色的用户的缓存，确保权限立即生效
  const affectedUsers = await User.find({ roles: role._id }).select('_id').lean();
  affectedUsers.forEach((u) => invalidateUserCache(u._id));

  const updatedRole = await Role.findById(role._id).populate({
    path: 'permissions',
    select: 'name code type module',
  });

  logger.info('角色权限已更新，相关用户缓存已失效', {
    role: role.name,
    affectedUsers: affectedUsers.length,
  });

  // 发送 WebSocket 事件
  emitWebSocketEvent(req, 'permissions-updated', {
    action: 'permissions-updated',
    roleId: role._id,
    roleName: role.name,
    permissions: uniquePermIds,
    timestamp: new Date().toISOString(),
  });

  // 全局模式影响所有持有该角色的用户：逐一定向推送新权限集。
  // 这些用户多数没有 role-management 房间的资格，只有定向推送能触达；
  // 必须在上方 invalidateUserCache 之后执行，否则重算命中旧缓存
  await syncPermissionsToUsers(
    req,
    affectedUsers.map((u) => u._id),
    {
      action: 'permissions-updated',
      roleId: role._id,
      roleName: role.name,
    }
  );

  return ApiResponse.success(res, updatedRole, '权限分配成功');
});

/**
 * 删除角色
 * DELETE /api/roles/:id
 */
const deleteRole = asyncHandler(async (req, res) => {
  const role = await Role.findById(req.params.id);
  if (!role) {
    return ApiResponse.notFound(res, '角色不存在');
  }

  if (role.isBuiltIn) {
    return ApiResponse.error(res, '内置角色不可删除', 403);
  }

  // 检查是否有用户使用该角色
  const userCount = await User.countDocuments({ roles: role._id });
  if (userCount > 0) {
    return ApiResponse.error(
      res,
      `有 ${userCount} 个用户正在使用该角色，请先移除这些用户的角色`,
      400
    );
  }

  await Role.findByIdAndDelete(req.params.id);

  logger.info(`角色已删除：${role.name}`);

  // 发送 WebSocket 事件
  emitWebSocketEvent(req, 'role-deleted', {
    action: 'deleted',
    roleId: role._id,
    roleName: role.name,
    timestamp: new Date().toISOString(),
  });

  return ApiResponse.success(res, null, '角色删除成功');
});

/**
 * 获取权限树（用于角色权限分配界面）
 * GET /api/roles/permissions/tree
 */
const getPermissionTree = asyncHandler(async (req, res) => {
  // 获取所有 active 权限，包括父级引用
  const permissions = await Permission.find({ status: 'active' })
    .populate({ path: 'parent', select: 'name code module' })
    .sort({ module: 1, sort: 1 });

  // 构建树形结构 - 按模块分组
  const moduleMap = new Map();
  const idToNode = new Map();

  // 第一步：创建所有节点
  permissions.forEach((perm) => {
    const node = {
      _id: perm._id.toString(),
      id: perm._id.toString(), // 兼容前端可能的 id 引用
      name: perm.name,
      code: perm.code,
      type: perm.type,
      module: perm.module,
      path: perm.path,
      method: perm.method,
      children: [],
    };
    idToNode.set(perm._id.toString(), node);

    // 按模块分组
    if (!moduleMap.has(perm.module)) {
      moduleMap.set(perm.module, {
        _id: `module-${perm.module}`,
        id: `module-${perm.module}`,
        name: getModuleName(perm.module),
        module: perm.module,
        children: [],
      });
    }
  });

  // 第二步：构建树（先挂到模块，再处理父子关系）
  permissions.forEach((perm) => {
    const node = idToNode.get(perm._id.toString());
    const moduleNode = moduleMap.get(perm.module);

    // 如果有父级且在当前结果集中
    if (perm.parent && idToNode.has(perm.parent._id.toString())) {
      const parentNode = idToNode.get(perm.parent._id.toString());
      if (!parentNode.children.find((c) => c._id === node._id)) {
        parentNode.children.push(node);
      }
    } else {
      // 直接挂到模块下
      if (!moduleNode.children.find((c) => c._id === node._id)) {
        moduleNode.children.push(node);
      }
    }
  });

  // 转换为数组返回
  const tree = Array.from(moduleMap.values());
  return ApiResponse.success(res, tree, '获取权限树成功');
});

// 辅助函数：模块编码转中文名
function getModuleName(code) {
  const map = {
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
  return map[code] || code;
}

module.exports = {
  getRoles,
  getAllRoles,
  getRoleById,
  createRole,
  updateRole,
  assignPermissions,
  deleteRole,
  getPermissionTree,
};
