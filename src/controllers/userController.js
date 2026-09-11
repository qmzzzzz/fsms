/**
 * 用户管理控制器
 * 处理用户的 CRUD 操作
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { getOperatorMaxLevel, matchesPermissionCodes } = require('../utils/permissionHelper');
const { syncPermissionsToUsers } = require('../utils/permissionSync');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, buildDataScopeFilter, assertRecordInScope } = require('../middleware/rbac');
const { validateSort, normalizePagination, isValidAvatar } = require('../utils/helpers');
const { validateRules } = require('../utils/ipRange');
const { decryptLoginCredential } = require('../utils/loginCipher');
const { validatePasswordStrength } = require('../utils/helpers');
const { checkSuperAdminMembership, isSuperAdminRole } = require('../utils/superAdmin');
const statsCache = require('../services/statsCache');
const { invalidateUserCache } = require('../middleware/auth');
const userService = require('../services/userService');

/**
 * 获取用户列表（支持分页、搜索、过滤）
 * GET /api/users
 */
const getUsers = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, status, department, role, sort = '-createdAt' } = req.query;

  // 校验并规范化排序参数
  const safeSort = validateSort(sort, {
    allowedFields: [
      'username',
      'email',
      'realName',
      'status',
      'department',
      'createdAt',
      'updatedAt',
      'lastLoginAt',
    ],
    defaultSort: '-createdAt',
  });

  const dataScope = await getDataScope(req.user.userId);
  const { roleFound, scopeAllowed, query } = await userService.buildListQuery(
    { search, status, department, role },
    dataScope
  );

  if (!roleFound || !scopeAllowed) {
    return ApiResponse.paginated(
      res,
      [],
      {
        page: parseInt(page),
        limit: parseInt(limit),
        total: 0,
        totalPages: 0,
      },
      '获取用户列表成功'
    );
  }

  // 规范化分页参数（统一限界）
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  // 执行查询
  const { users, count } = await userService.listUsers(query, safeSort, pageNum, limitNum);

  return ApiResponse.paginated(
    res,
    users,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取用户列表成功'
  );
});

/**
 * 获取单个用户详情
 * GET /api/users/:id
 */
const getUserById = asyncHandler(async (req, res) => {
  const user = await userService.getUserDetail(req.params.id);

  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // 数据范围校验：与列表接口口径一致，防止按 ID 横向越权
  // （本接口在路由上已有 user:read 权限门槛，这里补齐数据范围一致性）
  const { allowed } = await assertRecordInScope(req, user, 'createdBy', 'department');
  if (!allowed) {
    return ApiResponse.forbidden(res, '无权查看该用户');
  }

  return ApiResponse.success(res, user, '获取成功');
});

/**
 * 创建用户
 * POST /api/users
 */
const createUser = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { username, email, realName, phone, department, roles, allowedIPs } = req.body;

  // FE-M3：管理员建号口令密文轨（encPassword，与代设明文双轨）——
  // 解密失败返回统一 400（不区分原因），解密后补做强度校验
  let password;
  if (typeof req.body.encPassword === 'string' && req.body.encPassword) {
    try {
      password = await decryptLoginCredential(req.body.encPassword);
    } catch (err) {
      logger.warn(`管理员建号口令密文无效：${username}（${err.code || err.message}）`);
      return ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    }
    const strengthErr = validatePasswordStrength(password);
    if (strengthErr) {
      return ApiResponse.error(res, strengthErr, 400);
    }
  } else {
    password = req.body.password;
  }

  // IP 访问范围规则格式校验：非法片段直接回报，避免入库后规则静默失效
  if (allowedIPs !== undefined && allowedIPs !== '') {
    const check = validateRules(allowedIPs);
    if (!check.valid) {
      return ApiResponse.error(res, `IP 范围规则格式有误：${check.invalid.join('、')}`, 400);
    }
  }

  // 检查用户名是否已存在
  // P3-30：username 判重走 collation（大小写不敏感），与唯一索引 username_ci 同口径；
  // 邮箱保持默认 collation 以命中 email_1 索引，故不能合并为一次 $or 查询
  const [dupName, dupEmail] = await Promise.all([
    userService.findDuplicateUsername(username),
    userService.findOneUser({ email }),
  ]);
  if (dupName || dupEmail) {
    return ApiResponse.error(res, dupName ? '用户名已存在' : '邮箱已被使用', 400);
  }

  // 先校验角色，再创建用户，避免角色校验失败后留下孤儿用户
  let validatedRoles = [];
  if (roles && roles.length > 0) {
    const targetRoles = await userService.findRolesByIds(roles, 'level code isBuiltIn', {
      lean: true,
    });
    if (targetRoles.length !== roles.length) {
      return ApiResponse.error(res, '包含不存在的角色', 400);
    }
    // 超管唯一性：新建账户一律不得携带超管角色。
    // 层级校验不足以拦住这条路径——超管本人的 operatorMaxLevel 也是 10，
    // `targetMaxLevel > operatorMaxLevel` 判定为 false 会放行，
    // 从而凭空造出第二位超管
    if (targetRoles.some(isSuperAdminRole)) {
      logger.warn('创建用户时携带超管角色被拒', { operator: req.user.username || req.user.userId });
      return ApiResponse.codeError(res, 'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE');
    }
    // 获取当前操作者的最高角色层级
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    const targetMaxLevel = Math.max(...targetRoles.map((r) => r.level || 0));
    if (targetMaxLevel > operatorMaxLevel) {
      return ApiResponse.forbidden(res, '无权分配高于自身层级的角色');
    }
    validatedRoles = roles;
  }

  // 创建用户（带角色）
  const user = await userService.createUser({
    username,
    email,
    password,
    realName,
    phone,
    department,
    createdBy: req.user.userId,
    roles: validatedRoles,
    allowedIPs: allowedIPs || '',
  });

  logger.info('管理员创建用户', { operator: req.user.username, username });

  // 用户数据变更，失效操作者数据范围下的统计缓存
  statsCache.invalidateByUserId(req.user.userId);

  const createdUser = await userService.getCreatedUser(user._id);

  return ApiResponse.success(res, createdUser, '用户创建成功', 201);
});

/**
 * 更新用户信息
 * PUT /api/users/:id
 */
const updateUser = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { realName, email, phone, department, avatar, status, allowedIPs } = req.body;

  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // 层级保护：禁止修改等于或高于自身层级的用户（与删除/锁定/角色分配逻辑保持一致），
  // 防止低层级管理员篡改或禁用高层级账户（含 status 变更）；修改自身资料除外
  const targetRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetMaxLevel =
    targetRoles.length > 0 ? Math.max(...targetRoles.map((r) => r.level || 0)) : 0;

  const isSelf = String(user._id) === String(req.user.userId);
  if (!isSelf) {
    // 按操作者 ID 重新查询角色层级（req.user.roles 存的是角色编码，不能直接用于 _id 查询）
    const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
    if (targetMaxLevel >= operatorMaxLevel) {
      return ApiResponse.forbidden(res, '无权修改同级或更高级别的用户');
    }
  }

  // 禁止通过本接口禁用/锁定超级管理员（与 toggleUserLock 口径一致）。
  // 注意这里不带 isSelf 例外：超管把自己置为 inactive 后无人能解锁（层级校验
  // 会拦下所有针对 level=10 的操作），属自锁死路径
  const isBuiltInSuperAdmin = targetRoles.some(isSuperAdminRole);
  if (status && status !== 'active' && isBuiltInSuperAdmin) {
    return ApiResponse.codeError(res, 'CANNOT_DISABLE_SUPER_ADMIN');
  }

  // ===== 安全修复（自我锁死防护）：禁止变更自身状态 =====
  // 防止管理员把自己改成 inactive/locked 后无法登录、且无人能解锁
  if (isSelf && status !== undefined && String(status) !== String(user.status)) {
    return ApiResponse.error(res, '不能通过本接口修改自身账户状态，请联系其他管理员处理', 400);
  }

  // ===== 安全修复：status 变更须持 user:lock 权限 =====
  // 此前仅持 user:update 的操作者可直接改 status，绕过专用锁定接口
  // （PUT /api/security/users/:userId/lock）的 user:lock 权限门；*:* 通配视为持有全部权限
  if (!isSelf && status !== undefined && String(status) !== String(user.status)) {
    const operatorPermCodes = await userService.getPermissions(req.user.userId);
    if (!operatorPermCodes.includes('user:lock') && !operatorPermCodes.includes('*:*')) {
      return ApiResponse.forbidden(res, '无权变更用户状态（需要 user:lock 权限）');
    }
  }

  // 头像白名单校验：与个人资料更新接口同一口径，防止存储恶意 URL/data URI
  if (avatar !== undefined && avatar !== '' && !isValidAvatar(avatar)) {
    return ApiResponse.error(res, '头像必须是有效的图片 URL 或图片数据', 400);
  }

  // IP 访问范围规则格式校验：非法片段直接回报，避免入库后规则静默失效
  if (allowedIPs !== undefined && allowedIPs !== '') {
    const check = validateRules(allowedIPs);
    if (!check.valid) {
      return ApiResponse.error(res, `IP 范围规则格式有误：${check.invalid.join('、')}`, 400);
    }
  }

  // email 更新：前端用户编辑表单确实提交该字段，此前被静默丢弃；
  // 唯一性冲突处理与创建接口口径一致（先查重再写入）
  if (email !== undefined && email !== user.email) {
    const existing = await userService.findOneUser({ email, _id: { $ne: user._id } });
    if (existing) {
      return ApiResponse.error(res, '邮箱已被使用', 400);
    }
  }

  // 可更新的字段
  if (realName !== undefined) user.realName = realName;
  if (email !== undefined) user.email = email;
  if (phone !== undefined) user.phone = phone;
  if (department !== undefined) user.department = department;
  if (avatar !== undefined) user.avatar = avatar;
  if (status !== undefined) user.status = status;
  if (allowedIPs !== undefined) user.allowedIPs = allowedIPs;

  await userService.saveUser(user);

  // 用户状态变更时失效缓存（P3-3：解锁同样必须失效——
  // 原实现只对「变为非 active」失效，锁定/禁用解除后 authenticate 的
  // 60s 缓存仍持有旧的 status，合法用户最长 1 分钟仍被拒）
  if (status !== undefined) {
    // 统计缓存：状态变更影响统计口径，目标用户与操作者（统计视角）均需失效
    statsCache.invalidateByUserId(user._id);
    statsCache.invalidateByUserId(req.user.userId);
    invalidateUserCache(user._id);
  }

  // IP 范围规则变更需立即生效：authenticate 的用户缓存持有旧 allowedIPs，
  // 不失效会让新规则最长延迟 30 秒（存在越权访问窗口）
  if (allowedIPs !== undefined) {
    invalidateUserCache(user._id);
  }

  const updatedUser = await userService.getUpdatedUser(user._id);

  logger.info('用户信息已更新', { username: user.username });

  return ApiResponse.success(res, updatedUser, '用户信息更新成功');
});

/**
 * 分配角色给用户
 * PUT /api/users/:id/roles
 */
const assignRoles = asyncHandler(async (req, res) => {
  // 路由层 assignRolesValidation 的校验结果必须显式消费：
  // 只声明校验器不消费 = 校验链形同虚设（与其他接口口径统一，报告 O-3）
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { roles } = req.body;

  if (!roles || !Array.isArray(roles) || roles.length === 0) {
    return ApiResponse.error(res, '请提供有效的角色列表', 400);
  }

  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // M-01 修复：目标用户层级保护（口径对齐 updateUser/deleteUser/toggleUserLock）
  // 此前仅校验"被分配角色"的层级，未校验"目标用户"的层级，
  // 导致低层级管理员可剥离同级/更高级用户（含内置超管）的角色
  const targetUserRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetUserMaxLevel =
    targetUserRoles.length > 0 ? Math.max(...targetUserRoles.map((r) => r.level || 0)) : 0;

  // 验证新角色是否存在（同时取出 permissions 供权限子集校验）
  const validRoles = await userService.findRolesByIds(roles, 'level code permissions', {
    populate: { path: 'permissions', select: 'code' },
  });
  if (validRoles.length !== roles.length) {
    return ApiResponse.error(res, '存在无效的角色 ID', 400);
  }

  // 权限层级校验：禁止分配高于操作者自身层级的角色
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetMaxLevel = Math.max(...validRoles.map((r) => r.level || 0));
  if (targetMaxLevel > operatorMaxLevel) {
    return ApiResponse.forbidden(res, '无权分配高于自身层级的角色');
  }

  // 目标用户层级保护：禁止变更等于或高于自身层级的用户（修改自身除外）
  const isSelf = String(user._id) === String(req.user.userId);
  if (!isSelf && targetUserMaxLevel >= operatorMaxLevel) {
    return ApiResponse.forbidden(res, '无权变更同级或更高级别用户的角色');
  }

  // ===== P2-8 修复：权限子集校验 =====
  // 仅比 level 是不够的。createRole(:172-178) 与 assignPermissions(:338-345)
  // 都强制「授予的权限必须自身持有」，唯独 assignRoles 只看层级——
  // 于是两名同级（level 相同）但分管不同模块的管理员互挂对方角色，
  // 即可各自集齐双方全部权限，横向扩权且不触发任何层级告警。
  // isSelf 同样必须校验：给自己挂一个同级富权限角色是最直接的自我提权路径，
  // 而层级保护恰好对 isSelf 放行。
  const operatorPermCodes = await userService.getPermissions(req.user.userId);
  if (!operatorPermCodes.includes('*:*')) {
    // 精确匹配或模块通配（O-3：与 createRole/assignPermissions 共用唯一实现）
    const hasPerm = (code) => matchesPermissionCodes(operatorPermCodes, code);

    // 只校验「新增的」权限：目标用户已持有的权限不属于本次授予行为，
    // 否则操作者无法对权限比自己多的用户做任何角色调整（含收权）
    const currentPermCodes = new Set();
    const currentRoleDocs = await userService.findRolePermissionDocs(user.roles);
    for (const r of currentRoleDocs) {
      for (const p of r.permissions || []) {
        if (p?.code) currentPermCodes.add(p.code);
      }
    }

    const granting = new Set();
    for (const r of validRoles) {
      for (const p of r.permissions || []) {
        if (p?.code && !currentPermCodes.has(p.code)) granting.add(p.code);
      }
    }

    const lacking = [...granting].filter((code) => !hasPerm(code));
    if (lacking.length > 0) {
      logger.warn(
        `角色分配越权被拒：operator=${req.user.username || req.user.userId} ` +
          `target=${user.username} 缺少权限=${lacking.join(',')}`
      );
      return ApiResponse.forbidden(res, `无权授予以下权限：${lacking.join('、')}`);
    }
  }

  // ===== 后端复审 B-2：同级角色归属包含校验（纵深防御）=====
  // P2-8 只约束「权限」子集；本条补上「角色」本身的一道冗余闸门。
  //
  // 只对**与操作者同级**的角色生效，这是本条与最初实现的关键差别：
  // 最初写成「分配的角色必须全部属于操作者自身角色集合」，直接封死了
  // 「管理员把 GUEST 授予新人」这类最常见的合法操作——操作者本人当然
  // 不持有 GUEST。要求「想授予某角色就必须自己也持有」反而逼着管理员
  // 囤积角色，本身就是权限膨胀的反模式。
  //
  // 真正需要这道闸门的场景是**同级横向扩权**：两名 level 相同、分管不同
  // 模块的管理员互挂对方角色，各自集齐双方权限。高于操作者的角色已被上方
  // 层级校验拒绝，低于操作者的角色由 P2-8 权限子集校验兜住，
  // 只有「恰好同级」这一档需要额外要求归属。
  const operatorIsSuper = operatorPermCodes.includes('*:*');
  if (!operatorIsSuper) {
    // req.user.roleCodes 由 auth 中间件在请求期实时刷新（freshRoleCodes），
    // 非签发时快照，作为角色归属比对的事实来源
    const operatorRoleCodes = new Set(req.user.roleCodes || []);
    const peerLevelRoles = validRoles.filter((r) => (r.level || 0) === operatorMaxLevel);
    const foreignRoles = peerLevelRoles
      .map((r) => r.code)
      .filter((code) => !operatorRoleCodes.has(code));
    if (foreignRoles.length > 0) {
      logger.warn(
        `角色分配越权被拒（同级角色归属）：operator=${req.user.username || req.user.userId} ` +
          `target=${user.username} 非自身持有的同级角色=${foreignRoles.join(',')}`
      );
      return ApiResponse.forbidden(res, `无权分配自身未持有的同级角色：${foreignRoles.join('、')}`);
    }
  }

  // 超管归属不可变更（含操作者本人）：剥离会造成不可恢复的自锁死
  // （超管是唯一 *:* 来源，剥离后无任何接口能修回），授予会破坏唯一性。
  // 归属只由启动期 reconcileSuperAdmin 决定，详见 utils/superAdmin.js
  const nextRoleDocs = await userService.findRolesByIds(roles, 'code isBuiltIn', { lean: true });
  const membershipError = checkSuperAdminMembership(targetUserRoles, nextRoleDocs);
  if (membershipError) {
    logger.warn(
      `超管归属变更被拒：operator=${req.user.username || req.user.userId} ` +
        `target=${user.username} isSelf=${isSelf}`
    );
    return ApiResponse.codeError(res, membershipError.code, { message: membershipError.message });
  }

  // 原子更新替代读-改-save：user.save() 会把整个文档回写，并发窗口内的
  // 其他字段修改（如 status）会被本次内存快照覆盖；findByIdAndUpdate+$set 只写 roles
  await userService.updateRoles(user._id, roles);

  // 角色变更后失效缓存

  invalidateUserCache(user._id);
  // 统计缓存：目标用户与操作者（统计视角）均需失效
  statsCache.invalidateByUserId(user._id);
  statsCache.invalidateByUserId(req.user.userId);

  const updatedUser = await userService.getUpdatedUser(user._id);

  logger.info('用户角色已更新', { username: user.username });

  // 角色变更直接改变该用户的有效权限：定向推送新权限集，无需重新登录。
  // 必须在 invalidateUserCache 之后执行，否则重算会命中变更前的缓存
  await syncPermissionsToUsers(req, [user._id], {
    action: 'roles-assigned',
  });

  return ApiResponse.success(res, updatedUser, '角色分配成功');
});

/**
 * 删除用户
 * DELETE /api/users/:id
 */
const deleteUser = asyncHandler(async (req, res) => {
  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.notFound(res, '用户不存在');
  }

  // 不允许删除自己
  if (user._id.toString() === req.user.userId) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：禁止删除等于或高于自身层级的用户（与锁定/角色分配逻辑保持一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetMaxLevel =
    targetRoles.length > 0 ? Math.max(...targetRoles.map((r) => r.level || 0)) : 0;
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.forbidden(res, '无权删除同级或更高级别的用户');
  }

  // 超管账户不可删除：删账户等于让超管归属归零。
  // 上面的层级校验在当前数据下已能拦住（level=10 是上限），此处是显式兜底——
  // 若 SUPER_ADMIN 的 level 被下调，层级校验会失效而本判断仍然生效
  if (targetRoles.some(isSuperAdminRole)) {
    logger.warn('删除超管账户被拒', {
      operator: req.user.username || req.user.userId,
      target: user.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN');
  }

  const userId = user._id;
  await userService.deleteById(req.params.id);

  // 失效缓存

  invalidateUserCache(userId);
  // 统计缓存：目标用户与操作者（统计视角）均需失效
  statsCache.invalidateByUserId(userId);
  statsCache.invalidateByUserId(req.user.userId);

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
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { ids } = req.body;
  const BATCH_DELETE_MAX = 100; // 单次批量删除上限

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return ApiResponse.error(res, '请提供有效的用户 ID 列表', 400);
  }

  if (ids.length > BATCH_DELETE_MAX) {
    return ApiResponse.error(res, `单次批量删除最多 ${BATCH_DELETE_MAX} 个用户`, 400);
  }

  // 校验所有 ID 是否为合法 ObjectId
  const mongoose = require('mongoose');
  const invalidIds = ids.filter((id) => !mongoose.Types.ObjectId.isValid(id));
  if (invalidIds.length > 0) {
    return ApiResponse.error(
      res,
      `包含非法的用户 ID 格式: ${invalidIds.slice(0, 5).join(', ')}`,
      400
    );
  }

  // 检查是否包含自己（统一转为字符串比较，避免 ObjectId 类型不一致）
  if (ids.map(String).includes(String(req.user.userId))) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：批量目标中包含同级或更高级别用户时整体拒绝（与单个删除口径一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targets = await userService.findBatchUsers(ids);
  if (targets.length !== ids.length) {
    return ApiResponse.error(res, '包含不存在的用户 ID', 400);
  }
  const oversized = targets.find((t) => {
    const targetMaxLevel = t.roles?.length > 0 ? Math.max(...t.roles.map((r) => r.level || 0)) : 0;
    return targetMaxLevel >= operatorMaxLevel;
  });
  if (oversized) {
    return ApiResponse.forbidden(res, `无权删除同级或更高级别的用户：${oversized.username}`);
  }

  // 超管账户不可删除（与单个删除口径一致）：任一目标是超管则整批拒绝，
  // 避免"批量接口成为单个接口保护的绕过路径"
  const superTarget = targets.find((t) => (t.roles || []).some(isSuperAdminRole));
  if (superTarget) {
    logger.warn('批量删除含超管账户被拒', {
      operator: req.user.username || req.user.userId,
      target: superTarget.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN', {
      message: `不能删除超级管理员账户：${superTarget.username}（系统必须保留唯一的最高权限账户）`,
    });
  }

  const result = await userService.deleteMany({ _id: { $in: ids } });

  // 批量失效缓存

  ids.forEach(invalidateUserCache);
  ids.forEach((id) => statsCache.invalidateByUserId(id));
  // 统计缓存：操作者（统计视角）也需要同步失效
  statsCache.invalidateByUserId(req.user.userId);

  logger.info(`批量删除用户：${result.deletedCount} 个`);

  return ApiResponse.success(res, { deleted: result.deletedCount }, '批量删除成功');
});

/**
 * 获取用户统计信息
 * GET /api/users/stats
 */
const getUserStats = asyncHandler(async (req, res) => {
  // 数据范围控制：与列表/详情接口口径一致，防止越权看到全组织统计
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDataScopeFilter(dataScope, 'createdBy', 'department');

  // 统计缓存：缓存键由用户 ID + 数据范围稳定摘要组成，保证按用户+数据范围隔离
  const crypto = require('crypto');
  const scopeFingerprint = crypto
    .createHash('sha1')
    .update(JSON.stringify(scopeFilter))
    .digest('hex')
    .slice(0, 12);
  const cacheKey = `stats:${req.user.userId}:${scopeFingerprint}`;

  // 命中缓存直接返回，避免数据库往返
  const cached = statsCache.get(cacheKey);
  if (cached.hit) {
    return ApiResponse.success(res, cached.data, '获取用户统计成功');
  }

  // 本月起始时间
  const startOfMonth = new Date();
  startOfMonth.setDate(1);
  startOfMonth.setHours(0, 0, 0, 0);

  // $facet 单次聚合：冷缓存时 6 次串行 DB 往返合并为 1 次，降低冷启动/并发抖动
  const [facetResult] = await userService.aggregateStats([
    { $match: scopeFilter },
    {
      $facet: {
        // 总用户数
        total: [{ $count: 'count' }],
        // 活跃用户数（状态为 active）
        active: [{ $match: { status: 'active' } }, { $count: 'count' }],
        // 禁用用户数
        inactive: [{ $match: { status: 'inactive' } }, { $count: 'count' }],
        // 本月新增用户
        thisMonth: [{ $match: { createdAt: { $gte: startOfMonth } } }, { $count: 'count' }],
        // 按部门统计
        byDepartment: [
          { $match: { status: 'active' } },
          { $group: { _id: '$department', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        // 按角色统计（口径对齐 byDepartment：仅统计 active 用户，
        // 此前 byDepartment 只算 active 而 byRole 算全部，两个维度基数不一致）
        byRole: [
          { $match: { status: 'active' } },
          { $unwind: '$roles' },
          { $group: { _id: '$roles', count: { $sum: 1 } } },
          { $lookup: { from: 'roles', localField: '_id', foreignField: '_id', as: 'role' } },
          { $unwind: '$role' },
          {
            $project: {
              _id: 0,
              roleId: '$_id',
              roleName: '$role.name',
              roleCode: '$role.code',
              count: 1,
            },
          },
          { $sort: { count: -1 } },
        ],
      },
    },
  ]);

  const data = {
    total: facetResult?.total?.[0]?.count || 0,
    active: facetResult?.active?.[0]?.count || 0,
    inactive: facetResult?.inactive?.[0]?.count || 0,
    thisMonth: facetResult?.thisMonth?.[0]?.count || 0,
    byDepartment: facetResult?.byDepartment || [],
    byRole: facetResult?.byRole || [],
  };

  // 写入缓存（TTL 使用配置默认值），便于后续请求直接命中
  statsCache.set(cacheKey, data);

  return ApiResponse.success(res, data, '获取用户统计成功');
});

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  assignRoles,
  deleteUser,
  batchDeleteUsers,
  getUserStats,
};
