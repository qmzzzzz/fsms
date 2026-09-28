/**
 * 权限管理控制器：负责请求校验与 HTTP 响应编排。
 * 权限数据访问、引用完整性和批量写入语义统一下沉到 permissionService。
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
const permissionService = require('../services/permissionService');
// P1-14：权限定义变更后必须失效「权限解析缓存」（userPermissionService 的
// 进程内 TTL 缓存）。该缓存缓存的是**解析结果**，解析带 `status: active` 过滤，
// 因此停用/启用/删除权限后若不失效，所有已缓存用户最长仍按旧定义授权 30 秒。
const { invalidatePermissionCache } = require('../services/userPermissionService');

/**
 * 获取权限列表
 * GET /api/permissions
 */
const getPermissions = asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, module, type, status } = req.query;
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  const { permissions, count } = await permissionService.listPermissions({
    module,
    type,
    status,
    page: pageNum,
    limit: limitNum,
  });

  return ApiResponse.paginated(
    res,
    permissions,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取权限列表成功'
  );
});

/**
 * 获取权限详情
 * GET /api/permissions/:id
 */
const getPermissionById = asyncHandler(async (req, res) => {
  const permission = await permissionService.getPermissionById(req.params.id);
  if (!permission) {
    return ApiResponse.codeError(res, 'PERMISSION_NOT_FOUND');
  }

  return ApiResponse.success(res, permission, '获取成功');
});

/**
 * 创建权限
 * POST /api/permissions
 */
const createPermission = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { name, code, description, type, module, parent, path, method, sort } = req.body;
  const createdPerm = await permissionService.createPermission({
    name,
    code,
    description,
    type,
    module,
    parent,
    path,
    method,
    sort,
  });
  // P1-14：新建权限会改变权限树与角色可分配集合，统一失效（见文件头说明）
  invalidatePermissionCache();

  logger.info(`权限已创建：${createdPerm.name}`);
  return ApiResponse.success(res, createdPerm, '权限创建成功', 201);
});

/**
 * 更新权限
 * PUT /api/permissions/:id
 */
const updatePermission = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { name, description, type, module, parent, path, method, sort, status } = req.body;
  const permission = await permissionService.getPermissionForUpdate(req.params.id);
  if (!permission) {
    return ApiResponse.codeError(res, 'PERMISSION_NOT_FOUND');
  }

  // 内置超级通配 `*:*` 不可停用/改状态（与创建路径 permissionRoutes.js:41 的
  // `.not().equals('*:*')` 同口径，纵深防御）。userPermissionService.getPermissions
  // populate `match:{status:'active'}`——一旦把 `*:*` 置 inactive，全体超管解析时立刻失去
  // `*:*`，而本接口只有持 permission:update 的超管能调 → 改完自己也没权限改回 = DB 级自锁死。
  if (permission.code === '*:*' && status !== undefined) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: [{ path: 'status', msg: '内置超级权限 *:* 不可停用或变更状态' }],
    });
  }

  // 提供非空 parent 时必须真实存在且不能指向自身；
  // 显式传空值（''/null）表示清除父级、置为顶层权限。
  if (parent !== undefined && parent !== null && parent !== '') {
    if (String(parent) === String(permission._id)) {
      return ApiResponse.codeError(res, 'PARENT_PERMISSION_SELF');
    }

    const parentExists = await permissionService.getPermissionForUpdate(parent);
    if (!parentExists) {
      return ApiResponse.codeError(res, 'PARENT_PERMISSION_NOT_FOUND');
    }

    const MAX_DEPTH = 32;
    let cursor = parentExists;
    let depth = 0;
    while (cursor && depth < MAX_DEPTH) {
      if (String(cursor._id) === String(permission._id)) {
        return ApiResponse.codeError(res, 'PARENT_PERMISSION_CYCLE');
      }
      if (!cursor.parent) break;
      cursor = await permissionService.getAncestorForCycleCheck(cursor.parent);
      depth += 1;
    }
    if (depth >= MAX_DEPTH) {
      logger.warn(`权限树深度超过 ${MAX_DEPTH}，环路检测提前终止：permissionId=${permission._id}`);
      return ApiResponse.codeError(res, 'PERMISSION_TREE_DEPTH_ANOMALY');
    }

    permission.parent = parent;
  } else if (parent !== undefined) {
    permission.parent = null;
  }

  if (name !== undefined) permission.name = name;
  if (description !== undefined) permission.description = description;
  if (type !== undefined) permission.type = type;
  if (module !== undefined) permission.module = module;
  if (path !== undefined) permission.path = path;
  if (method !== undefined) permission.method = method;
  if (sort !== undefined) permission.sort = sort;
  if (status !== undefined) permission.status = status;

  const updatedPerm = await permissionService.savePermission(permission);

  // P1-14：status 变更直接改变解析结果；其余字段一并失效——
  // 这里刻意不做「哪些字段影响解析」的字段级判断：判断写错即静默失去防线，
  // 而失效的代价只是下一次请求重新查库（管理操作低频，可接受）
  invalidatePermissionCache();
  logger.info(`权限已更新：${updatedPerm.name}`);
  return ApiResponse.success(res, updatedPerm, '权限更新成功');
});

/**
 * 删除权限
 * DELETE /api/permissions/:id
 */
const deletePermission = asyncHandler(async (req, res) => {
  const permission = await permissionService.getPermissionForUpdate(req.params.id);
  if (!permission) {
    return ApiResponse.codeError(res, 'PERMISSION_NOT_FOUND');
  }

  await permissionService.deletePermission(permission._id);

  // P1-14：删除权限后失效（deletePermission 已先校验无角色引用，
  // 此处为防御性调用：避免未来放宽引用校验时留下陈旧缓存）
  invalidatePermissionCache();
  logger.info(`权限已删除：${permission.name}`);
  return ApiResponse.success(res, null, '权限删除成功');
});

/**
 * 批量创建权限（用于系统初始化）
 * POST /api/permissions/batch
 */
const batchCreatePermissions = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { permissions } = req.body;
  if (!permissions || !Array.isArray(permissions) || permissions.length === 0) {
    return ApiResponse.codeError(res, 'PERMISSION_LIST_INVALID');
  }

  const { created, skipped } = await permissionService.batchCreatePermissions(permissions);

  // P1-14：批量创建同样改变权限定义，统一失效
  invalidatePermissionCache();
  logger.info(`批量创建权限：成功 ${created.length}, 跳过 ${skipped.length}`);

  return ApiResponse.success(
    res,
    { created: created.length, skipped, details: created },
    `成功创建 ${created.length} 个权限`
  );
});

module.exports = {
  getPermissions,
  getPermissionById,
  createPermission,
  updatePermission,
  deletePermission,
  batchCreatePermissions,
};
