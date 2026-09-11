/**
 * 权限管理控制器：负责请求校验与 HTTP 响应编排。
 * 权限数据访问、引用完整性和批量写入语义统一下沉到 permissionService。
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');
const permissionService = require('../services/permissionService');

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
    return ApiResponse.notFound(res, '权限不存在');
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
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
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
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { name, description, type, module, parent, path, method, sort, status } = req.body;
  const permission = await permissionService.getPermissionForUpdate(req.params.id);
  if (!permission) {
    return ApiResponse.notFound(res, '权限不存在');
  }

  // 提供非空 parent 时必须真实存在且不能指向自身；
  // 显式传空值（''/null）表示清除父级、置为顶层权限。
  if (parent !== undefined && parent !== null && parent !== '') {
    if (String(parent) === String(permission._id)) {
      return ApiResponse.error(res, '父级权限不能是权限自身', 400);
    }

    const parentExists = await permissionService.getPermissionForUpdate(parent);
    if (!parentExists) {
      return ApiResponse.error(res, '父级权限不存在', 400);
    }

    const MAX_DEPTH = 32;
    let cursor = parentExists;
    let depth = 0;
    while (cursor && depth < MAX_DEPTH) {
      if (String(cursor._id) === String(permission._id)) {
        return ApiResponse.error(
          res,
          '父级权限设置会形成循环引用（该权限已是目标父级的祖先）',
          400
        );
      }
      if (!cursor.parent) break;
      cursor = await permissionService.getAncestorForCycleCheck(cursor.parent);
      depth += 1;
    }
    if (depth >= MAX_DEPTH) {
      logger.warn(`权限树深度超过 ${MAX_DEPTH}，环路检测提前终止：permissionId=${permission._id}`);
      return ApiResponse.error(res, '权限树层级异常，请联系管理员核查父级引用', 400);
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
    return ApiResponse.notFound(res, '权限不存在');
  }

  await permissionService.deletePermission(permission._id);
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
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }

  const { permissions } = req.body;
  if (!permissions || !Array.isArray(permissions) || permissions.length === 0) {
    return ApiResponse.error(res, '请提供有效的权限列表', 400);
  }

  const { created, skipped } = await permissionService.batchCreatePermissions(permissions);
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
