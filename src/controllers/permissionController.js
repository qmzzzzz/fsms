/**
 * 权限管理控制器
 * 处理权限的 CRUD 操作
 */

const { validationResult } = require('express-validator');
const mongoose = require('mongoose');
const Permission = require('../models/Permission');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { normalizePagination } = require('../utils/helpers');

/**
 * 获取权限列表
 * GET /api/permissions
 */
const getPermissions = asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, module, type, status } = req.query;

  const query = {};
  if (module) query.module = module;
  if (type) query.type = type;
  if (status) query.status = status;

  // 规范化分页参数
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  const permissions = await Permission.find(query)
    .populate({ path: 'parent', select: 'name code' })
    .sort({ module: 1, sort: 1, createdAt: -1 })
    .limit(limitNum)
    .skip((pageNum - 1) * limitNum);

  const count = await Permission.countDocuments(query);

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
  const permission = await Permission.findById(req.params.id).populate({
    path: 'parent',
    select: 'name code',
  });

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

  // 检查编码是否已存在
  const existing = await Permission.findOne({ code });
  if (existing) {
    return ApiResponse.error(res, '权限编码已存在', 400);
  }

  // parent 存在性校验（与 updatePermission 同口径）：悬空父引用会破坏权限树；
  // 同时拦截自引用（parent === 自身虽此时自身尚未创建，code 相同场景由上方拦截）
  if (parent) {
    if (!mongoose.Types.ObjectId.isValid(parent)) {
      return ApiResponse.error(res, '父级权限 ID 格式无效', 400);
    }
    const parentExists = await Permission.findById(parent).select('_id');
    if (!parentExists) {
      return ApiResponse.error(res, '父级权限不存在', 400);
    }
  }

  const permission = await Permission.create({
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

  const createdPerm = await Permission.findById(permission._id).populate({
    path: 'parent',
    select: 'name code',
  });

  logger.info(`权限已创建：${permission.name}`);

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

  const permission = await Permission.findById(req.params.id);
  if (!permission) {
    return ApiResponse.notFound(res, '权限不存在');
  }

  // ===== parent 引用完整性校验 =====
  // 提供非空 parent 时必须真实存在且不能指向自身，防止自引用/悬空引用破坏权限树；
  // 显式传空值（''/null）表示清除父级、置为顶层权限
  if (parent !== undefined && parent !== null && parent !== '') {
    if (String(parent) === String(permission._id)) {
      return ApiResponse.error(res, '父级权限不能是权限自身', 400);
    }
    const parentExists = await Permission.findById(parent);
    if (!parentExists) {
      return ApiResponse.error(res, '父级权限不存在', 400);
    }

    // P3-10：环路检测。原实现只拦自引用（A→A），不拦 A→B→A 或更长的环。
    // 成环后 getMenuTree 等自顶向下遍历会无限递归（栈溢出 500），
    // 且这些节点从权限树中永久消失（无根可达）。
    // 沿新父级向上回溯，若能走回自身即成环。
    const MAX_DEPTH = 32; // 防御性上限：库中已存在的脏环不应让本次校验挂死
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
      cursor = await Permission.findById(cursor.parent).select('_id parent');
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

  await permission.save();

  const updatedPerm = await Permission.findById(permission._id).populate({
    path: 'parent',
    select: 'name code',
  });

  logger.info(`权限已更新：${permission.name}`);

  return ApiResponse.success(res, updatedPerm, '权限更新成功');
});

/**
 * 删除权限
 * DELETE /api/permissions/:id
 */
const deletePermission = asyncHandler(async (req, res) => {
  const permission = await Permission.findById(req.params.id);
  if (!permission) {
    return ApiResponse.notFound(res, '权限不存在');
  }

  // 检查是否有子权限
  const childrenCount = await Permission.countDocuments({ parent: permission._id });
  if (childrenCount > 0) {
    return ApiResponse.error(res, `该权限下有 ${childrenCount} 个子权限，请先删除子权限`, 400);
  }

  // 检查是否被角色引用，避免留下悬空引用
  const Role = require('../models/Role');
  const refCount = await Role.countDocuments({ permissions: permission._id });
  if (refCount > 0) {
    return ApiResponse.error(res, `该权限已被 ${refCount} 个角色引用，请先解除引用后再删除`, 400);
  }

  await Permission.findByIdAndDelete(req.params.id);

  logger.info(`权限已删除：${permission.name}`);

  return ApiResponse.success(res, null, '权限删除成功');
});

/**
 * 批量创建权限（用于系统初始化）
 * POST /api/permissions/batch
 *
 * P2-23：必须消费 validationResult。此前控制器不调用它，
 * 路由层 isArray({max:500}) 与逐条校验全部形同虚设——
 * 501 条照收（逐条串行 findOne+create 构成慢速 DoS 点）、
 * `*:*` 保留通配可被批量铸造、parent 悬空引用无人拦截。
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

  // 批内重复 code 预检：逐条 create 撞唯一键只会进 skipped，
  // 调用方看到「成功 N 条」却不知哪条被静默吞掉，此处提前明确拒绝
  const seen = new Set();
  const dupes = [];
  for (const p of permissions) {
    const code = p?.code;
    if (seen.has(code)) dupes.push(code);
    seen.add(code);
  }
  if (dupes.length > 0) {
    return ApiResponse.error(res, `权限列表内存在重复编码：${[...new Set(dupes)].join('、')}`, 400);
  }

  const created = [];
  const skipped = [];

  // 已存在的 code 一次查完，避免逐条 findOne（N 次往返 → 1 次）
  const existingCodes = new Set(
    (
      await Permission.find({ code: { $in: [...seen] } })
        .select('code')
        .lean()
    ).map((p) => p.code)
  );
  // parent 引用同样一次查完
  const parentIds = [
    ...new Set(
      permissions
        .map((p) => p?.parent)
        .filter(Boolean)
        .map(String)
    ),
  ];
  const validParentIds = new Set(
    parentIds.length > 0
      ? (
          await Permission.find({ _id: { $in: parentIds } })
            .select('_id')
            .lean()
        ).map((p) => String(p._id))
      : []
  );

  // 预检过滤后一次性批量写入（报告 O-2：原 for 循环内逐条 await Permission.create，
  // 500 条上限退化为最多 500 次串行 DB 往返；insertMany(ordered:false) 收敛为 1 次）
  const validDocs = [];
  for (const permData of permissions) {
    if (existingCodes.has(permData.code)) {
      skipped.push({ code: permData.code, reason: '已存在' });
      continue;
    }

    // 显式列出允许的字段，防止批量赋值注入 schema 之外的字段（与单条创建口径一致）
    const { name, code, description, type, module, parent, path, method, sort } = permData;
    // parent 存在性校验（与单条创建同口径）：悬空父引用破坏权限树
    if (parent && !validParentIds.has(String(parent))) {
      skipped.push({ code, reason: '父级权限不存在' });
      continue;
    }
    validDocs.push({ name, code, description, type, module, parent, path, method, sort });
  }

  if (validDocs.length > 0) {
    try {
      created.push(...(await Permission.insertMany(validDocs, { ordered: false })));
    } catch (err) {
      // ordered:false 下并发/唯一键冲突只产生 writeErrors，已插入的文档不回滚：
      // 逐条把失败项转成 skipped（与原逐条 create 的 catch 语义一致），成功项保留
      if (
        err &&
        err.name === 'BulkWriteError' &&
        Array.isArray(err.writeErrors) &&
        err.writeErrors.length > 0
      ) {
        created.push(...(Array.isArray(err.insertedDocs) ? err.insertedDocs : []));
        for (const we of err.writeErrors) {
          const failed = validDocs[we.index] || {};
          skipped.push({ code: failed.code ?? 'unknown', reason: we.errmsg || '写入失败' });
        }
      } else {
        throw err;
      }
    }
  }

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
