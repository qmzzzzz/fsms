/**
 * 权限业务服务层：集中权限实体的数据访问与完整性校验，
 * 控制器只负责请求参数解析、HTTP 错误映射与统一响应。
 */

const Permission = require('../models/Permission');
const Role = require('../models/Role');
const ApiError = require('../utils/ApiError');

class PermissionService {
  async listPermissions({ module, type, status, page, limit }) {
    const query = {};
    if (module) query.module = module;
    if (type) query.type = type;
    if (status) query.status = status;

    const [permissions, count] = await Promise.all([
      Permission.find(query)
        .populate({ path: 'parent', select: 'name code' })
        .sort({ module: 1, sort: 1, createdAt: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Permission.countDocuments(query),
    ]);

    return { permissions, count };
  }

  async getPermissionById(id) {
    return Permission.findById(id).populate({ path: 'parent', select: 'name code' });
  }

  async createPermission(fields) {
    const { parent } = fields;
    const existing = await Permission.findOne({ code: fields.code });
    if (existing) {
      throw ApiError.badRequest('权限编码已存在');
    }

    if (parent) {
      const parentExists = await Permission.findById(parent).select('_id');
      if (!parentExists) {
        throw ApiError.badRequest('父级权限不存在');
      }
    }

    const permission = await Permission.create(fields);
    return this.getPermissionById(permission._id);
  }

  async getPermissionForUpdate(id) {
    return Permission.findById(id);
  }

  async getParentPermission(id) {
    return Permission.findById(id);
  }

  async getAncestorForCycleCheck(id) {
    return Permission.findById(id).select('_id parent');
  }

  async savePermission(permission) {
    await permission.save();
    return this.getPermissionById(permission._id);
  }

  async deletePermission(id) {
    const childrenCount = await Permission.countDocuments({ parent: id });
    if (childrenCount > 0) {
      throw ApiError.badRequest(`该权限下有 ${childrenCount} 个子权限，请先删除子权限`);
    }

    const refCount = await Role.countDocuments({ permissions: id });
    if (refCount > 0) {
      throw ApiError.badRequest(`该权限已被 ${refCount} 个角色引用，请先解除引用后再删除`);
    }

    await Permission.findByIdAndDelete(id);
  }

  async batchCreatePermissions(permissions) {
    const seen = new Set();
    const dupes = [];
    for (const item of permissions) {
      const code = item?.code;
      if (seen.has(code)) dupes.push(code);
      seen.add(code);
    }
    if (dupes.length > 0) {
      throw ApiError.badRequest(`权限列表内存在重复编码：${[...new Set(dupes)].join('、')}`);
    }

    const existingCodes = new Set(
      (
        await Permission.find({ code: { $in: [...seen] } })
          .select('code')
          .lean()
      ).map((item) => item.code)
    );

    const parentIds = [
      ...new Set(
        permissions
          .map((item) => item?.parent)
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
          ).map((item) => String(item._id))
        : []
    );

    const created = [];
    const skipped = [];
    const validDocs = [];

    for (const item of permissions) {
      if (existingCodes.has(item.code)) {
        skipped.push({ code: item.code, reason: '已存在' });
        continue;
      }

      const { name, code, description, type, module, parent, path, method, sort } = item;
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
        if (
          err?.name === 'BulkWriteError' &&
          Array.isArray(err.writeErrors) &&
          err.writeErrors.length > 0
        ) {
          created.push(...(Array.isArray(err.insertedDocs) ? err.insertedDocs : []));
          for (const writeError of err.writeErrors) {
            const failed = validDocs[writeError.index] || {};
            skipped.push({
              code: failed.code ?? 'unknown',
              reason: writeError.errmsg || '写入失败',
            });
          }
        } else {
          throw err;
        }
      }
    }

    return { created, skipped };
  }
}

module.exports = new PermissionService();
