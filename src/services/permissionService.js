/**
 * 权限业务服务层：集中权限实体的数据访问与完整性校验，
 * 控制器只负责请求参数解析、HTTP 错误映射与统一响应。
 */

const Permission = require('../models/Permission');
const Role = require('../models/Role');
const ApiError = require('../utils/ApiError');
// 保留通配码只在 utils/superAdmin 声明一次；路由的"不得铸造"与本文件的"不得停用"
// 必须是同一个值，否则两处防线会各拦一半。
const { RESERVED_WILDCARD_PERMISSION: RESERVED_WILDCARD } = require('../utils/superAdmin');
const { withListBudget, listCountOptions } = require('../utils/queryBudget');

class PermissionService {
  async listPermissions({ module, type, status, page, limit }) {
    const query = {};
    if (module) query.module = module;
    if (type) query.type = type;
    if (status) query.status = status;

    const [permissions, count] = await Promise.all([
      withListBudget(Permission.find(query))
        .populate({ path: 'parent', select: 'name code' })
        .sort({ module: 1, sort: 1, createdAt: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Permission.countDocuments(query, listCountOptions()),
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

  /**
   * 权限落库的唯一出口（update 路径只有这里）
   *
   * 保留通配 `*:*` 不得被停用：
   * SUPER_ADMIN 的全部权限解析都来自这一条文档（initData 里唯一持有 `*:*` 的角色），
   * 把它 status 改成 inactive 就等于**瞬间清空所有超管权限**——此后任何管理接口都是 403，
   * 界面上连"把它改回来"的入口都没了，只能直连数据库救。
   * 铸造路径早被路由的 `.not().equals('*:*')` 挡住，删除路径被"角色引用"检查挡住，
   * 唯独停用这条最短路径没人管。
   *
   * 为什么拦在服务层而不是控制器：updatePermission 圈复杂度已 22（上限 15），
   * 在控制器再加两支会直接撞 `lint:ratchet`「复杂度只降不升」基线；
   * 而服务层既是唯一落库出口、也自动覆盖将来任何新调用方。
   */
  async savePermission(permission) {
    if (permission.code === RESERVED_WILDCARD && permission.status !== 'active') {
      throw ApiError.badRequest(
        `保留通配权限 ${RESERVED_WILDCARD} 不允许停用（会导致全体超管失去权限）`
      );
    }
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
        // 判定用「错误形状」而非 name：驱动实际抛出的类名是 MongoBulkWriteError
        // （node_modules/mongodb/lib/error.js 的 getter），原先写 'BulkWriteError'
        // 永不匹配 → 真发生重名冲突时整批 500，"已插入保留、失败项转 skipped"
        // 从未生效。mongoose 会把驱动侧 writeErrors 归一化到 err.writeErrors
        // （model.js:3218-3220），并把未失败的文档挂到 err.insertedDocs（:3248），
        // 因此这两个字段同时存在即"部分成功"，与类名无关，升级驱动也不会再失配。
        if (Array.isArray(err?.writeErrors) && err.writeErrors.length > 0) {
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
