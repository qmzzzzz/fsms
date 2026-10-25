/**
 * 权限业务服务层：集中权限实体的数据访问与完整性校验，
 * 控制器只负责请求参数解析、HTTP 错误映射与统一响应。
 */

const Permission = require('../models/Permission');
const Role = require('../models/Role');
const ApiError = require('../utils/ApiError');
const logger = require('../utils/logger');
const { withTransaction } = require('../utils/transaction');
// 保留通配码只在 utils/superAdmin 声明一次；路由的"不得铸造"与本文件的"不得停用"
// 必须是同一个值，否则两处防线会各拦一半。
const { RESERVED_WILDCARD_PERMISSION: RESERVED_WILDCARD } = require('../utils/superAdmin');
const { withListBudget, listCountOptions } = require('../utils/queryBudget');
// 父级存在性判定的两个臂（构造 $in 清单 / 与库里结果比对）共用同一个归一入口，
// 不在本文件手写 String 去重（口径见 utils/helpers 的 canonicalIdString）。
const { uniqueIdStrings, canonicalIdString } = require('../utils/helpers');

/**
 * 列表内重复编码检测。
 *
 * @returns {{dupes: string[], codes: string[]}} dupes 为重复出现的编码，
 *   codes 为去重后的全量编码（供后续 $in 查询复用同一份集合，不重复遍历）
 */
const collectDuplicateCodes = (permissions) => {
  const seen = new Set();
  const dupes = [];
  for (const item of permissions) {
    const code = item?.code;
    if (seen.has(code)) dupes.push(code);
    seen.add(code);
  }
  return { dupes, codes: [...seen] };
};

/**
 * 库里已存在的编码集合（**含软删除**）
 *
 * 软删除不释放 code 的唯一索引，所以已删除文档占用的编码同样不能再插入。
 * 不把它们查出来，insertMany 会以 11000 收尾，把"编码被已删除的权限占用"
 * 误报成驱动写入失败。
 */
const findExistingCodes = async (codes) => {
  const rows = await Permission.find({ code: { $in: codes } })
    .setOptions({ includeDeleted: true })
    .select('code')
    .lean();
  return new Set(rows.map((item) => item.code));
};

/** session 为 null（standalone 降级）时不设置会话，避免把 null 透给驱动 */
const withSession = (query, session) => (session ? query.session(session) : query);

/**
 * 撤销软删除标记；失败时把完整文档写进日志供人工恢复。
 *
 * 只用于无事务（standalone）的补偿路径：文档始终留在库里，
 * 即使这里失败也不会丢数据，但必须让运维能从日志里拿到重建/恢复所需的全部字段。
 *
 * @param {object} doc 被本次删除认领的权限文档
 * @param {{childrenCount:number, refCount:number}} reason 复核结果，便于定位冲突来源
 * @returns {Promise<boolean>} 是否恢复成功
 */
const restoreSoftDeletedPermission = async (doc, reason) => {
  try {
    const result = await Permission.updateOne({ _id: doc._id }, { $set: { deletedAt: null } });
    if (result.matchedCount === 1) return true;
    logger.error('权限软删除恢复未命中任何文档（可能被并发物理删除），请人工核查', {
      permissionId: String(doc._id),
      ...reason,
      permission: doc.toObject(),
    });
  } catch (error) {
    logger.error('权限软删除恢复失败，请人工将 deletedAt 置回 null', {
      permissionId: String(doc._id),
      ...reason,
      permission: doc.toObject(),
      error: error.message,
    });
  }
  return false;
};

/**
 * 校验父级 id：先按归一入口构造 $in 清单，再与库里读回的值比对。
 *
 * 大小写是这一处的真缺陷：`isMongoId` 委托给十六进制判定，大写的 24 位 hex 一样过闸，
 * 而 `$in` 把两种写法都 cast 成同一个 12 字节 ⇒ 命中一份文档；库里读回来的
 * `String(_id)` 恒为小写（bson toHexString）。原先这里手写 `new Set(map(String))`
 * 只去重不转小写，于是 has(大写) miss ⇒ **真实存在的父级被判成「父级权限不存在」**，
 * 该项静默进 skipped（不 400、不报错、响应照样 success），批量导入表现为
 * "少建了几条权限且无人知晓"。构造清单与逐项比对必须走同一个归一入口。
 */
const findValidParentIds = async (permissions) => {
  const parentIds = uniqueIdStrings(permissions.map((item) => item?.parent).filter(Boolean));
  if (parentIds.length === 0) return new Set();
  const rows = await Permission.find({ _id: { $in: parentIds } })
    .select('_id')
    .lean();
  return new Set(rows.map((item) => String(item._id)));
};

/** 逐项分拣：已存在 / 父级不存在进 skipped，其余进待插入清单 */
const partitionCreatable = (permissions, existingCodes, validParentIds) => {
  const skipped = [];
  const validDocs = [];

  for (const item of permissions) {
    if (existingCodes.has(item.code)) {
      skipped.push({ code: item.code, reason: '已存在' });
      continue;
    }

    const { name, code, description, type, module, parent, path, method, sort } = item;
    if (parent && !validParentIds.has(canonicalIdString(parent))) {
      skipped.push({ code, reason: '父级权限不存在' });
      continue;
    }
    validDocs.push({ name, code, description, type, module, parent, path, method, sort });
  }

  return { skipped, validDocs };
};

/**
 * 批量落库：部分成功时保留已插入项、失败项转 skipped。
 *
 * 判定用「错误形状」而非 name：驱动实际抛出的类名是 MongoBulkWriteError
 * （node_modules/mongodb/lib/error.js 的 getter），原先写 'BulkWriteError'
 * 永不匹配 → 真发生重名冲突时整批 500，"已插入保留、失败项转 skipped"
 * 从未生效。mongoose 会把驱动侧 writeErrors 归一化到 err.writeErrors
 * （model.js:3218-3220），并把未失败的文档挂到 err.insertedDocs（:3248），
 * 因此这两个字段同时存在即"部分成功"，与类名无关，升级驱动也不会再失配。
 */
const insertDocsTolerant = async (validDocs, created, skipped) => {
  try {
    created.push(...(await Permission.insertMany(validDocs, { ordered: false })));
  } catch (err) {
    if (!Array.isArray(err?.writeErrors) || err.writeErrors.length === 0) throw err;
    created.push(...(Array.isArray(err.insertedDocs) ? err.insertedDocs : []));
    for (const writeError of err.writeErrors) {
      const failed = validDocs[writeError.index] || {};
      skipped.push({
        code: failed.code ?? 'unknown',
        reason: writeError.errmsg || '写入失败',
      });
    }
  }
};

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
    // 含软删除：编码被已删除权限占用时不能走到 create（唯一索引会抛 11000），
    // 必须给出可理解的 400 而不是 500。
    const existing = await Permission.findOne({ code: fields.code }).setOptions({
      includeDeleted: true,
    });
    if (existing) {
      throw ApiError.badRequest(
        existing.deletedAt
          ? '权限编码已被一个已删除的权限占用，请更换编码或恢复原权限'
          : '权限编码已存在'
      );
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

  /**
   * 删除权限 —— 软删除，根治「先删后复核」的恢复失败窗口。
   *
   * 原实现先 `findByIdAndDelete` 再复核引用，冲突时用 `Permission.create(removed.toObject())`
   * 恢复：一旦恢复本身失败（进程崩溃、写超时、并发重建同 code），权限就真的没了，
   * 而 Role.permissions 里还留着指向已不存在文档的悬空 id。
   *
   * 现在删除 = 打上 `deletedAt`，文档永不离开集合，因此不存在"恢复失败导致数据丢失"：
   *   · 副本集：整个「占位 → 复核 → 提交」在一个事务里，冲突时事务回滚即恢复；
   *   · standalone：没有事务，冲突时就地撤销 deletedAt；撤销失败文档仍在库里
   *     （只是处于已删除状态），并把完整文档写入日志供人工恢复。
   *
   * 删除后的文档对默认查询不可见（模型层 pre(/^find/) / countDocuments 过滤器），
   * 角色 populate、权限树、授权判定都不会再看到它。code 的唯一索引仍被占用，
   * 内置权限由 initPermissions 在下次启动时自动恢复。
   *
   * @param {string} id 权限 ID
   * @returns {Promise<boolean>} false = 文档不存在或已处于删除态
   */
  async deletePermission(id) {
    const removed = await withTransaction(async (session) => {
      const options = { new: true };
      if (session) options.session = session;
      // 原子认领：只有 deletedAt 仍为 null 的文档能进入复核；并发删除只有一个能继续。
      const doc = await Permission.findOneAndUpdate(
        { _id: id, deletedAt: null },
        { $set: { deletedAt: new Date() } },
        options
      );
      if (!doc) return null;

      const [childrenCount, refCount] = await Promise.all([
        withSession(Permission.countDocuments({ parent: id }), session),
        withSession(Role.countDocuments({ permissions: id }), session),
      ]);

      if (childrenCount === 0 && refCount === 0) return doc;

      // standalone 无事务回滚，必须显式撤销软删除；副本集交给事务 abort。
      if (!session && !(await restoreSoftDeletedPermission(doc, { childrenCount, refCount }))) {
        throw ApiError.serverError(
          `权限 ${id} 的删除复核未通过且自动恢复失败，该权限仍处于软删除状态，` +
            '请人工恢复（完整文档已写入服务端日志）'
        );
      }
      if (childrenCount > 0) {
        throw ApiError.badRequest(`该权限下有 ${childrenCount} 个子权限，请先删除子权限`);
      }
      throw ApiError.badRequest(`该权限已被 ${refCount} 个角色引用，请先解除引用后再删除`);
    });

    return Boolean(removed);
  }

  async batchCreatePermissions(permissions) {
    const { dupes, codes } = collectDuplicateCodes(permissions);
    if (dupes.length > 0) {
      throw ApiError.badRequest(`权限列表内存在重复编码：${[...new Set(dupes)].join('、')}`);
    }

    const existingCodes = await findExistingCodes(codes);
    const validParentIds = await findValidParentIds(permissions);
    const { skipped, validDocs } = partitionCreatable(permissions, existingCodes, validParentIds);

    const created = [];
    if (validDocs.length > 0) {
      await insertDocsTolerant(validDocs, created, skipped);
    }

    return { created, skipped };
  }
}

module.exports = new PermissionService();
