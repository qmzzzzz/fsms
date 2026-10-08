/**
 * 用户业务服务层：集中用户 CRUD、角色引用查询和统计聚合的数据访问。
 * 控制器保留数据范围判断、业务校验与响应编排。
 */

const User = require('../models/User');
const Role = require('../models/Role');
// 删除用户时要级联清理"进行中的指派"（见 deleteById 的注释），
// 这两个模型与 User 之间没有相互 require，不会成环。
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const { withListBudget, listCountOptions } = require('../utils/queryBudget');
const { withTransaction } = require('../utils/transaction');
const userPermissionService = require('./userPermissionService');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { escapeRegExp } = require('../utils/helpers');
const { DataMasking } = require('../utils/encryption');
const { USER_STATUS } = require('../utils/constants');
// 级联释放的状态面由巡检域档位表派生（F-151）：写字面量 ['pending','in_progress'] 时漏掉的正是
// `overdue`——调度器会把超期的开放计划改成它，越紧急的计划越容易漏在闸门外面；漏掉后开工/提交双双 409，
// 而 cancel 不卡执行人 ⇒ 唯一出路是把真做过的巡检登记成「已取消」。
const { INSPECTION_OPEN_STATUSES } = require('../constants/inspection');

const SIMPLE_ROLE_POPULATE = { path: 'roles', select: 'name code' };
const DETAIL_ROLE_POPULATE = {
  path: 'roles',
  select: 'name code description permissions',
  populate: { path: 'permissions', select: 'name code' },
};

/**
 * 管理员读用户响应的手机号口径：明文只在这里存在过一瞬，出去的是 `phoneMasked`。
 *
 * 为什么不沿用仓里已有的形状（`securityController.js:84` 的 my-info 就是
 * `phone: maskPhone(...)`）：my-info 是只读面板，而用户列表的值会**回填编辑表单**
 * （`web-admin/src/views/UserView.vue` 的 handleEdit）。让展示值占住 `phone` 这个
 * 可写字段的槽位，前端只剩两条必坏的路：
 *   1) 原样提交回填值 → `138****5678` 撞上 `userRoutes.js:110` 的 /^1[3-9]\d{9}$/ ⇒ 400；
 *   2) 那条校验是 `.optional({ values:'falsy' })`，空串照样过，而
 *      `userController.js:550` 写的是 `if (phone !== undefined) user.phone = phone`
 *      ⇒ 一次"我没动手机号"的保存把号码清空。
 * 改名成 `phoneMasked` 是把"误把展示值当可写字段"变成结构上不可能，而不是靠约定。
 *
 * 另一个不能两头各打一次的理由：`DataMasking.maskPhone` **不幂等**——
 * `138****5678` 再打一次得到 `****`（两条锚定正则都不命中，落到兜底分支）。
 * 所以打码点只有这里一个，前端只渲染。
 *
 * 返回 POJO 而非文档对象是刻意的：`toJSON()` 的输出与改造前的响应体逐字段同形
 * （getters 已开），差别只在 phone → phoneMasked；调用方（userController）只读属性
 * 与序列化，不碰文档方法。
 */
function toMaskedAdminUser(doc) {
  if (!doc) return doc;
  const obj = typeof doc.toJSON === 'function' ? doc.toJSON() : { ...doc };
  obj.phoneMasked = DataMasking.maskPhone(obj.phone);
  delete obj.phone;
  return obj;
}

class UserService {
  async buildListQuery(filters, dataScope) {
    const query = {};

    if (filters.search) {
      const escapedSearch = escapeRegExp(filters.search.trim());
      // P1-②（2026-09-30 决策修订）：realName **暂不加密**——姓名模糊检索是
      // 用户管理的日常操作，正则对密文不成立，加密它等于砍掉这个能力。
      // at-rest 加密当前只覆盖 phone（检索键 phoneKey）。realName 转入加密
      // 需要先给姓名检索另立方案（如 ES/前缀键），届时随迁移脚本一起走。
      query.$or = [
        { username: new RegExp(escapedSearch, 'i') },
        { email: new RegExp(escapedSearch, 'i') },
        { realName: new RegExp(escapedSearch, 'i') },
      ];
    }

    // 与 User schema 的 enum、userRoutes 的 isIn 同源（见 models/User.js 头注释）
    const VALID_USER_STATUS = Object.values(USER_STATUS);
    if (typeof filters.status === 'string' && VALID_USER_STATUS.includes(filters.status)) {
      query.status = filters.status;
    }

    if (typeof filters.department === 'string' && filters.department !== '') {
      query.department = filters.department;
    }

    if (filters.role) {
      const roleDoc = await this.findRoleByCode(filters.role);
      if (!roleDoc) return { roleFound: false, scopeAllowed: false, query: null };
      query.roles = roleDoc._id;
    }

    const scopeAllowed = applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.user);
    return { roleFound: true, scopeAllowed, query };
  }

  async listUsers(query, sort, page, limit) {
    const [users, count] = await Promise.all([
      withListBudget(User.find(query))
        .populate(SIMPLE_ROLE_POPULATE)
        .select(User.RESPONSE_EXCLUDE_PHONE_VISIBLE)
        .sort(sort)
        .limit(limit)
        .skip((page - 1) * limit)
        .then((docs) => docs.map(toMaskedAdminUser)),
      User.countDocuments(query, listCountOptions()),
    ]);
    return { users, count };
  }

  async getUserDetail(id) {
    const user = await User.findById(id)
      .populate(DETAIL_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PHONE_VISIBLE);
    return toMaskedAdminUser(user);
  }

  async getCreatedUser(id) {
    const user = await User.findById(id)
      .populate(SIMPLE_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PHONE_VISIBLE);
    return toMaskedAdminUser(user);
  }

  async getUpdatedUser(id) {
    const user = await User.findById(id)
      .populate(SIMPLE_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PHONE_VISIBLE);
    return toMaskedAdminUser(user);
  }

  /**
   * updateUser/assignRoles/deleteUser 的载入入口，其中 updateUser
   * （controllers/userController.js 里 saveUser 那一步）走的是
   * 读-改-save：排除凭证列必须由这里带上，否则那次 save 的 $set 会把
   * mfaSecret/mfaRecoveryCodes/mfaFailCount/phoneKey/passwordHistory 写成 schema 默认值
   * （机理与"为什么必须是对象形态"见 models/User.js 的 unselectedCredentialProjection）。
   */
  findUserForUpdate(id) {
    return User.findById(id).select(User.unselectedCredentialProjection());
  }

  findDuplicateUsername(username) {
    return User.findByUsername(username).select('_id').lean();
  }

  findOneUser(filter) {
    return User.findOne(filter);
  }

  createUser(fields) {
    return User.create(fields);
  }

  saveUser(user) {
    return user.save();
  }

  updateRoles(userId, roles) {
    return User.findByIdAndUpdate(userId, { $set: { roles } });
  }

  getPermissions(userId) {
    return userPermissionService.getPermissions(userId);
  }

  findRoleByCode(code) {
    return Role.findOne({ code });
  }

  findRolesByIds(ids, select = 'level code isBuiltIn', options = {}) {
    let query = Role.find({ _id: { $in: ids } }).select(select);
    if (options.populate) query = query.populate(options.populate);
    if (options.lean) query = query.lean();
    return query;
  }

  findRolePermissionDocs(roleIds) {
    return this.findRolesByIds(roleIds, 'permissions', {
      populate: { path: 'permissions', select: 'code' },
      lean: true,
    });
  }

  /**
   * 只含**生效角色 + 生效权限**的版本，专供 P2-8 子集校验的「排除集」。
   *
   * 排除集的语义是"目标已经实际持有的权限不算本次授予行为"（否则操作者连给
   * 下级收权都做不到）。停用角色/停用权限并不实际生效，把它们算进排除集会
   * 让操作者绕过子集校验：授出一个自己从不持有、目标当前也无法行使的权限码，
   * 等到管理员日后启用那条权限/角色，越权就静默落地（时间炸弹）。
   * 判据与 `userPermissionService.getPermissions` 的 populate match 同一条
   * （那边只算 status:'active'）——操作者侧与目标侧必须同口径，否则一侧宽一侧严
   * 就是漂移的开始。授予侧（grantRoleDocs）刻意仍用不过滤版本：
   * 停用角色里的权限码同样要过"操作者是否持有"的校验，宁可多拦不可漏。
   */
  findActiveRolePermissionDocs(roleIds) {
    return Role.find({ _id: { $in: roleIds }, status: 'active' })
      .select('permissions')
      .populate({ path: 'permissions', select: 'code', match: { status: 'active' } })
      .lean();
  }

  findBatchUsers(ids) {
    return User.find({ _id: { $in: ids } })
      .populate('roles', 'level code isBuiltIn')
      .lean();
  }

  /**
   * 只取"数据范围判定要用的字段"的批量查询（供写路径的对象级范围闸使用）
   *
   * 存在的必要性：范围闸需要按 id 反查用户的 `createdBy`/`department`，
   * 而 `controllers/` 层直连 model 会被分层棘轮（architecture/layeringRatchet）拒绝——
   * 数据访问一律经 service。投影固定两列，避免整档用户进出内存。
   */
  findScopeFieldsByIds(ids) {
    const list = [...new Set((ids || []).map((id) => String(id)))];
    return User.find({ _id: { $in: list } })
      .select('createdBy department')
      .lean();
  }

  /**
   * 释放"当前指派"引用（删除用户的级联清理）
   *
   * 用户记录被删后，仍指向其 ObjectId 的**进行中的指派**会把业务砖化，且没有任何出口：
   *   - FireAlarm：arrive/resolve 的条件是 `{status:'processing', handler: 操作者}`，
   *     false_alarm/cancel 的条件是 `handler ∈ {操作者, null, 不存在}`。
   *     悬空 ObjectId 四个都不匹配 → 一条处理中的报警**永远关不掉**，
   *     连超管也救不回来（范围判定能过，但 handler 永远不等于操作者）。
   *     只把 handler 置空仍不够：processing + handler:null 只剩误报一条出路
   *     （dispatch/cancel 的前置条件是 `status:'pending'`，arrive/resolve 要求
   *     `handler === 操作者`，null 谁也不等于）。真实出警的工单被强制登记成
   *     "误报"，在消防合规台账里等于把一起真事故从统计里抹掉。因此必须连同
   *     status 退回 pending —— 那才是本系统"无人认领"的既有语义。
   *   - Inspection：start 要求 `assignedTo: 操作者` 或 `assignedTo.0` 不存在；
   *     单元素幽灵数组两者都不满足 → 计划永远无法执行，却仍计入 pending 统计，
   *     把 completionRate 一起拖住。
   * 只清**进行中的指派**（报警 handler / 巡检 assignedTo），历史取证字段
   * （reporter.userId、processLog[].operator、reviewedBy、executionLog[].userId、
   *  createdBy）一律不动——"谁当时做了什么"必须留住，哪怕那个人已经不存在。
   * 与 DeviceService.deleteDevice 的级联同一手法（withTransaction：副本集原子，
   * standalone 下按序执行并告警一次）。
   *
   * dispatchedAt/arrivedAt 随 status 一起清空：它们是"本次派单"的时间戳，不是历史。
   * 留着会让报表把响应时长算成
   * `reportController.js` / `reportDashboardService.js` 里的 `dispatchedAt - receivedAt`，
   * 即上一个已删除账户的派单时间；原始派单过程由 processLog 追加记录完整保留。
   *
   * @param {Array} userIds 被删用户 id
   * @param {object|null} session 事务会话（standalone 降级时为 null）
   */
  async releaseOpenAssignments(userIds, session = null) {
    if (!userIds || userIds.length === 0) return;
    const opts = session ? { session } : {};
    const now = new Date();
    // 报警：处理中的退回待指派池并留痕。只认 processing ——
    // 全仓唯一的 handler 写入点是 AlarmService.dispatchAlarm，它把 handler 与
    // status:'processing' 写在同一条原子更新里，于是"pending 却挂着 handler"
    // 这种状态根本不存在，为它多写一条 updateMany 只会多一条永远为假的分支。
    await FireAlarm.updateMany(
      { handler: { $in: userIds }, status: 'processing' },
      {
        $set: { handler: null, status: 'pending', dispatchedAt: null, arrivedAt: null },
        $push: {
          processLog: {
            time: now,
            action: 'handler_released',
            operator: null,
            remark: '处理人账户已删除，工单退回待指派池',
          },
        },
      },
      opts
    );
    // 巡检：未开工/进行中的计划里摘掉该成员（全部摘掉后 assignedTo.0 不存在，
    // 同范围的合格执行人即可接手，这正是"无人认领"的既有语义）
    await Inspection.updateMany(
      { assignedTo: { $in: userIds }, status: { $in: INSPECTION_OPEN_STATUSES } },
      { $pull: { assignedTo: { $in: userIds } } },
      opts
    );
  }

  async deleteById(id) {
    let deleted = null;
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      deleted = await User.findByIdAndDelete(id, opts);
      await this.releaseOpenAssignments([id], session);
    });
    return deleted;
  }

  async deleteMany(filter) {
    let result = null;
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      // 先取 id：删除之后就再也不知道曾指向谁（级联必须以 id 列表为准）
      const affected = await User.find(filter, '_id').lean();
      const ids = affected.map((doc) => doc._id);
      result = await User.deleteMany(filter, opts);
      await this.releaseOpenAssignments(ids, session);
    });
    return result;
  }

  aggregateStats(pipeline) {
    return User.aggregate(pipeline);
  }
}

module.exports = new UserService();
