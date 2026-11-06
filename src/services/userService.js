/**
 * 用户业务服务层：集中用户 CRUD、角色引用查询和统计聚合的数据访问。
 * 控制器保留数据范围判断、业务校验与响应编排。
 */

const User = require('../models/User');
const { HONEYPOT_EXCLUDED_FILTER } = require('../constants/honeypotAccounts'); // 枚举面排除判据（单一声明，见 constants/honeypotAccounts.js）
const UserAvatar = require('../models/UserAvatar');
const Role = require('../models/Role');
// 删除用户时要级联清理"进行中的指派"（见 deleteById 的注释），
// 这两个模型与 User 之间没有相互 require，不会成环。
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const { withListBudget, listCountOptions } = require('../utils/queryBudget');
const { withTransaction } = require('../utils/transaction');
const userPermissionService = require('./userPermissionService');
const { anonymizeMany } = require('./userAnonymizationBatch');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { uniqueIdStrings } = require('../utils/helpers');
const { normalizeSearchTerm, substringPattern, prefixPattern } = require('../utils/searchPatterns');
// A3：email 加密后，用户列表的「按邮箱片段搜索」改走 n-gram 子串盲索引
const { piiSubstringKeys } = require('../utils/piiCrypto');
const { DataMasking } = require('../utils/encryption');
const { USER_STATUS } = require('../utils/constants');
// 级联释放的状态面由巡检域档位表派生（F-151）：写字面量 ['pending','in_progress'] 时漏掉的正是
// `overdue`——调度器会把超期的开放计划改成它，越紧急的计划越容易漏在闸门外面；漏掉后开工/提交双双 409，
// 而 cancel 不卡执行人 ⇒ 唯一出路是把真做过的巡检登记成「已取消」。
const { INSPECTION_OPEN_STATUSES } = require('../constants/inspection');
// A2（2026-10-16）：匿名化需要随机口令（改写密码以彻底断掉旧凭据）与留痕日志
const crypto = require('crypto');
const logger = require('../utils/logger');

/**
 * 匿名化的取值口径（A2，2026-10-16）——**单一声明**，判据只在这里。
 * 占位姓名刻意不用「已删除」：记录还在、只是不再指向某个具体的人，
 * 写成「已删除」会让读报表的人以为这条数据本身被删了。
 *
 * email 占位必须唯一（User.email 有唯一索引，且 A3 尚未实施加密）：
 * 置空会让第二个注销用户撞 E11000，故把 _id 编进占位里 —— 天然唯一、可回溯到原账号，
 * 且 `.invalid` 是 RFC 2606 保留域，永不会被投递。
 *
 */
const ANONYMIZED_REAL_NAME = '已注销用户';
const ANONYMIZED_EMAIL_PREFIX = 'deleted+';
const ANONYMIZED_EMAIL_DOMAIN = 'anonymized.invalid';

/** 构造某个用户 id 对应的匿名化邮箱占位（唯一、不可投递、可回溯） */
const buildAnonymizedEmail = (userId) =>
  `${ANONYMIZED_EMAIL_PREFIX}${String(userId)}@${ANONYMIZED_EMAIL_DOMAIN}`;

/** 是否已是匿名化占位邮箱（幂等标记，见 anonymizeById） */
const isAnonymizedEmail = (email) =>
  typeof email === 'string' && email.startsWith(ANONYMIZED_EMAIL_PREFIX);

const SIMPLE_ROLE_POPULATE = { path: 'roles', select: 'name code' };
const DETAIL_ROLE_POPULATE = {
  path: 'roles',
  select: 'name code description permissions',
  populate: { path: 'permissions', select: 'name code' },
};

/**
 * 管理员读用户响应的 PII 口径：明文只在这里存在过一瞬，出去的是 `phoneMasked` / `emailMasked`。
 *
 * 不复用 my-info 的 `phone: maskPhone(...)` 形状：用户列表的值会**回填编辑表单**
 * （UserView.vue 的 handleEdit），展示值占住可写字段的槽位后，原样提交会撞
 * `userRoutes.js:110` 的手机号正则 ⇒ 400；空串又能过 `.optional({values:'falsy'})`，
 * 继而被 `userController/update.js:165` 写成「把号码清空」。改名成 phoneMasked 是把这种
 * 误用变成结构上不可能，而不是靠约定；email 同规格（回填会撞 `.isEmail()`）。
 *
 * 打码点只有这里一个：`DataMasking.maskPhone` 不幂等（`138****5678` 再打一次得到 `****`）。
 * 返回 POJO 而非文档对象，是为了让响应体与改造前逐字段同形（差别只在两个 *Masked 键）。
 */
function toMaskedAdminUser(doc) {
  if (!doc) return doc;
  const obj = typeof doc.toJSON === 'function' ? doc.toJSON() : { ...doc };
  obj.phoneMasked = DataMasking.maskPhone(obj.phone);
  delete obj.phone;
  // maskEmail 对「无 @ / 本地部分为空」的形态按既有契约原样返回——它是展示函数，
  // 不是 egress 闸门。用户管理响应不能沿用这条例外：库里一旦有历史脏数据，
  // 原样返回就是整串明文。认不出邮箱形态时按兜底打码。
  const email = obj.email;
  const maskedEmail = DataMasking.maskEmail(email);
  obj.emailMasked = email && maskedEmail === String(email) ? '****' : maskedEmail;
  delete obj.email;
  return obj;
}

async function attachLastLoginIp(list, enabled) {
  if (!enabled || !list.length) return list;
  const rows = await User.find({ _id: { $in: list.map((u) => u._id) } })
    .select('lastLoginIp')
    .lean();
  const byId = new Map(rows.map((r) => [String(r._id), r.lastLoginIp]));
  list.forEach((u) => {
    if (byId.get(String(u._id))) u.lastLoginIp = byId.get(String(u._id));
  });
  return list;
}

class UserService {
  async buildListQuery(filters, dataScope) {
    const query = { ...HONEYPOT_EXCLUDED_FILTER }; // 列表与计数同源：蜜罐账户不得出现在任何面向人的用户清单/计数里

    const searchTerm = normalizeSearchTerm(filters.search);
    if (searchTerm) {
      // realName **暂不加密**——姓名模糊检索是用户管理的日常操作，正则对
      // 密文不成立，加密它等于砍掉这个能力。at-rest 加密当前覆盖 phone 与 email。
      //
      // A3（2026-10-16）：email 也已加密 ⇒ 原先那一支 `{ email: new RegExp(...) }`
      // 对密文**恒不命中、静默失效**（不报错、不告警，只是搜不到），
      // 「按邮箱片段找人」会无声消失。改走 emailGrams 子串盲索引：
      // 每行登记自己包含的全部 3-gram HMAC，查询侧切同样粒度求 $all 交集。
      // 判据与已知边界（它给的是**候选超集**而非精确子串）见 piiCrypto.piiSubstringKeys。
      //
      // username 是标识符 ⇒ 锚定前缀（可走索引）；realName 是自由文本 ⇒ 子串。
      query.$or = [
        { username: prefixPattern(searchTerm) },
        { realName: substringPattern(searchTerm) },
      ];
      // ⚠️ 长度不足 3 的搜索串切不出 gram，piiSubstringKeys 返回 `[]`；
      // 而 `{ emailGrams: { $all: [] } }` 在 MongoDB 里**匹配全部文档**——
      // 无条件塞进 $or 会让「搜 2 个字符」退化成「返回所有用户」。
      // 故空数组必须走"该分支不参与 $or"，这是本处唯一的正确写法。
      const emailGrams = piiSubstringKeys(searchTerm);
      if (emailGrams.length > 0) {
        query.$or.push({ emailGrams: { $all: emailGrams } });
      }
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
      if (!roleDoc) return { roleFound: false, query: null };
      query.roles = roleDoc._id;
    }

    // 范围不可用时 applyDataScopeToQuery 直接抛 403（#12），不再回 scopeAllowed:false
    // 让控制器拼一个空分页——那条路径与"真的没有用户"长得一模一样。
    applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.user);
    return { roleFound: true, query };
  }

  async listUsers(query, sort, page, limit, opts = {}) {
    const listQuery = withListBudget(User.find(query))
      .populate(SIMPLE_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PII_VISIBLE)
      .sort(sort)
      .limit(limit)
      .skip((page - 1) * limit);
    // username 的唯一索引 username_ci 带大小写不敏感 collation：查询不声明同一
    // collation 时该索引无法参与排序（会退化成阻塞排序）。仅在按 username 排序时
    // 声明，避免无谓改变其他排序/过滤的字符比较口径（$regex 仍保留 'i'，语义不变）。
    if (Object.prototype.hasOwnProperty.call(sort, 'username')) {
      listQuery.collation(User.USERNAME_COLLATION);
    }
    const [users, count] = await Promise.all([
      listQuery.then((docs) =>
        attachLastLoginIp(docs.map(toMaskedAdminUser), opts.includeLastLoginIp)
      ),
      User.countDocuments(query, listCountOptions()),
    ]);
    return { users, count };
  }

  async getUserDetail(id, opts = {}) {
    const user = await User.findById(id)
      .populate(DETAIL_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PII_VISIBLE);
    const masked = toMaskedAdminUser(user);
    if (masked) await attachLastLoginIp([masked], opts.includeLastLoginIp);
    return masked;
  }

  async getCreatedUser(id) {
    const user = await User.findById(id)
      .populate(SIMPLE_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PII_VISIBLE);
    return toMaskedAdminUser(user);
  }

  async getUpdatedUser(id) {
    const user = await User.findById(id)
      .populate(SIMPLE_ROLE_POPULATE)
      .select(User.RESPONSE_EXCLUDE_PII_VISIBLE);
    return toMaskedAdminUser(user);
  }

  /**
   * updateUser/assignRoles/deleteUser 的载入入口，其中 updateUser
   * （controllers/userController/update.js 里 saveUser 那一步）走的是
   * 读-改-save：排除凭证列必须由这里带上，否则那次 save 的 $set 会把
   * mfaSecret/mfaRecoveryCodes/mfaFailCount/phoneKey/passwordHistory 写成 schema 默认值
   * （机理与"为什么必须是对象形态"见 models/User.js 的 unselectedCredentialProjection）。
   */
  findUserForUpdate(id, expected, opts = {}) {
    // expected 为控制器判定时的状态快照（P1-3 匿名化复用）：带条件载入，
    // 避免"判定后目标被提权/改部门"仍按旧结论执行。不传时保持原语义。
    const filter = expected ? { _id: id, ...expected } : { _id: id };
    return User.findOne(filter, null, opts).select(User.unselectedCredentialProjection());
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

  saveUser(user, opts = {}) {
    return user.save(opts);
  }

  /**
   * 角色写入（L-06）：带上调用方校验时看到的 roles 快照做条件更新。
   * 无快照时保持旧语义（无条件写），既有调用方与测试不受影响。
   *
   * `$inc __v` 不是装饰：updateUser / setUserLockStatus 走的是「先按快照做层级/
   * 超管判定，再 user.save()」，而 User schema 开了 optimisticConcurrency，
   * save() 的过滤条件正是载入时的 __v。update query 不会自动推进版本号，
   * 不在这里显式递增，并发改掉目标角色后那次 save() 仍会命中 ⇒ 用旧角色集
   * 得出的授权结论被继续执行（提权/越权改状态）。推进 __v 让后到的 save()
   * 抛 VersionError，由 errorHandler 映射为「刷新重试」。
   * @returns {Promise<object|null>} null = 角色已被并发修改，控制器应回 409
   */
  updateRoles(userId, roles, expectedRoles) {
    const update = { $set: { roles }, $inc: { __v: 1 } };
    if (!expectedRoles) {
      return User.findByIdAndUpdate(userId, update);
    }
    return User.findOneAndUpdate({ _id: userId, roles: expectedRoles }, update, { new: true });
  }

  getPermissions(userId) {
    return userPermissionService.getPermissions(userId);
  }

  findRoleByCode(code) {
    return Role.findOne({ code });
  }

  /**
   * 按 id 取角色。activeOnly 供授予路径使用（L-05）：停用角色不得再被分配，
   * 否则角色恢复启用时，早已挂在其上的账户会静默获得权限。
   * 读路径/层级判定保持默认（不过滤），否则目标用户持有一个停用的高等级角色时，
   * 保护判定会按其"实际生效"的低层级放行，反而放宽了对象保护。
   */
  findRolesByIds(ids, select = 'level code isBuiltIn', options = {}) {
    const filter = { _id: { $in: ids } };
    if (options.activeOnly) filter.status = 'active';
    let query = Role.find(filter).select(select);
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
   * 只含**生效角色 + 生效权限**的版本，专供子集校验的「排除集」。
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
    const list = uniqueIdStrings(ids);
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
   * @param {object} [options] { remark } 过程记录文案；账户被停用/锁定而非删除时由调用方覆盖
   */
  async releaseOpenAssignments(userIds, session = null, options = {}) {
    if (!userIds || userIds.length === 0) return;
    const opts = session ? { session } : {};
    const now = new Date();
    const remark = options.remark || '处理人账户已删除，工单退回待指派池';
    // 报警：处理中的退回待指派池并留痕。只认 processing：handler 与 status:'processing' 在
    // AlarmService.dispatchAlarm 里由同一条原子更新写完，"pending 却挂着 handler" 不存在。
    await FireAlarm.updateMany(
      { handler: { $in: userIds }, status: 'processing' },
      {
        $set: { handler: null, status: 'pending', dispatchedAt: null, arrivedAt: null },
        $push: {
          processLog: {
            time: now,
            action: 'handler_released',
            operator: null,
            remark,
          },
        },
      },
      opts
    );
    // 巡检：未开工/进行中的计划里摘掉该成员（全摘后 assignedTo.0 不存在，同范围合格执行人即可接手，正是"无人认领"的既有语义）
    await Inspection.updateMany(
      { assignedTo: { $in: userIds }, status: { $in: INSPECTION_OPEN_STATUSES } },
      { $pull: { assignedTo: { $in: userIds } } },
      opts
    );
  }

  /**
   * 删除用户（M-01）：expected 是控制器做范围/层级/超管判定时读到的状态快照。
   * 条件删除保证"判定所依据的那份状态"就是"被删除的那份状态"——否则目标在
   * 判定之后被提权/改部门，删除仍会按旧结论执行。
   * @param {object} [expected] 形如 { roles, department, createdBy } 的过滤片段
   * @returns {Promise<object|null>} null = 状态已变，未删除任何数据
   */
  async deleteById(id, expected) {
    let deleted = null;
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      const filter = expected ? { _id: id, ...expected } : { _id: id };
      deleted = expected
        ? await User.findOneAndDelete(filter, opts)
        : await User.findByIdAndDelete(id, opts);
      if (!deleted) return;
      // 头像记录与用户同生命周期：删用户不删图 = 留下可被 /api/avatars/:id 拉到的残留
      await UserAvatar.deleteOne({ _id: deleted._id }, opts);
      await this.releaseOpenAssignments([deleted._id], session);
    });
    return deleted;
  }

  /**
   * 批量删除的快照查询：findBatchUsers 的 roles 已被 populate 成角色文档，
   * 不能直接当条件删除的过滤值（数组等值比较需要原始 ObjectId 列表）。
   */
  findUserSnapshots(ids) {
    if (!ids || ids.length === 0) return Promise.resolve([]);
    return User.find({ _id: { $in: ids } })
      .select('roles department createdBy')
      .lean();
  }

  /**
   * 批量删除（M-01）：expectedByTarget 为 Map<id, 快照>。逐个条件删除，
   * 任一目标状态已变即抛错中止事务（副本集下整批回滚），不留下"删了一半"。
   * @param {object} filter 无条件删除时的过滤条件
   * @param {Map<string, object>} [expectedByTarget]
   */
  async deleteMany(filter, expectedByTarget) {
    let result = null;
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      if (expectedByTarget) {
        const ids = [];
        for (const [id, snapshot] of expectedByTarget) {
          const deleted = await User.findOneAndDelete({ _id: id, ...snapshot }, opts);
          if (!deleted) {
            const err = new Error('批量删除中止：目标用户状态已变更');
            err.code = 'USER_STATE_CONFLICT';
            throw err;
          }
          ids.push(deleted._id);
        }
        result = { deletedCount: ids.length, acknowledged: true };
        await UserAvatar.deleteMany({ _id: { $in: ids } }, opts);
        await this.releaseOpenAssignments(ids, session);
        return;
      }
      // 先取 id：删除之后就再也不知道曾指向谁（级联必须以 id 列表为准）
      const affected = await User.find(filter, '_id').lean();
      const ids = affected.map((doc) => doc._id);
      result = await User.deleteMany(filter, opts);
      // 空数组不发写请求（Mongo 不报错，但会产生无意义写）
      if (ids.length > 0) await UserAvatar.deleteMany({ _id: { $in: ids } }, opts);
      await this.releaseOpenAssignments(ids, session);
    });
    return result;
  }

  /**
   * 匿名化一个用户（A2「删除权/注销」的落点，2026-10-16）
   *
   * 为什么不是硬删除：审计链（AuditLog.username 快照、FireAlarm.reporter.userId、
   * processLog[].operator、reviewedBy、executionLog[].userId、createdBy）到处指向用户；
   * 硬删后这些引用变成悬空指向（问不出「当时是谁做的」），而删除权的本意是「不再能识别到
   * 这个人」，不是抹掉他做过的事。匿名化兼顾两侧：保留 userId 与统计口径，抹除可识别信息。
   *
   * 抹除：realName → 固定占位；phone → ''（写侧钩子同步清 phoneKey）；email →
   * `deleted+<id>@anonymized.invalid`（唯一索引不能置空，占位带 _id 才天然唯一）；avatar → ''。
   * 保留：username（账号标识/审计快照/登录名）、department、roles、createdAt。
   *
   * 会话与工单：tokenVersion++ 吊销已签发令牌、status → inactive 禁登录、密码改写为随机值
   * （不落任何日志）、释放进行中的指派（复用 releaseOpenAssignments，与删号同口径）。
   *
   * 幂等：以 email 占位前缀为标记，重复调用直接返回（二次改写会让 tokenVersion 无谓自增）。
   *
   * @param {string|import('mongoose').Types.ObjectId} id 用户 id
   * @param {{reason?: string}} [options] 注销原因（仅用于日志与调用方留痕）
   * @returns {Promise<object|null>} 匿名化后的用户文档；用户不存在时为 null
   */
  async anonymizeById(id, { reason = 'deletion_request', expected } = {}) {
    let result = null;
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      const filter = expected ? { _id: id, ...expected } : { _id: id };
      // 排除投影不可省：这里后面是 user.save()，不写投影时 Mongoose 会把**本次没有
      // 从服务器取回**的 select:false 路径按 schema 默认值填上并写进 $set
      // （机理见 models/User.js 的 unselectedCredentialProjection）。
      // 实测后果：一次匿名化会把 mfaSecret 写成 ''、mfaRecoveryCodes 清空、
      // mfaFailCount/mfaLastCounter/mfaLockUntil 归零、passwordHistory 清空——
      // 本函数的契约里**没有**这几项（契约只写了 realName/phone/email/avatar），
      // 那些改写是"默认值回填"这个副作用的产物，不是有意设计。
      // 该站点由 src/tests/ci/userCredentialProjectionLedger.test.js 第 2 组捕获。
      //
      // 条件载入（expected）：控制器做范围/层级/超管判定时读到的状态快照必须就是
      // 被匿名化的那份状态；目标在判定之后被提权/改部门时返回 null，由控制器回 409。
      const user = await User.findOne(filter, null, opts).select(
        User.unselectedCredentialProjection()
      );
      if (!user) return;
      result = await this.anonymizeUserDocument(user, reason, opts);
      // 与删号同一口径：把"进行中的指派"退回池子（见 releaseOpenAssignments 的注释）
      await this.releaseOpenAssignments([user._id], session);
    });
    return result;
  }

  /**
   * 单文档匿名化（内部实现）：anonymizeById / anonymizeMany 共用，
   * 保证两条入口的抹除清单、幂等标记与审计字段完全同源。
   * @param {object} user 已加载的用户文档（须带 unselectedCredentialProjection）
   * @param {string} reason 注销原因
   * @param {object} opts mongoose 选项（含 session）
   * @returns {Promise<object>} 匿名化后的用户文档
   */
  async anonymizeUserDocument(user, reason, opts = {}) {
    if (isAnonymizedEmail(user.email)) return user; // 幂等：已匿名化不二次改写

    const now = new Date();
    user.realName = ANONYMIZED_REAL_NAME;
    user.phone = ''; // 写侧钩子会同步把 phoneKey 落成 ''
    user.email = buildAnonymizedEmail(user._id);
    user.avatar = '';
    // 匿名化只清指针不删图 = 图片仍可通过 /api/avatars/:id 拉到（读端查 UserAvatar）
    await UserAvatar.deleteOne({ _id: user._id }, opts);
    user.status = USER_STATUS.INACTIVE;
    user.password = crypto.randomBytes(32).toString('hex'); // pre('save') 钩子负责哈希
    user.passwordRetiredHash = null; // 审计二-2：注销后不得留「重置前那代口令」的 bcrypt 摘要——它是可离线爆破的 L4 凭证，删除权要求一并抹掉
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.mustChangePassword = false; // 匿名账户没有"改密后恢复"的语义
    user.deletionRequestedAt = user.deletionRequestedAt || now;
    user.anonymizedAt = now;
    user.anonymizationReason = String(reason || 'deletion_request').slice(0, 200);
    await user.save(opts);

    logger.warn(
      `用户已匿名化（删除权流程）：id=${String(user._id)} reason=${user.anonymizationReason}`
    );
    return user;
  }

  /**
   * 批量匿名化（P1-3）：任一目标状态已变即抛 USER_STATE_CONFLICT 中止事务
   * （副本集下整批回滚），与 deleteMany 的批量口径一致。
   * @param {object} filter 无快照时的过滤条件
   * @param {Map<string, object>} [expectedByTarget] Map<id, {roles,department,createdBy}>
   * @param {{reason?: string}} [options]
   * @returns {Promise<{anonymizedCount: number, acknowledged?: boolean}>}
   */
  async anonymizeMany(filter, expectedByTarget, options = {}) {
    return anonymizeMany(this, filter, expectedByTarget, options);
  }

  aggregateStats(pipeline) {
    return User.aggregate([{ $match: HONEYPOT_EXCLUDED_FILTER }, ...pipeline]); // 统计面同口径：蜜罐账户既不进总用户数，也不进部门/角色分布
  }
}

module.exports = new UserService();
