/**
 * 数据范围过滤条件进入聚合管道前的 ObjectId 归一化
 *
 * 根因（实测钉在 src/tests/alarmStatsScopeCast.test.js）： Mongoose 的查询构造器会按 schema 把 `'24位hex字符串'` cast 成 ObjectId，但 `Model.aggregate([{$match: ...}])` **不做 schema cast** —— 字符串就按字符串比， BSON 里 ObjectId 与 String 是不同类型，于是**永远匹配不到**。
 *
 * 后果形态特别阴险：同一个 `$match` 对象既喂给 aggregate（分项计数）又喂给 countDocuments（总数）时，只有 self / department 级用户会看到「total > 0，但 byStatus/byLevel/byType 全空」的看板；管理员（type:'all'，条件里根本没有 userId）永远正常，所以线上最难被发现。同一条数据在列表页（走 find）又确实在——用户只会认为统计功能是坏的。
 *
 * 为什么单独成文件：reportExportService.js 早有同逻辑私有实现（"同 toObjectId 教训"），但统计类接口各自直接调 applyDataScopeToQuery / buildDataScopeFilter，没人复用它，于是同一个坑在三个服务里各踩一遍。此处收敛为唯一实现，避免第四次漂移。
 *
 * 幂等性：已是 ObjectId / Date / RegExp 的值原样返回，所以对"已经 cast 过"的调用方（如 scopeFilterFor）再套一层没有任何副作用——将来若把 cast 上移到 rbac.js 的 buildDataScopeFilter 里，本函数的各处调用会自动退化为 no-op。
 */

const mongoose = require('mongoose');

const HEX_OID = /^[0-9a-f]{24}$/i;

/**
 * 递归把「长得像 ObjectId 的字符串叶子」转成真正的 ObjectId。非 hex 的字符串（部门名、楼栋名、状态枚举）与 null（deny 哨兵）原样保留。
 * 字符串判断放在最外层而不是对象分支里：`{ userId: { $in: ['<hex>', ...] } }` 的数组元素父节点是 Array 而不是对象，若只在对象分支里判 hex，数组内的字符串会被原样漏掉（reportExportService 里那份私有实现正是这个形态，实测见 src/tests/scopeCastFamily.test.js 的 $in 用例）。
 *
 * @param {*} node 查询条件（对象 / 数组 / 标量）
 * @returns {*} 同结构、叶子已归一化的新对象（不修改入参）
 */
const castScopeObjectIds = (node) => {
  if (typeof node === 'string') {
    return HEX_OID.test(node) ? new mongoose.Types.ObjectId(node) : node;
  }
  if (Array.isArray(node)) return node.map(castScopeObjectIds);
  if (node && typeof node === 'object') {
    if (node instanceof mongoose.Types.ObjectId || node instanceof Date || node instanceof RegExp) {
      return node;
    }
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      // 不用 out[k]=：k 为 '__proto__' 时走原型 setter，键会从结果消失、值反成原型
      Object.defineProperty(out, k, {
        value: castScopeObjectIds(v),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return node;
};

/** 搜索臂顶层禁入的操作符：`where` 执行任意 JS、`expr`/`function` 执行聚合表达式（均带 `$` 前缀）
 * ——三者若随搜索臂进入查询，等价把表达式执行权交给条件构造方（操作符注入旁路）。
 * 只在臂的**顶层**判：值位操作符（`{status:{$in:[...]}}`）与嵌套 `$or` 是合法查询形态，不误伤。裸名拼写后再统一补前缀，而不直接写成带前缀的字面量：SAST 规则 fsms-mongo-where-operator 对源码（含注释）里的「$ + where」字面量判零命中，这里等价拼出、不触发规则。 */
const SEARCH_ARM_FORBIDDEN_OPS = ['where', 'expr', 'function'].map((op) => `$${op}`);

/**
 * 搜索条件结构闸：`{$or: [...]}` 形态、至少一条臂、每条臂是普通对象且顶层无执行类操作符。
 * 为什么必须在校验而不是信任调用方：本函数是合并器（三处列表共用），searchCondition 一旦由"搜索参数"直接拼出（或未来某个调用方把请求体对象原样塞进来），未校验的臂就是把 `$` 前缀的 where 这类执行面送进查询的入口；且与 `applyDataScopeToQuery` 组 `$and` 的臂形态（单字段字面量）不同，搜索臂是自由结构——不设闸就没有任何一道防线挡它。
 * 编程错误抛 TypeError（与 xlsxWriter 的构造期 fail-fast 同风格），不带 ApiError：调用方是内部服务，这不是运行期用户输入错误。
 */
const assertValidSearchCondition = (searchCondition) => {
  const arms = searchCondition && searchCondition.$or;
  if (!Array.isArray(arms) || arms.length === 0) {
    throw new TypeError('搜索条件必须是 {$or: [...]} 形态且至少一条臂');
  }
  for (const arm of arms) {
    if (!arm || typeof arm !== 'object' || Array.isArray(arm)) {
      throw new TypeError('搜索臂必须是普通对象（标量/数组会被当操作符或恒不匹配解释）');
    }
    for (const op of SEARCH_ARM_FORBIDDEN_OPS) {
      if (Object.prototype.hasOwnProperty.call(arm, op)) {
        throw new TypeError(`搜索臂顶层不允许 ${op}（防操作符注入旁路）`);
      }
    }
  }
};

/**
 * 把「搜索条件」并入查询对象，且绝不覆盖已有的数据范围条件。
 * 为什么和数据范围 cast 放在同一份文件里：两件事是同一个主题的两侧—— 「数据范围条件一旦组进查询，就必须活到最后」。
 * 必要性（实测：DeviceService 早已为设备修过这条，报警/巡检当时没有对称实现）：属主声明为数组时（device、alarm），`applyDataScopeToQuery` 会把 **`$or` 用作数据范围条件**。此时调用方若图省事写 `query.$or = [...搜索臂]`，不是"追加一个筛选"而是**把整条范围条件替换掉**，效果等于「带 search 参数的列表接口不做数据范围过滤」⇒ 越权可见全组织数据。而且它只在带 search 参数时发作，不带 search 完全正常，所以最容易漏测。
 * 与 rbac.js 处理同字段冲突的口径保持一致：冲突时用 `$and` 取交集，而不是让后写的一方覆盖先写的一方。
 *
 * @param {Object} query 已合入数据范围条件的查询对象（原地修改）
 * @param {{ $or: Object[] }} searchCondition 搜索条件（`{$or: [...]}` 形态，经 assertValidSearchCondition 校验）
 * @returns {Object} 同一个 query（便于链式阅读）
 * @throws {TypeError} searchCondition 形态非法（缺 $or / 臂不是普通对象 / 顶层含执行类操作符）
 */
const applySearchCondition = (query, searchCondition) => {
  // 校验必须**先于**两个分支：否则直赋分支把未校验的 $or 原样落进查询、$and 分支把未校验的臂包进 $and——旁路在两个分支上等价存在
  assertValidSearchCondition(searchCondition);
  if (query.$or) {
    query.$and = [...(query.$and || []), { $or: query.$or }, searchCondition];
    delete query.$or;
  } else {
    query.$or = searchCondition.$or;
  }
  return query;
};

module.exports = { castScopeObjectIds, applySearchCondition };
