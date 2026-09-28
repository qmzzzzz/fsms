/**
 * 数据范围过滤条件进入聚合管道前的 ObjectId 归一化
 *
 * 根因（实测钉在 src/tests/alarmStatsScopeCast.test.js）：
 * Mongoose 的查询构造器会按 schema 把 `'24位hex字符串'` cast 成 ObjectId，
 * 但 `Model.aggregate([{$match: ...}])` **不做 schema cast** —— 字符串就按字符串比，
 * BSON 里 ObjectId 与 String 是不同类型，于是**永远匹配不到**。
 *
 * 后果形态特别阴险：同一个 `$match` 对象既喂给 aggregate（分项计数）又喂给
 * countDocuments（总数）时，只有 self / department 级用户会看到
 * 「total > 0，但 byStatus/byLevel/byType 全空」的看板；
 * 管理员（type:'all'，条件里根本没有 userId）永远正常，所以线上最难被发现。
 * 同一条数据在列表页（走 find）又确实在——用户只会认为统计功能是坏的。
 *
 * 为什么单独成文件：`reportExportService.js` 早就为导出路径写过一份同逻辑私有实现
 * （其注释里记着"同 utils/behaviorBaseline 的 toObjectId 教训"），但统计类接口
 * （AlarmService / InspectionService / DeviceService）各自直接调
 * `applyDataScopeToQuery` / `buildDataScopeFilter`，没人复用那份私有实现，
 * 于是同一个坑在三个服务里各踩一遍。此处收敛为唯一实现，避免第四次漂移。
 *
 * 幂等性：已是 ObjectId / Date / RegExp 的值原样返回，所以对"已经 cast 过"的
 * 调用方（如 scopeFilterFor）再套一层没有任何副作用——将来若把 cast 上移到
 * rbac.js 的 buildDataScopeFilter 里，本函数的各处调用会自动退化为 no-op。
 */

const mongoose = require('mongoose');

const HEX_OID = /^[0-9a-f]{24}$/i;

/**
 * 递归把「长得像 ObjectId 的字符串叶子」转成真正的 ObjectId。
 * 非 hex 的字符串（部门名、楼栋名、状态枚举）与 null（deny 哨兵）原样保留。
 *
 * 字符串判断放在最外层而不是对象分支里：`{ userId: { $in: ['<hex>', ...] } }` 的
 * 数组元素父节点是 Array 而不是对象，若只在对象分支里判 hex，数组内的字符串
 * 会被原样漏掉（reportExportService 里那份私有实现正是这个形态，实测见
 * src/tests/scopeCastFamily.test.js 的 $in 用例）。
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
      out[k] = castScopeObjectIds(v);
    }
    return out;
  }
  return node;
};

/**
 * 把「搜索条件」并入查询对象，且绝不覆盖已有的数据范围条件。
 *
 * 为什么和数据范围 cast 放在同一份文件里：两件事是同一个主题的两侧——
 * 「数据范围条件一旦组进查询，就必须活到最后」。
 *
 * 必要性（实测：DeviceService 早已为设备修过这条，报警/巡检当时没有对称实现）：
 * 属主声明为数组时（device、alarm），`applyDataScopeToQuery` 会把 **`$or` 用作
 * 数据范围条件**。此时调用方若图省事写 `query.$or = [...搜索臂]`，
 * 不是"追加一个筛选"而是**把整条范围条件替换掉**，效果等于
 * 「带 search 参数的列表接口不做数据范围过滤」⇒ 越权可见全组织数据。
 * 而且它只在带 search 参数时发作，不带 search 完全正常，所以最容易漏测。
 *
 * 与 rbac.js 处理同字段冲突的口径保持一致：冲突时用 `$and` 取交集，
 * 而不是让后写的一方覆盖先写的一方。
 *
 * @param {Object} query 已合入数据范围条件的查询对象（原地修改）
 * @param {{ $or: Object[] }} searchCondition 搜索条件（`{$or: [...]}` 形态）
 * @returns {Object} 同一个 query（便于链式阅读）
 */
const applySearchCondition = (query, searchCondition) => {
  if (query.$or) {
    query.$and = [...(query.$and || []), { $or: query.$or }, searchCondition];
    delete query.$or;
  } else {
    query.$or = searchCondition.$or;
  }
  return query;
};

module.exports = { castScopeObjectIds, applySearchCondition };
