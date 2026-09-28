/**
 * IP 名单类型清单（单一事实来源）
 *
 * 为什么需要：`['black', 'white']` 此前有 6 处**字面量副本**——
 * `models/IPBlacklist.js` 的 `enum`、`routes/securityRoutes.js` 的两处 `isIn(...)`
 * （查询与请求体各一）、`controllers/ipListController.js` 的入参守卫、
 * `docs/generate.js` 的两处文档 `enum`。副本今天内容完全相同 ⇒ 全仓测试全绿，
 * 失效方式是"加一档（比如灰名单）的那一天错"，三种分叉三种症状：
 *   - 只改 constants：路由 `isIn` 先 400 掉新值，schema 永远收不到，新档实际不可用；
 *   - 只改 schema：校验放行但 `save()` 抛 `ValidationError`
 *     （`insertMany({ordered:false})` 下表现为静默丢行）；
 *   - 只改生成器：只有对外文档漂移，**没有任何用例会红**（文档不是运行时）。
 *
 * 口径照搬本仓已建立的家族规范：`constants/audit.js`、`constants/permission.js`——
 * 值只有一份，其余位置一律引用。对账用例见
 * `src/tests/constants/permissionStatusSingleSource.test.js` 的同类结构。
 *
 * 语义（不是顺序敏感的枚举，别当等级用）：
 *   black = 拦截；white = 放行，且豁免黑名单与限流。
 *   加入黑名单时若已在白名单会被拒绝，见 ipListController 的同名守卫。
 */
const IP_LIST_TYPES = ['black', 'white'];

module.exports = { IP_LIST_TYPES };
