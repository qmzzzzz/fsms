/**
 * 权限/角色域的取值清单（单一事实来源）
 *
 * 为什么单独成文件（与 constants/audit.js 同理）：
 *   这三份清单此前各有 6/4/6 处**字面量副本**，分布在 Mongoose schema 的 `enum`、
 *   express-validator 的 `isIn(...)`、以及 OpenAPI 生成器里。副本的失效方式不是"现在错了"，
 *   而是"加一档的那一天错"：
 *     - 只改模型 ⇒ 路由校验先把新值 400 掉，模型永远收不到，新档位实际不可用；
 *     - 只改路由 ⇒ 校验放行、`insertMany`/`save` 抛 ValidationError；批量写入配
 *       `{ordered:false}` 时是**静默丢行**；
 *     - 两边都改、忘改文档 ⇒ 对外接口继续宣称旧集合（文档不是运行时，没有任何测试会红）。
 *   这正是本仓库 category/riskLevel 两条已经修过的同一族缺陷（见 constants/audit.js 头注释），
 *   所以对账口径也照搬：取值全集只有一份，其余位置一律引用。
 *
 * 不合并的边界（防被"顺手统一"）：
 *   User 的 status 是 ['active','inactive','locked']——多一档锁定语义，属**账号**域而非
 *   **资源启用**域。刻意不与此处共用一个常量：合并会把"用户被锁定"和"权限被停用"绑成
 *   同一份清单，任何一方加档都会误伤另一方。它的单一来源是
 *   `src/utils/constants.js` 的 `USER_STATUS`（models/User.js 的 enum、
 *   services/userService.js 的过滤白名单、userRoutes 的 isIn、OpenAPI 生成器都已改为引用它）。
 */

// 权限资源形态
const PERMISSION_TYPES = ['menu', 'button', 'api', 'data'];

// 权限所绑定的 HTTP 方法；'*' 是"不限方法"的哨兵值，不是通配符展开
const PERMISSION_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', '*'];

// Permission / Role 共用的启用-停用二态
const RESOURCE_STATUSES = ['active', 'inactive'];

module.exports = {
  PERMISSION_TYPES,
  PERMISSION_METHODS,
  RESOURCE_STATUSES,
};
