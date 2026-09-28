/**
 * 巡检（Inspection）域的枚举单一事实来源
 *
 * 与 constants/audit.js **分域**，不合并：两边取值今天恰好都是
 * low/medium/high/critical，语义却不同（审计记录的风险等级 vs 巡检发现的严重程度）。
 * 合并成一份之后，"只给审计加一档"会连带把巡检的校验也放宽（反之亦然），
 * 而两个域各自的可证伪门禁就再也说不清自己在钉什么。
 * 分域口径与并行会话在 handoff wave21 §4 确认过。
 *
 * 巡检状态的分档带（F-151）由下面的 `INSPECTION_STATUSES` **派生**，不再各写一份字面量：
 * 本域确实有"某几档及以上"的读取方（谁能开工、谁还算未开工、删除成员要释放哪些指派），
 * 而它们都是全集的子集切片。做法与 audit 域一致（见 constants/audit.js 的 riskLevelsAtLeast），
 * 差别只在巡检按"是否终态"划分而非按序取后缀。
 */

const INSPECTION_FINDING_SEVERITIES = ['low', 'medium', 'high', 'critical'];

/**
 * 巡检类型（F-150）
 *
 * 整改前这个 6 值清单在 5 处各写一遍：模型 schema enum、路由的 query 校验器 +
 * 两个 body 校验器，以及 `src/docs/generate.js` 的 OpenAPI 属性。
 * 副本飘了以后没有一处会红：文档侧原先只写 `type: string` 不带 enum，
 * 而路由一直 `.isIn(...)` ⇒ 照文档传 `inspectionType=whatever` 得到一个 400，
 * 契约上却宣称任意字符串都行。
 */
const INSPECTION_TYPES = ['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'];

/**
 * 巡检状态全集
 *
 * `overdue` 是**被调度器真实写入**的一档（`services/deviceReminder.js` 把 planEndTime 已过
 * 且仍 pending/in_progress 的计划置成它，看板按它统计超期数，`InspectionService` 还特意把
 * 它留在"可开始/可提交"集合里）。整改前 `src/docs/generate.js` 的 status query 枚举只有 4 档、
 * 独缺 `overdue` ⇒ 对外契约上"超期"这种**唯一带时效危害的状态根本筛不出来**，
 * 而后门里它是合法值——文档比运行时窄，比宽更难被发现。
 */
const INSPECTION_STATUSES = ['pending', 'in_progress', 'completed', 'overdue', 'cancelled'];

/**
 * 终态（F-151）：只有这两档是"不能再往里干活"的。
 * 判据是**划分**而不是清单——`INSPECTION_OPEN_STATUSES` 由全集减去本表派生，
 * 所以给 `INSPECTION_STATUSES` 加一档时不必再改第二处（这是收益）。
 * 但别把这句话读成"加一档会被门禁逼着回答它是终态吗"：M1 实测追加 'archived' 时
 * 派生式把它自动吸进 OPEN，**划分用例照绿**，红的是"四条档带取值逐一钉住"那行
 * （它才是要人显式表态的地方）与 F-150 的文档/产物枚举行；
 * 划分用例真正抓的是档带越出全集（M4 实测）。口径与常量侧写法闸门见
 * tests/constants/inspectionEnumSingleSource.test.js 同名分组（M6 补）。
 */
const INSPECTION_TERMINAL_STATUSES = ['completed', 'cancelled'];

/**
 * 仍开放的档位 = 全集 - 终态 ⇒ ['pending', 'in_progress', 'overdue']
 *
 * 用在删除成员的指派级联（`userService.releaseOpenAssignments`）。整改前那里写的是
 * 字面量 `['pending', 'in_progress']`，**独缺 `overdue`**，而 `overdue` 恰恰是最需要
 * 释放的一档：调度器会把超期的 pending/in_progress 改写成 overdue，此时删掉唯一执行人，
 * 开工/提交的准入是「assignedTo 含操作者」或「assignedTo.0 不存在」——单元素幽灵数组
 * 两者都不满足 ⇒ 这条**超期**巡检再也开不了工也提交不了结果（`cancelInspection` 不卡执行人，
 * 于是唯一的出路是把一条可能真做过的消防巡检登记成"已取消"，合规记录被改写）。
 * 反向不扩：终态的指派是历史归责依据，级联不得改写（有用例钉住）。
 */
const INSPECTION_OPEN_STATUSES = INSPECTION_STATUSES.filter(
  (s) => !INSPECTION_TERMINAL_STATUSES.includes(s)
);

/**
 * 可被判定为"事实上逾期"的档位 = 开放档位里尚未标记 overdue 的那些
 * ⇒ ['pending', 'in_progress']
 *
 * 两处消费方必须同口径，此前各自写着字面量副本：
 *   - `deviceReminder.markOverdueInspections` 按它改写状态（已是 overdue 的不重复写）；
 *   - `reportDashboardService` 的超期统计按它算"事实逾期"（并集 `status:'overdue'`）。
 * 两边一旦不同，看板就会统计出调度器永不改写的超期数（或反过来漏计），
 * 而"漏计"在看板上表现为"没有超期"——一个静默的负结果。
 */
const INSPECTION_OVERDUE_MARKABLE_STATUSES = INSPECTION_OPEN_STATUSES.filter(
  (s) => s !== 'overdue'
);

// 可开工 / 可提交（InspectionService 的原子更新准入条件，F-151 收口为派生）：
// 开工 = 开放档位里还没开工的；提交 = 开放档位里已经开工的。overdue 两边都在，
// 因为它是**时间标记**不是工作流阶段（详见 InspectionService 原注释）。
const INSPECTION_STARTABLE_STATUSES = INSPECTION_OPEN_STATUSES.filter((s) => s !== 'in_progress');
const INSPECTION_SUBMITTABLE_STATUSES = INSPECTION_OPEN_STATUSES.filter((s) => s !== 'pending');

// 巡检执行结果（提交时 body('result') 的取值面；模型 schema 同一份）
const INSPECTION_RESULTS = ['normal', 'abnormal', 'partial'];

// 审核结论。整改前 services/InspectionService.js 里还有一份 `includes([...])` 手抄闸门，
// 与路由校验器同值不同源（F-137 那一族：闸门与白名单各写一遍，单侧加值即放行不落库）
const INSPECTION_REVIEW_RESULTS = ['approved', 'rejected'];

module.exports = {
  INSPECTION_FINDING_SEVERITIES,
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_TERMINAL_STATUSES,
  INSPECTION_OPEN_STATUSES,
  INSPECTION_OVERDUE_MARKABLE_STATUSES,
  INSPECTION_STARTABLE_STATUSES,
  INSPECTION_SUBMITTABLE_STATUSES,
  INSPECTION_RESULTS,
  INSPECTION_REVIEW_RESULTS,
};
