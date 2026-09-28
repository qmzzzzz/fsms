/**
 * 报警域取值清单的单一来源（F-142）
 *
 * 整改前三组值各有 3~5 份手写副本，分属四个文件：
 *   - level（4 档）：models/FireAlarm.js 的 schema enum、routes/alarmRoutes.js 的
 *     query 校验器与 body 校验器、docs/generate.js 的 query 参数与 requestBody 属性；
 *   - alarmType（6 档）：model、alarmRoutes 的两处 isIn、generate.js；
 *   - status（5 档）：model、alarmRoutes 的 query 校验器、generate.js。
 * 副本不会同步，只会各写各的——最坏症状不是「校验不严」而是**清单窄于 schema**：
 * 给 FireAlarm.level 加第 5 档后，模型存得进去、路由却以「无效的报警级别」400 拒掉，
 * 且只有走到那条路由的测试会红（清单本身无人对账）。
 *
 * 约定与本目录其他文件一致（constants/audit.js、constants/permission.js、
 * constants/ipList.js）：**由本文件提供清单，model 的 enum 指过来**，
 * 校验器与 OpenAPI 生成器再引用同一份。本文件不是「看起来像集中管理」的零引用声明——
 * 那种伪枚举正是 utils/constants.js 头部记录过的 drift 源，已在 E-05 轮删除。
 * 判定标准：删掉本文件后如果 model 无值可指，它就是事实来源；
 * 如果只是给 model 复制一份「说明」，它就是待删的伪枚举。
 *
 * 顺序即文档顺序（OpenAPI enum 与前端下拉按此序展示），新增档位一律追加在尾部。
 */

// 报警级别：info → warning → critical → emergency 严重度递增
const ALARM_LEVELS = ['info', 'warning', 'critical', 'emergency'];

// 报警来源类型
const ALARM_TYPES = [
  'smoke', // 烟雾报警
  'temp_abnormal', // 温度异常
  'manual_button', // 手动按钮
  'phone_report', // 电话报警
  'patrol_find', // 巡检发现
  'other', // 其他
];

// 报警处理状态（默认 pending，状态机见 services/alarmService.js 的转换写点）
const ALARM_STATUSES = ['pending', 'processing', 'resolved', 'false_alarm', 'cancelled'];

// 报警原因（PUT /api/alarms/:id/resolve 的 cause 字段）。
// F-142 收敛三组清单时漏扫了这一组：它当时只写在 models/FireAlarm.js 的 schema enum 里，
// 路由校验器与文档生成器各抄一份字面量——给 schema 追加一档，路由会先 400 拒掉它，
// 而对外文档仍在推荐那一档，属同一族「清单漂移」。
const ALARM_CAUSES = ['fire', 'false_alarm', 'equipment_fault', 'test', 'unknown'];

module.exports = { ALARM_LEVELS, ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES };
