/**
 * 设备提醒档的唯一口径声明（与 dataScopeFields.js 同级：两者都是"口径"而非逻辑）。
 *
 * 背景：同一件事——"哪些设备算即将到期 / 已过期待维护"——在本仓有**五份**实现：
 *   DeviceService.getDeviceStats、DeviceService.getExpiringDevices、
 *   deviceReminder.getDeviceReminders、reportStatsService.getDeviceReportData、
 *   reportDashboardService（聚合 facet）。
 * 五份在两处彼此矛盾：
 *   ① 状态排除集：到期档有的排 scrapped、有的完全不排（已报废设备被当成"即将到期"送去换灭火器）；
 *      待维护档有的只排 maintenance、有的还排 scrapped（同一台报废设备在仪表盘计数、
 *      在提醒清单里却不出现，两个出口自相矛盾）。
 *   ② 窗口算法：`setDate(+30)`（日历日）与 `30*86400*1000`（定长毫秒）跨夏令时/31 天月份
 *      会差 1 小时到 1 天，边界上的设备在一处算"即将到期"、在另一处不算。
 * 这里把两件事收敛成一份声明，五个消费方只保留 countDocuments / find / facet 的形态差异。
 *
 * 另外补上此前**五个出口全部看不见**的一类（真实缺陷，不是重构副产品）：
 * 一台从未做过检查的设备 `nextCheckDate` 恒为 null——模型的排期钩子只在 `lastCheckDate`
 * 存在时才计算（FireDevice.pre('save')），而 `lastCheckDate` 既不在新建白名单也不在可更新字段里。
 * Mongo 的范围比较（`$lte`）不匹配缺失字段 ⇒ "没有任何排期"被读成"不需要排期"，
 * 一个装好五年、一次没检的灭火器在 stats/dashboard/reminders/expiring 四处全部隐身。
 * 零提醒即安全，是这类系统最危险的失败形态，因此单列 `unscheduled` / `expiryUnknown` 两档。
 *
 * 判据保持纯声明、无分支：档与档互斥（排期缺失与 `$lte now` 不可能同时命中），
 * 所以各档之和可以直接与 total 对齐做一致性断言。
 */

/** 报废即生命周期终点：不进到期/待维护任何一档 */
const SCRAPPED = 'scrapped';
/** 维护中的设备正在做，不重复催 */
const IN_MAINTENANCE = 'maintenance';

const ALERT_EXCLUDED_STATUS = Object.freeze([SCRAPPED]);
const MAINTENANCE_EXCLUDED_STATUS = Object.freeze([IN_MAINTENANCE, SCRAPPED]);

/** 到期提醒的默认窗口（天）；调用方可以传别的值，但算法只有一份 */
const DEFAULT_EXPIRING_DAYS = 30;

/**
 * 到期清单单次返回的条数上限（资源护栏，防止无界全库返回）。
 *
 * 上限本身不是问题，**静默**才是：本常量存在的一个原因就是让"清单会被截断"这件事
 * 在代码里有个名字，从而能被响应体引用（`DeviceService.getExpiringDevices` 的
 * `{devices,total}` 与控制器 `pagination.total`）。判据与用例：
 * `src/tests/controllers/deviceExpiringTruncation.test.js`（F-174）。
 * 与 `models/FireDevice.js:235`、`auditExportService.js:61`、
 * `reportWorkbookService.js:13` 同一条约定：截断必须可数，不能拿数组长度假装"这就是全部"。
 */
const EXPIRING_LIST_LIMIT = 50;

/**
 * 按日历日加天数（不是定长毫秒）：与 `setDate` 一致，
 * 使"30 天后"在任何时区规则下都指向同一日历日。
 * @param {Date} date
 * @param {number} days
 * @returns {Date}
 */
function addCalendarDays(date, days) {
  const next = new Date(date.getTime());
  next.setDate(next.getDate() + days);
  return next;
}

/**
 * 四档 + 两个"信息不全"档，全部返回可直接并入查询的 Mongo 条件片段。
 * @param {Date} now 判定时刻（同一次响应内必须只取一次，避免跨秒抖动）
 * @param {number} days 即将到期窗口
 */
function deviceAlertFilters(now, days = DEFAULT_EXPIRING_DAYS) {
  const windowEnd = addCalendarDays(now, days);
  return Object.freeze({
    /** 有效期已过但仍在册 */
    expired: Object.freeze({
      expiryDate: Object.freeze({ $lt: now }),
      status: Object.freeze({ $nin: ALERT_EXCLUDED_STATUS }),
    }),
    /** [now, now+days 日历日] 内到期 */
    expiringSoon: Object.freeze({
      expiryDate: Object.freeze({ $gte: now, $lte: windowEnd }),
      status: Object.freeze({ $nin: ALERT_EXCLUDED_STATUS }),
    }),
    /** 有排期且排期已过期，且当前不在维护中 */
    needMaintenance: Object.freeze({
      nextCheckDate: Object.freeze({ $lte: now }),
      status: Object.freeze({ $nin: MAINTENANCE_EXCLUDED_STATUS }),
    }),
    /** 根本没有排期（从未录入过检查日）：与 needMaintenance 互斥，单独成档 */
    needSchedule: Object.freeze({
      nextCheckDate: null,
      status: Object.freeze({ $nin: MAINTENANCE_EXCLUDED_STATUS }),
    }),
    /** 有效期未登记：既不算已过期也不算即将到期，但合规上必须可见 */
    expiryUnknown: Object.freeze({
      expiryDate: null,
      status: Object.freeze({ $nin: ALERT_EXCLUDED_STATUS }),
    }),
  });
}

/**
 * 「即将到期」窗口的天数归一——两个 HTTP 入口（`/devices/reminders`、
 * `/devices/expiring`）此前各写一份 `Math.min(365, Math.max(1, parseInt(days,10) || 30))`，
 * 其中 `|| 30` 把客户端显式提交的 `0` 翻译成默认值：请求要的是最窄窗口，
 * 拿回的却是 30 倍宽的集合，而且与不传参完全同形，调用方无从察觉。
 *
 * 规则按"**永不把请求放宽**"这一侧收口：
 *  - 可解析为整数 ⇒ 原样采用，负数收到 0（0 是"只看此刻"的下界，不是"未传"的哨兵）；
 *  - 不可解析（`abc` / 缺省）⇒ 回退默认 30 天。这条回退是**有意的既有行为**，
 *    与 `securityController.getUserActivity` 对 `days`/`limit` 的钳制同口径
 *    （那里注释写明是为了不让 NaN 直传查询），要不要改成 400 属对外契约变更，
 *    不在本函数里顺手改。
 *  - 上界 365 保持钳制而不是报错：它是资源护栏，且钳制方向是收窄不是放宽。
 *
 * @param {unknown} raw 查询参数原值
 * @param {number} [fallback] 不可解析时的默认窗口
 * @returns {number} 落在 [0, 365] 的整数天数
 */
function normalizeExpiringDays(raw, fallback = DEFAULT_EXPIRING_DAYS) {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(365, Math.max(0, parsed));
}

module.exports = {
  deviceAlertFilters,
  addCalendarDays,
  normalizeExpiringDays,
  DEFAULT_EXPIRING_DAYS,
  EXPIRING_LIST_LIMIT,
  ALERT_EXCLUDED_STATUS,
  MAINTENANCE_EXCLUDED_STATUS,
};
