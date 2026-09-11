/**
 * 业务时区单一声明（P3-18）
 *
 * 问题：同一个「今天」在仓库里有两套算法：
 *   - 仪表盘的今日边界用 `new Date(y, m-1, d)` —— 服务器本地时区
 *   - byDay 聚合用 `$dateToString` + `timezone: '+08:00'` —— 硬编码东八区
 * 容器通常跑 UTC，于是「今日报警数」按 UTC 天算、趋势图按东八区天算，
 * 两个数字在 UTC 的 16:00-24:00（东八区次日 0-8 点）必然对不上，
 * 且无人能从代码里看出哪个才是业务口径。
 *
 * 这里把业务时区收敛为唯一声明：
 *   - BUSINESS_TIMEZONE：IANA 名称，供 Intl / MongoDB $dateToString 使用
 *   - businessDayBounds()：取业务时区「某一天」对应的 UTC 起止瞬间
 * 两者都读同一个 env（TZ_BUSINESS），不再各自兜底。
 */

// IANA 时区名。MongoDB 的 $dateToString / $hour 均接受 IANA 名称，
// 优于 '+08:00' 这类固定偏移（后者不承载夏令时规则，跨区部署时无法正确迁移）
const BUSINESS_TIMEZONE = process.env.TZ_BUSINESS || 'Asia/Shanghai';

/**
 * 取业务时区下某个日期的 y/m/d 分量
 * @param {Date} [at=new Date()] 参考时刻
 * @returns {{year: number, month: number, day: number, dateStr: string}}
 */
const businessDateParts = (at = new Date()) => {
  // en-CA 的 formatToParts 输出稳定的 YYYY-MM-DD 分量，避免手工解析本地化字符串
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: BUSINESS_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(at);
  const pick = (type) => Number(parts.find((p) => p.type === type)?.value);
  const year = pick('year');
  const month = pick('month');
  const day = pick('day');
  const pad = (n) => String(n).padStart(2, '0');
  return { year, month, day, dateStr: `${year}-${pad(month)}-${pad(day)}` };
};

/**
 * 业务时区某一天对应的 UTC 起止瞬间
 *
 * 实现要点：先按「把该日期当成 UTC 零点」取一个基准，再用该时刻在业务时区的
 * 实际偏移做反向修正。不能直接 `new Date(y, m-1, d)`——那是服务器本地时区，
 * 正是本项修复要消除的假设。
 *
 * @param {string} [dateStr] YYYY-MM-DD；缺省取业务时区的今天
 * @returns {{start: Date, end: Date, dateStr: string}} start 含当日 00:00:00.000，end 含 23:59:59.999
 */
const businessDayBounds = (dateStr) => {
  const day =
    dateStr && /^\d{4}-\d{2}-\d{2}$/.test(dateStr) ? dateStr : businessDateParts().dateStr;

  // 该日期在业务时区的 00:00 对应的 UTC 时刻：
  // 以 UTC 零点为试探值，计算它在业务时区显示的钟点差，再回退相应毫秒数
  const probe = new Date(`${day}T00:00:00Z`);
  const shown = new Intl.DateTimeFormat('en-CA', {
    timeZone: BUSINESS_TIMEZONE,
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(probe);
  const num = (type) => Number(shown.find((p) => p.type === type)?.value);
  // shown 表示 probe 这一 UTC 瞬间在业务时区的墙上时间
  const shownUtcMs = Date.UTC(
    num('year'),
    num('month') - 1,
    num('day'),
    num('hour') % 24,
    num('minute'),
    num('second')
  );
  const offsetMs = shownUtcMs - probe.getTime();

  const start = new Date(probe.getTime() - offsetMs);
  const end = new Date(start.getTime() + 24 * 60 * 60 * 1000 - 1);
  return { start, end, dateStr: day };
};

/**
 * 「非常规时间」判定的单一声明（P3-7 / P3-18）
 *
 * 原先同一语义散落三处且口径不一：
 *   AuditLog.detectAnomalies  → hour < 6 || hour >= 23
 *   securityAlert.checkUnusualTime → hour < 6 || hour >= 22
 *   behaviorBaseline          → hour < 6 || hour >= 22
 * 报表与告警因此对同一批记录给出不同数字。此处收敛为唯一阈值。
 */
const OFF_HOURS_START = 22; // 含：22 点起算非常规
const OFF_HOURS_END = 6; // 不含：6 点起恢复常规

/**
 * 取某时刻在业务时区的小时数（0-23）
 * @param {Date|string|number} at
 * @returns {number}
 */
const businessHour = (at = new Date()) => {
  const hourStr = new Date(at).toLocaleString('en-GB', {
    timeZone: BUSINESS_TIMEZONE,
    hour12: false,
    hour: 'numeric',
  });
  // en-GB 在 24 点会输出 '24'，取模归一到 0
  return parseInt(hourStr, 10) % 24;
};

/**
 * 是否处于非常规时间（业务时区）
 * @param {Date|string|number} at
 * @returns {boolean}
 */
const isOffHours = (at = new Date()) => {
  const hour = businessHour(at);
  return hour < OFF_HOURS_END || hour >= OFF_HOURS_START;
};

module.exports = {
  BUSINESS_TIMEZONE,
  businessDateParts,
  businessDayBounds,
  businessHour,
  isOffHours,
  OFF_HOURS_START,
  OFF_HOURS_END,
};
