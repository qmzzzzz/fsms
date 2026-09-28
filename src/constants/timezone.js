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
//
// 这里的 trim 不是美化，是为了和启动闸门同口径（实测两条分叉，见
// src/tests/constants/tzBusinessEnvNormalization.test.js）：
// `config/validate.js` 的 collectTimezoneErrors 先 trim 再构造 Intl.DateTimeFormat，
// 而本行原先直接用裸 env ——
//   1) TZ_BUSINESS=' Asia/Shanghai'（带空格，yaml/env-file 里很容易出现）：
//      闸门放行，进程照启，直到**首个用户请求**走进 businessDateParts 才抛
//      RangeError: Invalid time zone specified——正是闸门注释自称"避免「校验通过
//      但运行期仍抛」"的那个结果，当时的注释承诺是假的。
//   2) TZ_BUSINESS='   '（只有空格）：更糟。`'   ' ||` 判真，连 'Asia/Shanghai'
//      兜底都不生效 ⇒ 模块加载期 100% 抛，而闸门把纯空格当作"未配置"放行。
// 归一化只放在消费侧（本行），不把闸门改成"不 trim"：这样闸门"构造即校验"的
// 判据重新等价于运行期，两处任何一处丢掉 trim 都会被上面那条用例判红。
const BUSINESS_TIMEZONE = (process.env.TZ_BUSINESS || '').trim() || 'Asia/Shanghai';

/**
 * 取业务时区下某个日期的 y/m/d 分量
 * @param {Date|string|number} [at=new Date()] 参考时刻
 * @returns {{year: number, month: number, day: number, dateStr: string}}
 */
const businessDateParts = (at = new Date()) => {
  // 复用 DAY_PARTS_FMT（en-CA 的 formatToParts，输出稳定的 YYYY-MM-DD 分量）：
  // 模块内只留这一枚 Intl 构造，时区与 hourCycle 只声明一次（F-198，原先本函数
  // 自建一枚只有 y/M/d 的 formatter，与下面 localDateOf/offsetAt 用的那枚分叉）。
  const p = partsOf(at);
  return {
    year: Number(p.year),
    month: Number(p.month),
    day: Number(p.day),
    dateStr: `${p.year}-${p.month}-${p.day}`,
  };
};

/**
 * 某一刻在指定时区的墙上时间分量（formatter 复用，同一时区一次构造多次取值）
 *
 * formatter 按时区缓存：报表接口允许前端传浏览器所在时区（IANA），时区串是
 * 客户端可控输入，缓存必须设上限——否则轮换时区串即可驱动 Intl 构造器撑爆内存
 * （与 securityAlert.alertRateLimit 同一条"容量必须有界"的纪律）。
 */
const DAY_PARTS_FMT_CACHE_LIMIT = 32;
const dayPartsFmtCache = new Map();
const dayPartsFmt = (timeZone) => {
  let fmt = dayPartsFmtCache.get(timeZone);
  if (!fmt) {
    if (dayPartsFmtCache.size >= DAY_PARTS_FMT_CACHE_LIMIT) dayPartsFmtCache.clear();
    fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone,
      hour12: false,
      // 时轮必须显式钉住，两枚选项各挡一种实测形状（本机 ICU 探针）：
      //   只留 hour12:false（丢掉本行）⇒ '00'，当前构建安全，但换构建可落到 h24 ⇒ 午夜输出 '24'；
      //   两枚都丢 ⇒ en-CA 直接走 h12，午夜输出 '12'——offsetAt 会把业务日界算偏 12 小时，
      //   同时 businessHour 读成 12 让 isOffHours 在午夜整点判成"常规时间"（漏报非常规时间告警）。
      // 判据由 src/tests/constants/businessHourSingleSource.test.js 的午夜臂钉住。
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    dayPartsFmtCache.set(timeZone, fmt);
  }
  return fmt;
};

const partsOf = (instantMs, timeZone = BUSINESS_TIMEZONE) =>
  dayPartsFmt(timeZone)
    .formatToParts(new Date(instantMs))
    .reduce((acc, p) => {
      acc[p.type] = p.value;
      return acc;
    }, {});

/** 该 UTC 瞬间在指定时区属于哪一天（YYYY-MM-DD） */
const localDateOf = (instantMs, timeZone = BUSINESS_TIMEZONE) => {
  const p = partsOf(instantMs, timeZone);
  return `${p.year}-${p.month}-${p.day}`;
};

/** 该 UTC 瞬间的墙上时间相对 UTC 的偏移（把墙上时间当 UTC 读回来即得偏移） */
const offsetAt = (instantMs, timeZone = BUSINESS_TIMEZONE) => {
  const p = partsOf(instantMs, timeZone);
  const shownUtcMs = Date.UTC(
    Number(p.year),
    Number(p.month) - 1,
    Number(p.day),
    // h24 构建下午夜会输出 '24'，取模归零；日期分量同批输出，故不影响 localDateOf
    Number(p.hour) % 24,
    Number(p.minute),
    Number(p.second)
  );
  return shownUtcMs - instantMs;
};

/**
 * 业务时区某一天 00:00 对应的 UTC 瞬间 = 「本地日期等于该日的最小瞬间」
 *
 * 不能直接 `new Date(y, m-1, d)`——那是服务器本地时区，正是本项修复要消除的假设。
 *
 * 为什么一次偏移修正不够：夏令时切换日一天有两个偏移，而我们要的是
 * **本地零点那一刻**的偏移。实测（本机 ICU）用 UTC 零点做一次性修正会在
 * "切换落在本地凌晨到正午之间"的区把日界算晚一小时：
 *   Pacific/Auckland 2024-04-07（NZDT→NZST 于 03:00）：探针 04-07T00:00Z 的墙上时间
 *   已是 +12，于是 start=04-06T12:00Z＝本地 01:00 ⇒ 本地 00:00–01:00 这一小时
 *   既被前一天 25h 窗口的 end 覆盖（重复计数），又不属于本窗口（自身缺 1h）。
 * 但也不能简单迭代到不动点——"本地零点不存在"的区会两值振荡：
 *   America/Havana 2024-03-10 本地 00:00→01:00，第一个候选 05:00Z 已经正确，
 *   再修正一次会跳到前一天 23:00。
 * 所以用"候选 + 极值判据"：反复修正产生候选，返回**第一个满足
 * `本地日期===该日 且 减 1ms 已属前一天`** 的。该判据定义的是唯一瞬间，
 * 因此候选里至多一个成立，取第一个即等于取最小值；无 DST 的区第一轮就中。
 */
const utcStartOfBusinessDay = (day, timeZone = BUSINESS_TIMEZONE) => {
  const probeMs = new Date(`${day}T00:00:00Z`).getTime();
  const isStartOfDay = (t) =>
    localDateOf(t, timeZone) === day && localDateOf(t - 1, timeZone) !== day;
  let cur = probeMs - offsetAt(probeMs, timeZone);
  for (let i = 0; i < 4; i += 1) {
    if (isStartOfDay(cur)) return new Date(cur);
    cur = probeMs - offsetAt(cur, timeZone);
  }
  // 兜底：候选里没有一个满足极值判据（本机 ICU 实测不会走到，全年 6 区扫描恒有解）
  // ⇒ 退回最后一次修正值，行为不劣于修前的一次性偏移。
  return new Date(cur);
};

/**
 * 非法日历日回夹到「当月最后一天」
 *
 * `new Date('2026-04-31T…')` 不会报错，而是**前滚**成 05-01；于是
 * `endDate=2026-04-31` 的区间实际含了 5 月 1 日全天，报表数字与用户输入的
 * 月份口径不一致（且 `dateStr` 会回显一个不存在的日期）。
 * 人的直觉里"4 月 31 日"就是"四月底"，所以按当月最后一天回夹：绝不会把窗口
 * 扩到下一个自然月。合法日期（含闰年 02-29）原样返回。
 * 只使用 UTC 构造/取值：本地时区口径由 utcStartOfBusinessDay 负责，见其注释。
 */
const clampToRealCalendarDay = (day) => {
  const [y, m, d] = day.split('-').map(Number);
  const last = new Date(Date.UTC(y, m, 0)).getUTCDate();
  if (d <= last) return day;
  return `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(last).padStart(2, '0')}`;
};

/**
 * 业务时区某一天对应的 UTC 起止瞬间
 *
 * @param {string} [dateStr] YYYY-MM-DD；缺省取业务时区的今天
 * @returns {{start: Date, end: Date, dateStr: string}} start 含当日 00:00:00.000，end 含 23:59:59.999
 *
 * 【end 必须用「次日的 start − 1ms」，不能用 start + 24h】
 * TZ_BUSINESS 是可配成任意 IANA 区的（validate.js 还专门校验它是合法 IANA 名），
 * 于是有夏令时的区每年两次失真：
 *   春季提前日只有 23 小时 → +24h 会越过次日零点 1 小时，"今日"窗口与次日重叠，
 *     仪表盘今日计数与按天聚合把同一批记录算两次；
 *   秋季回拨日有 25 小时 → +24h 差 1 小时才到次日零点，中间那 1 小时的记录
 *     既不属于昨天也不属于今天，从按天聚合里凭空消失。
 * 实测（America/Los_Angeles，2026 全年逐日）失配的正好是 3/8(-1h 重叠) 与 11/1(+1h 空洞)
 * 两天。取"次日零点 − 1ms"则两种情况都自动正确，且相邻日首尾相接成为恒等式。
 * 日期 +1 天走 UTC 日历（12:00Z 处加 24h 再取日期），不受本机时区与夏令时影响。
 */
const businessDayBounds = (dateStr) => zonedDayBounds(BUSINESS_TIMEZONE, dateStr);

/**
 * 任意 IANA 时区「某一天」对应的 UTC 起止瞬间（报表接口的浏览器时区口径）
 *
 * 与 businessDayBounds 同一条 DST 安全算法（见其注释），差别只在时区来自
 * 参数而非配置：前端把 `Intl.DateTimeFormat().resolvedOptions().timeZone`
 * 原样传上来，"今日"按**浏览器**所在时区的本地自然日计算——东八区管理员的
 * "今天"与纽约终端的"今天"各自正确，夏令时切换日由"次日 start − 1ms"的
 * 构造自动兼容（23/25 小时日都不重叠不空洞）。
 *
 * @param {string} timeZone IANA 时区名（调用方须先验证合法性，非法名 Intl 会抛 RangeError）
 * @param {string} [dateStr] YYYY-MM-DD；缺省取该时区的今天
 * @returns {{start: Date, end: Date, dateStr: string}} start 含当日 00:00:00.000，end 含 23:59:59.999
 */
const zonedDayBounds = (timeZone, dateStr) => {
  const day = clampToRealCalendarDay(
    dateStr && /^\d{4}-\d{2}-\d{2}$/.test(dateStr) ? dateStr : localDateOf(Date.now(), timeZone)
  );

  const start = utcStartOfBusinessDay(day, timeZone);
  const nextDay = new Date(new Date(`${day}T12:00:00Z`).getTime() + 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10);
  const end = new Date(utcStartOfBusinessDay(nextDay, timeZone).getTime() - 1);
  return { start, end, dateStr: day };
};

/**
 * 业务时区「本月 1 日 00:00」对应的 UTC 瞬间
 *
 * 「本月新增」这类月窗口若用 `setDate(1) + setHours(0,0,0,0)` 计算，取的是服务器
 * 本地时区：容器跑 UTC 时，业务时区每月 1 日 00:00–08:00 之间产生的记录会被算进
 * 上个月，而同一看板里按 businessDayBounds 统计的「今日」却是业务时区的——两个
 * 数字口径互相矛盾。月窗口与日窗口必须同源，所以在这里一次声明，各处只调用。
 *
 * @param {Date} [at=new Date()] 参考时刻
 * @returns {Date} 业务时区当月 1 日 00:00:00.000 对应的 UTC 瞬间
 */
const businessMonthStart = (at = new Date()) => {
  const { year, month } = businessDateParts(at);
  return businessDayBounds(`${year}-${String(month).padStart(2, '0')}-01`).start;
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
  // 与 localDateOf/offsetAt 同一枚 formatter（F-198）：原实现走
  // toLocaleString('en-GB', { hour12:false, hour:'numeric' }) 再 parseInt——parseInt
  // 解析的是本地化字符串，正是本模块在 businessDateParts 里点名要避免的写法；一旦某套
  // locale 数据把日期分量排在小时前面（'21/08/2026, 03:00:00'），parseInt 取到的就是
  // 「日」21，而 businessHour 的下游是 securityAlert 的「非常规时间」告警判定，
  // 3 点会被静默判成 21 点（误报/漏报都不会有用例变红）。
  // DAY_PARTS_FMT 已把 hourCycle 钉成 h23，午夜读数就是 '00'；取模留着，作为换构建时
  // 落到 h24（午夜输出 '24'）的兜底——否则 0 点会算成 24 点，isOffHours 在午夜整点翻转。
  return Number(partsOf(at).hour) % 24;
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
  businessMonthStart,
  businessHour,
  isOffHours,
  OFF_HOURS_START,
  OFF_HOURS_END,
  clampToRealCalendarDay,
  // 报表接口的浏览器时区口径（任意 IANA 区的 DST 安全日界）
  zonedDayBounds,
};
