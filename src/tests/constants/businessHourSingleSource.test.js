/**
 * 业务时区读数单源（第三轮审计 F-198）
 *
 * 缺陷面：constants/timezone.js 的头注释自称把「业务时区」收敛为唯一声明，但模块内实际
 * 有三套时区敏感的读数路径——
 *   businessDateParts 自建 en-CA formatter；
 *   DAY_PARTS_FMT 是 en-CA + hourCycle:'h23' 的复用 formatter；
 *   businessHour 用 toLocaleString('en-GB', {hour12:false, hour:'numeric'}) 再 parseInt。
 * 最后一处的 parseInt **解析的是本地化字符串**，正是本模块 businessDateParts 注释里点名
 * 要避免的写法（「避免手工解析本地化字符串」）。businessHour 的下游是 securityAlert.js:330
 * 的「非常规时间」判定：只要某套 ICU/locale 数据让 en-GB 的输出带上日期前缀
 * （'21/08/2026, 03:00:00'），parseInt 取到的就是「日」（21），3 点被判成 21 点 ⇒
 * 告警静默误报，且全仓不会有任何一处变红。
 *
 * 收口：businessHour / businessDateParts 都改用模块内已有的 partsOf（同一枚
 * DAY_PARTS_FMT），时区与 hourCycle 只声明一次。
 *
 * 门禁两面：
 *  ① 源码计数闸（跑注释遮蔽后的代码视图，F-128 同法）：Intl 构造点只允许 1 处、
 *     toLocale* 只允许 0 处；判据本身用合成源自证——数不出 2/1 的计数器是摆设。
 *  ② 行为面：期望值用**纯 UTC 算术**写死（不镜像模块的 Intl 选项），钉跨业务日界的
 *     (日期, 小时) 与「午夜不得读成 24」；再用第二个 TZ_BUSINESS 取值做差分，钉读数是
 *     跟着 BUSINESS_TIMEZONE 走的（硬编码 +8 在这一臂转红）。
 */

const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '../../constants/timezone.js'), 'utf8');

/** 去掉块注释与行注释，避免「注释里提了一句 Intl」被当成代码（F-128 同法） */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/([^:])\/\/.*$/gm, '$1');

const countIn = (src, re) => (stripComments(src).match(re) || []).length;

/** 在指定 TZ_BUSINESS 取值下重载 constants/timezone（BUSINESS_TIMEZONE 是模块加载期常量） */
const loadTimezone = (businessZone) => {
  const saved = process.env.TZ_BUSINESS;
  process.env.TZ_BUSINESS = businessZone;
  try {
    let mod;
    jest.isolateModules(() => {
      mod = require('../../constants/timezone');
    });
    return mod;
  } finally {
    if (saved === undefined) delete process.env.TZ_BUSINESS;
    else process.env.TZ_BUSINESS = saved;
  }
};

describe('业务时区读数收口到 DAY_PARTS_FMT 单源（F-198）', () => {
  test('计数判据自证：合成源里造出 2 处 Intl 构造 + 1 处 toLocaleString，必须分别数出 2 和 1', () => {
    const synth = [
      "const a = new Intl.DateTimeFormat('en-CA');",
      "const b = new Intl.DateTimeFormat('en-CA', { timeZone: 'UTC' });",
      '// new Intl.DateTimeFormat 出现在注释里不得计数',
      '/* new Intl.DateTimeFormat 出现在块注释里也不得计数 */',
      "d.toLocaleString('zh-CN', { hour12: false });",
    ].join('\n');
    expect(countIn(synth, /new Intl\.DateTimeFormat/g)).toBe(2);
    expect(countIn(synth, /\.toLocale(String|DateString|TimeString)\s*\(/g)).toBe(1);
  });

  test('模块内只允许一处 Intl 构造、零处 toLocale* 读数（多处＝各写各的时区口径）', () => {
    expect(countIn(SRC, /new Intl\.DateTimeFormat/g)).toBe(1);
    expect(countIn(SRC, /\.toLocale(String|DateString|TimeString)\s*\(/g)).toBe(0);
  });

  test('东八区读数：跨业务日界的小数/日期与午夜 hour 都为纯算术期望值', () => {
    const { businessHour, businessDateParts, isOffHours } = loadTimezone('Asia/Shanghai');
    // UTC 15:30 = 东八区 23:30；UTC 16:00 = 东八区次日 00:00（午夜）
    expect(businessHour('2026-08-20T15:30:00Z')).toBe(23);
    expect(businessHour('2026-08-20T16:00:00Z')).toBe(0); // hourCycle 若是 h24 会读成 24
    expect(businessDateParts(new Date('2026-08-20T15:59:59Z')).dateStr).toBe('2026-08-20');
    expect(businessDateParts(new Date('2026-08-20T16:00:00Z')).dateStr).toBe('2026-08-21');
    expect(businessDateParts(new Date('2026-08-20T16:00:00Z')).hour).toBeUndefined();
    // 告警窗口口径：22:00 起含、06:00 起不含（OFF_HOURS_START/END 单一声明）
    expect(isOffHours('2026-08-20T16:00:00Z')).toBe(true); // 业务 00:00
    expect(isOffHours('2026-08-20T14:00:00Z')).toBe(true); // 业务 22:00
    expect(isOffHours('2026-08-20T13:59:59Z')).toBe(false); // 业务 21:59:59
    expect(isOffHours('2026-08-20T22:00:00Z')).toBe(false); // 业务 06:00
  });

  test('差分臂：读数跟着 TZ_BUSINESS 走（硬编码 +8 在这一臂转红）', () => {
    const { businessHour, businessDateParts, isOffHours } = loadTimezone('UTC');
    expect(businessHour('2026-08-20T15:30:00Z')).toBe(15);
    expect(businessDateParts(new Date('2026-08-20T16:00:00Z')).dateStr).toBe('2026-08-20');
    // 同一切换瞬间在 UTC 业务区是常规时间（16:00），在东八区是次日 00:00（非常规）
    expect(isOffHours('2026-08-20T16:00:00Z')).toBe(false);
  });

  test('前提自证：两次加载拿到的 BUSINESS_TIMEZONE 确实不同（差分臂的地基）', () => {
    expect(loadTimezone('Asia/Shanghai').BUSINESS_TIMEZONE).toBe('Asia/Shanghai');
    expect(loadTimezone('UTC').BUSINESS_TIMEZONE).toBe('UTC');
  });
});
