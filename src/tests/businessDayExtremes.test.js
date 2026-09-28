/**
 * 业务日窗口必须是"该业务日的极值区间"（防另一类错法：整体平移）
 *
 * 姊妹文件 `zzqoder_timezoneDstBoundary.test.js` 钉的是**首尾相接**
 * （`end + 1ms === 次日 start`，LA 2026 全年逐日）。那条判据有个盲区：
 * 如果 `utcStartOfBusinessDay` 把整天的边界都算晚了一小时，
 * 相邻日依然严丝合缝，而"今日报警数"会少算/多算一小时 —— 平移不破坏邻接。
 *
 * 这种偏移在真实配置里可达：`TZ_BUSINESS` 允许任意 IANA 区
 * （`config/validate.js` 专门校验它必须是合法 IANA 名），而有些区的夏令时切换
 * 正好在**午夜**：`America/Havana` 2024-03-10 本地 00:00→01:00，
 * 那一天的"本地 00:00"根本不存在。正确实现在那里给出的就是 01:00Z-偏移那个瞬间。
 *
 * 所以判据写成极值形式而不是"等于 00:00"：
 *   start = 属于该业务日的**最小**瞬间（start-1ms 已属前一天）
 *   end   = 属于该业务日的**最大**瞬间（end+1ms 已属后一天）
 * 午夜切换区同样成立，而任何常数级偏移都会在这里转红。
 * 覆盖 6 个区 × 全年逐日（含 2024 闰年、南半球反向夏令时、
 * Australia/Lord_Howe 的**半小时**夏令时、Pacific/Kiritimati 的 UTC+14 极端偏移）。
 */

const loadTz = (tz) => {
  const saved = process.env.TZ_BUSINESS;
  jest.resetModules();
  process.env.TZ_BUSINESS = tz;
  let mod;
  jest.isolateModules(() => {
    mod = require('../constants/timezone');
  });
  if (saved === undefined) delete process.env.TZ_BUSINESS;
  else process.env.TZ_BUSINESS = saved;
  return mod;
};

const HOUR = 60 * 60 * 1000;

const nextDateStr = (dateStr) => {
  const d = new Date(`${dateStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
};

/** 某个瞬间在该时区属于哪一个业务日（YYYY-MM-DD），formatter 复用以免测试自身变成性能样本 */
const dayLabelOf = (tz) => {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
  return (instant) => {
    const p = fmt.formatToParts(instant).reduce((acc, x) => ({ ...acc, [x.type]: x.value }), {});
    return `${p.year}-${p.month}-${p.day}`;
  };
};

const eachDay = (year, fn) => {
  let cursor = `${year}-01-01`;
  const stop = `${year}-12-31`;
  for (;;) {
    fn(cursor);
    if (cursor === stop) return;
    cursor = nextDateStr(cursor);
  }
};

describe('zzqoder 业务日窗口的极值语义（跨 6 个区全年逐日）', () => {
  afterAll(() => {
    loadTz('Asia/Shanghai');
  });

  const ZONES = [
    ['默认生产口径（无夏令时）', 'Asia/Shanghai', '2026'],
    ['北美双向夏令时 + 闰年', 'America/Los_Angeles', '2024'],
    ['南半球（夏令时方向相反）', 'Pacific/Auckland', '2024'],
    ['午夜切换（3/10 本地 00:00 不存在）', 'America/Havana', '2024'],
    ['UTC+14 极端偏移', 'Pacific/Kiritimati', '2024'],
    ['半小时夏令时 +10:30→+11:00', 'Australia/Lord_Howe', '2024'],
  ];

  test.each(ZONES)('%s：%s 全年每一天都满足极值判据', (_label, tz, year) => {
    const { businessDayBounds } = loadTz(tz);
    const dayOf = dayLabelOf(tz);
    const violations = [];

    eachDay(year, (dateStr) => {
      const { start, end } = businessDayBounds(dateStr);
      if (dayOf(start) !== dateStr) {
        violations.push({ dateStr, why: `start 落在别的日子（${dayOf(start)}）` });
      }
      if (dayOf(new Date(start.getTime() - 1)) === dateStr) {
        violations.push({ dateStr, why: 'start 偏晚：前一天最后一毫秒仍属本日' });
      }
      if (dayOf(end) !== dateStr) {
        violations.push({ dateStr, why: `end 落在别的日子（${dayOf(end)}）` });
      }
      if (dayOf(new Date(end.getTime() + 1)) === dateStr) {
        violations.push({ dateStr, why: 'end 偏早：本日后一毫秒仍属本日' });
      }
    });

    expect(violations).toEqual([]);
  });

  test('前提自证：样本里真的有夏令时切换日（否则以上只是在测无切换区）', () => {
    const dayLengths = (tz, year) => {
      const { businessDayBounds } = loadTz(tz);
      const set = new Set();
      eachDay(year, (dateStr) => {
        const { start, end } = businessDayBounds(dateStr);
        set.add((end.getTime() - start.getTime()) / HOUR);
      });
      return set;
    };

    const la = dayLengths('America/Los_Angeles', '2024');
    const auckland = dayLengths('Pacific/Auckland', '2024');
    const howe = dayLengths('Australia/Lord_Howe', '2024');
    const shanghai = dayLengths('Asia/Shanghai', '2024');

    // 存在非 24 小时的日子 = 样本里确实有切换日；量级也必须在合理区间内
    expect([...la].some((h) => h !== 24)).toBe(true);
    expect([...auckland].some((h) => h !== 24)).toBe(true);
    expect(Math.min(...la)).toBeGreaterThanOrEqual(22);
    expect(Math.max(...la)).toBeLessThanOrEqual(25);
    // 豪勋爵岛的夏令时是**半小时**（+10:30↔+11:00）⇒ 23.5h / 24.5h 两种日长必须出现
    // （实测集合 = {24 - 1ms, 23.5h - 1ms, 24.5h - 1ms}；若实现按整小时处理就会缺）
    expect([...howe]).toEqual(
      expect.arrayContaining([(23.5 * HOUR - 1) / HOUR, (24.5 * HOUR - 1) / HOUR])
    );
    // 默认区恒 23 小时差值（24h - 1ms）：反向保护，不许为了过极值判据放宽窗口
    expect([...shanghai]).toEqual([(24 * HOUR - 1) / HOUR]);
  });

  test('午夜切换日的具体形状：该日本地不存在 00:00，窗口必须从 01:00 起算（Havana 2024-03-10）', () => {
    const { businessDayBounds } = loadTz('America/Havana');
    const dayOf = dayLabelOf('America/Havana');
    const { start, end } = businessDayBounds('2024-03-10');
    const next = businessDayBounds('2024-03-11');

    // 本日长度 23 小时（午夜直接跳到 01:00）
    expect(end.getTime() - start.getTime()).toBe(23 * HOUR - 1);
    // start 是"属于 3/10 的最小瞬间"：早 1ms 已属 3/9
    expect(dayOf(start)).toBe('2024-03-10');
    expect(dayOf(new Date(start.getTime() - 1))).toBe('2024-03-09');
    // 邻接依然成立（与姊妹文件的判据在此重合，两个方向都锁住）
    expect(end.getTime() + 1).toBe(next.start.getTime());
    // 且本地钟面此时是 01:00 而不是 00:00 —— 这条钉住"极值判据"在缺小时时的真实含义
    const hhmm = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'America/Havana',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(start);
    expect(hhmm).toBe('01:00');
  });
});
