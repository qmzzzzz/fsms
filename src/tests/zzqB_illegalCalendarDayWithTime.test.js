/**
 * 带时间后缀的"不存在的日历日"不得前滚进下一月/下一年
 *
 * `helpers.parseDateBoundary` 对 date-only 串走 `businessDayBounds`，后者用
 * `clampToRealCalendarDay` 把 `2026-04-31` 回夹成 `2026-04-30`——口径注释写得很清楚：
 * "人的直觉里 4 月 31 日就是四月底，绝不会把窗口扩到下一个自然月"。
 * 但这道闸门只挂在 date-only 分支上：同一意图换成带时间的写法
 * （`2026-04-31T10:00`、`2026-04-31 23:00`、`2026-04-31T00:00:00Z`）就绕过去了，
 * 落到 `new Date()` 的**前滚**语义：实测 `2026-04-31T10:00` → 5 月 1 日 10:00、
 * `2026-06-31T10:00` → 7 月 1 日、`2027-02-29T12:00` → 3 月 1 日。
 * 于是"四月报表"含 5 月 1 日——正是回夹要防的那件事，
 * 而且入参在 `isValidDateParam` 三道判据下**全部放行**（是字符串、非纯数字、能被 Date 解析）。
 * 前滚会跨出年的那些写法（`2026-12-32…`、`2026-13-01…`）实测 V8 直接判 Invalid Date，
 * 上游按 400 拒掉，与 date-only 分支同结论 ⇒ 不在本闸门射程内，本文件把它作为**前提**钉住。
 *
 * 修的方向与既有口径一致：**只回夹日期部分，时间部分原样保留**，
 * 因此合法串完全不受影响（`clampToRealCalendarDay` 对真实日历日是恒等变换），
 * 也就不存在"把 23:59 的终态时刻挪走"这类副作用。
 * 非零填充的带时间串（`2026-4-31T10:00`）不在处理范围：实测 V8 直接判 Invalid Date，
 * `isValidDateParam` 返回 false，上游已按 400 拒掉——这里把它当**前提**钉住，
 * 因为它一旦哪天变成可解析，本文件的闸门就会出现同一个洞。
 */
const { parseDateBoundary, isValidDateParam, buildDateRangeFilter } = require('../utils/helpers');
const { businessDayBounds } = require('../constants/timezone');
const { buildAuditQuery } = require('../utils/auditQuery');

const ms = (d) => d.getTime();
/** 业务时区某个自然日的起点（用它做"没有越到次月/次年"的判据，与本机时区无关） */
const dayStart = (day) => businessDayBounds(day).start;

describe('非法日历日 + 时间后缀：回夹到当月最后一天，时间部分保留', () => {
  test('月末非法日：与"手写最后一天同一时刻"逐毫秒相等，且不进入次月', () => {
    const bad = parseDateBoundary('2026-04-31T10:00:00', 'start');
    expect(bad).toEqual(parseDateBoundary('2026-04-30T10:00:00', 'start'));
    expect(ms(bad)).toBeGreaterThanOrEqual(ms(dayStart('2026-04-30')));
    expect(ms(bad)).toBeLessThan(ms(dayStart('2026-05-01')));
  });

  test('年内越月的每一格都回夹（6-31 / 11-31 / 2-31 同一判据，且不跨月）', () => {
    const arms = [
      ['2026-06-31T10:00:00', '2026-06-30T10:00:00', '2026-06-01', '2026-07-01'],
      ['2026-11-31T23:00:00', '2026-11-30T23:00:00', '2026-11-01', '2026-12-01'],
      ['2026-02-31T08:00:00', '2026-02-28T08:00:00', '2026-02-01', '2026-03-01'],
    ];
    for (const [bad, good, monthStart, nextMonthStart] of arms) {
      const parsed = parseDateBoundary(bad, 'end');
      expect(parsed).toEqual(parseDateBoundary(good, 'end'));
      // 上下界都用业务时区的首日零点：本机时区与 TZ_BUSINESS 不一致也不会误判
      expect(ms(parsed)).toBeGreaterThanOrEqual(ms(dayStart(monthStart)));
      expect(ms(parsed)).toBeLessThan(ms(dayStart(nextMonthStart)));
    }
  });

  test('与 date-only 分支的**拒绝面**也保持一致：日序 > 31 仍然判非法（不是静默回夹）', () => {
    // date-only 的闸门是 `1 <= dd <= 31` 再交给 clampToRealCalendarDay，
    // 所以 12-32 这类"日序本身越界"的值今天就是 400。带时间后缀必须同一结论，
    // 否则"回夹"会从校验漏洞变成对外契约变更（把 400 悄悄换成一个可用窗口）。
    expect(isValidDateParam('2026-12-32')).toBe(false);
    expect(isValidDateParam('2026-12-32T00:00:00')).toBe(false);
    expect(Number.isNaN(parseDateBoundary('2026-12-32T00:00:00', 'end').getTime())).toBe(true);
  });

  test('闰年判定按真实年份：2027-02-29 回夹 2 月底，2028-02-29（真闰日）原样', () => {
    expect(parseDateBoundary('2027-02-29T12:00:00', 'start')).toEqual(
      parseDateBoundary('2027-02-28T12:00:00', 'start')
    );
    expect(parseDateBoundary('2028-02-29T10:00:00', 'start')).toEqual(
      new Date('2028-02-29T10:00:00')
    );
  });

  test('分隔符与时区后缀的各种写法同一条闸门（空格形式 V8 也接受）', () => {
    for (const raw of [
      '2026-04-31T10:00',
      '2026-04-31T10:00:00',
      '2026-04-31 10:00:00',
      '2026-04-31T10:00:00Z',
      '2026-04-31 10:00:00Z',
    ]) {
      expect(isValidDateParam(raw)).toBe(true);
      // 只比"落在哪一天"：带 Z 的串本来就该保留 UTC 瞬间，不比时刻只比日期归属
      const parsed = parseDateBoundary(raw, 'start');
      expect(ms(parsed)).toBeLessThan(ms(dayStart('2026-05-01')));
      expect(ms(parsed)).toBeGreaterThanOrEqual(ms(dayStart('2026-04-29')));
    }
  });

  test('控制臂：合法时间串必须原样透传（不得被过度回夹挪走时刻）', () => {
    for (const raw of ['2026-04-30T10:00:00', '2026-12-31T23:59:59.999Z', '2026-01-01T00:00:00']) {
      expect(parseDateBoundary(raw, 'start')).toEqual(new Date(raw));
      expect(parseDateBoundary(raw, 'end')).toEqual(new Date(raw));
    }
  });

  test('date-only 既有口径不变：回夹 + 业务时区当日首尾', () => {
    expect(parseDateBoundary('2026-04-31', 'start')).toEqual(dayStart('2026-04-30'));
    expect(parseDateBoundary('2026-04-31', 'end')).toEqual(businessDayBounds('2026-04-30').end);
    expect(parseDateBoundary('2026-04-30', 'end')).toEqual(businessDayBounds('2026-04-30').end);
  });

  test('前提钉住：非零填充的带时间串在入口就被判为非法（本闸门只需管零填充形态）', () => {
    expect(isValidDateParam('2026-4-31T10:00:00')).toBe(false);
    expect(Number.isNaN(new Date('2026-4-31T10:00:00').getTime())).toBe(true);
  });
});

describe('消费方拿到的查询边界同样不越月（报表与审计两条链）', () => {
  test('buildDateRangeFilter：四月区间不得含五月', () => {
    const filter = buildDateRangeFilter('2026-04-01', '2026-04-31T23:00:00');
    expect(ms(filter.$gte)).toBeGreaterThanOrEqual(ms(dayStart('2026-04-01')));
    expect(ms(filter.$lte)).toBeLessThan(ms(dayStart('2026-05-01')));
  });

  test('buildAuditQuery：审计查询的 $lte 与列表侧同一口径（同一函数，两处入口）', () => {
    const { query } = buildAuditQuery({
      query: { startDate: '2026-04-01', endDate: '2026-04-31T23:00:00' },
    });
    expect(query.timestamp.$lte).toEqual(parseDateBoundary('2026-04-31T23:00:00', 'end'));
    expect(ms(query.timestamp.$lte)).toBeLessThan(ms(dayStart('2026-05-01')));
    expect(ms(query.timestamp.$gte)).toBeGreaterThanOrEqual(ms(dayStart('2026-04-01')));
  });
});
