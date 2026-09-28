'use strict';

/**
 * 日期参数口径：补零与否不得改变结果，非日期形态不得被"解析成功"
 *
 * 两条实测确认的缺陷（本轮修复）：
 *  ① `parseDateBoundary` 只对零填充的 `YYYY-MM-DD` 走业务时区，其余一律透传 `new Date()`。
 *     `TZ=UTC` 下 `'2026-08-01'` → `2026-07-31T16:00Z`（业务口径），
 *     而 `'2026-8-1'` → `2026-08-01T00:00Z`（服务器本地）⇒ **同一意图两种写法差 8 小时**，
 *     报表/告警列表按非补零日期筛选就跨日漏数——正是 `constants/timezone.js` 声明已消除的偏移。
 *  ② `isValidDateParam` 只判 `!isNaN(new Date(v))`，对非字符串全放行：
 *     实测 `null / false / 0 / 20260801 / '123'` 全部返回 true，而 `'123'` 会变成
 *     **公元 0122 年**的有效时刻 ⇒ 参数写错退化成"窄得离谱却看起来正常"的结果集。
 *
 * 刻意保留的两条既有契约（不是遗漏）：
 *  · `'2026-04-31'` 仍放行 —— 入口三道判据都拦不住前滚式解析，收口在
 *    `clampToRealCalendarDay`（由 businessDayBoundsIllegalCalendarDay 套件钉住）；
 *  · 完整 ISO 时间串仍原样透传（报表接口允许带时分秒）。
 */

const {
  parseDateBoundary,
  isValidDateParam,
  buildDateRangeFilter,
} = require('../../utils/helpers');
const { businessDayBounds, businessDateParts } = require('../../constants/timezone');

describe('日期参数：补零形态与非法形态', () => {
  test('① 同一天的补零与非补零写法必须给出同一个业务日窗口', () => {
    const pairs = [
      ['2026-08-01', '2026-8-1'],
      ['2026-12-09', '2026-12-9'],
      ['2026-01-01', '2026-1-1'],
      ['2024-02-29', '2024-2-29'], // 闰日
    ];
    for (const [padded, loose] of pairs) {
      for (const edge of ['start', 'end']) {
        expect(parseDateBoundary(loose, edge).getTime()).toBe(
          parseDateBoundary(padded, edge).getTime()
        );
      }
      // 且必须等于业务时区口径的那一天，而不是"服务器本地午夜"
      const b = businessDayBounds(padded);
      expect(parseDateBoundary(loose, 'start').getTime()).toBe(b.start.getTime());
      expect(parseDateBoundary(loose, 'end').getTime()).toBe(b.end.getTime());
    }
  });

  test('①b 非补零串不得被静默换成"今天"（直接把原串转给 businessDayBounds 就会这样）', () => {
    const today = businessDateParts().dateStr;
    const loose = '2019-3-4';
    const thatDay = businessDayBounds('2019-03-04');
    expect(parseDateBoundary(loose, 'start').getTime()).toBe(thatDay.start.getTime());
    // end 也要钉：本机时区恰好与业务时区相同（UTC+8）时，"服务器本地午夜"与
    // "业务日 00:00 的 UTC 瞬间"是同一个点 ⇒ 只比 start 的断言在开发机上会假绿，
    // 而差 8 小时的真实后果出现在 UTC 容器上。end 两侧相差近 24 小时，谁都蒙不过去。
    expect(parseDateBoundary(loose, 'end').getTime()).toBe(thatDay.end.getTime());
    // 前提自证：'2019-3-4' 与今天确实不是同一天，否则上面两条是空转
    expect(thatDay.start.getTime()).not.toBe(businessDayBounds(today).start.getTime());
  });

  test('①c 完整 ISO 时间串仍原样透传（既有契约，不得被业务日窗口改写）', () => {
    const iso = '2026-08-01T05:06:07.008Z';
    expect(parseDateBoundary(iso, 'start').getTime()).toBe(new Date(iso).getTime());
    expect(parseDateBoundary(iso, 'end').getTime()).toBe(new Date(iso).getTime());
  });

  test('①d 月/日越界不在此兜底：交回 new Date 判成无效（且不得抛错），由上游拒成 400', () => {
    for (const bad of ['2026-13-45', '2026-00-10', '2026-12-00']) {
      // 越界月/日一旦进了 businessDayBounds，会在 Intl 格式化处抛 RangeError ⇒
      // "该 400 的坏参数"变成 500，比原来的静默窄结果更糟。这里两个方向都钉。
      let out;
      expect(() => {
        out = parseDateBoundary(bad, 'start');
      }).not.toThrow();
      expect(Number.isNaN(out.getTime())).toBe(true);
      expect(isValidDateParam(bad)).toBe(false);
    }
  });

  test('② 非法日期参数一律拒；未传仍放行', () => {
    for (const v of [undefined, null, '']) expect(isValidDateParam(v)).toBe(true);
    for (const v of ['2026-08-01', '2026-8-1', '2026-08-01T05:00:00Z']) {
      expect(isValidDateParam(v)).toBe(true);
    }
    // 旧实现对这些全部放行（`new Date('123')` 是"公元 0122 年"的有效时刻）
    for (const v of ['123', '20260801', 20260801, 0, false, true, {}, [], 'not-a-date', ' ']) {
      expect(isValidDateParam(v)).toBe(false);
    }
  });

  test('②b 负前提：不存在的日历日仍放行（收口在 clampToRealCalendarDay，不在这里 400）', () => {
    expect(isValidDateParam('2026-04-31')).toBe(true);
    const b = businessDayBounds('2026-04-31');
    expect(b.dateStr).toBe('2026-04-30'); // 由回夹兜住，不会造出 48 小时窗口
  });

  test('②c 入口放行而边界拒：buildDateRangeFilter 不再把 ' + "'123' 变成公元 0122 年的窗口", () => {
    // 旧行为：isValidDateParam('123') → true → 下面得到 $gte=0122 年，查询静默变窄
    expect(isValidDateParam('123')).toBe(false);
    const filter = buildDateRangeFilter('2026-8-1', '2026-8-2');
    expect(filter.$gte.getTime()).toBe(businessDayBounds('2026-08-01').start.getTime());
    expect(filter.$lte.getTime()).toBe(businessDayBounds('2026-08-02').end.getTime());
  });
});
