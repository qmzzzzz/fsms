/**
 * 非法日历日不能把业务日窗口推到下一个自然月
 *
 * 缺陷形状：`new Date('2026-04-31')` 不报错而是前滚成 05-01，于是
 * `endDate=2026-04-31` 的报表实际含了 5 月 1 日全天，且 `dateStr` 回显一个不存在的日期。
 * 上游拦不住：路由用**非 strict** 的 isISO8601（只校格式），
 * `isValidDateParam` 用 `!isNaN(new Date(v))`（前滚后当然不是 NaN）——
 * 下面有两条用例专门把这个事实钉住，避免有人"在入口修一次"就把这里的回夹删掉。
 */
const validator = require('validator');
const { businessDayBounds, businessDateParts } = require('../../constants/timezone');
const { parseDateBoundary, isValidDateParam } = require('../../utils/helpers');

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const localDay = (t) => businessDateParts(t).dateStr;

describe('非法日历日回夹到当月最后一天', () => {
  test.each([
    ['2026-04-31', '2026-04-30'],
    ['2026-02-29', '2026-02-28'],
    ['2026-02-30', '2026-02-28'],
    ['2026-02-31', '2026-02-28'],
    ['2026-12-32', '2026-12-31'],
    ['2026-06-31', '2026-06-30'],
  ])('%s ⇒ 窗口整体落在 %s 这一个业务日内', (input, expected) => {
    const b = businessDayBounds(input);
    expect(b.dateStr).toBe(expected);
    expect(localDay(b.start)).toBe(expected);
    expect(localDay(b.end)).toBe(expected);
  });

  test('合法日期与闰日原样保留（回夹不得吃掉闰年 02-29）', () => {
    for (const day of ['2028-02-29', '2026-02-28', '2026-04-30', '2026-12-31']) {
      const b = businessDayBounds(day);
      expect({ day, got: b.dateStr }).toEqual({ day, got: day });
      expect(localDay(b.start)).toBe(day);
      expect(localDay(b.end)).toBe(day);
    }
  });

  test('业务日窗口首尾相接：end 与次日 start 相差 1ms（回夹不得造出 48h 窗口）', () => {
    const b = businessDayBounds('2026-04-31');
    const next = businessDayBounds('2026-05-01');
    expect(next.start.getTime() - b.end.getTime()).toBe(1);
    expect(b.end.getTime() - b.start.getTime()).toBe(MS_PER_DAY - 1);
  });

  test('5 月 1 日的瞬间不再被 4 月区间命中（over-inclusion 的实际后果）', () => {
    const { end } = businessDayBounds('2026-04-31');
    const mayOne = new Date('2026-05-01T02:00:00Z'); // 北京 5/1 10:00
    expect(mayOne.getTime() > end.getTime()).toBe(true);
    const aprThirty = new Date('2026-04-30T02:00:00Z');
    expect(aprThirty.getTime() <= end.getTime()).toBe(true);
  });
});

describe('为什么修在这里而不是入口', () => {
  test('上游三道判据全部放行 2026-04-31（负前提，防"入口已拦"的错觉）', () => {
    expect(validator.isISO8601('2026-04-31')).toBe(true); // 路由用的就是非 strict 形态
    expect(isNaN(new Date('2026-04-31').getTime())).toBe(false);
    expect(isValidDateParam('2026-04-31')).toBe(true);
  });

  test('strict 形态确实能拒（说明差距只在调用选项，不是库的能力边界）', () => {
    expect(validator.isISO8601('2026-04-31', { strict: true })).toBe(false);
    expect(validator.isISO8601('2028-02-29', { strict: true })).toBe(true);
  });
});

describe('消费方共用同一判据', () => {
  test('parseDateBoundary 的 end 与 businessDayBounds 完全一致（不得再各写一份窗口）', () => {
    for (const day of ['2026-04-31', '2026-02-29', '2026-04-30']) {
      const b = businessDayBounds(day);
      expect(parseDateBoundary(day, 'end').getTime()).toBe(b.end.getTime());
      expect(parseDateBoundary(day, 'start').getTime()).toBe(b.start.getTime());
    }
  });

  test('非 YYYY-MM-DD 形态仍按"今天"处理，且今天必然是合法日历日', () => {
    for (const bad of ['2026-4-1', '2026/04/01', '2026-04', '', undefined, null]) {
      const b = businessDayBounds(bad);
      expect(b.dateStr).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(b.dateStr).toBe(businessDateParts().dateStr);
    }
  });
});
