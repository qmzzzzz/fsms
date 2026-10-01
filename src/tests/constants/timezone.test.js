/**
 * 业务时区单一声明的单元测试（P3-18）
 *
 * 关键不变量：无论服务器本地时区是什么（容器通常 UTC），
 * businessDayBounds 返回的都必须是「业务时区那一天」的 UTC 起止瞬间。
 * 原实现里仪表盘用服务器本地时区、byDay 聚合硬编码 +08:00，
 * 两个「今天」在 UTC 16:00-24:00 必然错位。
 */

describe('业务时区收敛（P3-18）', () => {
  const load = () => {
    jest.resetModules();
    return require('../../constants/timezone');
  };

  afterEach(() => {
    delete process.env.TZ_BUSINESS;
    jest.resetModules();
  });

  test('默认业务时区为 Asia/Shanghai（IANA 名而非固定偏移）', () => {
    const { BUSINESS_TIMEZONE } = load();
    expect(BUSINESS_TIMEZONE).toBe('Asia/Shanghai');
    // 必须是 IANA 名：固定偏移不承载夏令时规则，跨区部署无法正确迁移
    expect(BUSINESS_TIMEZONE).not.toMatch(/^[+-]\d{2}:\d{2}$/);
  });

  test('可由 TZ_BUSINESS 覆盖', () => {
    process.env.TZ_BUSINESS = 'America/Los_Angeles';
    const { BUSINESS_TIMEZONE } = load();
    expect(BUSINESS_TIMEZONE).toBe('America/Los_Angeles');
  });

  test('东八区某日的起止即 UTC 前一日 16:00 → 当日 15:59:59.999', () => {
    const { businessDayBounds } = load();
    const { start, end } = businessDayBounds('2026-08-26');
    expect(start.toISOString()).toBe('2026-08-25T16:00:00.000Z');
    expect(end.toISOString()).toBe('2026-08-26T15:59:59.999Z');
  });

  test('区间恰好覆盖一整天（含首尾毫秒，不重不漏）', () => {
    const { businessDayBounds } = load();
    const { start, end } = businessDayBounds('2026-01-01');
    expect(end.getTime() - start.getTime()).toBe(24 * 60 * 60 * 1000 - 1);
    // 相邻两天首尾相接：前一天的 end + 1ms === 后一天的 start
    const next = businessDayBounds('2026-01-02');
    expect(end.getTime() + 1).toBe(next.start.getTime());
  });

  test('负偏移时区同样正确（洛杉矶 UTC-7/-8）', () => {
    process.env.TZ_BUSINESS = 'America/Los_Angeles';
    const { businessDayBounds } = load();
    // 2026-07-01 处于夏令时（PDT, UTC-7）
    const { start } = businessDayBounds('2026-07-01');
    expect(start.toISOString()).toBe('2026-07-01T07:00:00.000Z');
    // 2026-01-01 为标准时（PST, UTC-8）——固定偏移方案会在这里出错
    const winter = businessDayBounds('2026-01-01');
    expect(winter.start.toISOString()).toBe('2026-01-01T08:00:00.000Z');
  });

  /**
   * 原写法是 `expect(businessDayBounds().dateStr).toBe(businessDateParts().dateStr)`——
   * **结构恒真**：两枚函数都落到同一枚 `dayParts` formatter 上，实现整体漂移
   * （删掉非法日历日的前滚、把缺省时刻来源换成服务器本地时区）时两边同步移动，
   * 相等关系不变 ⇒ 永远绿。而且真分叉也只在业务时区 00:00–08:00 那段窗口里偶然响。
   *
   * 现在两侧各自钉**人算出来的绝对值**，跨日界各取一个瞬间（上海 23:30 与次日 00:30），
   * 相等那条降级为"方向相反的第二把锁"：绝对值防的是同步漂移，相等防的是分叉。
   */
  test('缺省参数的"今天"：两个瞬间各钉绝对值，再钉两侧同源', () => {
    const { businessDayBounds, businessDateParts } = load();
    const INSTANTS = [
      // 2026-08-26T15:30Z = 上海 2026-08-26 23:30（还在 26 日）
      { now: '2026-08-26T15:30:00.000Z', dateStr: '2026-08-26', start: '2026-08-25T16:00:00.000Z' },
      // 2026-08-26T16:30Z = 上海 2026-08-27 00:30（服务器还在 26 日，业务日已是 27 日）
      { now: '2026-08-26T16:30:00.000Z', dateStr: '2026-08-27', start: '2026-08-26T16:00:00.000Z' },
    ];
    for (const t of INSTANTS) {
      expect(businessDateParts(new Date(t.now)).dateStr).toBe(t.dateStr);
      jest.useFakeTimers().setSystemTime(new Date(t.now));
      const day = businessDayBounds();
      jest.useRealTimers();
      expect(day.dateStr).toBe(t.dateStr);
      expect(day.start.toISOString()).toBe(t.start);
    }
    expect(businessDayBounds().dateStr).toBe(businessDateParts().dateStr);
  });

  test('非法日期串回退为今天而非产生 Invalid Date', () => {
    const { businessDayBounds } = load();
    const { start, end } = businessDayBounds('not-a-date');
    expect(Number.isNaN(start.getTime())).toBe(false);
    expect(Number.isNaN(end.getTime())).toBe(false);
  });

  test('businessDateParts 分量与 dateStr 自洽', () => {
    const { businessDateParts } = load();
    const { year, month, day, dateStr } = businessDateParts(new Date('2026-08-26T20:00:00Z'));
    // UTC 20:00 → 东八区次日 04:00
    expect(dateStr).toBe('2026-08-27');
    expect(year).toBe(2026);
    expect(month).toBe(8);
    expect(day).toBe(27);
  });
});
