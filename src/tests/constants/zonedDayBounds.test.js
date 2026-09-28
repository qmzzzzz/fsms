/**
 * zonedDayBounds 单元测试（任意 IANA 时区的 DST 安全日界）
 *
 * 报表接口「今日」按浏览器所在时区计算时，时区来自前端
 * `Intl.DateTimeFormat().resolvedOptions().timeZone`。日界算法必须对
 * 夏令时切换日免疫——23 小时日（春季提前）不与次日重叠、25 小时日
 * （秋季回拨）不从按天聚合里丢数据。期望值不是快照：每个断言都来自
 * 该时区该日 UTC 偏移的**可推导事实**（EST=-5/EDT=-4 等），
 * 算法换掉而事实不变时断言仍然成立。
 */

const {
  zonedDayBounds,
  businessDayBounds,
  BUSINESS_TIMEZONE,
} = require('../../constants/timezone');

describe('zonedDayBounds（任意 IANA 时区的 DST 安全日界）', () => {
  test('无夏令时时区（Asia/Shanghai）：start = 本地 00:00 换算的 UTC 瞬间', () => {
    const b = zonedDayBounds('Asia/Shanghai', '2026-09-28');
    expect(b.dateStr).toBe('2026-09-28');
    expect(b.start.toISOString()).toBe('2026-09-27T16:00:00.000Z'); // UTC+8
    expect(b.end.toISOString()).toBe('2026-09-28T15:59:59.999Z');
  });

  test('春季提前日（America/New_York 2026-03-08，23 小时日）窗口不与次日重叠', () => {
    const b = zonedDayBounds('America/New_York', '2026-03-08');
    // 当天零点仍是 EST(-5)；次日零点已是 EDT(-4)
    expect(b.start.toISOString()).toBe('2026-03-08T05:00:00.000Z');
    expect(b.end.toISOString()).toBe('2026-03-09T03:59:59.999Z');
    // 23 小时日：start+23h 正好是 end+1ms（+24h 会越过次日零点造成重复计数）
    expect(b.end.getTime() - b.start.getTime() + 1).toBe(23 * 60 * 60 * 1000);
  });

  test('秋季回拨日（America/New_York 2026-11-01，25 小时日）窗口无空洞', () => {
    const b = zonedDayBounds('America/New_York', '2026-11-01');
    // 当天零点是 EDT(-4)（回拨发生在本地 02:00→01:00）；次日零点是 EST(-5)
    expect(b.start.toISOString()).toBe('2026-11-01T04:00:00.000Z');
    expect(b.end.toISOString()).toBe('2026-11-02T04:59:59.999Z');
    // 25 小时日：+24h 差 1 小时才到次日零点，"次日 start − 1ms" 自动补齐
    expect(b.end.getTime() - b.start.getTime() + 1).toBe(25 * 60 * 60 * 1000);
  });

  test('非法日历日回夹到当月最后一天（2026-04-31 → 04-30，口径同业务时区）', () => {
    const b = zonedDayBounds('Asia/Shanghai', '2026-04-31');
    expect(b.dateStr).toBe('2026-04-30');
  });

  test('缺省日期取该时区的今天（形如 YYYY-MM-DD 即可，不锚定具体值）', () => {
    const b = zonedDayBounds('Asia/Shanghai');
    expect(b.dateStr).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  test('businessDayBounds 与 zonedDayBounds(业务时区, …) 同源（泛化不得分叉）', () => {
    const a = businessDayBounds('2026-09-28');
    const b = zonedDayBounds(BUSINESS_TIMEZONE, '2026-09-28');
    expect(a.start.getTime()).toBe(b.start.getTime());
    expect(a.end.getTime()).toBe(b.end.getTime());
  });
});
