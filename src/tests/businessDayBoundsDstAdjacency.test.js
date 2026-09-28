/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：constants/timezone.js 的 businessDayBounds 跨夏令时行为
 * 守护的不变式：「今天」窗口在夏令时切换日必须仍首尾相接（春季 23h、秋季 25h 都不得重叠或漏秒）
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 更名（旧名带已废弃的会话前缀，逐字旧名见 `git log --follow`）。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   会话前缀已全仓清除，故不再逐字保留旧名；按旧名回溯请用 `git log --follow <本文件>`。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 业务时区"今天"窗口必须跨夏令时仍然首尾相接
 *
 * `businessDayBounds()` 的 end 原先按 `start + 24h - 1ms` 计算。这在无夏令时的
 * 时区（默认 Asia/Shanghai）完全正确，但 `TZ_BUSINESS` 是**可配置成任意 IANA 区**的
 * （validate.js 还专门校验它必须是合法 IANA 名），于是换成 America/* 之后每年两次失真：
 *   春季提前那天天只有 23 小时 → end 越过次日零点 1 小时，"今日"窗口与次日重叠，
 *     仪表盘今日计数与 byDay 聚合会把同一批记录算两次；
 *   秋季回拨那天天有 25 小时 → end 差 1 小时才到次日零点，中间 1 小时的记录
 *     既不属于昨天也不属于今天，从按天聚合里凭空消失。
 * 既有 `constants/timezone.test.js` 测的是 1 月与 8 月的普通日，
 * "相邻两天首尾相接"那条断言恰好在无切换的日期上自动成立，所以从没照出这件事。
 *
 * 本文件用三样东西钉住：两个切换日、一整个年度的逐日无缝性（365 天全覆盖）、
 * 以及"普通日仍是 24h"的反向保护（防止收口变成一律缩短窗口）。
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
const DAY = 24 * HOUR;

// UTC 日历上的加一天（不能加"24 小时"——那正是本文件要修的错处）
const nextDateStr = (dateStr) => {
  const d = new Date(`${dateStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
};

describe('业务时区日界必须跨夏令时保持无缝', () => {
  afterAll(() => {
    loadTz('Asia/Shanghai'); // 让后续套件拿到的模块图不受本次 resetModules 影响
  });

  const LA = 'America/Los_Angeles';

  test('春季提前日（2026-03-08，LA 当天只有 23 小时）：end 不得越过次日零点', () => {
    const { businessDayBounds } = loadTz(LA);
    const { start, end } = businessDayBounds('2026-03-08');
    const next = businessDayBounds('2026-03-09');

    // 当天真实长度 = 23h
    expect(end.getTime() - start.getTime()).toBe(23 * HOUR - 1);
    // 无缝：今天的 end + 1ms 必须正好是明天的开始
    expect(end.getTime() + 1).toBe(next.start.getTime());
  });

  test('秋季回拨日（2026-11-01，LA 当天有 25 小时）：不得漏掉 1 小时', () => {
    const { businessDayBounds } = loadTz(LA);
    const { start, end } = businessDayBounds('2026-11-01');
    const next = businessDayBounds('2026-11-02');

    expect(end.getTime() - start.getTime()).toBe(25 * HOUR - 1);
    expect(end.getTime() + 1).toBe(next.start.getTime());
  });

  test('反向保护：无切换的普通日仍是 24 小时（收口不得变成一律缩短窗口）', () => {
    const { businessDayBounds } = loadTz(LA);
    const { start, end } = businessDayBounds('2026-01-15');
    expect(end.getTime() - start.getTime()).toBe(DAY - 1);
    expect(end.getTime() + 1).toBe(businessDayBounds('2026-01-16').start.getTime());
  });

  test('默认区（Asia/Shanghai 无夏令时）口径一字不变：00:00 CST = 前一日 16:00Z', () => {
    const { businessDayBounds } = loadTz('Asia/Shanghai');
    const { start, end } = businessDayBounds('2026-08-26');
    expect(start.toISOString()).toBe('2026-08-25T16:00:00.000Z');
    expect(end.toISOString()).toBe('2026-08-26T15:59:59.999Z');
  });

  test('整年逐日无缝：LA 2026 年每一天都满足 end+1ms === 次日 start', () => {
    const { businessDayBounds } = loadTz(LA);
    let cursor = '2026-01-01';
    const gaps = [];
    for (let i = 0; i < 364; i++) {
      const today = businessDayBounds(cursor);
      const tomorrowStr = nextDateStr(cursor);
      const tomorrow = businessDayBounds(tomorrowStr);
      if (today.end.getTime() + 1 !== tomorrow.start.getTime()) {
        gaps.push({
          dateStr: cursor,
          diffHours: (tomorrow.start.getTime() - today.end.getTime() - 1) / HOUR,
        });
      }
      cursor = tomorrowStr;
    }
    // 断言"没有任何一天失配"，而不是"失配数少于 N"
    expect(gaps).toEqual([]);
  });

  test('缺省取值仍是业务时区的今天，且不抛（dateStr 非法时的既有兜底）', () => {
    const { businessDayBounds, businessDateParts } = loadTz(LA);
    const { start, end, dateStr } = businessDayBounds('not-a-date');
    expect(dateStr).toBe(businessDateParts().dateStr);
    expect(Number.isNaN(start.getTime())).toBe(false);
    expect(Number.isNaN(end.getTime())).toBe(false);
    expect(end.getTime() - start.getTime()).toBeLessThan(26 * HOUR);
  });
});
