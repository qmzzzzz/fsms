'use strict';

/**
 * （2026-09-19）：behaviorBaseline 的窗口参数与"去重基数不可除以窗长"
 *
 * 本模块目前**没有生产调用方**（`grep -rn "evaluateDeviation|extractFeatures|collectDailySamples" src`
 * 只命中自身与测试），所以两条都是"等谁来接就会中招"的潜伏缺陷，按潜伏评等：
 *  1) 窗口参数不校验：`windowDays=0` ⇒ `since=now` 查不到东西，
 *     `requestsPerDay = total/0 = Infinity`；`windowDays=-7` ⇒ `since` 落在未来 ⇒ 永远空结果；
 *     `minSamples=0` ⇒ 样本判据恒假 ⇒ 拿 1 个样本算 σ=0 然后按 ±Infinity 报警。
 *     三者都会返回一个**看起来可信的判定**，而不是错误。
 *  2) distinctIPs / distinctFingerprints 是**去重基数**，除以 recentDays 既不是日均、
 *     也不能与单日基数比 ⇒ 7 天窗内的真实激增被摊薄成"正常"（漏报方向，安全检测最坏的一侧）。
 *     修法：这两个维度只在 recentDays===1 时参与告警；窗长 >1 时仍返回 z 但标 comparable:false。
 */

jest.mock('../models/AuditLog', () => ({
  aggregate: jest.fn(),
}));

const AuditLog = require('../models/AuditLog');
const baseline = require('../services/behaviorBaseline');

const DAY_MS = 24 * 60 * 60 * 1000;
const daysAgo = (n) => new Date(Date.now() - n * DAY_MS - 30 * 60 * 1000); // 避开窗口的分钟级边界
// 突发放在 6 小时前：同时落在 recentDays=1 与 recentDays=7 两个观测窗内，
// 又被两条基线窗的 excludeRecentDays 排除（否则观测值混进基线会稀释偏离度）
const burstTime = new Date(Date.now() - 6 * 60 * 60 * 1000);

/** 从管道里取出 $match 的时间窗与分桶方式（不写聚合语义，只读参数） */
function readPipelineShape(pipeline = []) {
  const match = pipeline.find((s) => s.$match)?.$match || {};
  const group = pipeline.find((s) => s.$group)?.$group || {};
  return {
    since: match?.timestamp?.$gte ? new Date(match.timestamp.$gte).getTime() : null,
    until: match?.timestamp?.$lt ? new Date(match.timestamp.$lt).getTime() : Infinity,
    byDay: group._id !== null,
  };
}

/** 按天（或整窗）分桶 */
function bucketize(rows, byDay) {
  const buckets = new Map();
  for (const r of rows) {
    const key = byDay
      ? new Date(r.timestamp).toLocaleDateString('en-CA', { timeZone: 'Asia/Shanghai' })
      : null;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(r);
  }
  return buckets;
}

const countDistinct = (list, field) =>
  new Set(list.map((r) => r[field]).filter((v) => v != null)).size;

/** 复刻 dailyFeatureStages 的聚合语义（与既有 behaviorBaseline.test.js 同法，拆成小函数以过复杂度棘轮） */
function mockRows(rows) {
  AuditLog.aggregate.mockImplementation((pipeline = []) => {
    const { since, until, byDay } = readPipelineShape(pipeline);
    const filtered = rows.filter((r) => {
      const t = new Date(r.timestamp).getTime();
      if (since === null) return t < until;
      return t >= since && t < until; // since 为 NaN（荒谬窗）时恒假 ⇒ 零样本，正是期望的"判不了"
    });
    const out = [];
    for (const [key, list] of bucketize(filtered, byDay).entries()) {
      out.push({
        _id: key,
        total: list.length,
        failures: 0,
        writes: 0,
        highRisk: 0,
        offHours: 0,
        distinctIPs: countDistinct(list, 'ip'),
        distinctFingerprints: countDistinct(list, 'fingerprint'),
      });
    }
    return Promise.resolve(out);
  });
}

/** 基线：第 10~17 天各 1 条、每天 1 个 IP；突发：第 1 天 20 条 20 个 IP */
function fixture() {
  const rows = [];
  for (let d = 17; d >= 10; d -= 1) {
    rows.push({ timestamp: daysAgo(d), ip: `10.0.0.${d}`, fingerprint: 'fp-a' });
  }
  for (let i = 0; i < 20; i += 1) {
    rows.push({ timestamp: burstTime, ip: `203.0.113.${i}`, fingerprint: `fp-${i}` });
  }
  mockRows(rows);
  return rows;
}

describe('zzqoder 行为基线窗口判据', () => {
  afterEach(() => jest.clearAllMocks());

  test.each([
    ['0 天窗', 'extractFeatures', 0],
    ['负数窗', 'extractFeatures', -7],
    ['小数天', 'extractFeatures', 1.5],
    ['字符串天', 'extractFeatures', '3'],
  ])('%s ⇒ extractFeatures 直接拒绝（不返回"看起来可信"的判定）', async (_label, _fn, win) => {
    mockRows([]);
    await expect(baseline.extractFeatures('u1', win)).rejects.toThrow(/windowDays 必须是正整数天/);
  });

  test('evaluateDeviation 把非法窗口参数转成可见的 reason，而不是静默假判定', async () => {
    mockRows([]);
    const r = await baseline.evaluateDeviation('u1', { recentDays: 0 });
    expect(r.evaluated).toBe(false);
    expect(r.reason).toContain('评估异常');
    expect(r.reason).toContain('recentDays');
  });

  test('minSamples=0 被拒：否则 1 个样本就能算 σ=0 并按 ±Infinity 报警', async () => {
    fixture();
    const r = await baseline.evaluateDeviation('u1', { minSamples: 0, recentDays: 1 });
    expect(r.evaluated).toBe(false);
    expect(r.reason).toContain('minSamples');
  });

  test('荒谬大的窗不会产出 evaluated:true（真实驱动下会抛 CastError，同样落在 reason 里）', async () => {
    fixture();
    const r = await baseline.evaluateDeviation('u1', {
      baselineDays: 1e9,
      recentDays: 1,
      minSamples: 1,
    });
    expect(r.evaluated).toBe(false);
  });

  test('去重基数在 recentDays>1 时不参与告警（除以窗长会把激增摊薄成正常）', async () => {
    fixture();
    const r = await baseline.evaluateDeviation('u1', {
      baselineDays: 30,
      recentDays: 7,
      minSamples: 5,
      zThreshold: 3,
    });
    expect(r.evaluated).toBe(true);
    expect(r.scores.distinctIPs.comparable).toBe(false);
    expect(r.scores.distinctFingerprints.comparable).toBe(false);
    expect(r.scores.totalRequests.comparable).toBe(true);
    // 摊薄后的观测值确实还在（20/7≈2.86），只是不再据此告警
    expect(r.scores.distinctIPs.observed).toBeCloseTo(20 / 7, 3);
    expect(r.anomalies).not.toContain('distinctIPs');
    // 可加量仍然按日均归一并参与判定：1 → 2.86 的跳升在 σ=0 的基线下必报
    expect(r.anomalies).toContain('totalRequests');
  });

  test('正对照：同样数据在 recentDays=1 时必须报出 distinctIPs（证明上一条不是"根本没数据"）', async () => {
    fixture();
    const r = await baseline.evaluateDeviation('u1', {
      baselineDays: 30,
      recentDays: 1,
      minSamples: 5,
      zThreshold: 3,
    });
    expect(r.evaluated).toBe(true);
    expect(r.scores.distinctIPs.comparable).toBe(true);
    expect(r.scores.distinctIPs.observed).toBe(20);
    expect(r.anomalies).toContain('distinctIPs');
    expect(r.isAnomalous).toBe(true);
  });

  test('collectDailySamples 的 excludeRecentDays 允许 0（默认"不排除"）但拒负数/小数', async () => {
    mockRows([]);
    await expect(baseline.collectDailySamples('u1', 30, 0)).resolves.toEqual([]);
    await expect(baseline.collectDailySamples('u1', 30, -1)).rejects.toThrow(
      /excludeRecentDays 必须是非负整数天/
    );
    await expect(baseline.collectDailySamples('u1', 0, 0)).rejects.toThrow(
      /baselineDays 必须是正整数天/
    );
  });
});
