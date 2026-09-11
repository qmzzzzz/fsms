/**
 * 行为基线服务单测
 *
 * 通过 mock AuditLog.aggregate 隔离数据库，专注验证特征提取与偏离评估的统计逻辑。
 * P3-20 起特征聚合改在数据库侧完成（$group + $addToSet），因此这里的 mock
 * 需要复刻聚合语义：按 $match 的时间窗过滤 → 按 _id 表达式分桶 → 输出计数与基数。
 */

jest.mock('../../models/AuditLog', () => ({
  aggregate: jest.fn(),
}));

const AuditLog = require('../../models/AuditLog');
const baseline = require('../../services/behaviorBaseline');

const WRITE_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];
const HIGH_RISK = ['high', 'critical'];

/**
 * 构造 AuditLog.aggregate 的返回：在内存里模拟 dailyFeatureStages 的输出
 *
 * 按 $match.timestamp 的 $gte/$lt 过滤，模拟真实查询行为——
 * 否则近期窗会读到全部基线数据、基线窗会混入观测期数据。
 * 分桶键取 $group._id：null → 整窗一行；$dateToString → 按业务时区日期分桶。
 */
const mockRows = (rows) => {
  AuditLog.aggregate.mockImplementation((pipeline = []) => {
    const match = pipeline.find((s) => s.$match)?.$match || {};
    const group = pipeline.find((s) => s.$group)?.$group || {};
    const since = match?.timestamp?.$gte ? new Date(match.timestamp.$gte).getTime() : null;
    const until = match?.timestamp?.$lt ? new Date(match.timestamp.$lt).getTime() : Infinity;

    const filtered = rows.filter((r) => {
      const t = new Date(r.timestamp).getTime();
      return (since === null || t >= since) && t < until;
    });

    // _id 为 null 表示整窗聚合；否则按「业务时区日期」分桶
    const byDay = group._id !== null;
    const buckets = new Map();
    for (const r of filtered) {
      const key = byDay
        ? new Date(r.timestamp).toLocaleDateString('en-CA', { timeZone: 'Asia/Shanghai' })
        : null;
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push(r);
    }

    const out = [];
    for (const [key, group_] of buckets.entries()) {
      const ips = new Set(group_.map((r) => r.ip).filter((v) => v != null));
      const fps = new Set(group_.map((r) => r.fingerprint).filter((v) => v != null));
      out.push({
        _id: key,
        total: group_.length,
        failures: group_.filter((r) => r.success === false).length,
        writes: group_.filter((r) => WRITE_METHODS.includes(r.method)).length,
        highRisk: group_.filter((r) => HIGH_RISK.includes(r.riskLevel)).length,
        offHours: 0,
        distinctIPs: ips.size,
        distinctFingerprints: fps.size,
      });
    }
    return Promise.resolve(out);
  });
};

// 生成指定小时数之前的时间戳。用固定小时偏移而非「归一到某时刻」的日期，
// 保证近期窗（24h）与基线窗的包含关系不随测试运行时刻漂移——
// 此前 daysAgo 归一到 UTC 04:00，北京时间 12 点前运行时昨天的数据
// 会落入近期窗，导致观测值翻倍、用例偶发失败
const hoursAgo = (n) => new Date(Date.now() - n * 60 * 60 * 1000);

// 兼容保留：天数偏移（按 24h 计）
const daysAgo = (n) => hoursAgo(n * 24);

describe('behaviorBaseline 行为基线', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('meanStd 均值与标准差', () => {
    it('空数组返回 0', () => {
      expect(baseline.meanStd([])).toEqual({ mean: 0, std: 0 });
    });

    it('单元素标准差为 0', () => {
      expect(baseline.meanStd([5])).toEqual({ mean: 5, std: 0 });
    });

    it('常量序列标准差为 0', () => {
      const { mean, std } = baseline.meanStd([3, 3, 3, 3]);
      expect(mean).toBe(3);
      expect(std).toBe(0);
    });

    it('计算样本标准差（n-1 分母）', () => {
      const { mean, std } = baseline.meanStd([2, 4, 6]);
      expect(mean).toBe(4);
      expect(std).toBeCloseTo(2, 5);
    });
  });

  describe('extractFeatures 特征提取', () => {
    it('无数据时各项特征为 0', async () => {
      mockRows([]);
      const f = await baseline.extractFeatures('u1', 1);
      expect(f.totalRequests).toBe(0);
      expect(f.failureRate).toBe(0);
      expect(f.distinctIPs).toBe(0);
      expect(f.requestsPerDay).toBe(0);
    });

    it('正确统计失败率与写操作占比', async () => {
      mockRows([
        { method: 'GET', success: true, riskLevel: 'low', ip: '1.1.1.1', timestamp: daysAgo(0) },
        { method: 'POST', success: false, riskLevel: 'low', ip: '1.1.1.1', timestamp: daysAgo(0) },
        {
          method: 'DELETE',
          success: true,
          riskLevel: 'high',
          ip: '2.2.2.2',
          timestamp: daysAgo(0),
        },
        { method: 'GET', success: true, riskLevel: 'low', ip: '1.1.1.1', timestamp: daysAgo(0) },
      ]);
      const f = await baseline.extractFeatures('u1', 1);
      expect(f.totalRequests).toBe(4);
      expect(f.failureRate).toBe(0.25);
      expect(f.writeRatio).toBe(0.5);
      expect(f.highRiskCount).toBe(1);
      expect(f.distinctIPs).toBe(2);
    });

    it('统计不同指纹数量', async () => {
      mockRows([
        { method: 'GET', success: true, fingerprint: 'fp-a', timestamp: daysAgo(0) },
        { method: 'GET', success: true, fingerprint: 'fp-b', timestamp: daysAgo(0) },
        { method: 'GET', success: true, fingerprint: 'fp-a', timestamp: daysAgo(0) },
        { method: 'GET', success: true, timestamp: daysAgo(0) },
      ]);
      const f = await baseline.extractFeatures('u1', 1);
      expect(f.distinctFingerprints).toBe(2);
    });

    it('requestsPerDay 按窗口天数归一化', async () => {
      mockRows(
        Array.from({ length: 30 }, () => ({
          method: 'GET',
          success: true,
          timestamp: daysAgo(1),
        }))
      );
      const f = await baseline.extractFeatures('u1', 10);
      expect(f.requestsPerDay).toBe(3);
    });
  });

  describe('collectDailySamples 按日分桶', () => {
    it('按日期聚合为多个样本', async () => {
      mockRows([
        { method: 'GET', success: true, ip: '1.1.1.1', timestamp: daysAgo(1) },
        { method: 'GET', success: true, ip: '1.1.1.1', timestamp: daysAgo(1) },
        { method: 'POST', success: false, ip: '2.2.2.2', timestamp: daysAgo(2) },
      ]);
      const samples = await baseline.collectDailySamples('u1', 30);
      expect(samples).toHaveLength(2);
      const totals = samples.map((s) => s.totalRequests).sort();
      expect(totals).toEqual([1, 2]);
    });
  });

  describe('evaluateDeviation 偏离评估', () => {
    it('基线样本不足时不做判定', async () => {
      mockRows([
        { method: 'GET', success: true, timestamp: daysAgo(1) },
        { method: 'GET', success: true, timestamp: daysAgo(2) },
      ]);
      const r = await baseline.evaluateDeviation('u1', { minSamples: 7 });
      expect(r.evaluated).toBe(false);
      expect(r.reason).toContain('基线样本不足');
    });

    it('行为平稳时不报异常', async () => {
      // 今天 5 条（1 小时前，落入近期窗）+ 基线 10 天每天 5 条（26h 前起每 24h 一组，
      // 均在 24h 观测窗之外、31d 基线窗之内）。固定小时偏移保证包含关系
      // 不随测试运行时刻漂移
      const rows = [];
      for (let i = 0; i < 5; i++) {
        rows.push({
          method: 'GET',
          success: true,
          ip: '1.1.1.1',
          fingerprint: 'fp',
          timestamp: hoursAgo(1),
        });
      }
      for (let d = 1; d <= 10; d++) {
        for (let i = 0; i < 5; i++) {
          rows.push({
            method: 'GET',
            success: true,
            ip: '1.1.1.1',
            fingerprint: 'fp',
            timestamp: hoursAgo(24 * d + 2),
          });
        }
      }
      mockRows(rows);
      const r = await baseline.evaluateDeviation('u1', { minSamples: 7, recentDays: 1 });
      expect(r.evaluated).toBe(true);
      expect(r.sampleDays).toBeGreaterThanOrEqual(7);
      expect(r.isAnomalous).toBe(false);
    });

    it('请求量骤升时报异常', async () => {
      // 基线每天 5 条（std=0），今天突然 50 条 → z=+Infinity，应告警
      const rows = [];
      for (let i = 0; i < 50; i++) {
        rows.push({
          method: 'GET',
          success: true,
          ip: '1.1.1.1',
          fingerprint: 'fp',
          timestamp: hoursAgo(1),
        });
      }
      for (let d = 1; d <= 10; d++) {
        for (let i = 0; i < 5; i++) {
          rows.push({
            method: 'GET',
            success: true,
            ip: '1.1.1.1',
            fingerprint: 'fp',
            timestamp: hoursAgo(24 * d + 2),
          });
        }
      }
      mockRows(rows);
      const r = await baseline.evaluateDeviation('u1', { minSamples: 7, recentDays: 1 });
      expect(r.evaluated).toBe(true);
      expect(r.isAnomalous).toBe(true);
      expect(r.anomalies).toContain('totalRequests');
    });

    it('请求量骤降不报异常（方向语义：休假不是攻击）', async () => {
      // 基线每天 5 条（std=0），今天 0 条 → z=-Infinity，按「仅升高告警」不触发
      const rows = [];
      for (let d = 1; d <= 10; d++) {
        for (let i = 0; i < 5; i++) {
          rows.push({
            method: 'GET',
            success: true,
            ip: '1.1.1.1',
            fingerprint: 'fp',
            timestamp: hoursAgo(24 * d + 2),
          });
        }
      }
      mockRows(rows);
      const r = await baseline.evaluateDeviation('u1', { minSamples: 7, recentDays: 1 });
      expect(r.evaluated).toBe(true);
      expect(r.isAnomalous).toBe(false);
    });

    it('评估结果包含各维度 z 值与基线统计量', async () => {
      const rows = [];
      for (let d = 0; d < 10; d++) {
        rows.push({
          method: 'GET',
          success: true,
          ip: '1.1.1.1',
          fingerprint: 'fp',
          timestamp: daysAgo(d),
        });
      }
      mockRows(rows);
      const r = await baseline.evaluateDeviation('u1', { minSamples: 7 });
      expect(r.scores).toHaveProperty('totalRequests');
      expect(r.scores).toHaveProperty('failureRate');
      expect(r.scores).toHaveProperty('distinctIPs');
      expect(r.scores.totalRequests).toHaveProperty('baselineMean');
      expect(r.scores.totalRequests).toHaveProperty('baselineStd');
      expect(r.scores.totalRequests).toHaveProperty('z');
    });

    it('查询异常时返回 evaluated=false 而非抛错', async () => {
      AuditLog.aggregate.mockRejectedValue(new Error('db down'));
      const r = await baseline.evaluateDeviation('u1');
      expect(r.evaluated).toBe(false);
      expect(r.reason).toContain('db down');
    });
  });
});
