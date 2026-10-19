'use strict';

/**
 * 审计异常检测 MTTD 指标（Plan B）
 *
 * 钉住四件事：
 *   ① 目标口径是统一 1× 生效间隔（2× 在默认 5 分钟间隔下恒绿，没有判别力）；
 *   ② 维度是闭合集合，未知维度并入 other，不按调用方文本建 series；
 *   ③ 文本与快照同口径，且延迟不可得时**不产出样本**（不伪造 0）；
 *   ④ 规则 ↔ 指标闭环：alert-rules.yml 引用的检测指标必须真的渲染得出来。
 */

const fs = require('fs');
const path = require('path');

const detectionMetrics = require('../../utils/metricsDetection');
const metrics = require('../../utils/metrics');
const {
  DETECTION_DIMENSIONS,
  UNKNOWN_DETECTION_DIMENSION,
  resolveDetectionTargetMs,
  evaluateDetectionLag,
  normalizeDetectionDimension,
} = require('../../constants/detectionObjectives');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const sampleOf = (text, name, labels = '') => {
  const re = new RegExp(
    '^' + name + (labels ? `\\{${labels}\\}` : '(?:\\{[^}]*\\})?') + ' ([0-9.eE+-]+)$',
    'm'
  );
  const m = text.match(re);
  return m ? Number(m[1]) : null;
};

describe('检测延迟目标：统一 1× 生效间隔', () => {
  test('目标 = 间隔本身，非法间隔返回 null（不得据此记样本）', () => {
    expect(resolveDetectionTargetMs(300000)).toBe(300000);
    expect(resolveDetectionTargetMs(30000)).toBe(30000);
    for (const bad of [0, -1, NaN, Infinity, undefined, null, 'abc']) {
      expect(resolveDetectionTargetMs(bad)).toBeNull();
    }
  });

  test('判定边界：lag == target 达标，超过 1ms 即未达标', () => {
    expect(evaluateDetectionLag({ intervalMs: 300000, lagMs: 300000 })).toEqual({
      targetMs: 300000,
      withinObjective: true,
    });
    expect(evaluateDetectionLag({ intervalMs: 300000, lagMs: 300001 }).withinObjective).toBe(false);
  });

  test('反向对照：interval ≥ 60s 时 2× 目标恒绿——证明为什么不用它', () => {
    // 检测窗口 W = interval + 60s，lag 必然 ≤ W；只要 interval ≥ 60s 就有 W ≤ 2×interval，
    // 即 2× 目标永远不可能被突破。默认 5 分钟与更大的间隔全部落在这个区间。
    for (const intervalMs of [60000, 300000, 3600000]) {
      const windowMs = intervalMs + 60000;
      expect(windowMs).toBeLessThanOrEqual(2 * intervalMs);
    }
  });

  test('lag 非法时 withinObjective 为 null（未知 ≠ 未达标）', () => {
    expect(evaluateDetectionLag({ intervalMs: 300000, lagMs: NaN }).withinObjective).toBeNull();
    expect(evaluateDetectionLag({ intervalMs: 300000, lagMs: -5 }).withinObjective).toBeNull();
    expect(evaluateDetectionLag({ intervalMs: NaN, lagMs: 5 })).toEqual({
      targetMs: null,
      withinObjective: null,
    });
  });

  test('维度闭合：三个已知维度原样保留，其余并入 other', () => {
    for (const dimension of DETECTION_DIMENSIONS) {
      expect(normalizeDetectionDimension(dimension)).toBe(dimension);
    }
    for (const odd of ['custom', '', null, undefined, '__proto__']) {
      expect(normalizeDetectionDimension(odd)).toBe(UNKNOWN_DETECTION_DIMENSION);
    }
  });
});

describe('检测延迟指标：渲染与快照同口径', () => {
  beforeEach(() => detectionMetrics.__resetForTest());

  test('空状态：三个维度恒输出 0 行（缺席与为 0 必须可区分）', () => {
    const out = detectionMetrics.formatDetection().join('\n');
    for (const dimension of DETECTION_DIMENSIONS) {
      expect(out).toContain(`detection_lag_seconds_sum{dimension="${dimension}"} 0`);
      expect(out).toContain(`detection_lag_seconds_count{dimension="${dimension}"} 0`);
      expect(out).toContain(
        `detections_within_objective_total{dimension="${dimension}",within_objective="true"} 0`
      );
      expect(out).toContain(
        `detections_within_objective_total{dimension="${dimension}",within_objective="false"} 0`
      );
    }
    // 目标未知时不输出 gauge（0 会被读成"目标为零"）
    expect(out).not.toContain('detection_objective_seconds{');
    // 跳过原因恒输出
    expect(out).toContain('detection_lag_skipped_total{reason="missing_first_event_at"} 0');
  });

  test('记录样本：毫秒内部存储、秒渲染，文本与快照一致', () => {
    detectionMetrics.recordDetection({
      dimension: 'high_frequency_failure',
      lagMs: 90000,
      intervalMs: 300000,
    });
    detectionMetrics.recordDetection({
      dimension: 'high_frequency_failure',
      lagMs: 330000,
      intervalMs: 300000,
    });

    const out = detectionMetrics.formatDetection().join('\n');
    expect(sampleOf(out, 'detection_lag_seconds_sum', 'dimension="high_frequency_failure"')).toBe(
      420
    );
    expect(sampleOf(out, 'detection_lag_seconds_count', 'dimension="high_frequency_failure"')).toBe(
      2
    );
    expect(sampleOf(out, 'detection_objective_seconds', 'dimension="high_frequency_failure"')).toBe(
      300
    );
    expect(
      sampleOf(
        out,
        'detections_within_objective_total',
        'dimension="high_frequency_failure",within_objective="true"'
      )
    ).toBe(1);
    expect(
      sampleOf(
        out,
        'detections_within_objective_total',
        'dimension="high_frequency_failure",within_objective="false"'
      )
    ).toBe(1);

    const snap = detectionMetrics.getDetectionSnapshot();
    const row = snap.dimensions.find((d) => d.dimension === 'high_frequency_failure');
    expect(row).toEqual({
      dimension: 'high_frequency_failure',
      lagSecondsSum: 420,
      lagSampleCount: 2,
      withinObjective: 1,
      outsideObjective: 1,
      objectiveSeconds: 300,
    });
  });

  test('未知维度并入 other，不产生新 series', () => {
    detectionMetrics.recordDetection({ dimension: 'zz_custom', lagMs: 1000, intervalMs: 300000 });
    const out = detectionMetrics.formatDetection().join('\n');
    expect(out).toContain('detection_lag_seconds_count{dimension="other"} 1');
    expect(out).not.toContain('zz_custom');
  });

  test('lag 不可得：不记样本，只记跳过原因（不伪造 0 延迟）', () => {
    detectionMetrics.recordDetection({
      dimension: 'unusual_time_operation',
      lagMs: NaN,
      intervalMs: 300000,
    });
    detectionMetrics.recordDetection({
      dimension: 'unusual_time_operation',
      lagMs: -1,
      intervalMs: 300000,
    });
    detectionMetrics.recordDetection({
      dimension: 'unusual_time_operation',
      lagMs: 1,
      intervalMs: NaN,
    });

    const out = detectionMetrics.formatDetection().join('\n');
    expect(out).toContain('detection_lag_seconds_count{dimension="unusual_time_operation"} 0');
    expect(out).toContain('detection_lag_skipped_total{reason="missing_first_event_at"} 1');
    expect(out).toContain('detection_lag_skipped_total{reason="negative_lag"} 1');
    expect(out).toContain('detection_lag_skipped_total{reason="invalid_interval"} 1');
  });

  test('接入 metrics.js：文本与快照都带上 detection（business.detection）', () => {
    detectionMetrics.recordDetection({
      dimension: 'high_frequency_failure_by_ip',
      lagMs: 1000,
      intervalMs: 300000,
    });
    const text = metrics.formatPrometheus();
    expect(text).toContain(
      'detection_lag_seconds_count{dimension="high_frequency_failure_by_ip"} 1'
    );

    const snap = metrics.getSnapshot();
    expect(snap.business.detection.dimensions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          dimension: 'high_frequency_failure_by_ip',
          lagSampleCount: 1,
          withinObjective: 1,
        }),
      ])
    );
    expect(Array.isArray(snap.business.detection.skipped)).toBe(true);
  });
});

describe('检测延迟：规则 ↔ 指标闭环', () => {
  const alertRulesYml = read('deployment/observability/alert-rules.yml');

  beforeEach(() => detectionMetrics.__resetForTest());

  test('规则引用 detections_within_objective_total 且按未达标标签过滤', () => {
    expect(alertRulesYml).toContain('detections_within_objective_total{within_objective="false"}');
    expect(alertRulesYml).toMatch(/alert:\s*AuditDetectionLagOutsideObjective/);
  });

  test('规则引用的检测指标真的渲染得出来（只加规则不补指标会恒不触发）', () => {
    detectionMetrics.recordDetection({
      dimension: 'high_frequency_failure',
      lagMs: 1000,
      intervalMs: 300000,
    });
    const out = metrics.formatPrometheus();
    expect(out).toContain('detections_within_objective_total{');
    expect(out).toContain('detection_lag_skipped_total{');
  });

  test('目标声明含 1× 依据，且明确 2× 恒绿的理由', () => {
    const src = read('src/constants/detectionObjectives.js');
    expect(src).toContain('OBJECTIVE_MULTIPLIER = 1');
    expect(src).toContain('60s');
    expect(src).toContain('2×');
  });
});
