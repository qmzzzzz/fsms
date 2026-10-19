/**
 * 审计异常检测的 MTTD 指标（Plan B，2026-10-19）
 *
 * 与 metricsAuditDrops / metricsRuntime 单独成文件的理由相同：
 * `utils/metrics.js` 的 max-lines 贴着 300 行棘轮红线。
 *
 * 维度是**闭合集合**（见 constants/detectionObjectives.js）：绝不按调用方
 * 自由文本建 series。未知维度并入 `other`，与 metrics_series_dropped_total
 * 的 store 闭合纪律同源。
 *
 * 指标：
 *   - detection_lag_seconds_sum{dimension} / _count{dimension}
 *       检测延迟（秒）的累计和与样本数；内部存毫秒，渲染时换算。
 *   - detections_within_objective_total{dimension,within_objective}
 *       达标/未达标次数。`within_objective` 是字符串 "true"/"false"，
 *       让 PromQL 可以直接按标签过滤。
 *   - detection_objective_seconds{dimension}
 *       当前目标值（秒）的 gauge；只在目标已知时输出——输出 0 会被读成
 *       "目标为零"，与"尚未测得目标"是两种状态。
 *   - detection_lag_skipped_total{reason}
 *       无法计算延迟的样本数（firstEventAt 缺失、时钟倒挂、间隔非法）。
 *       没有它时，缺失数据与"从未命中"在 Prometheus 侧不可区分。
 *
 * 采集**始终开启**：纯内存操作，METRICS_ENABLED 只控制 /metrics 端点是否暴露。
 */

'use strict';

const {
  DETECTION_DIMENSIONS,
  UNKNOWN_DETECTION_DIMENSION,
  normalizeDetectionDimension,
  evaluateDetectionLag,
} = require('../constants/detectionObjectives');

/** 跳过原因闭合集合：未知原因并入 other，避免高基数 */
const SKIP_REASONS = Object.freeze(['missing_first_event_at', 'negative_lag', 'invalid_interval']);
const UNKNOWN_SKIP_REASON = 'other';
const SKIP_REASON_SET = new Set([...SKIP_REASONS, UNKNOWN_SKIP_REASON]);

const ALL_DIMENSIONS = [...DETECTION_DIMENSIONS, UNKNOWN_DETECTION_DIMENSION];

/** dimension -> { sumMs, count } */
const lagStats = new Map();
/** dimension -> { true: n, false: n } */
const objectiveCounts = new Map();
/** dimension -> 目标毫秒数（最近一次成功判定时记录） */
const objectiveMs = new Map();
/** reason -> 累计跳过次数 */
const skipped = new Map();

function ensureLag(dimension) {
  let row = lagStats.get(dimension);
  if (!row) {
    row = { sumMs: 0, count: 0 };
    lagStats.set(dimension, row);
  }
  return row;
}

function ensureObjective(dimension) {
  let row = objectiveCounts.get(dimension);
  if (!row) {
    row = { true: 0, false: 0 };
    objectiveCounts.set(dimension, row);
  }
  return row;
}

/**
 * 记录一次检测延迟。
 *
 * @param {{dimension: string, lagMs: number, intervalMs: number}} input
 * @returns {{targetMs: number|null, withinObjective: boolean|null}}
 */
function recordDetection({ dimension, lagMs, intervalMs } = {}) {
  const dim = normalizeDetectionDimension(dimension);
  const { targetMs, withinObjective } = evaluateDetectionLag({ intervalMs, lagMs });

  if (targetMs === null) {
    recordSkipped('invalid_interval');
    return { targetMs, withinObjective };
  }
  if (!Number.isFinite(lagMs) || lagMs < 0) {
    recordSkipped(Number.isFinite(lagMs) ? 'negative_lag' : 'missing_first_event_at');
    return { targetMs, withinObjective };
  }

  const row = ensureLag(dim);
  row.sumMs += lagMs;
  row.count += 1;
  objectiveMs.set(dim, targetMs);
  ensureObjective(dim)[withinObjective ? 'true' : 'false'] += 1;

  return { targetMs, withinObjective };
}

/** 记录一次无法计算延迟的样本（原因闭合，未知并入 other） */
function recordSkipped(reason) {
  const key = SKIP_REASON_SET.has(reason) ? reason : UNKNOWN_SKIP_REASON;
  skipped.set(key, (skipped.get(key) || 0) + 1);
}

const seconds = (ms) => Number((ms / 1000).toFixed(6));

/** 渲染 Prometheus 文本（供 metrics.formatPrometheus 拼接） */
function formatDetection() {
  const out = [];

  out.push('# HELP detection_lag_seconds Detection lag from first matching event to detection');
  out.push('# TYPE detection_lag_seconds summary');
  for (const dimension of ALL_DIMENSIONS) {
    const row = lagStats.get(dimension) || { sumMs: 0, count: 0 };
    out.push(`detection_lag_seconds_sum{dimension="${dimension}"} ${seconds(row.sumMs)}`);
    out.push(`detection_lag_seconds_count{dimension="${dimension}"} ${row.count}`);
  }

  out.push(
    '# HELP detections_within_objective_total Detections evaluated against the MTTD objective'
  );
  out.push('# TYPE detections_within_objective_total counter');
  for (const dimension of ALL_DIMENSIONS) {
    const row = objectiveCounts.get(dimension) || { true: 0, false: 0 };
    for (const within of ['true', 'false']) {
      out.push(
        `detections_within_objective_total{dimension="${dimension}",` +
          `within_objective="${within}"} ${row[within]}`
      );
    }
  }

  const objectiveDimensions = ALL_DIMENSIONS.filter((d) => objectiveMs.has(d));
  if (objectiveDimensions.length > 0) {
    out.push('# HELP detection_objective_seconds Current MTTD objective by dimension');
    out.push('# TYPE detection_objective_seconds gauge');
    for (const dimension of objectiveDimensions) {
      out.push(
        `detection_objective_seconds{dimension="${dimension}"} ${seconds(objectiveMs.get(dimension))}`
      );
    }
  }

  out.push(
    '# HELP detection_lag_skipped_total Detections whose lag could not be computed (missing data)'
  );
  out.push('# TYPE detection_lag_skipped_total counter');
  for (const reason of [...SKIP_REASONS, UNKNOWN_SKIP_REASON]) {
    out.push(`detection_lag_skipped_total{reason="${reason}"} ${skipped.get(reason) || 0}`);
  }

  return out;
}

/** 快照侧同一事实（/api/metrics 面板读这份，口径必须与文本一致） */
function getDetectionSnapshot() {
  const dimensions = ALL_DIMENSIONS.map((dimension) => {
    const lag = lagStats.get(dimension) || { sumMs: 0, count: 0 };
    const within = objectiveCounts.get(dimension) || { true: 0, false: 0 };
    return {
      dimension,
      lagSecondsSum: seconds(lag.sumMs),
      lagSampleCount: lag.count,
      withinObjective: within.true,
      outsideObjective: within.false,
      objectiveSeconds: objectiveMs.has(dimension) ? seconds(objectiveMs.get(dimension)) : null,
    };
  });
  return {
    dimensions,
    skipped: [...SKIP_REASONS, UNKNOWN_SKIP_REASON].map((reason) => ({
      reason,
      count: skipped.get(reason) || 0,
    })),
  };
}

/** 仅供测试重置（生产不调用） */
function __resetForTest() {
  lagStats.clear();
  objectiveCounts.clear();
  objectiveMs.clear();
  skipped.clear();
}

module.exports = {
  SKIP_REASONS,
  recordDetection,
  recordSkipped,
  formatDetection,
  getDetectionSnapshot,
  __resetForTest,
};
