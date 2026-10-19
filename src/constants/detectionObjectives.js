/**
 * 审计异常检测的 MTTD 目标声明（Plan B，2026-10-19）
 *
 * 口径：**统一 1× 生效检测间隔**（AUDIT_MONITOR_INTERVAL_MS，已在 auditMonitor
 * 中按 30s 下限钳制）。三个维度共用同一目标，不再按维度写不同倍数。
 *
 * 为什么不是 2×：
 *   检测窗口 W = interval + WINDOW_OVERLAP_MS（重叠余量 = 2×MIN_INTERVAL_MS = 60s），
 *   而 firstEventAt 必然落在窗口内，故 lag ≤ W。默认 5 分钟间隔下 W = 6 分钟，
 *   2× 目标（10 分钟）永远大于 W ⇒ 指标恒绿、没有任何判别力。
 *   1× 目标有意义，代价是窗口重叠余量会让最多 60s 的延迟落在目标之外——
 *   这是**已声明**的漏检带，不是实现偏差。
 *
 * 本模块只做纯计算，不 require auditMonitor（避免循环依赖）；调用方传入
 * 当前生效间隔。
 */

'use strict';

/** 检测维度闭合集合（与 auditMonitor 的三路聚合一一对应） */
const DETECTION_DIMENSIONS = Object.freeze([
  'high_frequency_failure',
  'high_frequency_failure_by_ip',
  'unusual_time_operation',
]);

/** 未登记维度统一并入 other，绝不按调用方自由文本建 series */
const UNKNOWN_DETECTION_DIMENSION = 'other';

const DETECTION_DIMENSION_SET = new Set([...DETECTION_DIMENSIONS, UNKNOWN_DETECTION_DIMENSION]);

/** 统一目标倍数：1× 生效检测间隔 */
const OBJECTIVE_MULTIPLIER = 1;

const OBJECTIVE_BASIS =
  '统一 1× 生效检测间隔；检测窗口 = 间隔 + 60s 重叠余量，' +
  '因此最多 60s 的延迟会落在目标之外（已声明的漏检带）';

/** 维度归一：未登记值并入 other */
function normalizeDetectionDimension(dimension) {
  return DETECTION_DIMENSION_SET.has(dimension) ? dimension : UNKNOWN_DETECTION_DIMENSION;
}

/**
 * 目标毫秒数。
 * @param {number} intervalMs 当前生效检测间隔
 * @returns {number|null} 非法间隔返回 null（调用方不得据此记样本）
 */
function resolveDetectionTargetMs(intervalMs) {
  const value = Number(intervalMs);
  if (!Number.isFinite(value) || value <= 0) return null;
  return value * OBJECTIVE_MULTIPLIER;
}

/**
 * 判定一次检测延迟是否达标。
 * @param {{intervalMs: number, lagMs: number}} input
 * @returns {{targetMs: number|null, withinObjective: boolean|null}}
 *   lag 非法时 withinObjective 为 null（未知，不等于未达标）
 */
function evaluateDetectionLag({ intervalMs, lagMs } = {}) {
  const targetMs = resolveDetectionTargetMs(intervalMs);
  if (targetMs === null) return { targetMs: null, withinObjective: null };
  if (!Number.isFinite(lagMs) || lagMs < 0) {
    return { targetMs, withinObjective: null };
  }
  return { targetMs, withinObjective: lagMs <= targetMs };
}

module.exports = {
  DETECTION_DIMENSIONS,
  UNKNOWN_DETECTION_DIMENSION,
  OBJECTIVE_MULTIPLIER,
  OBJECTIVE_BASIS,
  normalizeDetectionDimension,
  resolveDetectionTargetMs,
  evaluateDetectionLag,
};
