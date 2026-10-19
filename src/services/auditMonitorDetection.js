/**
 * 审计异常检测的 MTTD 记账（Plan B，2026-10-19）
 *
 * 从 auditMonitor.runDetection 抽出的纯记账层：把 detectAnomalies 的三路结果
 * 换算成每个维度的检测延迟，写入指标并生成告警载荷里的 `detection` 字段。
 *
 * 口径（见 constants/detectionObjectives.js）：
 *   - 统一 1× 生效检测间隔；
 *   - 每个维度取**组内最早事件**（min firstEventAt）作为起点——它是"这组行为
 *     从什么时候开始"的可观测下界，而不是窗口起点；
 *   - 缺少 firstEventAt（旧模型/测试替身）或时钟倒挂时不猜测，记 skipped
 *     并以 null 透出，指标样本不增加；
 *   - **所有命中的维度都记账**，不受"当日只推送一次"频控影响：频控是通知策略，
 *     不是检测是否发生的判据。
 */

'use strict';

const { DETECTION_DIMENSIONS } = require('../constants/detectionObjectives');
const detectionMetrics = require('../utils/metricsDetection');

/** 三路结果 → 维度名（顺序固定，与指标闭合集合一致） */
const DIMENSION_SOURCES = Object.freeze([
  ['high_frequency_failure', 'failedOperations'],
  ['high_frequency_failure_by_ip', 'failedOperationsByIp'],
  ['unusual_time_operation', 'unusualTimeOperations'],
]);

/** 取一组聚合行的最早事件时间（毫秒）；缺失/非法返回 null */
function firstEventMsOf(rows) {
  let earliest = null;
  for (const row of rows || []) {
    if (!row || row.firstEventAt === undefined || row.firstEventAt === null) continue;
    const ms = new Date(row.firstEventAt).getTime();
    if (!Number.isFinite(ms)) continue;
    if (earliest === null || ms < earliest) earliest = ms;
  }
  return earliest;
}

/**
 * 记录一轮检测的延迟，并返回告警载荷用的逐维度明细。
 *
 * @param {object} result detectAnomalies 的返回值
 * @param {number} detectedAt 检测完成的时刻（Date.now()，在 await 之后立即取）
 * @param {number} intervalMs 当前生效检测间隔
 * @returns {Array<{dimension: string, lagSeconds: number|null,
 *   targetSeconds: number|null, withinObjective: boolean|null,
 *   firstEventAt: string|null}>}
 */
function recordDetectionLag(result, detectedAt, intervalMs) {
  const rows = result || {};
  const entries = [];

  for (const [dimension, key] of DIMENSION_SOURCES) {
    if (!DETECTION_DIMENSIONS.includes(dimension)) continue;
    const groupRows = rows[key] || [];
    if (groupRows.length === 0) continue;

    const firstEventMs = firstEventMsOf(groupRows);
    const firstEventAt = firstEventMs === null ? null : new Date(firstEventMs).toISOString();

    // 时钟倒挂（NTP 回拨 / 固定时钟用例）不得被当成 0 延迟：把负值原样交给
    // recordDetection 归入 negative_lag，展示侧再折算成 null。
    const rawLag = firstEventMs === null ? NaN : detectedAt - firstEventMs;
    const lagMs = Number.isFinite(rawLag) && rawLag >= 0 ? rawLag : null;

    const { targetMs, withinObjective } = detectionMetrics.recordDetection({
      dimension,
      lagMs: rawLag,
      intervalMs,
    });

    entries.push({
      dimension,
      lagSeconds: lagMs === null ? null : Number((lagMs / 1000).toFixed(3)),
      targetSeconds: targetMs === null ? null : Number((targetMs / 1000).toFixed(3)),
      withinObjective,
      firstEventAt,
    });
  }

  return entries;
}

module.exports = { recordDetectionLag, firstEventMsOf };
