/**
 * 审计丢失/积压的 Prometheus 信号（2026-09-26 审计 Top-6）
 *
 * 缺陷：`services/auditBuffer.js` 有三条丢弃审计记录的路径（缓冲超硬上限裁剪、
 * 毒文档整批丢弃、预铸造拒收），全部只累加到模块内的 `droppedCount`——而它只能经
 * `GET /api/metrics`（需 security:audit 权限）的 JSON 看到。
 * 于是「审计记录被丢弃」这一**合规核心故障**在 Prometheus 侧完全不可见，
 * 仓内 5 条告警规则无一能覆盖它：留痕出现空洞，而所有面板照常满格。
 * auditBuffer 自己的注释写得很清楚——「静默丢弃审计数据在合规上等同于篡改」。
 *
 * 为什么单独成文件（而不是写在 utils/metrics.js 里）：那个文件的
 * max-lines 计数原本就贴着 300 的棘轮红线，新增这一节实测把它顶过线
 * （`[max-lines] 0 -> 1`）。按本仓纪律「体积/复杂度债只许降不许升」，
 * 拆出去是唯一出路；顺带让"审计丢失"这一组信号自成一体、可被单独断言。
 */

'use strict';

// reason 是**闭合集合**：绝不按调用方传的自由文本建 series，
// 否则又成了"用高基数计数器监控高基数"（与 metrics_series_dropped_total 的
// SERIES_STORES 同一条纪律）。'other' 收口未知取值，让拼错的 reason 不静默消失。
const AUDIT_DROP_REASONS = ['buffer_overflow', 'poison_doc', 'precast', 'other'];
const auditDrops = new Map(); // reason -> 累计丢弃条数

/**
 * 审计记录丢弃计数（auditBuffer 调用）
 *
 * @param {'buffer_overflow'|'poison_doc'|'precast'} reason 闭合集合外的取值一律并入 other
 * @param {number} [n=1] 本次丢弃条数；非正数不记账（"丢了 0 条"不该出现，
 *   出现即调用方算错，静默接受会让计数变成无法解释的漂移）
 */
function incAuditDrop(reason, n = 1) {
  try {
    const key = AUDIT_DROP_REASONS.includes(reason) ? reason : 'other';
    if (!Number.isFinite(n) || n <= 0) return;
    auditDrops.set(key, (auditDrops.get(key) || 0) + n);
  } catch (_) {
    /* 采集失败不影响审计主流程 */
  }
}

/**
 * 审计缓冲积压量（gauge）：**拉取时取值**，不由 auditBuffer 在每条变更点上上报。
 *
 * 为什么不做成 push：gauge 是时点量，而缓冲长度会在 push / flush / 回退 /
 * 裁剪 / 重放等**多处**变化，靠调用方逐个同步点上报，漏掉任何一条路径就得到
 * 一个悄悄偏小的数——那比没有这个指标更糟（面板会替"丢数据"作证清白）。
 * 拉取时读一次从构造上消灭了这一类漏报。
 *
 * 惰性 require 断开 util→service 的加载环（auditBuffer 反向 require metrics），
 * 且取不到时回 0 而不是抛错：抓取指标绝不能影响业务。
 */
function auditBacklog() {
  try {
    return require('../services/auditBuffer').getStats().bufferLength;
  } catch (_) {
    return 0;
  }
}

/**
 * 渲染本组信号：reason 恒定各一行（含 0）。
 *
 * 打 0 而不是"没有丢弃就不输出"：PromQL 里「series 不存在」与「series 为 0」
 * 是两种状态（前者让 increase() 无从绑定），运维在面板上不该去分辨
 * "从没丢过" 和 "这一版代码没上报这个指标"。
 */
function formatAuditDrops() {
  const out = [];
  out.push(
    '# HELP audit_records_dropped_total Audit records discarded before persistence (compliance hole)'
  );
  out.push('# TYPE audit_records_dropped_total counter');
  for (const reason of AUDIT_DROP_REASONS) {
    out.push(
      'audit_records_dropped_total{reason="' + reason + '"} ' + (auditDrops.get(reason) || 0)
    );
  }
  out.push(
    '# HELP audit_buffer_backlog_records Audit records currently held in the in-process buffer'
  );
  out.push('# TYPE audit_buffer_backlog_records gauge');
  out.push('audit_buffer_backlog_records ' + auditBacklog());
  return out;
}

module.exports = { AUDIT_DROP_REASONS, incAuditDrop, formatAuditDrops, _auditDrops: auditDrops };
