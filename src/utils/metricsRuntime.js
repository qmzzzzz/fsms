/**
 * 运行时健康信号（2026-09-28 审计：告警覆盖面缺口）
 *
 * 缺陷：`deployment/observability/alert-rules.yml` 原有的 7 条规则只覆盖
 * 「抓取目标存活 / 5xx / P95 / 安全告警突发 / series 截断 / 审计记录丢弃」，
 * 而下面这 4 类故障在 Prometheus 侧**完全没有信号**：
 *   · MongoDB 不可用 —— 进程还活着、/metrics 照样能抓，业务已经干不了活；
 *   · 磁盘写满 —— WAL / 审计缓冲 / 日志全写不进去，最先表现为"静默丢数据"；
 *   · /readyz 判定失败 —— 编排器/LB 正在摘流量，而监控面板全绿；
 *   · 日志投递失败/丢行 —— SIEM 侧出现空洞，本地日志却照常完整。
 *
 * **只往 yml 里加规则是不行的**：指标不存在时规则**永远不触发**，
 * 那会造出"看起来在守护、实际是装饰"的静默规则——正是本轮在修的同一类缺陷。
 * 所以顺序必须是**先补信号，再补规则**。
 *
 * 为什么单独成文件：`utils/metrics.js` 的 max-lines 计数贴着棘轮红线
 * （与 metricsAuditDrops.js 同一个理由），且这组信号自成一体、可被单独断言。
 *
 * 采集方式分两类，选择理由各自写在下方注释里：
 *   · counter（转发失败 / 丢行 / 探针失败）：**push**。事件点唯一且明确，
 *     调用方就在事发处，不存在"漏掉某条路径"的空间。
 *   · gauge（就绪判定）：**记录最近一次观测**，不自己起定时器去 ping Mongo。
 *     代价是"没人探测就没有新值"——用 `readyz_verdict_age_seconds` 与
 *     `absent()` 把这件事本身也变成可观测量，配套规则见 ReadinessProbeMissing。
 */

'use strict';

const fs = require('fs');
const { LOG_DIR } = require('./logPaths');

// result 是**闭合集合**：绝不按调用方自由文本建 series（高基数纪律）。
// 取值 = healthChecks.checkMongoReady 的 reason 枚举 + /readyz 的兜底 catch 分支。
const READYZ_RESULTS = ['ok', 'disconnected', 'timeout', 'unreachable', 'error'];
const readyzChecks = new Map(); // result -> 累计判定次数
let lastReadyz = null; // { ok, result, at } | null = 从未被观测

/**
 * 记录一次 /readyz 判定结果。
 *
 * 为什么不在这里自己起定时器 ping Mongo：`/readyz` 已被 LB/编排器高频调用，
 * 且 `checkMongoReady` 自带 1s 进程内缓存（S-M1：防止探针变成对 Mongo 的
 * 间接 DoS 放大）。再起一个定时器等于把这个放大倍数翻倍。
 *
 * @param {'ok'|'disconnected'|'timeout'|'unreachable'|'error'} result 闭合集合外的取值并入 error
 * @param {boolean} ok
 */
function recordReadyz(result, ok) {
  try {
    const key = READYZ_RESULTS.includes(result) ? result : 'error';
    readyzChecks.set(key, (readyzChecks.get(key) || 0) + 1);
    lastReadyz = { ok: ok === true, result: key, at: Date.now() };
  } catch (_) {
    /* 采集失败绝不影响探针响应 */
  }
}

// 日志投递：计数走 push —— 事件点唯一（转发失败、裁剪丢弃），调用方就在事发处。
let shipperFlushFailures = 0;
let shipperDroppedLines = 0;

/** 一次批量转发失败（logShipper._flush 的 catch） */
function incLogShipperFlushFailure() {
  try {
    shipperFlushFailures += 1;
  } catch (_) {
    /* 采集失败不影响日志主流程 */
  }
}

/**
 * 因缓冲触顶丢弃的**真日志行数**（不含断档标记那一格）
 *
 * @param {number} [n=1] 非正数不记账：调用方算错时静默接受会让计数变成无法解释的漂移
 */
function incLogShipperDroppedLines(n = 1) {
  try {
    if (Number.isFinite(n) && n > 0) shipperDroppedLines += n;
  } catch (_) {
    /* 同上 */
  }
}

// 磁盘：statfsSync 是同步系统调用，抓取路径上不能每抓一次打一次
// （LOG_DIR 在容器里常是网络卷）。加 15s 进程内缓存。
// 探针失败只记数、不抛，且**不输出**磁盘 series —— 让"量不到"与"量为 0"
// 区分开，由 disk_probe_failures_total 单独暴露（配套规则 DiskProbeFailing）。
const DISK_TTL_MS = 15000;
let diskAt = 0;
let diskRows = null;
let diskProbeFailures = 0;

function probeDisk() {
  const now = Date.now();
  if (now - diskAt < DISK_TTL_MS) return diskRows;
  diskAt = now;
  try {
    const st = fs.statfsSync(LOG_DIR);
    diskRows = { free: st.bsize * st.bavail, total: st.bsize * st.blocks };
  } catch (_) {
    diskProbeFailures += 1;
    diskRows = null;
  }
  return diskRows;
}

/** Prometheus label value 转义（`\` `"` 换行）；Windows 路径含反斜杠，必须转 */
function labelValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

/**
 * 就绪判定：result 恒定各一行（含 0）。
 *
 * verdict 只在**被观测过之后**才输出：从未观测时输出一个伪造的 1 会让
 * "没人探测" 与 "探测正常" 无法区分，ReadinessProbeMissing 也就永远不触发。
 */
function formatReadyz() {
  const out = [
    '# HELP readyz_checks_total /readyz verdicts by result',
    '# TYPE readyz_checks_total counter',
  ];
  for (const result of READYZ_RESULTS) {
    out.push('readyz_checks_total{result="' + result + '"} ' + (readyzChecks.get(result) || 0));
  }
  if (!lastReadyz) return out;
  out.push('# HELP readyz_verdict Last /readyz verdict (1=ready, 0=unready)');
  out.push('# TYPE readyz_verdict gauge');
  out.push('readyz_verdict ' + (lastReadyz.ok ? 1 : 0));
  out.push('# HELP readyz_verdict_age_seconds Seconds since the last /readyz verdict');
  out.push('# TYPE readyz_verdict_age_seconds gauge');
  out.push('readyz_verdict_age_seconds ' + Math.floor((Date.now() - lastReadyz.at) / 1000));
  return out;
}

/** 磁盘：探针成功才输出 free/total；失败恒输出失败计数（含 0） */
function formatDisk() {
  const out = [
    '# HELP disk_probe_failures_total Disk statfs probes that failed (metric would be missing otherwise)',
    '# TYPE disk_probe_failures_total counter',
    'disk_probe_failures_total ' + diskProbeFailures,
  ];
  const rows = probeDisk();
  if (!rows) return out;
  const pathLabel = labelValue(LOG_DIR);
  out.push('# HELP disk_free_bytes Free bytes on the volume holding the log directory');
  out.push('# TYPE disk_free_bytes gauge');
  out.push('disk_free_bytes{path="' + pathLabel + '"} ' + rows.free);
  out.push('# HELP disk_total_bytes Total bytes on the volume holding the log directory');
  out.push('# TYPE disk_total_bytes gauge');
  out.push('disk_total_bytes{path="' + pathLabel + '"} ' + rows.total);
  return out;
}

/** 日志投递：恒定输出（含 0）——「从没失败过」与「这一版没上报」必须可区分 */
function formatShipper() {
  return [
    '# HELP log_shipper_flush_failures_total Log batches that failed to reach the SIEM endpoint',
    '# TYPE log_shipper_flush_failures_total counter',
    'log_shipper_flush_failures_total ' + shipperFlushFailures,
    '# HELP log_shipper_dropped_lines_total Log lines dropped because the in-process buffer hit its cap',
    '# TYPE log_shipper_dropped_lines_total counter',
    'log_shipper_dropped_lines_total ' + shipperDroppedLines,
  ];
}

/** 渲染本组全部信号（供 metrics.formatPrometheus 拼接） */
function formatRuntime() {
  return [...formatReadyz(), ...formatDisk(), ...formatShipper()];
}

/** 仅供测试重置（生产不调用） */
function __resetForTest() {
  readyzChecks.clear();
  lastReadyz = null;
  shipperFlushFailures = 0;
  shipperDroppedLines = 0;
  diskAt = 0;
  diskRows = null;
  diskProbeFailures = 0;
}

module.exports = {
  READYZ_RESULTS,
  recordReadyz,
  incLogShipperFlushFailure,
  incLogShipperDroppedLines,
  formatRuntime,
  __resetForTest,
};
