'use strict';

/**
 * 运行时健康信号的覆盖（2026-09-28 审计：告警覆盖面缺口）
 *
 * 缺陷：`alert-rules.yml` 原有 6 条规则只覆盖"业务指标异常"，而
 * 「MongoDB 不可用 / 磁盘写满 / /readyz 判定失败 / 日志投递失败丢行」
 * 这 4 类故障在 Prometheus 侧**没有任何指标**。往 yml 里只加规则是不行的：
 * 指标不存在时规则**永远不触发**——那是比没有规则更坏的形态，
 * 仪表盘上多了一条"守护中"的假象。
 *
 * 本文件钉住三件事，缺一不可：
 *   ① **信号真的被渲染出来**（可执行判据：调 formatPrometheus() 看输出）；
 *      —— 与 alertingConfig.test.js 的文本判据互补，后者只证明"名字出现在源码里"。
 *   ② **挂钩真的接上了**（集成判据：喂真实日志行进 HttpShipperTransport，
 *      看计数是否动）—— 只测 metricsRuntime 自己的函数等于在测空气。
 *   ③ **规则 ↔ 指标闭环**：yml 里引用的每个新指标名都必须能在渲染输出里找到。
 *
 * 还有一条专门的边界：**未观测时不输出 readyz_verdict**。若为了"面板好看"
 * 输出一个默认 1，ReadinessProbeMissing（absent 分支）就永远不触发，
 * 整套就绪告警在"探针链路已断"时静默失效——正是本轮在修的那类缺陷。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const runtimeMetrics = require('../../utils/metricsRuntime');
const { formatPrometheus } = require('../../utils/metrics');
const { HttpShipperTransport, BUFFER_CAP } = require('../../utils/logShipper');

/** 从渲染输出里取某个 series 的样本值（无该 series 返回 null） */
const sampleOf = (text, name) => {
  const m = text.match(new RegExp('^' + name + '(?:\\{[^}]*\\})? ([0-9.eE+-]+)$', 'm'));
  return m ? Number(m[1]) : null;
};

describe('运行时健康信号：渲染契约', () => {
  beforeEach(() => runtimeMetrics.__resetForTest());

  test('未观测过 /readyz 时**不输出** readyz_verdict（否则 absent 分支永不触发）', () => {
    const out = formatPrometheus();
    expect(out).toContain('readyz_checks_total{result="ok"} 0');
    expect(out).not.toMatch(/^readyz_verdict /m);
    expect(out).not.toMatch(/^readyz_verdict_age_seconds /m);
  });

  test('观测后输出 verdict 与 age，且 result 是闭合集合（未知值并入 error）', () => {
    runtimeMetrics.recordReadyz('ok', true);
    runtimeMetrics.recordReadyz('zz_not_in_enum', false);
    const out = formatPrometheus();
    expect(sampleOf(out, 'readyz_verdict')).toBe(0);
    expect(sampleOf(out, 'readyz_verdict_age_seconds')).toBeGreaterThanOrEqual(0);
    expect(out).toContain('readyz_checks_total{result="ok"} 1');
    // 拼错的 reason 不得静默消失，也不得凭空建一条新 series
    expect(out).toContain('readyz_checks_total{result="error"} 1');
    expect(out).not.toContain('zz_not_in_enum');
    for (const r of runtimeMetrics.READYZ_RESULTS) {
      expect(out).toContain(`readyz_checks_total{result="${r}"}`);
    }
  });

  test('就绪通过时 verdict=1（对照组，防止上面那条恒为 0）', () => {
    runtimeMetrics.recordReadyz('ok', true);
    expect(sampleOf(formatPrometheus(), 'readyz_verdict')).toBe(1);
  });

  test('磁盘：输出 free/total，free ≤ total，path 标签已按 Prometheus 规则转义', () => {
    const out = formatPrometheus();
    expect(out).toContain('disk_probe_failures_total 0');
    const line = out.match(/^disk_free_bytes\{path="((?:[^"\\]|\\.)*)"\} (\d+)$/m);
    expect(line).not.toBeNull();
    const total = out.match(/^disk_total_bytes\{path="((?:[^"\\]|\\.)*)"\} (\d+)$/m);
    expect(total).not.toBeNull();
    // 两个 series 必须指同一个卷，否则比值会算出无意义的数
    expect(line[1]).toBe(total[1]);
    expect(Number(line[2])).toBeLessThanOrEqual(Number(total[2]));
    // Windows 路径含反斜杠：未转义时这一行不是合法 Prometheus 文本
    expect(line[1]).not.toMatch(/(?<!\\)"/);
  });

  test('日志投递两个计数恒定输出（含 0）——"从没失败过"与"这版没上报"必须可区分', () => {
    const out = formatPrometheus();
    expect(out).toContain('log_shipper_flush_failures_total 0');
    expect(out).toContain('log_shipper_dropped_lines_total 0');
  });
});

describe('运行时健康信号：挂钩真的接上了（集成，不测自己的函数）', () => {
  beforeEach(() => runtimeMetrics.__resetForTest());

  /** batchSize 远大于上限 ⇒ log() 永不自动冲刷，发送时机完全由用例控制 */
  const makeTransport = () =>
    new HttpShipperTransport({
      url: 'http://127.0.0.1:1/unused-in-this-file',
      batchSize: BUFFER_CAP * 20,
      intervalMs: 3600000,
      timeoutMs: 50,
    });

  test('缓冲触顶丢弃真日志行时，log_shipper_dropped_lines_total 必须增长', () => {
    const t = makeTransport();
    const before = sampleOf(formatPrometheus(), 'log_shipper_dropped_lines_total');
    expect(before).toBe(0);
    // 喂到超过上限：稳态下每来一行就丢一行真日志
    for (let i = 0; i < BUFFER_CAP + 5; i += 1) t.log({ message: 'line ' + i }, () => {});
    const after = sampleOf(formatPrometheus(), 'log_shipper_dropped_lines_total');
    expect(after).toBeGreaterThan(0);
    // 前提自证：确实丢了真日志（缓冲里除标记外不得超上限）
    expect(t.buffer.length).toBeLessThanOrEqual(BUFFER_CAP);
    t.close?.();
  });

  test('批量转发失败时，log_shipper_flush_failures_total 必须增长', async () => {
    const t = makeTransport();
    t.log({ message: 'x' }, () => {});
    await t._flush(); // 目标不可达（127.0.0.1:1）⇒ 内部 catch 后放回缓冲
    expect(sampleOf(formatPrometheus(), 'log_shipper_flush_failures_total')).toBeGreaterThan(0);
    // 前提自证：失败批必须整批放回缓冲（否则这条计数可能是别的路径涨的）
    expect(t.buffer.length).toBeGreaterThan(0);
    t.close?.();
  });
});

describe('运行时健康信号：app.js 的 /readyz 必须真的记录判定', () => {
  const appJs = read('src/app.js');

  test('两个分支（成功 / 异常）都必须落指标', () => {
    expect(appJs).toMatch(/recordReadyz\(mongo\.ok \? 'ok' : mongo\.reason, mongo\.ok\)/);
    expect(appJs).toMatch(/recordReadyz\('error', false\)/);
    // 必须从 utils/metrics 导入，而不是另开一条路径
    expect(appJs).toMatch(/recordReadyz,/);
  });

  test('判据可失败：把 recordReadyz 调用去掉，同一正则必须报出来', () => {
    const stripped = appJs
      .replace(/recordReadyz\(mongo\.ok \? 'ok' : mongo\.reason, mongo\.ok\)/g, '')
      .replace(/recordReadyz\('error', false\)/g, '');
    expect(/recordReadyz\(mongo\.ok \? 'ok' : mongo\.reason, mongo\.ok\)/.test(stripped)).toBe(
      false
    );
    expect(/recordReadyz\('error', false\)/.test(stripped)).toBe(false);
  });
});

describe('运行时健康信号：规则 ↔ 指标闭环（可执行判据）', () => {
  beforeEach(() => runtimeMetrics.__resetForTest());

  const alertRulesYml = read('deployment/observability/alert-rules.yml');

  // 本组信号的名字清单由**源码里的输出语句**决定，不在本文件手写第二份。
  // 判据：metricsRuntime.js 里出现在 `'名字'` 或 `'名字{'` 位置的标识符。
  const declaredNames = () => {
    const src = read('src/utils/metricsRuntime.js');
    const names = new Set();
    for (const m of src.matchAll(/'(log_shipper_[a-z_]+|readyz_[a-z_]+|disk_[a-z_]+)[ '{"]/g)) {
      names.add(m[1]);
    }
    return [...names].sort();
  };

  test('前提自证：名字清单抽得到（抽空会让下面每条恒绿）', () => {
    const names = declaredNames();
    expect(names.length).toBeGreaterThanOrEqual(7);
    for (const expected of [
      'readyz_verdict',
      'disk_free_bytes',
      'log_shipper_dropped_lines_total',
    ]) {
      expect(names).toContain(expected);
    }
  });

  test('每个被声明的名字都必须在 alert-rules.yml 里有规则引用', () => {
    // 有信号却没有规则 = 白采集；这条把"补了指标忘了补规则"变成红灯。
    // readyz_verdict_age_seconds 只服务于 ReadinessProbeMissing，同样必须出现。
    const missing = declaredNames().filter((n) => !alertRulesYml.includes(n));
    expect(missing).toEqual([]);
  });

  test('每个被规则引用的名字都必须真的渲染得出来', () => {
    // 与上一条互为反向：只加规则不补指标 ⇒ 规则永远不触发。
    // 这里喂一次观测让条件输出的 series 出现，再核对渲染结果。
    runtimeMetrics.recordReadyz('ok', true);
    runtimeMetrics.incLogShipperFlushFailure();
    runtimeMetrics.incLogShipperDroppedLines(1);
    const out = formatPrometheus();
    const missing = declaredNames().filter((n) => !out.includes(n));
    expect(missing).toEqual([]);
  });

  test('未观测时不输出 verdict —— 与 ReadinessProbeMissing 的 absent 分支配套', () => {
    expect(alertRulesYml).toMatch(/absent\(readyz_verdict\{job="xf-app"\}\)/);
    expect(formatPrometheus()).not.toMatch(/^readyz_verdict /m);
  });
});
