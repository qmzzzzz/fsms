/**
 * 告警规则的语法/语义校验门禁（2026-09-26 审计 Top-6 后半）
 *
 * 缺陷原文：「`alert-rules.yml`（全仓 0 promtool）—— 告警规则**从未被求值/校验**：
 * PromQL 语法错 → Prometheus 整组加载失败 → 全部告警静默失效而 CI 全绿」。
 *
 * 这类失效的可怕之处在于**它把监控变成安慰剂**：规则文件里一个括号写错，
 * Prometheus 启动时整组加载失败（只在自己的日志里报一行），而本仓的
 * `alertingConfig.test.js` 只做"字符串级"一致性（severity 覆盖、指标名存在），
 * 对"这段 PromQL 能不能被解析"一个字都管不到 —— 于是 CI 全绿、上线后没有告警。
 *
 * 本文件把 `scripts/alertRulesPolicy.js` 接到 CI：它随 `npm test` 跑，
 * 不需要新增依赖、也不需要联网取 promtool 二进制。
 * 每条夹具都同时有**正对照**（合法写法必须放行）——否则一个"永远报错"的
 * 校验器也能让所有负向用例通过，而那会让规则文件永远改不动。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { validateAlertRules, parseAlertRules } = require('../../../scripts/alertRulesPolicy');

const ROOT = path.resolve(__dirname, '../../..');
const RULES_PATH = path.join(ROOT, 'deployment/observability/alert-rules.yml');
const REAL = fs.readFileSync(RULES_PATH, 'utf8');

/** 造一条最小合法规则，供各夹具按需污染 */
const rule = ({
  name = 'Demo',
  expr = 'up{job="xf-app"} == 0',
  forText = '1m',
  severity = 'critical',
} = {}) =>
  [
    'groups:',
    '  - name: demo',
    '    rules:',
    `      - alert: ${name}`,
    `        expr: ${expr}`,
    ...(forText === null ? [] : [`        for: ${forText}`]),
    '        labels:',
    ...(severity === null ? [] : [`          severity: ${severity}`]),
    '        annotations:',
    "          summary: 'demo'",
    '',
  ].join('\n');

describe('Top-6 后半：真实告警规则文件必须零问题', () => {
  test('解析出全部规则（解析器退化会让本门禁恒绿）', () => {
    const rules = parseAlertRules(REAL);
    // 前提自证：至少 6 条（可用性/延迟/安全/自监控两组 + 审计丢弃），
    // 且每条都真的拿到了 expr 与 severity
    expect(rules.length).toBeGreaterThanOrEqual(6);
    for (const r of rules) {
      expect({ name: r.name, hasExpr: r.expr.length > 0 }).toMatchObject({
        name: expect.any(String),
        hasExpr: true,
      });
    }
    expect(rules.map((r) => r.name)).toEqual(
      expect.arrayContaining([
        'BackendDown',
        'HighErrorRate',
        'HighP95Latency',
        'SecurityAlertBurst',
        'MetricsSeriesTruncated',
        'AuditRecordsDropped',
      ])
    );
  });

  test('validateAlertRules 对真实文件返回空问题集', () => {
    expect(validateAlertRules(REAL)).toEqual([]);
  });

  test('每条规则都拿到了 for 时长（块标量/行内两种写法都被解析）', () => {
    const rules = parseAlertRules(REAL);
    // 本文件里 expr 既有行内（`expr: up{...} == 0`）也有块标量（`expr: |`），
    // 两种形态都必须被吃下——只认行内的话，多行表达式会被静默截断成半句。
    expect(rules.some((r) => r.expr.includes('\n'))).toBe(true);
    for (const r of rules) expect(r.forText).not.toBe('');
  });
});

describe('Top-6 后半：各类"整组加载失败"形态必须被拦下', () => {
  test('括号不配平', () => {
    expect(validateAlertRules(rule({ expr: 'sum(rate(x_total[5m])' }))).toEqual([
      expect.stringContaining('括号不配平'),
    ]);
    expect(validateAlertRules(rule({ expr: 'sum(rate(x_total[5m])) > 0' }))).toEqual([]);
  });

  test('函数名拼错（PromQL 不认识）', () => {
    const bad = validateAlertRules(rule({ expr: 'histogram_quantile_x(0.95, x_bucket) > 1' }));
    expect(bad).toEqual([expect.stringContaining('histogram_quantile_x')]);
    expect(validateAlertRules(rule({ expr: 'histogram_quantile(0.95, x_bucket) > 1' }))).toEqual(
      []
    );
  });

  test('聚合修饰 by/without 不被误判为"未知函数"（正对照，防过严门禁）', () => {
    // `sum by (le) (...)` 里 `by` 后面紧跟 `(`，最容易被写成"未知函数"而误报。
    // 这类误报的代价是门禁变成噪声、最终被人绕过。
    for (const expr of [
      'sum by (le) (rate(x_bucket[5m])) > 1',
      'sum without (instance) (rate(x_total[5m])) > 0',
      'count by (route) (x_total) > 100',
    ]) {
      expect({ expr, problems: validateAlertRules(rule({ expr })) }).toMatchObject({
        expr,
        problems: [],
      });
    }
  });

  test('区间向量时长写法非法', () => {
    for (const dur of ['5min', '5', 'm5', '5 m']) {
      expect(validateAlertRules(rule({ expr: `increase(x_total[${dur}]) > 0` }))).toEqual([
        expect.stringContaining('区间向量时长非法'),
      ]);
    }
    // 正对照：多段时长是合法写法
    expect(validateAlertRules(rule({ expr: 'increase(x_total[1h30m]) > 0' }))).toEqual([]);
  });

  test('for 时长非法', () => {
    expect(validateAlertRules(rule({ forText: '1min' }))).toEqual([
      expect.stringContaining('for 时长非法'),
    ]);
    expect(validateAlertRules(rule({ forText: '0m' }))).toEqual([]);
  });

  test('缺 severity 标签（Alertmanager 无路由可命中）', () => {
    expect(validateAlertRules(rule({ severity: null }))).toEqual([
      expect.stringContaining('severity'),
    ]);
  });

  test('alert 名重复', () => {
    const dup = rule({ name: 'Dup' }) + rule({ name: 'Dup', expr: 'up{job="x"} == 1' });
    expect(validateAlertRules(dup)).toEqual([expect.stringContaining('alert 名重复')]);
  });

  test('expr 为空', () => {
    const src = ['groups:', '  - name: g', '    rules:', '      - alert: NoExpr', ''].join('\n');
    expect(validateAlertRules(src)).toEqual([expect.stringContaining('expr 为空')]);
  });

  test('解析不出任何规则 → 报"解析器漂移"而不是静默通过', () => {
    // 这是本门禁自身的假绿形态：结构一变（比如有人把 rules 改成别的层级），
    // 解析器返回空数组，若那时判"没问题"，门禁就永久空转了。
    for (const src of ['', '# 只有注释\n', 'groups: []\n', 'something_else:\n  a: 1\n']) {
      expect(validateAlertRules(src)).toEqual([expect.stringContaining('未能从 alert-rules.yml')]);
    }
  });

  test('引号内的括号不参与配平判定（防误报）', () => {
    // `{status_code=~"5.."}` 这类正则里出现括号是常见的；不剥引号就会误报。
    expect(
      validateAlertRules(rule({ expr: 'sum(rate(x_total{path=~"/(a|b)"}[5m])) > 0' }))
    ).toEqual([]);
  });
});
