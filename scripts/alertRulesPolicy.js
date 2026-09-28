/**
 * 告警规则的静态校验（2026-09-26 审计 Top-6 后半）
 *
 * 缺陷原文：「`alert-rules.yml`（全仓 0 promtool）—— 告警规则**从未被求值/校验**：
 * PromQL 语法错 → Prometheus 整组加载失败 → 全部告警静默失效而 CI 全绿」，
 * 修复面「CI 加 promtool」。
 *
 * 为什么不直接调 promtool：本仓的硬约束是**不新增依赖**，而 promtool 是 Prometheus
 * 官方二进制（既非 npm 包，也不在镜像里），CI 要用它就得引入一个下载步骤与版本钉桩；
 * 而 `deploy.yml` 的现状是「从未在 GitHub Actions 上真实跑过」（文件头自陈），
 * 再加一条需要联网取二进制的步骤，等于把一个未验证的环节接进唯一的上线路径。
 *
 * 于是这里实现 promtool 在**本仓真正需要**的那个子集——即"错一处就让整组规则加载失败"
 * 的形态（promtool 的 `check rules` 主要就是在抓这几类）：
 *   1. 括号/方括号/花括号不配平（PromQL 最常见的加载期错误）；
 *   2. 函数名不在 PromQL 内置函数表里（拼错 `histogram_quantile` / 少个字母）；
 *   3. 区间向量时长写法非法（`[5min]` / `[5]` / `[m5]`）；
 *   4. `for:` 时长非法（`for: 1min`）—— 这条会让规则整条加载失败；
 *   5. 缺 expr / 缺 severity / alert 名重复（后者让 Prometheus 加载报 duplicate）。
 *
 * 能力边界（如实说明）：这不是 PromQL 完整语法分析器，不做类型检查、不校验
 * 标签匹配语义、不验证指标是否真实存在（后者由
 * src/tests/observability/alertingConfig.test.js 覆盖）。
 * 若将来本仓引入 promtool，应把它作为**补充**而非替代：本模块抓得住
 * "指标名拼错"（promtool 抓不住，因为它不认识本服务的指标）。
 *
 * 零依赖：与 compliance-alerting.js 同样的逐行解析思路，不引 js-yaml
 * （它是传递依赖，进 CI 门禁会把锁文件变更变成红灯）。
 *
 * 结构说明：解析与校验都按"一类问题一个小函数"拆开，而不是一个大状态机。
 * 这不是为拆分而拆分——单函数版本实测触发复杂度棘轮（0 -> 2 warn），
 * 而按本仓纪律基线只许降不许升；拆开后每个函数各自可被单独断言。
 */

'use strict';

/** PromQL 内置函数 + 语法上紧跟 `(` 的关键字（by/without/on/ignoring…） */
const PROMQL_CALLABLES = new Set([
  // 聚合运算符
  'sum',
  'min',
  'max',
  'avg',
  'group',
  'stddev',
  'stdvar',
  'count',
  'count_values',
  'bottomk',
  'topk',
  'quantile',
  'limitk',
  'limit_ratio',
  // 聚合修饰（`sum by (le) (...)` 里 `by` 后面就是 `(`）
  'by',
  'without',
  'on',
  'ignoring',
  'group_left',
  'group_right',
  // 函数
  'abs',
  'absent',
  'absent_over_time',
  'acos',
  'acosh',
  'asin',
  'asinh',
  'atan',
  'atanh',
  'avg_over_time',
  'ceil',
  'changes',
  'clamp',
  'clamp_max',
  'clamp_min',
  'cos',
  'cosh',
  'count_over_time',
  'day_of_month',
  'day_of_week',
  'day_of_year',
  'days_in_month',
  'deg',
  'delta',
  'deriv',
  'exp',
  'floor',
  'histogram_avg',
  'histogram_count',
  'histogram_fraction',
  'histogram_quantile',
  'histogram_stddev',
  'histogram_stdvar',
  'histogram_sum',
  'holt_winters',
  'hour',
  'idelta',
  'increase',
  'irate',
  'label_join',
  'label_replace',
  'last_over_time',
  'ln',
  'log10',
  'log2',
  'mad_over_time',
  'max_over_time',
  'min_over_time',
  'minute',
  'month',
  'pi',
  'predict_linear',
  'present_over_time',
  'quantile_over_time',
  'rad',
  'rate',
  'resets',
  'round',
  'scalar',
  'sgn',
  'sin',
  'sinh',
  'sort',
  'sort_by_label',
  'sort_by_label_desc',
  'sort_desc',
  'sqrt',
  'stddev_over_time',
  'stdvar_over_time',
  'sum_over_time',
  'tan',
  'tanh',
  'time',
  'timestamp',
  'vector',
  'year',
]);

/** Prometheus 时长字面量：1h30m / 5m / 30s / 100ms（可多段拼接） */
const DURATION_RE = /^(\d+(ms|s|m|h|d|w|y))+$/;

/** 规则块起点：`- alert: Name` */
const ALERT_LINE_RE = /^[ \t]*-[ \t]*alert:[ \t]*(\S.*)$/gm;

/** 按 `- alert:` 切块；块体 = 本行之后到下一个 alert 行之前 */
function splitRuleBlocks(source) {
  const starts = [...source.matchAll(ALERT_LINE_RE)];
  return starts.map((m, i) => ({
    name: m[1].trim(),
    body: source.slice(
      m.index + m[0].length,
      i + 1 < starts.length ? starts[i + 1].index : undefined
    ),
  }));
}

/** 取 `key: value` 的行内标量（`for:` / `severity:` 等） */
function readScalar(body, key) {
  const m = body.match(new RegExp(`^[ \\t]*${key}:[ \\t]*(\\S.*)$`, 'm'));
  return m ? m[1].trim() : '';
}

/**
 * 取 expr：行内值或块标量（`expr: |` / `expr: >-`）。
 *
 * 块标量的续行 = 缩进比 `expr:` 那一行更深、且不是新键的行。
 * 只认行内写法的话，多行表达式会被静默截成半句——而"半句"通常仍然括号平衡、
 * 函数名也认识，于是门禁放行、Prometheus 照样加载失败。这是本模块最容易假绿的一处。
 */
function readExpr(body) {
  const lines = body.split(/\r?\n/);
  const idx = lines.findIndex((l) => /^[ \t]*expr:/.test(l));
  if (idx < 0) return '';
  const head = lines[idx].match(/^([ \t]*)expr:[ \t]*(.*)$/);
  const rest = (head ? head[2] : '').trim();
  if (rest && !/^[|>][-+]?$/.test(rest)) return rest;

  const indent = (head ? head[1] : '').length;
  const out = [];
  for (let i = idx + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '') continue;
    if (lines[i].match(/^\s*/)[0].length <= indent) break;
    out.push(lines[i].trim());
  }
  return out.join('\n').trim();
}

/** 解析入口：返回形状稳定为 name / expr / forText / severity */
function parseAlertRules(source) {
  return splitRuleBlocks(source).map(({ name, body }) => ({
    name,
    expr: readExpr(body),
    forText: readScalar(body, 'for'),
    severity: readScalar(body, 'severity'),
  }));
}

/** 去掉引号内文本（`{x="("}` 里的括号不该参与配平判定） */
const stripStrings = (s) => s.replace(/"[^"]*"/g, '""').replace(/'[^']*'/g, "''");

/** 括号/方括号/花括号配平；返回第一个不平衡处的描述，平衡则返回 null */
function unbalancedAt(expr) {
  const pairs = { ')': '(', ']': '[', '}': '{' };
  const stack = [];
  for (const ch of expr) {
    if (ch === '(' || ch === '[' || ch === '{') stack.push(ch);
    else if (pairs[ch] && stack.pop() !== pairs[ch]) return `括号不配平（遇到 ${ch}）`;
  }
  return stack.length > 0 ? `括号不配平（未闭合的 ${stack.join('')}）` : null;
}

/** expr 的三类问题：配平 / 未知函数 / 区间时长 */
function exprProblems(where, expr) {
  const problems = [];
  const bracket = unbalancedAt(expr);
  if (bracket) problems.push(`${where}：${bracket}`);

  for (const m of expr.matchAll(/([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\(/g)) {
    if (!PROMQL_CALLABLES.has(m[1])) {
      problems.push(`${where}：调用了非 PromQL 内置函数「${m[1]}」（拼错即整组规则加载失败）`);
    }
  }
  for (const m of expr.matchAll(/\[([^\]]*)\]/g)) {
    const dur = m[1].trim();
    if (!DURATION_RE.test(dur)) {
      problems.push(`${where}：区间向量时长非法「[${dur}]」（合法形如 [5m] / [1h30m]）`);
    }
  }
  return problems;
}

/** 规则元数据问题：for 时长 / severity */
function metaProblems(where, rule) {
  const problems = [];
  if (rule.forText && !DURATION_RE.test(rule.forText)) {
    problems.push(`${where}：for 时长非法「${rule.forText}」（合法形如 1m / 0m / 1h）`);
  }
  if (!rule.severity) {
    problems.push(
      `${where}：未声明 severity 标签（Alertmanager 路由按它分发，缺失即无路由可命中）`
    );
  }
  return problems;
}

/** 重名检查（Prometheus 加载报 duplicate） */
function duplicateProblems(seen) {
  const problems = [];
  for (const [name, n] of seen) {
    if (n > 1) problems.push(`alert 名重复「${name}」（×${n}）：Prometheus 加载报 duplicate`);
  }
  return problems;
}

/**
 * 校验一组规则。返回问题描述数组（空数组 = 通过）。
 * @param {string} source alert-rules.yml 原文
 * @returns {string[]}
 */
function validateAlertRules(source) {
  const rules = parseAlertRules(source);

  // 前提自证：解析不出规则比"校验通过"严重得多——那会让整道门禁空转
  if (rules.length === 0) {
    return ['未能从 alert-rules.yml 解析出任何规则：解析器或文件结构已漂移（本门禁会因此恒绿）'];
  }

  const problems = [];
  const seen = new Map();
  for (const r of rules) {
    const where = `规则 ${r.name || '(无名)'}`;
    if (!r.name) problems.push('存在没有 alert 名的规则');
    else seen.set(r.name, (seen.get(r.name) || 0) + 1);

    if (!r.expr) {
      problems.push(`${where}：expr 为空（Prometheus 加载期即报错）`);
      continue;
    }
    problems.push(...exprProblems(where, stripStrings(r.expr)));
    problems.push(...metaProblems(where, r));
  }
  problems.push(...duplicateProblems(seen));
  return problems;
}

module.exports = { parseAlertRules, validateAlertRules, PROMQL_CALLABLES };
