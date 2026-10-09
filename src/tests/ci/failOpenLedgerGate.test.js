/**
 * fail-open 站点台账的完整性门禁（2026-10-09）
 *
 * ## 为什么需要它
 * 本仓有一条成文纪律在三个文件里被重复声明（`middleware/security.js:668-672`、
 * `middleware/rateLimitStore.js:53-56`、`services/websocketService.js:723-725`）：
 * **fail-open 必须有显式可观测信号**。但纪律只在注释里——没有任何东西把
 * 「站点集合」与「每个站点的信号」钉在一起，于是第四处漏了：
 * `services/captchaService.js` 的上限判定被跳过时，唯一痕迹是 `sharedCache.js:432`
 * 的 `logger.debug`，而生产默认 `LOG_LEVEL=info`（`utils/logger.js:85`）⇒ 不落盘。
 * 没有日志、没有指标、没有告警。这就是「已修的同类漏了一处」。
 *
 * ## 本闸钉四条（都是双向的，两个方向都红）
 *  ① 生产码里每个 `incSecurityAlert(<字面量>, <字面量>)` 调用点，必须能在台账里
 *     找到 `type@file` 且 `level` 完全一致；台账里登记的条目也必须真的有调用点。
 *     ⇒ 逼作者回答「这是降级，还是安全事件上报？」——降级就必须有信号、方向与告警覆盖。
 *  ② 台账里每个 fail-open 站点的 type，必须被 `alert-rules.yml` 的持续型规则覆盖。
 *     ⇒ 「登记了信号但忘了加告警」变红，而不是等运维发现信号没人看。
 *  ③ 每个站点的 `direction` / `why` / `tightening` 必须非空，且 `direction` 取值合法。
 *  ④ 采集器必须有前提自证（真实树扫到足量站点）+ 反向对照（合成输入走**同一条**采集器）。
 *
 * ## 如实声明：本闸抓不到什么
 * 采集器的锚点是 `incSecurityAlert` 的**调用点**。所以一个**既不发信号、也没被注意到**的
 * 新 fail-open 站点不会被本闸抓到——它压根不出现在采集结果里。本闸能做的是：
 * 让已有信号无法悄悄消失、让新增信号必须被归类、让登记过的信号必须真的接上告警。
 * 别把本闸当成「fail-open 全都被管住了」的证据（同 `src/constants/failOpenSites.js` 的声明）。
 *
 * ## 与仓内既有闸的关系
 * 与 `credentialDoorCheckLedger.test.js` 同形：采集器与台账都导出，真实树与合成反例
 * 走同一条函数（避免"判据在自证里被重抄一遍"）。注释剥离一律走仓内唯一实现
 * `tests/helpers/jsCodeOnly.js`——自己写一份剥注释的口径，就等于复制一份可能改坏的口径。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');
const {
  FAIL_OPEN_SITES,
  OTHER_ALERT_SIGNALS,
  PASS_THROUGH,
  FAIL_OPEN_ALERT_TYPES,
} = require('../../constants/failOpenSites');
const { parseAlertRules } = require('../../../scripts/alertRulesPolicy');

const ROOT = path.resolve(__dirname, '../../..');
const SRC_DIR = path.join(ROOT, 'src');
const RULES_PATH = path.join(ROOT, 'deployment/observability/alert-rules.yml');
/** 本仓既有的持续型 fail-open 规则名（台账 ② 的对接对象） */
const SUSTAINED_RULE = 'SecurityFailOpenSustained';

/**
 * 台账自身所在的文件：**必须排除**在扫描之外。
 *
 * 它不是特例豁免，而是必要条件：台账的字段值里必然出现
 * `incSecurityAlert(alertType, level)` 这类**说明性文本**（写在字符串字面量里，
 * 因此 `jsCodeOnly` 不会剥掉——它只剥注释）。不排除的话，台账会把自己描述成
 * 一个动态调用点，采集结果与台账永远对不上。实测踩过：第一版正是这样红的。
 * 反过来，把 `failOpenSites.js` 当成"调用点来源"也没有任何意义——它是数据不是代码。
 */
const LEDGER_FILE = 'constants/failOpenSites.js';

const DIRECTIONS = ['fail-open', 'fail-closed', 'mixed'];

/** 生产码 js 文件（与仓内其余静态闸同口径：跳过 tests 与 node_modules） */
function listProdFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'tests') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** 仓内统一口径：**相对 `src/`** 的路径（与 `constants/failOpenSites.js` 的 file 字段一致） */
const relOf = (full) => path.relative(SRC_DIR, full).split(path.sep).join('/');

const CALL_RE = /incSecurityAlert\(\s*([^,)]+?)\s*,\s*([^,)]+?)\s*\)/g;
/** 指标定义本体那一行（`function incSecurityAlert(type, level)`）不是调用点 */
const DEFINITION_RE = /function\s+incSecurityAlert\s*\(/;

/** 同文件里把裸标识符实参解析成字面量（如 PII_V1_ALERT → 'pii_v1_rows_unmigrated'） */
function resolveConst(cleanSrc, ident) {
  const m = cleanSrc.match(new RegExp(`const\\s+${ident}\\s*=\\s*'([^']+)'`));
  return m ? m[1] : null;
}

/**
 * 采集器：`{name, text}` 列表 → 调用点数组。
 *
 * 每条：`{file, line, type, level, dynamic}`
 *   · `type`/`level` 为字面量（或可由同文件常量解析）时 `dynamic: false`；
 *   · 任一为裸标识符且解析不出时 `dynamic: true`，`type` 保留原始实参文本。
 *
 * 导出以便合成反例走同一条函数（前提自证）。
 */
function collectAlertCalls(files) {
  const calls = [];
  for (const { name, text } of files) {
    const clean = jsCodeOnlyKeepingLines(text);
    clean.split('\n').forEach((line, i) => {
      if (DEFINITION_RE.test(line)) return;
      for (const m of line.matchAll(CALL_RE)) {
        const rawType = m[1].trim();
        const rawLevel = m[2].trim();
        const typeLit = rawType.startsWith("'")
          ? rawType.slice(1, -1)
          : resolveConst(clean, rawType);
        const levelLit = rawLevel.startsWith("'")
          ? rawLevel.slice(1, -1)
          : resolveConst(clean, rawLevel);
        calls.push({
          file: name,
          line: i + 1,
          type: typeLit !== null ? typeLit : rawType,
          level: levelLit !== null ? levelLit : rawLevel,
          dynamic: typeLit === null || levelLit === null,
        });
      }
    });
  }
  return calls;
}

const realFiles = () =>
  listProdFiles()
    .map((f) => ({ name: relOf(f), text: fs.readFileSync(f, 'utf8') }))
    .filter((f) => f.name !== LEDGER_FILE);

const CALLS = collectAlertCalls(realFiles());
const STATIC_CALLS = CALLS.filter((c) => !c.dynamic);
const DYNAMIC_CALLS = CALLS.filter((c) => c.dynamic);

/** 台账键：`type@file`（同一 type 可能分布在多个文件，`audit_write_failed` 就是） */
const keyOf = (type, file) => `${type}@${file}`;
const REGISTERED = new Map();
for (const s of [...FAIL_OPEN_SITES, ...OTHER_ALERT_SIGNALS]) {
  REGISTERED.set(keyOf(s.type, s.file), s);
}

const ruleText = fs.readFileSync(RULES_PATH, 'utf8');

describe('fail-open 台账完整性：信号站点必须被登记、登记必须接上告警', () => {
  test('前提自证：采集器在真实树上扫到足量站点，且定义行/注释行都不被收成调用点', () => {
    // 规模下界：18 个真实调用点（2026-10-09 实测），留余量防"采集器退化后空集恒绿"
    expect(CALLS.length).toBeGreaterThanOrEqual(12);
    expect(FAIL_OPEN_SITES.length).toBeGreaterThanOrEqual(4);
    // 定义本体（utils/metrics.js 的 `function incSecurityAlert(type, level)`）**一个调用点都不是**：
    // 它既不是静态站点也不是动态转发点。这条断言钉住 DEFINITION_RE 的排除真的生效
    // （排除失效的话它会以 `type`/`level` 两个裸标识符的形状混进 DYNAMIC_CALLS）。
    expect(CALLS.some((c) => c.file === 'utils/metrics.js')).toBe(false);
    // 台账自身必须被排除，且排除不能因为文件名写错而静默失效
    expect(listProdFiles().map(relOf)).toContain(LEDGER_FILE);
    expect(CALLS.some((c) => c.file === LEDGER_FILE)).toBe(false);
    // 动态转发点：实测只有投递门面一处
    expect(DYNAMIC_CALLS.map((c) => c.file).sort()).toEqual(['services/securityAlertDelivery.js']);

    // 反向对照：合成输入走**同一条** collectAlertCalls
    const synthetic = collectAlertCalls([
      {
        name: 'x/demo.js',
        text: [
          "// 历史注释：这里曾经 incSecurityAlert('ghost', 'high')",
          "const PII = 'pii_demo';",
          'function incSecurityAlert(type, level) {}',
          "require('./m').incSecurityAlert('real_type', 'high');",
          "incSecurityAlert(PII, 'medium');",
          'incSecurityAlert(alertType, level);',
        ].join('\n'),
      },
    ]);
    expect(synthetic.map((c) => `${c.type}|${c.level}|${c.dynamic}`)).toEqual([
      'real_type|high|false',
      'pii_demo|medium|false',
      'alertType|level|true',
    ]);
  });

  test('① 双向闭合：代码里的静态站点 ⇄ 台账条目，多一个少一个都红', () => {
    const measured = STATIC_CALLS.map((c) => keyOf(c.type, c.file)).sort();
    const declared = [...REGISTERED.keys()].sort();
    const unregistered = measured.filter((k) => !declared.includes(k));
    const stale = declared.filter((k) => !measured.includes(k));
    expect({ unregistered, stale }).toEqual({ unregistered: [], stale: [] });
  });

  test('① 每条的 level 必须与代码实测一致（级别漂移也要同步台账）', () => {
    for (const c of STATIC_CALLS) {
      const entry = REGISTERED.get(keyOf(c.type, c.file));
      expect({ key: keyOf(c.type, c.file), level: c.level }).toEqual({
        key: keyOf(c.type, c.file),
        level: entry.level,
      });
    }
  });

  test('③ 每个 fail-open 站点必须声明 direction/why/tightening，且方向取值合法', () => {
    for (const s of FAIL_OPEN_SITES) {
      expect({ type: s.type, direction: DIRECTIONS.includes(s.direction) }).toEqual({
        type: s.type,
        direction: true,
      });
      // why / tightening 必须是能拿去问人的具体句子，不接受空串或占位
      expect(s.why.length).toBeGreaterThan(30);
      expect(s.tightening.length).toBeGreaterThan(20);
      // signal 口径必须点名自己的 type（防止抄错告警名）
      expect(`security_alerts_total{type=${s.type}}`).toContain(s.type);
    }
    // OTHER_ALERT_SIGNALS 反过来不得声称自己是降级
    for (const s of OTHER_ALERT_SIGNALS) {
      expect(s.direction).toBeUndefined();
      expect(s.why.length).toBeGreaterThan(5);
    }
  });

  test('② 台账里每个 fail-open 的 type 都必须被持续型告警规则覆盖（登记信号 ≠ 接上告警）', () => {
    const rules = parseAlertRules(ruleText);
    const sustained = rules.find((r) => r.name === SUSTAINED_RULE);
    expect(sustained).toBeTruthy();
    const missing = FAIL_OPEN_ALERT_TYPES.filter((t) => !sustained.expr.includes(t));
    expect({ rule: SUSTAINED_RULE, missing }).toEqual({ rule: SUSTAINED_RULE, missing: [] });
    // 前提自证：规则确实是「持续型」而不是瞬时型——丢了 for 就退化回速率告警
    expect(sustained.forText).toBe('10m');
    expect(sustained.expr).toContain('increase(');
  });

  test('② 反向对照：规则表达式里出现的 type 必须都在台账里（防规则点名一个不存在的信号）', () => {
    const rules = parseAlertRules(ruleText);
    const sustained = rules.find((r) => r.name === SUSTAINED_RULE);
    const listed = [...sustained.expr.matchAll(/type=~"([^"]+)"/g)].flatMap((m) => m[1].split('|'));
    expect(listed.length).toBeGreaterThan(0);
    const unknown = listed.filter((t) => !FAIL_OPEN_ALERT_TYPES.includes(t));
    expect({ listed: listed.sort(), unknown }).toEqual({
      listed: FAIL_OPEN_ALERT_TYPES,
      unknown: [],
    });
  });

  test('动态转发点必须登记在案（无法枚举 type，但必须说明它是转发点）', () => {
    const declared = PASS_THROUGH.map((p) => p.file).sort();
    expect(DYNAMIC_CALLS.map((c) => c.file).sort()).toEqual(declared);
    for (const p of PASS_THROUGH) expect(p.why.length).toBeGreaterThan(10);
  });

  test('台账的四个导出都是冻结的（防止测试运行时被就地改写）', () => {
    for (const arr of [FAIL_OPEN_SITES, OTHER_ALERT_SIGNALS, PASS_THROUGH, FAIL_OPEN_ALERT_TYPES]) {
      expect(Object.isFrozen(arr)).toBe(true);
    }
  });
});
