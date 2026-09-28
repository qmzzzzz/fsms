/**
 * 出站告警契约闸：档位词表 + 投递名次表 + 调用点闭包。
 *
 * 【为什么要这一闸（实测于 2026-09-26）】
 * 同一份四档阶梯在本仓被手抄了三遍，且第三遍带**名次**、缺失时朝"静默不投递"那一侧失败：
 *   1. `src/constants/audit.js` 的 `AUDIT_RISK_LEVELS`（权威，且是有序的）；
 *   2. `src/services/securityAlert.js` 的 `ALERT_LEVELS`（第二份，值今天与权威相等）；
 *   3. `src/services/securityAlertDelivery.js` 里的 `const levelOrder = { low:1, medium:2, high:3, critical:4 }`
 *      （第三份，带名次），紧跟着
 *      `if ((levelOrder[level] || 0) < (levelOrder[minLevel] || 3)) return;`。
 * `constants/audit.js` 的头注释已经把话说死了：档位是有序清单，"某档及以上"的判据必须由
 * `riskLevelsAtLeast` 派生，因为给权威加一档（例如 `'urgent'`）时的失效模式**不是报错，是静默漏**（F-149）。
 * 第 3 处正是那条明令的漏网：名次表漏一档 ⇒ `levelOrder[level] || 0` ⇒ 该档告警**永远不进传输层**，
 * 而在它之前的结构化日志与 `incSecurityAlert` 计数都已经走了 ⇒ `/metrics` 显示"N 条告警"、
 * 下游收到 0 条。这与本仓反复清理的「失败渲染成健康零值」是同一个形状，只是方向朝外。
 *
 * 【判据（四条，全部实测过才钉）】
 *   A. 词表一致：`ALERT_LEVELS` 的取值集合 == `AUDIT_RISK_LEVELS`（活的常量断言，双向红）。
 *   B. 名次表覆盖词表：**阈值放到最低档时，词表里每个档位都必须真的走到传输层**——
 *      这条直接钉住上面那个失效模式，且它测的是行为不是文本，改名次表怎么写都躲不过。
 *   C. 反向对照：**不在词表里的档位当前不投递**（同时证明 B 不是恒真），
 *      并钉住"文件日志照走、传输层没走"这组分叉——今天它是这样，将来谁改成 fail-open，
 *      这条会以"意外通过"的形式逼人来复核，而不是让分歧悄悄消失。
 *   D. 调用点闭包：按文本扫 `dispatchNotification(` / `sendNotification(` 的前两个实参，
 *      档位必须 ∈ 词表；类型必须是 `ALERT_TYPES.<真实键>` 或**带出处的登记字面量**
 *      （今天 2 处：`ip_blacklist_hit`、`audit_anomaly_detected`，都不在 `ALERT_TYPES` 里）。
 *      登记项一旦被收进 `ALERT_TYPES` ⇒ 红，逼着把账销掉，而不是留下双份。
 *
 * 【为什么只钉"当前不投递"而不顺手改成拒绝启动】
 * 名次表漏档到底是 fail-open（照投）还是 fail-closed（不投 + 报错），以及
 * `SECURITY_ALERT_MIN_LEVEL` 写成 `CRITICAL`/`warning` 这类非法值（当前经 `|| 3` 静默按 `high` 处理）
 * 该怎么办，都是**安全阈值的取值决策**，不由 agent 单方定；已连同台账一起交给用户拍板。
 * 本批不改任何产品码。
 *
 * 【已知边界】
 *   · D 的文本判据看不见"档位来自变量"的调用点（今天的唯一动态点是 `dispatchNotification`
 *     自己的转发）。动态点数必须数量可见（前提自证里钉着），不许悄悄少算。
 *   · B/C 只走 `postJson` 这一层，`jest.mock` 掉它，全程不碰网络。
 */

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { AUDIT_RISK_LEVELS } = require('../../constants/audit');

jest.mock('../../utils/httpPostJson', () => ({ postJson: jest.fn() }));

const securityAlert = require('../../services/securityAlert');
const logger = require('../../utils/logger');
const { postJson } = require('../../utils/httpPostJson');

const { ALERT_LEVELS, ALERT_TYPES, sendNotification } = securityAlert;

const ROOT = path.resolve(__dirname, '../../..');
const SCAN_ROOTS = ['src', 'scripts', 'migrations'];
const SKIP_DIR = /(^|[/\\])(?:tests?|__tests__|node_modules)([/\\]|$)/;

/** 今天 `ALERT_TYPES` 之外、但确实有下游订阅的出站类型（出处必须能被逐字核对） */
const REGISTERED_OUTBOUND_TYPES = [
  {
    type: 'ip_blacklist_hit',
    at: 'src/middleware/security.js',
    why: '黑名单拦截通知由中间件直接派发，未进 ALERT_TYPES；改名等于洗掉下游订阅方按类型路由的规则',
  },
  {
    type: 'audit_anomaly_detected',
    at: 'src/services/auditMonitor.js',
    why: '审计异常监控 await 裸投递（要拿投递结果做自己的记账），类型也不在 ALERT_TYPES 里',
  },
];

const IDENT = /^[A-Za-z_$][\w$]*$/;
const CALL = /(?:dispatchNotification|sendNotification)\s*\(\s*([^,)]+?),\s*([^,)]+?),/g;

function walkFiles(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (SKIP_DIR.test(path.relative(ROOT, full))) continue;
    if (entry.isDirectory()) walkFiles(full, acc);
    else if (/\.js$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

const norm = (s) => s.replace(/\s+/g, ' ').trim();

/** 抽静态调用点：`[{file, typeExpr, levelExpr, callText}]`；动态（裸标识符实参）单独计数 */
function scanEmitSites(rel, raw) {
  const code = jsCodeOnly(raw);
  const sites = [];
  let dynamic = 0;
  for (const m of code.matchAll(CALL)) {
    const typeExpr = norm(m[1]);
    const levelExpr = norm(m[2]);
    if (IDENT.test(typeExpr) || IDENT.test(levelExpr)) {
      dynamic += 1;
      continue;
    }
    // 不报行号：这些调用点大多是折行写法，匹配文本横跨多行，给一个"起始行"只会指错地方。
    // 站点由 file + 两个实参表达式唯一确定（前提自证里按这个键去重）。
    sites.push({ file: rel, typeExpr, levelExpr, callText: m[0] });
  }
  return { sites, dynamic };
}

const allEmitSites = () => {
  const sites = [];
  let dynamic = 0;
  for (const f of scanEmitRootFiles()) {
    const r = scanEmitSites(path.relative(ROOT, f).replace(/\\/g, '/'), fs.readFileSync(f, 'utf8'));
    sites.push(...r.sites);
    dynamic += r.dynamic;
  }
  return { sites, dynamic };
};

const scanEmitRootFiles = () => SCAN_ROOTS.flatMap((r) => walkFiles(path.join(ROOT, r))).sort();

const stripQuote = (expr) => {
  const m = /^['"]([^'"]*)['"]$/.exec(expr);
  return m ? m[1] : null;
};

const resolveLevel = (expr) => {
  const key = /^ALERT_LEVELS\.([A-Z_]+)$/.exec(expr);
  if (key) {
    return ALERT_LEVELS[key[1]] === undefined
      ? { bad: `ALERT_LEVELS.${key[1]} 这个键不存在` }
      : { value: ALERT_LEVELS[key[1]] };
  }
  const lit = stripQuote(expr);
  return lit === null ? { bad: `既不是 ALERT_LEVELS 键也不是字面量：${expr}` } : { value: lit };
};

const resolveType = (expr) => {
  const key = /^ALERT_TYPES\.([A-Z_]+)$/.exec(expr);
  if (key) {
    return ALERT_TYPES[key[1]] === undefined
      ? { bad: `ALERT_TYPES.${key[1]} 这个键不存在` }
      : { value: ALERT_TYPES[key[1]] };
  }
  const lit = stripQuote(expr);
  return lit === null ? { bad: `既不是 ALERT_TYPES 键也不是字面量：${expr}` } : { value: lit };
};

const LEVEL_VALUES = Object.values(ALERT_LEVELS);

describe('出站告警：档位词表、投递名次表、调用点闭包', () => {
  const WEBHOOK = 'https://alert.example.invalid/hook';
  let infoSpy;

  beforeEach(() => {
    postJson.mockReset();
    postJson.mockResolvedValue({ ok: true });
    infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    process.env.SECURITY_ALERT_WEBHOOK = WEBHOOK;
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = '';
    // 阈值压到词表的最低档：这样"能不能投递"就只由名次表说了算
    process.env.SECURITY_ALERT_MIN_LEVEL = 'low';
  });

  afterEach(() => {
    infoSpy.mockRestore();
    delete process.env.SECURITY_ALERT_WEBHOOK;
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    delete process.env.SECURITY_ALERT_MIN_LEVEL;
  });

  test('A 词表：ALERT_LEVELS 的取值与权威 AUDIT_RISK_LEVELS 集合相等', () => {
    expect([...LEVEL_VALUES].sort()).toEqual([...AUDIT_RISK_LEVELS].sort());
    // B 用例把阈值压到 'low' 当"最低档"用：这个前提得钉住，否则 B 测的就不是名次表
    expect(LEVEL_VALUES).toContain('low');
  });

  test('B 名次表：阈值放在最低档时，词表里每个档位都必须真的走到传输层', async () => {
    const delivered = [];
    for (const level of LEVEL_VALUES) {
      postJson.mockClear();
      await sendNotification('gate_probe', level, `档位 ${level} 的探针`, {});
      const calls = postJson.mock.calls;
      expect(calls).toHaveLength(1);
      delivered.push(JSON.parse(calls[0][2]).alert.level);
    }
    // 逐档都能投出去，且投递体里的 level 与传入一致（名次表漏一档 ⇒ 这里少一档）
    expect(delivered.sort()).toEqual([...LEVEL_VALUES].sort());
  });

  test('C 反向对照：不在词表里的档位当前**不投递**，而文件日志照走（分歧必须可见）', async () => {
    postJson.mockClear();
    await sendNotification('gate_probe', 'zz-not-a-level', '探针', {});
    expect(postJson).not.toHaveBeenCalled();
    expect(infoSpy.mock.calls.map((c) => c[0])).toContain('SECURITY_ALERT');
  });

  test('D1 调用点闭包（档位）：静态调用点的档位实参必须 ∈ 词表', () => {
    const { sites } = allEmitSites();
    const bad = [];
    for (const s of sites) {
      const r = resolveLevel(s.levelExpr);
      if (r.bad) bad.push(`${s.file} ${s.levelExpr} ⇒ ${r.bad}`);
      else if (!LEVEL_VALUES.includes(r.value)) {
        bad.push(`${s.file} 档位 ${JSON.stringify(r.value)} ∉ ALERT_LEVELS`);
      }
    }
    expect(bad).toEqual([]);
  });

  test('D2 调用点闭包（类型）：必须走 ALERT_TYPES，或进带出处的登记清单（双向）', () => {
    const { sites } = allEmitSites();
    const emitted = new Set();
    const bad = [];
    for (const s of sites) {
      const r = resolveType(s.typeExpr);
      if (r.bad) bad.push(`${s.file} ${s.typeExpr} ⇒ ${r.bad}`);
      else emitted.add(r.value);
    }
    expect(bad).toEqual([]);

    const registered = new Set(REGISTERED_OUTBOUND_TYPES.map((x) => x.type));
    const alertTypeValues = new Set(Object.values(ALERT_TYPES));
    // 登记项不得同时挂在 ALERT_TYPES 里（进了表就该销账，否则一份类型两本账）
    for (const item of REGISTERED_OUTBOUND_TYPES) {
      expect(alertTypeValues.has(item.type)).toBe(false);
      expect(emitted.has(item.type)).toBe(true);
    }
    // 反向：实际发出的类型若不在表里也不在清单里 ⇒ 新增的漏网类型，必须显式承认
    const unregistered = [...emitted].filter((t) => !alertTypeValues.has(t) && !registered.has(t));
    expect(unregistered).toEqual([]);
  });

  test('前提自证：扫描集与调用点数量都是实测的（空集会让他条用例假绿）', () => {
    expect(scanEmitRootFiles().length).toBeGreaterThanOrEqual(150);
    const { sites, dynamic } = allEmitSites();
    // 实测（2026-09-26）：6 个调用点 = 5 静态 + 1 动态（dispatchNotification 自己的转发）
    expect(sites.length).toBeGreaterThanOrEqual(4);
    expect(dynamic).toBe(1);
    expect(new Set(sites.map((s) => `${s.file}#${s.callText}`)).size).toBe(sites.length);
    // 登记表不能是空谈：每条的出处必须真的写着这个类型
    for (const item of REGISTERED_OUTBOUND_TYPES) {
      const code = jsCodeOnly(fs.readFileSync(path.join(ROOT, item.at), 'utf8'));
      expect(code).toContain(`'${item.type}'`);
      expect(item.why.length).toBeGreaterThan(10);
    }
  });

  test('有牙证明（内存变异真源码）：把一处真档位改错 ⇒ D1 必须只报这一处', () => {
    const { sites } = allEmitSites();
    // 挑一个"档位写字面量"的站点（今天两处），变异面最小
    const target = sites.find((s) => stripQuote(s.levelExpr) !== null);
    expect(target).toBeTruthy();
    const abs = path.join(ROOT, target.file);
    const raw = fs.readFileSync(abs, 'utf8');
    // 调用文本必须在该文件里唯一，否则变异会波及别的站点
    expect(raw.split(target.callText).length - 1).toBe(1);
    const mutated = raw.replace(target.callText, () =>
      target.callText.replace(target.levelExpr, () => "'zz-not-a-level'")
    );
    expect(mutated).not.toBe(raw);
    expect(raw.includes('zz-not-a-level')).toBe(false);

    const { sites: mSites } = scanEmitSites(target.file, mutated);
    expect(mSites.length).toBe(sites.filter((s) => s.file === target.file).length);
    const bad = mSites.filter((s) => {
      const r = resolveLevel(s.levelExpr);
      return Boolean(r.bad) || !LEVEL_VALUES.includes(r.value);
    });
    expect(bad.map((s) => s.levelExpr)).toEqual(["'zz-not-a-level'"]);
  });
});
