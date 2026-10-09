/**
 * 依赖审计硬门禁（**含 devDependencies**）：未登记的 advisory 一律阻断；
 * 已登记项必须按期复核，且在上游修好后**自动失效**。
 *
 * ## 补的是什么缺口
 * CI 的 security-audit 作业原本两处都是 `npm audit --omit=dev` —— dev 树里的
 * advisory 对门禁**完全不可见**。2026-10-09 实测：含 dev 35 条（30 high / 5 moderate），
 * 而 `--omit=dev` 为 0、web-admin 两侧均为 0。即「devDependencies 带 30 条高危」
 * 可以长期全绿合并。本步把 dev 树纳入判定。
 *
 * ## 为什么不是「把阈值一收紧就完事」
 * 实测两个根因公告**根本没有修复版本**：
 *   - GHSA-vfj7-8cjw-p6xm（braces，high，CVSS 7.5）：`vulnerable: <=3.0.3`，
 *     registry 上 braces 的 latest 就是 3.0.3 ⇒ `overrides` **无版本可指向**
 *     （与 uuid override 不同：那个有已修复版本 11.1.1）；
 *   - GHSA-hp3w-g68c-fv3c（sprintf-js，moderate，CVSS 5.3）：`vulnerable: <=1.1.3`，同样无补丁。
 * 因此直接收紧阈值会让 CI **永久红**，而永久红第一次出现就会被 `continue-on-error`
 * 或注释消化掉——本仓 docs/security-dependency-watch.md 自己记录过这条失败模式
 * （morgan 中危长期静默通过）。故采用**硬门禁 + 显式允许清单**：无补丁项逐条登记
 * 理由与复核期限，其余任何新 advisory 立刻阻断。
 *
 * ## fail-closed 的三条判据（缺一不可）
 *  1. **未登记**：≥ threshold 的根因公告不在清单里 ⇒ 红；
 *  2. **已过期**：清单项 `reviewBy` 早于今天 ⇒ 红（登记不是永久豁免）；
 *  3. **已陈旧**：清单项在本次报告里已无 ≥ threshold 的对应公告（上游修好了，
 *     或被降级到阈值以下）⇒ 红，必须删掉该行。否则清单只增不减，
 *     半年后没人知道哪几条还成立——「零引用登记项」正是这样长出来的。
 *
 * ## 判据来源是「根因公告」而不是「受影响包」
 * npm audit 的 `vulnerabilities` 是**包**维度的，一个 advisory 会沿依赖链传染出
 * 几十个包（实测 35 条 = 2 条根因）。按包登记必然得到一份腐烂清单，故只取 `via` 里
 * **带 `source` 的对象**（即 advisory 本身），按 GHSA id 去重。
 * 注意 `via.source` 是 registry 的**数字** advisory id，GHSA 字符串只在 `url` 里，
 * 故 id 从 url 末段取、数字 id 仅作展示与交叉核对。
 *
 * ## 用法
 *   npm audit --audit-level=moderate --json > .audit-all.json || true
 *   node scripts/check-audit-allowlist.js --report .audit-all.json
 * `--report -` 从 stdin 读；`--today YYYY-MM-DD` 固定时钟（测试用）。
 * 本脚本**不自己 spawn npm**（不起子进程）⇒ 判定确定、可离线测试、可在沙箱内跑。
 *
 * 本文件刻意保持精短：本仓有 max-lines 棘轮。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_ALLOWLIST = path.resolve(ROOT, 'deployment', 'audit-allowlist.json');

const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

/** `https://github.com/advisories/GHSA-xxxx-...` → `GHSA-xxxx-...`（取不到则回退数字 id） */
function advisoryId(via) {
  const tail = String(via.url || '')
    .split('/')
    .filter(Boolean)
    .pop();
  return /^GHSA-/i.test(tail || '') ? tail : String(via.source);
}

/**
 * 把一条 `via` 项并入聚合表。非根因（字符串项 = 传递依赖、无 source 的畸形项）直接跳过；
 * 同一 advisory 命中多包时保留**最高**严重度那一条，并把包名收进 `packages`。
 */
function mergeAdvisory(found, pkg, via) {
  if (typeof via !== 'object' || via === null || !via.source) return;
  const id = advisoryId(via);
  const rank = SEVERITY_RANK[via.severity] ?? -1;
  const prev = found.get(id);
  if (!prev || rank > prev.rank) {
    found.set(id, {
      id,
      source: via.source,
      rank,
      severity: via.severity,
      title: via.title,
      url: via.url,
      range: via.range,
      pkg: via.name || via.dependency || pkg,
      packages: [],
    });
  }
  const entry = found.get(id);
  if (!entry.packages.includes(pkg)) entry.packages.push(pkg);
}

/**
 * 从 audit 报告聚合「根因公告」，按 GHSA id 去重。
 * @returns {{id:string, source:number, rank:number, severity:string, title:string,
 *            url:string, range:string, pkg:string, packages:string[]}[]}
 */
function collectRootAdvisories(report) {
  const found = new Map();
  for (const [pkg, v] of Object.entries((report && report.vulnerabilities) || {})) {
    for (const via of (v && v.via) || []) {
      mergeAdvisory(found, pkg, via);
    }
  }
  return [...found.values()].sort((a, b) => b.rank - a.rank || a.id.localeCompare(b.id));
}

/**
 * 判定核心（纯函数：不读 argv、不调 process.exit、不打印）。
 *
 * 抽出来的理由是可证伪性：判据若与 CLI 混写，测试只能**复刻**一份逻辑，
 * 而「复刻版全绿、真门禁已写坏」本仓实测发生过（见 installScriptGate 的文件头）。
 *
 * @param {object} p
 * @param {object} p.report    npm audit --json 的解析结果
 * @param {object} p.allowlist 允许清单（threshold + entries）
 * @param {string} p.today     YYYY-MM-DD，用于判定 reviewBy 是否过期
 */
function evaluate({ report, allowlist, today }) {
  const advisories = collectRootAdvisories(report);
  const thresholdRank = SEVERITY_RANK[allowlist.threshold];
  const gate = advisories.filter((a) => a.rank >= thresholdRank);
  const gateIds = new Set(gate.map((a) => a.id));
  const registered = new Set(allowlist.entries.map((e) => e.id));
  return {
    threshold: allowlist.threshold,
    advisories,
    gate,
    offenders: gate.filter((a) => !registered.has(a.id)),
    expired: allowlist.entries.filter((e) => e.reviewBy < today),
    stale: allowlist.entries.filter((e) => !gateIds.has(e.id)),
  };
}

/** 读清单并校验形状（fail-closed：字段缺失/日期格式错一律抛错，不静默放行） */
function loadAllowlist(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!SEVERITY_RANK[raw.threshold]) throw new Error(`threshold 非法：${raw.threshold}`);
  if (!Array.isArray(raw.entries)) throw new Error('entries 必须是数组');
  for (const e of raw.entries) {
    if (!e.id || !e.reason) throw new Error(`清单项缺 id/reason：${JSON.stringify(e)}`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(e.reviewBy)))
      throw new Error(`清单项 ${e.id} 的 reviewBy 必须是 YYYY-MM-DD`);
  }
  return raw;
}

/** 读 audit 报告（`-` 表示 stdin）。端点报错/树陈旧的报告要判为 infra 错误而非策略违规 */
function readReport(file) {
  const text = file === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(file, 'utf8');
  const report = JSON.parse(text);
  if (!report || !report.metadata || !report.metadata.vulnerabilities) {
    throw new Error(
      'audit 报告缺少 metadata.vulnerabilities —— 可能是 registry 端点报错，' +
        '或 node_modules 陈旧（npm 的 "Invalid package tree, run npm install"），' +
        '属基础设施问题而非策略违规'
    );
  }
  return report;
}

function describe(a) {
  return `${a.severity.padEnd(8)} ${a.id} ${a.pkg}（影响 ${a.packages.length} 个包，区间 ${a.range}）`;
}

/** @returns {number} 退出码（0=通过 / 1=策略违规 / 2=用法或 IO 错误） */
function run({ reportFile, allowlistFile, today }) {
  let allowlist;
  let report;
  try {
    allowlist = loadAllowlist(allowlistFile);
  } catch (e) {
    console.error(
      `Error: 无法读取/校验允许清单 ${allowlistFile}：${String(e.message).slice(0, 300)}`
    );
    return 2;
  }
  try {
    report = readReport(reportFile);
  } catch (e) {
    console.error(
      `Error: 无法读取/解析 audit 报告 ${reportFile}：${String(e.message).slice(0, 300)}`
    );
    return 2;
  }

  const r = evaluate({ report, allowlist, today });
  const total = report.metadata.vulnerabilities;

  console.log(`[含 dev 依赖审计] 包维度：${JSON.stringify(total)}`);
  console.log(
    `阈值 ${r.threshold}；根因公告 ${r.advisories.length} 条，其中达阈值 ${r.gate.length} 条：`
  );
  for (const a of r.gate)
    console.log(`  ${registered(r, a) ? '✅ 已登记' : '❌ 未登记'} ${describe(a)}`);
  const below = r.advisories.filter((a) => a.rank < SEVERITY_RANK[r.threshold]);
  for (const a of below) console.log(`  ➖ 低于阈值 ${describe(a)}`);

  if (r.expired.length || r.stale.length) {
    console.error('\n允许清单自身需要维护（fail-closed）：');
    for (const e of r.expired)
      console.error(`  已过期 reviewBy=${e.reviewBy}：${e.id}（${e.package}）—— 重新评估或删除`);
    for (const e of r.stale)
      console.error(`  已陈旧（本次报告里已无对应公告）：${e.id}（${e.package}）—— 必须删掉该行`);
  }
  if (r.offenders.length) {
    console.error('\n未登记的依赖 advisory（fail-closed，阻断合并）：');
    for (const a of r.offenders) console.error(`  ${describe(a)}`);
    console.error(
      '\n若确认可带洞上线：把 GHSA id 加入 deployment/audit-allowlist.json 的 entries，'
    );
    console.error('写明理由、可达性判断与复核期限，随提交评审。');
  }
  if (r.offenders.length || r.expired.length || r.stale.length) return 1;

  console.log(`\n✅ 含 dev 依赖审计通过（未登记 0，清单 ${allowlist.entries.length} 条全部有效）`);
  return 0;
}

const registered = (r, a) => !r.offenders.includes(a);

function parseArgs(argv) {
  const opts = {
    reportFile: '.audit-all.json',
    allowlistFile: DEFAULT_ALLOWLIST,
    today: new Date().toISOString().slice(0, 10),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const [flag, inline] = argv[i].split('=');
    const value = inline !== undefined ? inline : argv[++i];
    if (flag === '--report') opts.reportFile = value;
    else if (flag === '--allowlist') opts.allowlistFile = value;
    else if (flag === '--today') opts.today = value;
    else return { error: `未知参数：${argv[i]}（支持 --report / --allowlist / --today）` };
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.error) {
    console.error(opts.error);
    process.exit(2);
  }
  process.exit(run(opts));
}

// 作为脚本执行时才跑 CLI；被 require 时只暴露判据（测试真调 evaluate，不复刻逻辑）
if (require.main === module) main();

module.exports = {
  SEVERITY_RANK,
  advisoryId,
  collectRootAdvisories,
  evaluate,
  loadAllowlist,
  readReport,
};
