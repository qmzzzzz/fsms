#!/usr/bin/env node
/**
 * ESLint 体积 / 复杂度棘轮（O-3 第六档 + E-02 第七档）
 *
 * 背景：max-lines / max-lines-per-function（体积，第六档）与 complexity
 * （圈复杂度，E-02 第七档）以 warn 级接入（eslint.config.js）。这类债
 * 与 linter 错误性质不同——后者清零即收，前者须随瘦身/拆函数逐步消化，
 * 因此不走「清零提 error」，而是逐文件计数基线：
 *
 *   - 基线文件 eslint.ratchet.json 记录每个文件当前 warn 计数（按规则维度）
 *   - 检查模式（默认）：任何文件任何规则计数超过基线 → 退出码 1（棘轮只进不退）
 *   - 收紧模式：--update-baseline 以当前实测重写基线（瘦身生效后手动执行）
 *
 * error 级（severity 2）违例不属棘轮范畴：lint 门禁本身要求 0 error，
 * 本脚本遇到 error 同样判失败，避免棘轮变相放水。
 *
 * 用法:
 *   node scripts/lint-ratchet.js                     # 检查模式（CI / 本地门禁）
 *   node scripts/lint-ratchet.js --update-baseline    # 收紧基线（本地，需随提交走评审）
 *
 * 退出码:
 *   0 = 无回退（或有改善但未收紧——改善需 --update-baseline 落盘）
 *   1 = 存在回退 / 存在 error / 基线不可信
 *       （检查模式：基线不存在；收紧模式：基线存在但解析失败 ⇒ 拒绝按实测重建）
 *   2 = 用法错误（未知参数）——不与"有债"混码，但同样非零，CI 一律拦
 *
 * 零新增依赖：ESLint Node API（eslint 已是 devDependency）+ Node 内置模块。
 */

const fs = require('fs');
const path = require('path');

/** 本脚本认的全部参数 */
const KNOWN_FLAGS = ['--update-baseline'];

/**
 * 未知参数必须拒绝，不能当成"没传"。
 * 手误 `--update-basline` 原先会静默落到检查模式：工作树干净时它打印「通过」并 exit 0，
 * 操作者以为基线已经收紧（这是"以为设了防"的错觉），而 `eslint.ratchet.json` 一个字节没变——
 * 于是那轮想消化的债原地不动，且没有任何信号。同仓破坏性脚本已立过这条规矩
 * （resign-audit-chain-v3.js 的 parseArgs：未知参数 ⇒ 打印可用参数后退出）。
 *
 * 只在**作为脚本执行**时调用（main 里）：本模块同时被 gateSelfTest 用 require 载入，
 * 而在模块顶层校验 jest 的 argv 会让测试进程直接 exit 2——那是"require 不得有副作用"
 * 这条既有守卫专门盯着的失效。
 */
function assertKnownArgs(argv) {
  const unknown = argv.slice(2).filter((a) => !KNOWN_FLAGS.includes(a));
  if (unknown.length === 0) return;
  console.error(
    `[lint-ratchet] 未知参数：${unknown.join(' ')}\n` +
      `                可用参数：${KNOWN_FLAGS.join(' ')}（不带参数 = 检查模式）`
  );
  process.exit(2);
}

const UPDATE_MODE = process.argv.includes('--update-baseline');

const repoRoot = path.resolve(__dirname, '..');
const BASELINE_PATH = path.join(repoRoot, 'eslint.ratchet.json');
// 与 `npm run lint` **同一目标集**（package.json scripts.lint = eslint src scripts e2e eslint.config.js）。
// 少列一个目录不等于"那个目录没债"，而是给它开了一条旁路：那条目录里的 warn 照样会被
// npm run lint 打印、计入"45 warning"的观感，却**不进棘轮账本**——此后它随便长都不红。
// 曾有 e2e 被漏掉（本文件实测目标集与 lint 目标集的一致性由
// src/tests/security/gateSelfTest.test.js 钉住，改一处漏一处会立即转红）。
const LINT_TARGETS = ['src', 'scripts', 'e2e', 'eslint.config.js'];

/** 路径统一为仓库相对 + 正斜杠，保证基线跨端（Windows/CI）可比 */
const toRepoRelative = (filePath) => path.relative(repoRoot, filePath).replace(/\\/g, '/');

const readBaseline = (strict = true) => {
  if (!fs.existsSync(BASELINE_PATH)) return null;
  let raw = fs.readFileSync(BASELINE_PATH, 'utf8');
  // 容忍 BOM：Windows 工具链（PowerShell 5 的 Set-Content utf8）写入时可能带上，
  // 基线文件允许人工编辑，不能因一个字节卡死整条门禁
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  try {
    return JSON.parse(raw);
  } catch (err) {
    // 收紧模式遇损坏基线直接重写修复；检查模式必须 fail-loud
    if (!strict) return null;
    console.error(`[lint-ratchet] 基线文件解析失败：${err.message}`);
    process.exit(1);
  }
};

const writeBaseline = (baseline) => {
  // 键排序保证 diff 稳定（git 评审友好）
  const sorted = {};
  for (const file of Object.keys(baseline).sort()) {
    sorted[file] = Object.fromEntries(
      Object.entries(baseline[file]).sort(([a], [b]) => a.localeCompare(b))
    );
  }
  fs.writeFileSync(BASELINE_PATH, `${JSON.stringify(sorted, null, 2)}\n`, 'utf8');
};

const runLint = async () => {
  const { ESLint } = require('eslint');
  const eslint = new ESLint({ cwd: repoRoot });
  return eslint.lintFiles(LINT_TARGETS);
};

/**
 * 聚合 lint 结果：每个文件按规则维度的 warn 计数 + error 总数
 * @param {Array} results ESLint lintFiles 结果
 * @returns {{ current: Object, errorTotal: number }}
 */
const aggregateWarnCounts = (results) => {
  const current = {}; // file -> { ruleId -> warnCount }
  let errorTotal = 0;

  for (const result of results) {
    const rel = toRepoRelative(result.filePath);
    for (const msg of result.messages) {
      if (msg.severity === 2) {
        errorTotal += 1;
        continue; // error 不进棘轮基线：lint 门禁要求 0 error，这里只判失败
      }
      if (!msg.ruleId) continue; // 无规则可归因的告警（如解析器消息），无法棘轮化
      current[rel] = current[rel] || {};
      current[rel][msg.ruleId] = (current[rel][msg.ruleId] || 0) + 1;
    }
  }
  return { current, errorTotal };
};

/**
 * 与基线比对，产出三类差异（回退 / 改善 / 残留）
 * @param {Object} baseline 基线（文件 -> 规则 -> 计数）
 * @param {Object} current 当前实测（同构）
 * @returns {{ regressions: string[], improvements: string[], stale: string[] }}
 */
const diffBaseline = (baseline, current) => {
  const regressions = []; // 基线回退（计数上升 / 新文件带 warn）
  const improvements = []; // 计数下降（可收紧）
  const stale = []; // 基线残留（文件已无该规则违例或已删除）

  for (const [file, rules] of Object.entries(current)) {
    for (const [rule, count] of Object.entries(rules)) {
      const allowed = baseline[file]?.[rule] ?? 0;
      if (count > allowed) {
        regressions.push(`${file} [${rule}] ${allowed} -> ${count}`);
      } else if (count < allowed) {
        improvements.push(`${file} [${rule}] ${allowed} -> ${count}`);
      }
    }
  }

  for (const [file, rules] of Object.entries(baseline)) {
    if (!fs.existsSync(path.join(repoRoot, file))) {
      stale.push(`${file}（文件已删除）`);
      continue;
    }
    for (const [rule, allowed] of Object.entries(rules)) {
      const now = current[file]?.[rule] ?? 0;
      if (now === 0 && allowed > 0) {
        stale.push(`${file} [${rule}]（已清零，基线残留 ${allowed}）`);
      }
    }
  }

  return { regressions, improvements, stale };
};

/**
 * 「只许降不许升」在**写基线那一刻**的守卫。
 *
 * 为什么必须存在：检查模式只保证"当前实测不超过基线"，而 --update-baseline
 * 是无条件按实测重写的——没有这道守卫时，制造回退的人只要再跑一次
 * `--update-baseline` 就能把上升**洗白**（检查模式此后再也不会红），
 * 于是"只许降不许升"只剩注释里的一句话。
 *
 * 两类违例：
 *  ① 既有 (文件, 规则) 计数上升；
 *  ② 基线里没有的 (文件, 规则) —— 新债不得免费入场（本脚本头注释的既有承诺）。
 * 改善（计数下降）与清零不在此列，正是 --update-baseline 唯一允许的方向。
 *
 * @returns {string[]} 违例行（空数组表示可以安全收紧）
 */
function findBaselineIncreases(before, current) {
  const violations = [];
  for (const [file, rules] of Object.entries(current)) {
    for (const [rule, count] of Object.entries(rules)) {
      const allowed = before[file] && before[file][rule];
      if (allowed === undefined) {
        violations.push(`${file} [${rule}] 基线无此项 -> ${count}（新增债务）`);
      } else if (count > allowed) {
        violations.push(`${file} [${rule}] ${allowed} -> ${count}（上升）`);
      }
    }
  }
  return violations;
}

/**
 * 收紧模式（--update-baseline）的完整决策。
 *
 * 从 main() 里独立出来有两个理由：① 这里是"写盘"的一侧，判定顺序（先拒绝、后落盘）
 * 必须由端到端用例钉住，函数级断言证明不了它；② 三条守卫叠在 main() 里会把
 * 它的圈复杂度推过 eslint 的 15 上限——为了塞守卫而放宽基线是本末倒置。
 *
 * @param {Object} current 当前实测（文件 -> 规则 -> warn 计数）
 */
function updateBaseline(current) {
  const before = readBaseline(false);
  if (!before) {
    // 「文件不存在」与「文件存在但解析不了」必须分开处理。
    // 前者是首次接入，按实测建账本没有争议；后者意味着账本被改坏了
    // （合并冲突残留、手工编辑漏逗号、截断写入），此时若同样"按当前实测重建"，
    // 等于把**账本坏掉期间涨掉的债**直接写成新地板——而 findBaselineIncreases
    // 正因为"没有可比对象"被整段跳过，"只许降不许升"恰在最需要它的时刻失效，
    // 且整个过程 exit 0、无人被提示去看 diff。机器不许猜账本，人来修（git 里有上一版）。
    if (fs.existsSync(BASELINE_PATH)) {
      console.error('[lint-ratchet] 基线文件存在但解析失败，拒绝按当前实测重建。');
      console.error(
        '                重建会把基线损坏期间新增或上升的债静默洗成新地板（绕过只降不升守卫）。'
      );
      console.error(
        '                请修复 eslint.ratchet.json（必要时从 git 取回上一版）后重跑。'
      );
      process.exit(1);
    }
    writeBaseline(current);
    console.log(
      `[lint-ratchet] 基线文件不存在，已按当前实测建立：${Object.keys(current).length} 个含 warn 文件。`
    );
    return;
  }
  const increases = findBaselineIncreases(before, current);
  if (increases.length > 0) {
    console.error(
      '[lint-ratchet] 拒绝更新基线——棘轮只许降不许升，以下条目相对基线上升或属新增债务：'
    );
    for (const line of increases) console.error(`  + ${line}`);
    console.error('              请拆文件/拆函数把债消化掉再收紧；确需扩大基线，只能人工修改');
    console.error('              eslint.ratchet.json 并让评审在 diff 里看到它。');
    process.exit(1);
  }
  writeBaseline(current);
  const beforeFiles = Object.keys(before).length;
  const afterFiles = Object.keys(current).length;
  console.log(`[lint-ratchet] 基线已更新：${beforeFiles} -> ${afterFiles} 个含 warn 文件。`);
  console.log('              体积/复杂度债只许降不许升，本次收紧已落盘 eslint.ratchet.json。');
}

const main = async () => {
  // 参数校验放在跑 lint **之前**：用法错误要在几毫秒内报出来，而不是等全量 lint 跑完
  assertKnownArgs(process.argv);

  // ── 1. 跑 lint，聚合每个文件按规则维度的 warn 计数与 error 总数 ──
  const { current, errorTotal } = aggregateWarnCounts(await runLint());

  if (errorTotal > 0) {
    console.error(`[lint-ratchet] 检测到 ${errorTotal} 个 error 级违例——error 不属棘轮范畴，`);
    console.error('                请先修复（npm run lint 应保持 0 error）。');
    process.exit(1);
  }

  // ── 2. 与基线比对 ──
  if (UPDATE_MODE) {
    updateBaseline(current);
    return;
  }

  const baseline = readBaseline();
  if (!baseline) {
    console.error('[lint-ratchet] 基线文件 eslint.ratchet.json 不存在。');
    console.error('                首次接入请执行：node scripts/lint-ratchet.js --update-baseline');
    process.exit(1);
  }

  const { regressions, improvements, stale } = diffBaseline(baseline, current);

  // ── 3. 输出与退出码 ──
  if (improvements.length > 0) {
    console.log('[lint-ratchet] 改善（可收紧，执行 --update-baseline 落盘）：');
    for (const line of improvements) console.log(`  - ${line}`);
  }
  if (stale.length > 0) {
    console.log('[lint-ratchet] 基线残留（同样经 --update-baseline 清理）：');
    for (const line of stale) console.log(`  - ${line}`);
  }

  if (regressions.length > 0) {
    console.error('[lint-ratchet] 棘轮回退——以下文件 warn 计数超过基线：');
    for (const line of regressions) console.error(`  + ${line}`);
    console.error(
      '                体积/复杂度债只许降不许升：拆分文件/函数，或与评审确认后收紧基线。'
    );
    process.exit(1);
  }

  // 零命中守卫：基线非空却实测 0 个含 warn 文件，几乎必然是 lint 根本没匹配到
  // 目标（规则被关成 off / eslint ignores 覆盖了 src / ESLINT_TARGETS 被改坏），
  // 而非"真的全干净"。此时若静默 exit 0，棘轮会在无人察觉时永久失效（假绿）。
  // 注：更极端的"一个文件都没扫到"由 ESLint 自己抛 NoFilesFoundError /
  // AllFilesIgnoredError 兜住（实测两种形态都抛，脚本的 catch 转 exit 1），
  // 因此这里不再重复加 scanned==0 守卫——那会是条不可达的死分支。
  if (Object.keys(current).length === 0 && Object.keys(baseline).length > 0) {
    console.error(
      '[lint-ratchet] 实测 0 个含 warn 文件，但基线含 ' + Object.keys(baseline).length + ' 个——'
    );
    console.error(
      '                疑似 lint 未匹配任何文件（规则被关闭或 ignores 覆盖了源码），拒绝判定通过。'
    );
    process.exit(1);
  }

  console.log(`[lint-ratchet] 通过：${Object.keys(current).length} 个含 warn 文件均未超过基线。`);
};

// E-02 加固（2026-09-16）：仅在直接执行时跑 main，并导出纯函数供单测。
// 原实现 `main()` 在文件尾部无条件调用——任何 `require()` 本模块的代码
// （单测、工具链）都会连带跑一遍全量 ESLint 并在有回退时 process.exit(1)，
// 把「引个工具」变成「可能拖垮调用方进程」。与 L-24 的生成器副作用同源。
if (require.main === module) {
  main().catch((err) => {
    console.error(`[lint-ratchet] 执行失败：${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  aggregateWarnCounts,
  diffBaseline,
  findBaselineIncreases,
  toRepoRelative,
  // 导出供门禁自检比对 `npm run lint` 的目标集（漏一个目录就是一条旁路）
  LINT_TARGETS,
};
