#!/usr/bin/env node
/**
 * ESLint 体积棘轮（O-3，第六档）
 *
 * 背景：max-lines / max-lines-per-function 以 warn 级接入（eslint.config.js
 * 棘轮第六档）。体积债与 linter 错误性质不同——后者清零即收，前者须随
 * 控制器瘦身逐步消化，因此不走「清零提 error」，而是逐文件计数基线：
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
 *   1 = 存在回退 / 存在 error / 基线缺失（检查模式且基线文件不存在）
 *
 * 零新增依赖：ESLint Node API（eslint 已是 devDependency）+ Node 内置模块。
 */

const fs = require('fs');
const path = require('path');

const UPDATE_MODE = process.argv.includes('--update-baseline');

const repoRoot = path.resolve(__dirname, '..');
const BASELINE_PATH = path.join(repoRoot, 'eslint.ratchet.json');
// 与 npm run lint 同一目标集（package.json scripts.lint）
const LINT_TARGETS = ['src', 'scripts', 'eslint.config.js'];

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

const main = async () => {
  // ── 1. 跑 lint，聚合每个文件按规则维度的 warn 计数与 error 总数 ──
  const results = await runLint();

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

  if (errorTotal > 0) {
    console.error(`[lint-ratchet] 检测到 ${errorTotal} 个 error 级违例——error 不属棘轮范畴，`);
    console.error('                请先修复（npm run lint 应保持 0 error）。');
    process.exit(1);
  }

  // ── 2. 与基线比对 ──
  if (UPDATE_MODE) {
    const before = readBaseline(false) || {};
    writeBaseline(current);
    const beforeFiles = Object.keys(before).length;
    const afterFiles = Object.keys(current).length;
    console.log(`[lint-ratchet] 基线已更新：${beforeFiles} -> ${afterFiles} 个含 warn 文件。`);
    console.log('                体积债只许降不许升，本次收紧已落盘 eslint.ratchet.json。');
    return;
  }

  const baseline = readBaseline();
  if (!baseline) {
    console.error('[lint-ratchet] 基线文件 eslint.ratchet.json 不存在。');
    console.error('                首次接入请执行：node scripts/lint-ratchet.js --update-baseline');
    process.exit(1);
  }

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
    console.error('                体积债只许降不许升：拆分文件/函数，或与评审确认后收紧基线。');
    process.exit(1);
  }

  console.log(`[lint-ratchet] 通过：${Object.keys(current).length} 个含 warn 文件均未超过基线。`);
};

main().catch((err) => {
  console.error(`[lint-ratchet] 执行失败：${err.message}`);
  process.exit(1);
});
