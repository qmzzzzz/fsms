'use strict';

/**
 * 注释密度统计与棘轮基线（Q-1，见 ADR-011）
 *
 * 口径：逐行判定，只看**整行注释**与纯代码行：
 *   - 整行注释：trim 后以 `//`、`/*`、`*` 开头（含块注释续行 ` * `）；
 *   - 空行不计入分母；行尾注释依附代码行，不单独计数。
 * 与审计报告 §3.1 的 39.2% 同一口径：注释整行 / 非空行。
 *
 * 统计面只含生产代码（`src/**` 排除 `src/tests/**`）：测试里的夹具说明不承载
 * 运行期约束，混进来会让"删测试"看起来像"注释治理"。
 *
 * 用法：
 *   node scripts/commentDensity.js                 打印总量
 *   node scripts/commentDensity.js --print         逐文件 JSON（人工查看）
 *   node scripts/commentDensity.js --update-baseline  收紧基线（存在回退时拒绝）
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BASELINE_PATH = path.join(__dirname, 'commentDensity.baseline.json');

const LINE_COMMENT = /^\s*(\/\/|\/\*|\*)/;

/** 新文件允许的注释密度上限：低于全仓现状，新代码不得免费入场 */
const NEW_FILE_MAX = 0.3;

/** 收集指定根目录下的 .js 文件（跳过 node_modules / 生成物） */
function collect(dir, acc = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'coverage') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) collect(full, acc);
    else if (e.name.endsWith('.js')) acc.push(full);
  }
  return acc;
}

/**
 * 单文件密度。
 * @param {string} text
 * @returns {{comment:number, code:number, total:number, ratio:number}}
 */
function measure(text) {
  const lines = String(text).split(/\r?\n/);
  let comment = 0;
  let code = 0;
  for (const line of lines) {
    if (line.trim() === '') continue;
    if (LINE_COMMENT.test(line)) comment += 1;
    else code += 1;
  }
  const total = comment + code;
  return { comment, code, total, ratio: total === 0 ? 0 : comment / total };
}

/** 全仓（src 下，含测试）逐文件度量，键为仓库相对路径 */
function survey(root = path.join(ROOT, 'src')) {
  const out = {};
  for (const file of collect(root)) {
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    const m = measure(fs.readFileSync(file, 'utf8'));
    if (m.total > 0) out[rel] = m;
  }
  return out;
}

/** 生产代码面：排除 src/tests/** */
function production() {
  return Object.fromEntries(
    Object.entries(survey()).filter(([rel]) => !rel.startsWith('src/tests/'))
  );
}

const totalsOf = (files) =>
  Object.values(files).reduce(
    (a, m) => ({ comment: a.comment + m.comment, code: a.code + m.code }),
    { comment: 0, code: 0 }
  );

/**
 * 基线比较。纯函数：真实基线与测试里的合成反例走同一条逻辑。
 *
 * 判定只看**注释行数**，不看 ratio 的四舍五入：同一文件里删代码会让 ratio 上升，
 * 但"注释体量不变"不是新增负债；反过来新增一行注释在任何 ratio 下都必须先还一行。
 *
 * @param {{files: Object<string,{comment:number}>}} baseline
 * @param {Object<string,{comment:number,ratio:number}>} current
 * @param {{newFileMax?: number}} [opts]
 */
function evaluate(baseline, current, opts = {}) {
  const newFileMax = opts.newFileMax ?? NEW_FILE_MAX;
  const baseFiles = baseline.files || {};
  const regressions = [];
  const stale = [];
  const newFiles = [];
  const newFilesOverCap = [];

  for (const [rel, m] of Object.entries(current)) {
    const base = baseFiles[rel];
    if (!base) {
      newFiles.push({ file: rel, ratio: m.ratio });
      if (m.ratio > newFileMax) newFilesOverCap.push({ file: rel, ratio: m.ratio });
    } else if (m.comment > base.comment) {
      regressions.push({ file: rel, base: base.comment, now: m.comment });
    }
  }
  for (const rel of Object.keys(baseFiles)) {
    if (!current[rel]) stale.push(rel);
  }

  const now = totalsOf(current);
  const baseTotal = baseline.total || { comment: 0, code: 0 };
  return {
    regressions,
    stale,
    newFiles,
    newFilesOverCap,
    totalRegressed: now.comment > baseTotal.comment,
    total: now,
    ok:
      regressions.length === 0 &&
      newFilesOverCap.length === 0 &&
      stale.length === 0 &&
      now.comment <= baseTotal.comment,
  };
}

function snapshot(files) {
  const total = totalsOf(files);
  const grand = total.comment + total.code;
  return {
    note:
      '注释密度棘轮基线（生产代码：src/** 排除 src/tests/**）。只许收紧；' +
      '新增文件密度上限见 scripts/commentDensity.js 的 NEW_FILE_MAX。',
    files,
    total: { ...total, ratio: grand === 0 ? 0 : Number((total.comment / grand).toFixed(4)) },
  };
}

function readBaseline() {
  if (!fs.existsSync(BASELINE_PATH)) return null;
  return JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
}

function main() {
  const files = production();
  const total = totalsOf(files);
  const grand = total.comment + total.code;

  if (process.argv.includes('--update-baseline')) {
    const current = snapshot(files);
    const baseline = readBaseline();
    if (baseline) {
      const verdict = evaluate(baseline, current.files);
      if (!verdict.ok) {
        const details = [
          ...verdict.regressions.map((r) => `回归 ${r.file}: ${r.base} → ${r.now}`),
          ...verdict.newFilesOverCap.map(
            (r) => `新文件超密度上限 ${r.file}: ${(r.ratio * 100).toFixed(1)}%`
          ),
          ...verdict.stale.map((f) => `清单残留 ${f}（文件已删除/改名，需同批更新基线）`),
          ...(verdict.totalRegressed ? [`总量回归：上限 ${baseline.total.comment} 行`] : []),
        ];
        process.stderr.write(`拒绝收紧基线：\n  ${details.join('\n  ')}\n`);
        process.exit(1);
      }
    }
    fs.writeFileSync(BASELINE_PATH, `${JSON.stringify(current, null, 2)}\n`);
    process.stdout.write(
      `已写入 ${path.relative(ROOT, BASELINE_PATH)}：files=${Object.keys(files).length} ` +
        `comment=${total.comment} code=${total.code}\n`
    );
    return;
  }

  process.stdout.write(
    `files=${Object.keys(files).length} comment=${total.comment} code=${total.code} ` +
      `ratio=${((total.comment / grand) * 100).toFixed(1)}%\n`
  );
  if (process.argv.includes('--print')) {
    const rounded = {};
    for (const rel of Object.keys(files).sort()) {
      rounded[rel] = Math.floor(files[rel].ratio * 10000) / 10000;
    }
    process.stdout.write(`${JSON.stringify(rounded, null, 2)}\n`);
  }
}

if (require.main === module) main();

module.exports = {
  measure,
  survey,
  production,
  evaluate,
  totalsOf,
  collect,
  LINE_COMMENT,
  NEW_FILE_MAX,
  BASELINE_PATH,
};
