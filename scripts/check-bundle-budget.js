#!/usr/bin/env node
/**
 * 前端产物体积预算门禁（check-bundle-budget）
 *
 * 背景：web-admin/vite.config.js 的 chunkSizeWarningLimit 只是构建期**警告**，
 * 不阻断构建。误引入大依赖、manualChunks 规则失效把懒加载组件拽回首屏、
 * 或 PWA 预缓存膨胀，都会让 CI 全绿而用户端首屏变慢——直到有人抱怨。
 * 本脚本把「体积」变成硬门禁：超预算即非零退出。
 *
 * 统计口径（零新增依赖，只用 fs / path / zlib）：
 *   - 遍历 dist 下全部 .js/.css，逐文件记录原始字节与 gzip 字节
 *   - 首屏（entry）单独计量：只统计 dist/index.html 直接引用的
 *     <script src> / <link rel="modulepreload"> / <link rel="stylesheet">。
 *     首屏才是用户感知的加载成本；懒加载 chunk 再多也不该算进首屏预算。
 *   - 另设防呆下限（jsChunks / cssChunks）：dist 为空或构建半途失败时，
 *     「0 字节 < 预算」会假绿，必须显式拦下（构建完整性下限，不是体积棘轮）。
 *
 * 预算数值来源（2026-09-18 实测，Node v24.15.0 + `npm --prefix web-admin run build`，
 * 口径即本脚本 zlib 等级 6 输出，与 nginx / CDN 常规压缩档位一致）：
 *   entryJsGzip   168859 B（首屏 JS：index-2SIdwEoy.js 3583 + vue-vendor-DfObs9Da.js 42199
 *                  + router-D4mFCbIK.js 99973 + store-Cls9lj9v.js 20759
 *                  + rolldown-runtime-QTnfLwEv.js 423 + registerSW.js 126
 *                  + theme-bootstrap.js 474）
 *   entryCssGzip   18009 B（首屏 CSS：index-CtlDbCLb.css 15773 + css-B7R8nRWz.css 1960）
 *   totalRaw     2267046 B（全部 JS+CSS 原始字节之和）
 *   totalGzip     709616 B（全部 JS+CSS gzip 字节之和）
 *   maxChunkGzip  191643 B（最大分块 echarts，懒加载，不进首屏）
 *   jsChunks 68 / cssChunks 37（分块数，用于防呆下限）
 *   预算 = 实测 × (1 + HEADROOM) 向上取整到 ROUND_TO 字节；余量留给正常迭代，
 *   而任何「把首屏拽大」的改动（例如 echarts 191 KB gzip 进首屏）都会立刻红灯。
 *   数值以 web-admin/bundle-budget.json 为唯一事实来源（可 diff、可评审），
 *   本文件的常量只定义预算策略。
 *
 * 用法（退出码：0 = 通过；1 = 超预算 / 低于下限 / 产物不完整 / 基线缺失或损坏；
 * 2 = 用法错误——未知参数或缺值的 --dist/--baseline，此时**尚未读任何产物**）:
 *   node scripts/check-bundle-budget.js                    # 检查（CI / 本地门禁，基线缺失即失败）
 *   node scripts/check-bundle-budget.js --update-baseline  # 按当前实测收紧预算（需先构建）
 *   node scripts/check-bundle-budget.js --update-baseline --allow-growth   # 显式放宽预算
 * 路径覆盖只认 `--dist=<目录>` / `--baseline=<文件>` 这一种形态（写成空格分隔会被判用法错误，
 * 见 bundleBudgetPolicy.js 的 parseCliArgs 注释）。
 * 收紧模式的一条硬规则：基线文件**存在但读不出旧预算**（JSON 坏 / 结构缺项）时，
 * 「本次是否放宽」不可判定，因此按放宽对待——必须带 --allow-growth 才会写入。
 * 否则「先弄坏基线再重写」就是放宽门禁的免确认通道（这条闸本身有专项用例）。
 *   node scripts/check-bundle-budget.js --dist=<dir> --baseline=<file>     # 测试 / 排障用
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
// 判据（基线结构 / 比对 / 收紧公式 / 参数解析）在 bundleBudgetPolicy.js；
// 本文件只负责读产物、呈现与退出码
const {
  METRICS,
  BUDGET_KEYS,
  FLOOR_KEYS,
  isBudget,
  validateBaseline,
  compare,
  tighten,
  parseCliArgs,
} = require('./bundleBudgetPolicy');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_DIST_DIR = path.join(REPO_ROOT, 'web-admin', 'dist');
const DEFAULT_BASELINE_PATH = path.join(REPO_ROOT, 'web-admin', 'bundle-budget.json');

// 参数解析判据在 bundleBudgetPolicy.js：本文件撞过体积棘轮 max-lines=300，
// 而棘轮只许降不许升（见该文件头注释的同一处理），故按既有边界拆过去而不是收紧基线。
const CLI = parseCliArgs(process.argv.slice(2));
const UPDATE_MODE = CLI.updateMode;
const ALLOW_GROWTH = CLI.allowGrowth;

/** gzip 字节数：zlib 默认等级 6，与 nginx / CDN 的常规压缩档位一致 */
const gzipSize = (buf) => zlib.gzipSync(buf).length;
const toPosix = (p) => p.split(path.sep).join('/');
/** 仓库相对路径（正斜杠）；仓库外路径原样返回 */
const relToRepo = (abs) => {
  const rel = path.relative(REPO_ROOT, abs);
  return rel.startsWith('..') ? abs : toPosix(rel);
};

/** 递归列出目录下所有文件（绝对路径）；目录不存在返回空数组 */
function listFiles(dir) {
  const out = [];
  const queue = fs.existsSync(dir) ? [dir] : [];
  while (queue.length > 0) {
    const current = queue.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) queue.push(abs);
      else if (entry.isFile()) out.push(abs); // 只收文件
    }
  }
  return out;
}

/** 统计 dist 下全部 .js/.css 的原始与 gzip 字节；files 按 gzip 降序 */
function collectStats(distDir) {
  const files = [];
  let totalRaw = 0;
  let totalGzip = 0;
  let jsChunks = 0;
  let cssChunks = 0;
  let maxChunkGzip = 0;
  let maxChunkName = '';
  for (const abs of listFiles(distDir)) {
    const rel = toPosix(path.relative(distDir, abs));
    const ext = path.extname(rel).toLowerCase();
    if (ext !== '.js' && ext !== '.css') continue;
    const buf = fs.readFileSync(abs);
    const gz = gzipSize(buf);
    files.push({ rel, raw: buf.length, gzip: gz });
    totalRaw += buf.length;
    totalGzip += gz;
    if (ext === '.js') jsChunks += 1;
    else cssChunks += 1;
    if (gz > maxChunkGzip) [maxChunkGzip, maxChunkName] = [gz, rel];
  }
  files.sort((a, b) => b.gzip - a.gzip);
  return { files, jsChunks, cssChunks, totalRaw, totalGzip, maxChunkGzip, maxChunkName };
}

const SRC_OR_HREF_RE = /\b(?:src|href)="([^"]*)"/;
const REL_RE = /\brel="([^"]*)"/;
const MODULE_TYPE_RE = /\btype="module"/;

/** 解析 index.html 的首屏资源引用：script[src] / link[rel=modulepreload|stylesheet] */
function parseEntryRefs(html) {
  const refs = [];
  const tagRe = /<(script|link)\b([^>]*)>/gi;
  let match;
  while ((match = tagRe.exec(html)) !== null) {
    const attrs = match[2];
    const href = (attrs.match(SRC_OR_HREF_RE) || [])[1];
    if (!href) continue;
    const rel = (attrs.match(REL_RE) || [])[1] || '';
    if (match[1].toLowerCase() === 'script') {
      refs.push({ href, kind: 'script', rel: '', isModule: MODULE_TYPE_RE.test(attrs) });
    } else if (/\b(modulepreload|stylesheet)\b/.test(rel)) {
      refs.push({ href, kind: 'link', rel, isModule: false });
    }
  }
  return refs;
}

/** 单个首屏引用：解析绝对路径 → 存在性/空文件校验 → 累加 gzip 字节 */
function measureEntryRef(distDir, ref, acc, push) {
  if (!ref.href.startsWith('/')) return; // 非自托管引用由 inspect 提前判定，这里只管本地资源
  const relPath = ref.href.slice(1);
  const abs = path.join(distDir, relPath.split('/').join(path.sep));
  if (relPath.split('/').includes('..') || !abs.startsWith(distDir + path.sep)) {
    return push('entry-ref-escapes-dist', `首屏引用越出 dist 目录：${ref.href}`);
  }
  const isJs = relPath.toLowerCase().endsWith('.js');
  const isCss = relPath.toLowerCase().endsWith('.css');
  if (!isJs && !isCss) return; // 只有 js/css 参与首屏体积预算
  if (!fs.existsSync(abs))
    return push('missing-entry-asset', `index.html 引用的资源不存在：${ref.href}`);
  const buf = fs.readFileSync(abs);
  if (buf.length === 0) return push('empty-entry-asset', `首屏资源为空文件（0 字节）：${ref.href}`);
  if (acc.seen.has(abs)) return;
  acc.seen.add(abs);
  acc[isJs ? 'entryJsGzip' : 'entryCssGzip'] += gzipSize(buf);
}

/** 结构校验：入口 script / stylesheet 必须存在，非自托管 js/css 在 CSP 下必然失败 */
function checkEntryStructure(refs, push) {
  for (const ref of refs) {
    if (!ref.href.startsWith('/') && /\.(js|css)$/i.test(ref.href)) {
      const hint = `首屏引用了非自托管资源（CSP script-src 'self' 下无法执行）：${ref.href}`;
      push('entry-ref-not-local', hint);
    }
  }
  const hasEntry = refs.some((r) => r.kind === 'script' && r.isModule && /\.js$/i.test(r.href));
  const hasStyle = refs.some((r) => r.kind === 'link' && r.rel.includes('stylesheet'));
  if (!hasEntry) push('no-entry-script', 'index.html 中没有 module 入口脚本——构建产物不完整');
  if (!hasStyle) push('no-entry-style', 'index.html 中没有 stylesheet 引用——构建产物不完整');
}

/**
 * 结构校验 + 首屏计量。
 * @returns {{ structural: Array<{code: string, message: string}>, stats: Object|null }}
 *   stats 为 null 表示产物不可用（此时 structural 非空）
 */
function inspect(distDir) {
  const structural = [];
  const push = (code, message) => structural.push({ code, message });
  const indexPath = path.join(distDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    const hint = `构建产物不存在：${relToRepo(indexPath)}（请先执行 npm --prefix web-admin run build）`;
    push('missing-build', hint);
    return { structural, stats: null };
  }
  const refs = parseEntryRefs(fs.readFileSync(indexPath, 'utf8'));
  checkEntryStructure(refs, push);
  const acc = { entryJsGzip: 0, entryCssGzip: 0, seen: new Set() };
  for (const ref of refs) measureEntryRef(distDir, ref, acc, push);
  const entry = {
    entryJsGzip: acc.entryJsGzip,
    entryCssGzip: acc.entryCssGzip,
    entryRefCount: refs.length,
  };
  return { structural, stats: { ...collectStats(distDir), ...entry } };
}

/** 校验基线结构：任一指标缺失即拒绝放行（fail-closed） */

/** 与基线比对：budgets 段不得超过上限，floors 段不得低于下限 */

/** 按实测收紧基线：预算 = 实测 ×(1+HEADROOM) 取整；防呆下限 = 实测分块数 ×FLOOR_RATIO */

function readBaseline(baselinePath, strict) {
  if (!fs.existsSync(baselinePath)) return null;
  let raw = fs.readFileSync(baselinePath, 'utf8');
  // 容忍 BOM（Windows 工具链写入的 JSON 可能带 BOM），与 scripts/lint-ratchet.js 同口径
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  try {
    return JSON.parse(raw);
  } catch (err) {
    if (!strict) return null; // 收紧模式：损坏基线直接重写修复
    console.error(`[budget] 基线解析失败：${err.message}（${relToRepo(baselinePath)}）`);
    process.exit(1);
  }
}

/** 逐项对比表的一行：指标名 padStart 到 14 列 + 数值右对齐 9 列 */
const row = (key, value, unit) =>
  `${key}${' '.repeat(Math.max(1, 14 - key.length))}${String(value).padStart(9)}${unit ? ` ${unit}` : ''}`;

/** 打印逐项对比表（无论通过与否都输出实测值，供 CI 日志留痕） */
function printTable(stats, baseline) {
  console.log('[budget]   指标             实测          预算          余量        状态');
  for (const metric of METRICS) {
    const { key, section, unit } = metric;
    const limit = baseline[section][key];
    const budgeted = isBudget(metric);
    const ok = budgeted ? stats[key] <= limit : stats[key] >= limit;
    const cap = budgeted ? `${limit} B` : `${limit} 个（下限）`;
    const margin = budgeted ? `${String(limit - stats[key]).padStart(9)} B` : '';
    const label = ok ? 'OK' : budgeted ? 'OVER' : 'UNDER';
    console.log(
      `[budget]   ${row(key, stats[key], unit)}  ${cap.padEnd(14)}  ${margin}  ${label}`.trimEnd()
    );
  }
}

/** 统一失败出口：打印到 stderr 并退出 1 */
function fail(lines) {
  for (const line of lines) console.error(`[budget] ${line}`);
  process.exit(1);
}

/**
 * 收紧模式的「上一版基线」：文件存在时必须能被当作比较基准，否则不能推断 raised。
 *
 * 为什么不能像原先那样"解析失败就当没有旧基线"：`tighten()` 靠
 * `budgets[key] > previous.budgets[key]` 决定是否要求 `--allow-growth`。
 * previous 缺失 ⇒ raised 恒空 ⇒ **把基线弄坏（或让其被工具写坏）就成了
 * 放宽门禁的免确认通道**——同一套件里"上调需显式确认"那条用例会被无声绕过。
 *
 * 也不因此卡死运维（原用例「不因解析失败卡死」的诉求保留）：
 * 仍可用 `--update-baseline --allow-growth` 重建，只是必须显式确认一次。
 */
function previousForUpdate(baselinePath) {
  if (!fs.existsSync(baselinePath)) return {}; // 首次接入：没有旧预算可比，按建立处理
  const prev = readBaseline(baselinePath, false);
  const problems = validateBaseline(prev);
  if (problems.length === 0) return prev;
  // 拒绝是默认姿态；但必须留一条**真的能走通**的出路（原用例「不因解析失败卡死」）。
  // 拒绝文案里让操作员追加 --allow-growth，就得在这里认这个 flag——
  // 否则它是个死胡同：加了 flag 仍然被拒，等于把「可修复」降级成「必须人工改文件」。
  if (!ALLOW_GROWTH) {
    fail([
      `已有基线文件但无法作为「上一版预算」使用，拒绝据此静默重写：${relToRepo(baselinePath)}`,
      ...problems.map((p) => `  - ${p}`),
      '原因：与旧预算无法比较时，"本次是否放宽了门禁"不可判定，' +
        '静默按新实测重写会让「上调预算需 --allow-growth 显式确认」这道闸被绕过。',
      '确认可接受当前实测为准，请追加 --allow-growth 重跑；' +
        '或先 git checkout -- 恢复基线（更常见：文件被工具链写坏而非预算真的该放宽）。',
    ]);
  }
  console.error(
    '[budget] 已带 --allow-growth：旧基线不可用，按「重建基线」处理（本次不与旧预算比较）。'
  );
  return {};
}

/** 收紧模式：产物必须完整，新基线需自检通过；放宽预算需 --allow-growth */
function runUpdateMode(stats, structural, baselinePath) {
  if (!stats || structural.length > 0) {
    fail([...structural.map((v) => `✗ ${v.message}`), '产物不完整时拒绝收紧基线。']);
  }
  const { baseline: next, raised } = tighten(stats, previousForUpdate(baselinePath));
  const selfCheck = compare(stats, next);
  if (selfCheck.length > 0) {
    const head = '内部错误：收紧后的基线无法通过自检，已放弃写入。';
    fail([head, ...selfCheck.map((v) => `  - ${v.message}`)]);
  }
  if (raised.length > 0 && !ALLOW_GROWTH) {
    const lines = raised.map((line) => `  + ${line}`);
    fail([
      '以下预算将被上调（放宽门禁），需显式确认：',
      ...lines,
      '确属预期请追加 --allow-growth 重跑。',
    ]);
  }
  fs.writeFileSync(baselinePath, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  console.log(`[budget] 基线已写入（实测日期 ${next.measuredAt}）：${relToRepo(baselinePath)}`);
  printTable(stats, next);
}

/** 检查模式：基线缺失/损坏/结构不完整一律 fail-closed，产物不完整同样失败 */
function runCheckMode(stats, structural, baselinePath) {
  const baseline = readBaseline(baselinePath, true);
  if (!baseline) {
    const hint = '首次接入：先构建，再执行 --update-baseline 生成基线。';
    fail([`基线文件不存在：${relToRepo(baselinePath)}`, hint]);
  }
  const problems = validateBaseline(baseline);
  if (problems.length > 0) {
    fail(['基线结构不完整（fail-closed，拒绝放行）：', ...problems.map((p) => `  - ${p}`)]);
  }
  if (!stats) fail([...structural.map((v) => `✗ ${v.message}`), '产物不可用，门禁失败。']);
  printTable(stats, baseline);
  const counts = `${stats.jsChunks} 个 JS + ${stats.cssChunks} 个 CSS 分块；首屏引用 ${stats.entryRefCount} 个资源`;
  console.log(`[budget]   产物：${counts}`);
  console.log(`[budget]   最大分块：${stats.maxChunkName}（gzip ${stats.maxChunkGzip} B）`);
  const violations = [...structural, ...compare(stats, baseline)];
  if (violations.length > 0) {
    const top = stats.files.slice(0, 5).map((f) => `  - ${f.rel} raw=${f.raw} B gzip=${f.gzip} B`);
    const tail = [
      '  最大 5 个分块（按 gzip）：',
      ...top,
      '处理：确属预期则本地 --update-baseline 收紧并随提交评审。',
    ];
    fail([
      `✗ 未通过（${violations.length} 项）：`,
      ...violations.map((v) => `  - ${v.message}`),
      ...tail,
    ]);
  }
  console.log(
    `[budget] 通过：${BUDGET_KEYS.length} 项预算 + ${FLOOR_KEYS.length} 项防呆下限均满足。`
  );
}

function main() {
  if (CLI.errors.length > 0) {
    for (const e of CLI.errors) console.error(`[budget] 用法错误：${e}`);
    console.error(
      '[budget] 用法: node scripts/check-bundle-budget.js ' +
        '[--update-baseline [--allow-growth]] [--dist=<目录>] [--baseline=<文件>]'
    );
    process.exit(2);
  }
  const distDir = path.resolve(CLI.dist || DEFAULT_DIST_DIR);
  const baselinePath = path.resolve(CLI.baseline || DEFAULT_BASELINE_PATH);
  const tag = '[budget] 前端产物体积预算门禁（首屏单列 + 总量 + 假绿防护）';
  console.log(tag);
  console.log(`[budget]   dist = ${relToRepo(distDir)} 基线 = ${relToRepo(baselinePath)}`);
  const { structural, stats } = inspect(distDir);
  if (UPDATE_MODE) runUpdateMode(stats, structural, baselinePath);
  else runCheckMode(stats, structural, baselinePath);
}

// 仅在直接执行时跑 main；require() 本模块（单测）不得触发文件读取或 process.exit
if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`[budget] 执行失败：${err.message}`);
    process.exit(1);
  }
}

// 供单测与工具链复用：本文件是**唯一** require 入口——计量函数在此，
// 判据从 bundleBudgetPolicy.js 透出（不另立第二份清单）。
module.exports = {
  ...require('./bundleBudgetPolicy'),
  gzipSize,
  parseEntryRefs,
  collectStats,
  inspect,
};
