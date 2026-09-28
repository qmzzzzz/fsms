/**
 * 扫描面双向对账闸：`npm run lint`（根 + 前端）与 `npm run format:check` 必须看见同一批 .js。
 *
 * 为什么需要这条闸（2026-09-26 实测，脚本 `zztmpctl/zZbScanFace89b.js`，输出
 * `zztmpctl/b89scanface2.txt`）：三面原本无人对账，结果是一批文件**同时**逃过 lint 与
 * 棘轮——`migrations/` 的 4 个迁移、`migrate-mongo-config.js`、`playwright.config.js` 共 6 个
 * 在 format 面里、却不在任何 lint lane 里；反方向 `eslint.config.js`、`web-admin/eslint.config.js`、
 * `web-admin/vite.config.js` 被 lint 却从不被 prettier 检查，实测其中
 * `web-admin/eslint.config.js` **已经排版漂移**（`npx prettier --check` exit 1，
 * `zztmpctl/b89webfmt.txt`）——漂移的正是那条"没有闸"的方向。
 *
 * 本闸只登记、不改门禁脚本：把 6 个旁路收进 lint 目标集要同时改 `package.json` 的 `scripts.lint`
 * 与 `scripts/lint-ratchet.js` 的 `LINT_TARGETS`（只改前者会让 `gateSelfTest.test.js` 的
 * "棘轮必须覆盖每个 lint 目标"立刻红），而 `scripts/lint-ratchet.js` 有 +152 行未提交的在途改动
 * 待独立评审（见台账批次 62 的"门禁脚本自身的在途改动待独立评审"）。修法已作为交接项给出。
 *
 * 登记表是**双向**的：新增一个未登记的旁路文件即红；旁路被真的修好之后，残留的登记项同样即红
 * （届时删掉那几行即可，不要删用例）。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const WEB_DIR = path.join(ROOT, 'web-admin');

/** 与两条门禁命令自身的排除口径一致：这些目录既不进 lint 也不进 format。 */
const SKIP_DIRS = new Set([
  'node_modules',
  'coverage',
  'logs',
  'backups',
  'dist',
  'zztmpctl',
  'zznpmtest',
]);

/**
 * 已登记的面差。`because` 为空 ⇒ 这是**待修的债**；非空 ⇒ 有明确理由的除外，
 * 且理由必须能在 `eslint.config.js` 的 `ignores` 里找到实据（见用例 5）。
 */
const LINT_BLIND = [
  { file: 'migrations/20260830000000-backfill-token-version.js', because: '' },
  { file: 'migrations/20260831000000-reconcile-audit-index-options.js', because: '' },
  { file: 'migrations/20260919000000-reconcile-audit-ttl-to-retention.js', because: '' },
  { file: 'migrations/20260926000000-cursor-tiebreak-compound-indexes.js', because: '' },
  { file: 'migrations/20260928000000-audit-username-ci-index.js', because: '' },
  { file: 'migrate-mongo-config.js', because: '' },
  { file: 'playwright.config.js', because: '' },
  { file: 'scripts/perf/k6-core-journeys.js', because: 'scripts/perf/k6-*.js' },
];

const FORMAT_BLIND = ['eslint.config.js', 'web-admin/eslint.config.js', 'web-admin/vite.config.js'];

/** `eslint <目标...> [flag...]`：非 flag 参数才是扫描面。 */
function parseTargets(script) {
  return script
    .split(/\s+/)
    .slice(1)
    .filter((a) => a.length > 0 && !a.startsWith('-'));
}

function walkJs(abs, out) {
  if (!fs.existsSync(abs)) return out;
  const st = fs.statSync(abs);
  const rel = path.relative(ROOT, abs).replace(/\\/g, '/');
  if (st.isFile()) {
    if (/\.(c|m)?js$/.test(abs)) out.add(rel);
    return out;
  }
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    const child = path.join(abs, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walkJs(child, out);
    } else if (/\.(c|m)?js$/.test(e.name)) {
      out.add(path.relative(ROOT, child).replace(/\\/g, '/'));
    }
  }
  return out;
}

/** 目标集 ⇒ 该 lane 名义上覆盖的 .js（尚未扣掉 eslint 的 ignores）。 */
function faceOf(targets, baseDir) {
  const set = new Set();
  const missing = [];
  for (const t of targets) {
    const abs = path.join(baseDir, t);
    if (!fs.existsSync(abs)) missing.push(t);
    walkJs(abs, set);
  }
  return { set, missing };
}

/** 扁平配置里的 `**` 跨目录、`*` 不跨目录；本仓 ignores 只有这两种通配。 */
function ignorePatternToRegExp(pattern) {
  const body = pattern
    .split('**')
    .map((seg) => {
      const escaped = seg.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      return escaped.replace(/\*/g, '[^/]*');
    })
    .join('.*');
  return new RegExp(`^${body}$`);
}

function isIgnoredBy(file, patterns) {
  return patterns.some((p) => ignorePatternToRegExp(p).test(file));
}

function readScripts(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8')).scripts;
}

/** 行锚判据前统一换行：`ci.yml` 与前端配置都是 CRLF，`$` 前面会留一个 `\r`（实测 518 处）。 */
function readText(file) {
  return fs.readFileSync(file, 'utf8').replace(/\r\n?/g, '\n');
}

const rootScripts = readScripts(path.join(ROOT, 'package.json'));
const webScripts = readScripts(path.join(WEB_DIR, 'package.json'));

const ROOT_LINT_TARGETS = parseTargets(rootScripts.lint);
const WEB_LINT_TARGETS = parseTargets(webScripts.lint);
const FORMAT_TARGETS = parseTargets(rootScripts['format:check']);

const rootLintFace = faceOf(ROOT_LINT_TARGETS, ROOT);
const webLintFace = faceOf(WEB_LINT_TARGETS, WEB_DIR);
const formatFace = faceOf(FORMAT_TARGETS, ROOT);

const ESLINT_IGNORES = require(path.join(ROOT, 'eslint.config.js')).flatMap(
  (c) => (c && c.ignores) || []
);
const WEB_PREFIX = 'web-admin/';
/**
 * 前端那份是 **ESM**（`import js from '@eslint/js'`），jest 的 CJS 运行时 require 不动它；
 * 而纯 node 下 `require(esm)` 返回的是**命名空间对象**、不是 default 数组——探针第一版用
 * `Array.isArray(cfg) ? cfg : []` 兜底，于是把真实的 5 条 ignores 静默读成"前端零忽略"。
 * 抓到这件事的是下面用例 5 的文本判据（不是我想到要去查）。所以这里按文本抽
 * `ignores: [...]` 里的字符串，并在用例 5 自证"文件里有这个键 ⇒ 一定抽得出东西"。
 */
function extractIgnores(text) {
  const block = /ignores:\s*\[([\s\S]*?)\]/.exec(text);
  if (!block) return [];
  return [...block[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1]);
}

const WEB_CFG_TEXT = readText(path.join(WEB_DIR, 'eslint.config.js'));
const WEB_ESLINT_IGNORES = extractIgnores(WEB_CFG_TEXT);

/**
 * "被 lint 看过"要按 eslint 的实际行为算：目标目录里被 `ignores` 排除的文件不算。
 * 不扣这一层，`scripts/perf/k6-*.js` 这类**有理由的除外**就会伪装成已覆盖，而它逃过 lint 的理由
 * 和那 6 个旁路逃过 lint 的理由在文件集合上完全一样。忽略表**按 lane 各扣各的、且按各自 baseDir
 * 匹配**：根配置里有 `web-admin/**`，拿它去扣前端面会把 119 个前端文件全部误判成旁路。
 */
function lintedFiles() {
  const kept = new Set();
  for (const f of rootLintFace.set) {
    if (!isIgnoredBy(f, ESLINT_IGNORES)) kept.add(f);
  }
  for (const f of webLintFace.set) {
    const rel = f.startsWith(WEB_PREFIX) ? f.slice(WEB_PREFIX.length) : f;
    if (!isIgnoredBy(rel, WEB_ESLINT_IGNORES)) kept.add(f);
  }
  return kept;
}

function difference(a, b) {
  return [...a].filter((f) => !b.has(f)).sort();
}

describe('lint 与 format 两条门禁的扫描面必须同源', () => {
  test('前提自证：目标集解析成功、每条目标真实存在、且各面基数在量级上（否则差集会空得毫无意义）', () => {
    expect(ROOT_LINT_TARGETS.length).toBeGreaterThanOrEqual(3);
    expect(WEB_LINT_TARGETS.length).toBeGreaterThanOrEqual(2);
    expect(FORMAT_TARGETS.length).toBeGreaterThanOrEqual(10);
    expect(rootLintFace.missing).toEqual([]);
    expect(webLintFace.missing).toEqual([]);
    expect(formatFace.missing).toEqual([]);
    // 实测：rootLint=658 / webLint=119 / format=780。下限取一半：够不到就说明解析或目录漂了。
    expect(rootLintFace.set.size).toBeGreaterThanOrEqual(300);
    expect(webLintFace.set.size).toBeGreaterThanOrEqual(60);
    expect(formatFace.set.size).toBeGreaterThanOrEqual(300);
  });

  test('前提自证（判据有牙）：忽略匹配器本身可证伪，且把 lint 面人为削掉 src/ 时旁路必须暴涨', () => {
    // 匹配器若"恒假"，`scripts/perf/k6-*.js` 就不会进旁路集合；若"恒真"，整个前端面都会被判成
    // 旁路。两种失效都会撞到登记表等式，但那样红的是"数字不对"而不是"匹配器坏了"——这里直给。
    expect(isIgnoredBy('scripts/perf/k6-core-journeys.js', ['scripts/perf/k6-*.js'])).toBe(true);
    expect(isIgnoredBy('scripts/perf/other.js', ['scripts/perf/k6-*.js'])).toBe(false);
    expect(isIgnoredBy('web-admin/src/a.js', ['web-admin/**'])).toBe(true);
    expect(isIgnoredBy('src/web-admin/a.js', ['web-admin/**'])).toBe(false);

    // 差集判据最容易死在"两侧都是空集"上。这里不改盘，只在内存里造一次洞。
    const linted = lintedFiles();
    const holed = new Set([...linted].filter((f) => !f.startsWith('src/')));
    expect(difference(formatFace.set, holed).length).toBeGreaterThan(300);
    expect(difference(formatFace.set, linted)).toHaveLength(LINT_BLIND.length);
  });

  test('format 看得见、任何 lint lane 都看不见的 .js 必须逐条登记（新旁路即红；旁路修好后残留登记也即红）', () => {
    const lintBlind = difference(formatFace.set, lintedFiles());
    expect(lintBlind).toEqual(LINT_BLIND.map((e) => e.file).sort());
    // 登记项指向的文件必须还在：删了迁移却忘了摘登记，也要红得有名有姓。
    for (const e of LINT_BLIND) {
      expect(fs.existsSync(path.join(ROOT, e.file))).toBe(true);
    }
  });

  test('lint 看得见、format 看不见的 .js 必须逐条登记（反方向同一条纪律）', () => {
    const formatBlind = difference(lintedFiles(), formatFace.set);
    expect(formatBlind).toEqual([...FORMAT_BLIND].sort());
    for (const f of FORMAT_BLIND) {
      expect(fs.existsSync(path.join(ROOT, f))).toBe(true);
    }
  });

  test('登记表里每条"有理由的除外"都必须能在 eslint.config.js 的 ignores 找到实据，且模式真命中该文件', () => {
    const justified = LINT_BLIND.filter((e) => e.because);
    // 前提自证：这条判据不能跑在空表上——全表都"无理由"时它只会恒真。
    expect(justified.length).toBeGreaterThanOrEqual(1);
    for (const e of justified) {
      expect(ESLINT_IGNORES).toContain(e.because);
      expect(isIgnoredBy(e.file, [e.because])).toBe(true);
    }
    // 无理由的债也要有数：当前 8 条旁路里 7 条待修（交接项），这个数字只该往下走。
    // 2026-09-28 由 6→7：补记 20260928000000 迁移文件入库时漏掉的登记（当时被
    // test job 的 18.x fail-fast 连坐掩盖，红灯从未真正跑到这里）。
    expect(LINT_BLIND.filter((e) => !e.because)).toHaveLength(7);
    // 前端 lane 的忽略表是**按文本抽**出来的（ESM 在 jest 的 CJS 运行时 require 不动）。
    // 抽取会静默少读：不判"抽到了几条"，而是判"文件里有这个键 ⇒ 抽取器一定不空"。
    // 缺了这条，哪天 ignores 写成 `ignores: getIgnores()` 或换行形制变了，抽取器返回 []，
    // lintedFiles() 就当"前端零忽略"继续绿——这正是本批探针已经真实踩过一次的那个坑。
    const hasIgnoresKey = /^[ \t]*ignores:/m.test(WEB_CFG_TEXT);
    expect(WEB_ESLINT_IGNORES.length > 0).toBe(hasIgnoresKey);
  });

  test('前端 lint 必须真在 CI 里跑，否则 119 个文件的"被覆盖"只是本地自觉', () => {
    const ci = readText(path.join(ROOT, '.github', 'workflows', 'ci.yml'));
    // 前端 lane：working-directory 切到 web-admin 后紧接的那条 run 必须是 lint（200 字符窗口内）
    expect(
      /^[ \t]*working-directory:[ \t]*web-admin[ \t]*$/m.test(ci) &&
        /working-directory:[ \t]*web-admin[\s\S]{0,200}?^[ \t]*run:[ \t]*npm run lint[ \t]*$/m.test(
          ci
        )
    ).toBe(true);
    // 反向对照：光有前端那条不算数——`run: npm run lint` 必须在 CI 里出现两次（后端 job 一条、
    // 前端 job 一条）。只断言"存在一条 npm run lint"的话，删掉后端那条也照样绿。
    const lintRuns = ci.match(/^[ \t]*run:[ \t]*npm run lint[ \t]*$/gm) || [];
    expect(lintRuns).toHaveLength(2);
    expect(/^[ \t]*run:[ \t]*npm run lint:ratchet[ \t]*$/m.test(ci)).toBe(true);
    expect(/^[ \t]*run:[ \t]*npm run format:check[ \t]*$/m.test(ci)).toBe(true);
  });
});
