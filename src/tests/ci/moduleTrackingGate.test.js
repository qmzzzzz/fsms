/**
 * 模块入库闭包门禁：被跟踪源码引用到的**本地模块，必须也在版本库里**
 *
 * 为什么需要它（2026-10-31 实测的真实形状）：工作树里长期挂着 5 个源码文件**没入库**——
 * `src/constants/reportExportColumns.js`（被 reportExportService 引用）、`src/utils/pngStructure.js` 与
 * `src/utils/avatarImageError.js`（被 avatarImage 引用）、`web-admin/src/i18n/auditReasons.js`（被
 * AuditLogView 引用）、`src/tests/deploy/helpers/releaseNotesScript.js`（被两个 deploy 套件引用）。
 * 本机跑什么都绿——因为文件就在盘上；**干净克隆会直接 MODULE_NOT_FOUND**。
 * 这类缺陷不属于「某条判据写错了」，而属于「交付物不完整」：门禁在本地永远看不见它。
 *
 * 与既有门禁的分工（刻意不重叠，避免第二份真源）：
 *   · `src/tests/architecture/requireCycles.test.js` 判「相对 require 能否解析到真实文件」——它只认盘上有没有；
 *   · `src/tests/ci/testTreePurity.test.js` 判「src/tests 下的 *.test.js 是否入库」——只管测试树；
 *   · 本条判「**解析得到**的本地目标是否入库」——恰好是上面两条之间的缝：能被解析、但没入库。
 *
 * 判据口径（为什么不是「所有 require 都要入库」）：
 *   · 只查**解析得到真实文件**的说明符。解析不到的（`require('./zz_幽灵模块')` 这类反向自证夹具、
 *     字符串里的示例代码）不归本条管——requireCycles 已有 src 侧判据，这里再判一次只会制造第二口径；
 *   · 注释先剥掉：注释里描述历史的 `require('./x')` 不执行，算进来就是凭空造红；
 *   · 字符串里的说明符会误入（实测 scripts/production-drill.js:207 有一行**作为夹具文本**的
 *     `require('./src/config/validate.js')`）——但它按本文件所在目录解析成 scripts/src/config/validate.js，
 *     盘上没有 ⇒ 走「解析不到」分支，天然不误报。这条是设计使然，不是碰巧。
 *
 * 反向自证（本条门禁自己的牙）：`survey()` 吃 {file, source} 数组而不是直接读盘——读盘版只能
 * 「对着真实仓库断言 0 条」，永远证不了自己有牙。用例里喂一份**指向盘上已存在但未入库文件**的合成
 * 模块，必须被点名；再喂一份指向已入库文件的，必须不点名。
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
// 「什么算注释」的口径只有一份（src/tests/helpers/jsCodeOnly.js）：本闸判的是源码文本，
// 自己再写一份剥离正则就等于复制一份口径——任一处改坏另一处仍然绿（见 commentViewSingleSource 闸）。
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

/** 仓库根（本文件在 src/tests/ci/ 下） */
const ROOT = path.join(__dirname, '..', '..', '..');

/** 扫描根：源码 + 脚本 + 迁移 + e2e + 前端源码（其余目录要么是产物要么是第三方） */
const SCAN_ROOTS = ['src', 'scripts', 'migrations', 'e2e', 'web-admin/src'];

/** 解析候选后缀与 `index` 兜底，与 Node 的 CommonJS 解析顺序一致 */
const EXTS = ['.js', '.cjs', '.mjs', '.ts', '.vue', '.json'];

/** 前缀别名 → 基准目录。前端 `@/` 指向 web-admin/src（与 vite 配置一致） */
const ALIASES = [['@/', path.join(ROOT, 'web-admin', 'src')]];

/** 遍历时跳过的目录名（产物/第三方，里面的引用不代表源码依赖） */
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage']);

/** 扫描文件的后缀（只要可能出现 require/import 的） */
const SCAN_EXT = /\.(js|cjs|mjs|ts|vue)$/;

/**
 * 提取「本地说明符」：相对路径（./ ../）与前缀别名（@/）。
 * `import x from 'vue'`、`require('fs')` 这类裸包名不是本地模块，不归本条管。
 * @param {string} src 已剥注释的源码
 * @returns {string[]}
 */
const localSpecs = (src) =>
  [...src.matchAll(/(?:require\(\s*|from\s+|import\s*\(\s*)['"]([^'"]+)['"]/g)]
    .map((m) => m[1])
    .filter((spec) => spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('@/'));

/**
 * 说明符 → 盘上真实文件（解析不到返回 null）。
 * @param {string} fromFile 引用方绝对路径
 * @param {string} spec
 * @returns {string|null}
 */
const resolveLocal = (fromFile, spec) => {
  const alias = ALIASES.find(([prefix]) => spec.startsWith(prefix));
  const base = alias
    ? path.join(alias[1], spec.slice(alias[0].length))
    : path.resolve(path.dirname(fromFile), spec);
  const candidates = [
    base,
    ...EXTS.map((e) => base + e),
    ...EXTS.map((e) => path.join(base, 'index' + e)),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  }
  return null;
};

/** 仓库相对路径（正斜杠，与 git ls-files 同口径） */
const relOf = (abs) => path.relative(ROOT, abs).replace(/\\/g, '/');

/**
 * 体检：解析得到的本地引用里，哪些目标不在 `tracked` 集合里。
 * 吃 {file, source} 数组而不是直接读盘 —— 见文件头「反向自证」。
 * @param {Array<{file: string, source: string}>} modules
 * @param {Set<string>} tracked 仓库相对路径集合（正斜杠）
 * @returns {{total: number, strays: Array<{from: string, spec: string, target: string}>}}
 */
const survey = (modules, tracked) => {
  const strays = [];
  let total = 0;
  for (const { file, source } of modules) {
    for (const spec of localSpecs(jsCodeOnly(source))) {
      const hit = resolveLocal(file, spec);
      if (hit === null) continue; // 解析不到不归本条管（见文件头口径）
      total += 1;
      const target = relOf(hit);
      if (!tracked.has(target)) strays.push({ from: relOf(file), spec, target });
    }
  }
  return { total, strays };
};

/** 递归收集扫描根下的源码文件 */
const collectFiles = (dir, acc = []) => {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectFiles(full, acc);
    else if (SCAN_EXT.test(entry.name)) acc.push(full);
  }
  return acc;
};

/** 真实仓库的 {file, source} 全量（每个文件读一次） */
const realModules = () =>
  SCAN_ROOTS.flatMap((r) => collectFiles(path.join(ROOT, r))).map((file) => ({
    file,
    source: fs.readFileSync(file, 'utf8'),
  }));

let tracked;

beforeAll(() => {
  // 缺 .git 时**不跳过、直接失败**：静默跳过等于把这条门禁变成 fail-open，
  // 而这条门禁恰恰是唯一能发现「交付物不完整」的那条（本地全绿、干净克隆崩）。
  if (!fs.existsSync(path.join(ROOT, '.git'))) {
    throw new Error(
      '未找到 .git：本条依赖 git ls-files 判定「是否入库」，请在 git 检出目录内运行测试。' +
        '刻意不用 try/catch 退化成跳过——那等于让门禁静默失效'
    );
  }
  const out = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' });
  tracked = new Set(out.split(/\r?\n/).filter(Boolean));
});

describe('模块入库闭包：解析得到的本地引用，目标必须已入库', () => {
  test('全仓本地引用无一指向未入库文件', () => {
    const { total, strays } = survey(realModules(), tracked);

    // 前提自证：扫描器坏掉（正则失配、根写错）时 total 会塌成 0，那时"0 条违规"是假绿。
    // 实测 2026-10-31：解析得到的本地引用 5025 条（含 src/tests 下的夹具互引）。
    expect(total).toBeGreaterThan(3000);

    expect(
      strays
        .map(
          (s) =>
            `${s.from} 引用 ${s.spec} ⇒ ${s.target} 未入库` +
            '（本机跑得动是因为文件在盘上；干净克隆会 MODULE_NOT_FOUND：要么 git add，要么把引用删掉）'
        )
        .join('\n')
    ).toBe('');
  });

  test('反向自证：指向「盘上有、未入库」的目标必须被点名', () => {
    // 在仓库里造一个未入库的夹具（名字用 .zz 前缀且**不是** *.test.js：
    // 既避开 testMatch，也避开 testTreePurity 的测试树判据，只测本条自己）
    const fixture = path.join(ROOT, 'src', `.zzmodtrack-${process.pid}-fixture.js`);
    fs.writeFileSync(fixture, 'module.exports = 1;\n', 'utf8');
    try {
      const modules = [
        {
          file: path.join(ROOT, 'src', 'app.js'),
          source: `require('./${path.basename(fixture)}');\n`,
        },
      ];
      const { total, strays } = survey(modules, tracked);
      expect(total).toBe(1);
      expect(strays.map((s) => s.target)).toEqual([relOf(fixture)]);
    } finally {
      fs.rmSync(fixture, { force: true });
    }
    expect(fs.existsSync(fixture)).toBe(false); // 夹具不得留残
  });

  test('正向对照：指向已入库的目标不得被点名（否则上面那条恒红）', () => {
    const modules = [{ file: path.join(ROOT, 'src', 'app.js'), source: "require('./config');\n" }];
    const { total, strays } = survey(modules, tracked);
    expect(total).toBe(1);
    expect(strays).toEqual([]);
  });

  test('判据的前提：注释里的 require 不算引用（否则注释能凭空造红）', () => {
    // 刻意挑一个**解析得到**的说明符（./config ⇒ src/config/index.js）：只有这种
    // 才能证明「剥注释」真的生效——解析不到的说明符即便不剥注释也会被放过。
    const file = path.join(ROOT, 'src', 'app.js');
    const line = "require('./config')";
    expect(survey([{ file, source: line + '\n' }], tracked).total).toBe(1);
    expect(survey([{ file, source: '// ' + line + '\n' }], tracked).total).toBe(0);
    expect(survey([{ file, source: '/* ' + line + ' */\n' }], tracked).total).toBe(0);
  });
});
