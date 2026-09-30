/**
 * 测试树纯净性：`src/tests/**` 与 `web-admin/src/tests/**` 下不得存在未跟踪的 `*.test.js`
 *
 * 为什么这条值得做成门禁（它的失效形态是"不出错、只污染信号"）：
 *
 *  jest 的 testMatch 是「任意层级下的 src/tests/ 里的 *.test.js」（写成通配式时
 *  两处通配符连着斜杠，即 `**` 紧跟 `/`——这个序列不能出现在块注释里：它会被
 *  当成注释结束符，本文件第一次写出来就是这么炸的）。也就是说，**放在这两个目录下的
 *  任何 .test.js 都会被执行**——包括那些从未提交、只是某人调试时落下的草稿。
 * 后果有两层，且都不会报错：
 *   1. 那些草稿的 pass/fail 混进 `npm test` 的总数里。本仓库的判读方式是
 *      "477/481 套件通过"，多出来的条目会让这个信号的含义变得不确定；
 *   2. 更糟的方向：一个**本该入库**的用例如果因为误用 `git add` 的路径写法而漏掉，
 *      本地全绿、CI 上根本不存在这条用例 ⇒ 覆盖率与回归防线静默少一块。
 *
 * 本仓库已经吃过一次这个亏：工作树里曾躺过 `src/tests/probe/` 三个未跟踪的
 * `*.test.js`（草稿性质的交互式探针），它们既被 gitignore 规则漏掉、又实实在在
 *  参与每次本地 `npm test`。它们最终在一次 `git stash -u` 中丢失 —— 而"丢失"这件事
 * 一开始没有任何提示，因为文件从来没进过版本库。
 *
 * 本门禁把这件事从"靠人注意"变成"机器拦"：
 *   - 未跟踪 ⇒ 报红，并同时给出两条出路（要么真该入库就去 add，要么是草稿就挪出
 *     `src/tests/`，因为放在这里它一定会被执行）；
 *   - 顺带钉住仓库既有约定的另一侧：`zzz-*` 探针**不得入库**（.gitignore:70 的
 *     P1-30 约定，原 8 个 `zzz-*.test.js` / 591 行 / 51 test / 0 expect 曾被一并
 *     提交过）。只拦未跟踪一侧的话，"顺手 git add ."能立刻把那批探针带进去。
 *
 * 两条方向相反、缺一不可：拦未跟踪 = 防草稿污染信号；拦已跟踪的 `zzz-*` = 防草稿入库。
 *
 * 为什么不用 `git status --porcelain`：它输出受 core.quotePath 影响（中文路径会被
 * 加引号转义），而本仓库的工作目录路径里就有中文。这里一律用 `-z`（NUL 分隔），
 * git 因此不做任何转义。
 */

const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');

/** 两个会被 testMatch / vitest include 扫到的测试树 */
const TEST_TREES = [
  { label: '后端 jest（testMatch: **/src/tests/**/*.test.js）', dir: path.join(ROOT, 'src/tests') },
  {
    label: '前端 vitest（include: src/tests/**/*.test.js）',
    dir: path.join(ROOT, 'web-admin', 'src', 'tests'),
  },
];

/** 遍历目录收集 *.test.js（跳过 node_modules 与构建产物） */
function collectTestFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && entry.name.endsWith('.test.js')) out.push(full);
    }
  }
  return out;
}

/** git 命令一律 -z 输出，避免 core.quotePath 把中文路径加引号转义 */
const gitZ = (args) =>
  execFileSync('git', [...args, '-z'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split('\0')
    .filter(Boolean);

/** 仓库路径（/ 分隔，相对根）→ 绝对路径 */
const toAbsolute = (repoPath) => path.join(ROOT, ...repoPath.split('/'));

let tracked;

beforeAll(() => {
  // 缺 .git 时**不跳过、直接失败**：静默跳过等于把这条门禁变成 fail-open，
  // 而"门禁悄悄不生效"正是本仓反复在防的那件事（删掉门禁不会让任何东西变红）。
  if (!fs.existsSync(path.join(ROOT, '.git'))) {
    throw new Error(
      '未找到 .git：本门禁依赖 git ls-files 判定"是否入库"，请在 git 检出目录内运行测试。' +
        '刻意不用 try/catch 退化成跳过——那等于让门禁静默失效'
    );
  }
  tracked = new Set(gitZ(['ls-files']).map((p) => toAbsolute(p)));
});

describe('测试树纯净性：未跟踪的 *.test.js 不得留在 src/tests 下', () => {
  test.each(TEST_TREES.map((t) => [t.label, t.dir]))(
    '%s：每一份用例都必须已入库',
    (_label, dir) => {
      const files = collectTestFiles(dir);
      // 空树会让本门禁整条恒真，故显式钉住规模
      expect(files.length).toBeGreaterThan(10);

      const strays = files.filter((f) => !tracked.has(f)).map((f) => path.relative(ROOT, f));
      expect(
        strays
          .slice()
          .sort()
          // 报错信息必须给出出路，否则这个红只能靠猜
          .map(
            (f) => `${f}（要么 git add 入库，要么挪出 src/tests/：放在这里 testMatch 一定会执行它）`
          )
          .join('\n')
      ).toBe('');
    }
  );

  test('反向自查：git 管道确实能列出"未入库"的路径（否则上一条可能因 git 异常而恒绿）', () => {
    // 判据刻意用 `ls-files --others`（**不带** --exclude-standard）：本仓有大量
    // 被 gitignore 的临时区（zztmpctl / zznpmtest / .jesttmp / .lint-ratchet-selftest-* …），
    // 它们正是这条命令返回非空的证据。集合为空 ⇒ git 调用坏了，而不是仓库真的干净。
    //
    // 顺带说明为什么**判据本身**不能用 --exclude-standard：那会漏掉"被 gitignore
    // 规则误伤"的文件——而本门禁上线当天抓到的第一个真实案例（web-admin 下的
    // manualChunks.test.js）恰恰就是被 .gitignore 的 `build/` 规则吞掉的，
    // 用 --exclude-standard 的话它会隐身。用 `!tracked.has(f)` 才两种都拦。
    const others = gitZ(['ls-files', '--others']);
    expect(others.length).toBeGreaterThan(0);
  });

  test('已跟踪的用例确实都在 tracked 集合里（防止 tracked 集合取错口径）', () => {
    const sample = collectTestFiles(path.join(ROOT, 'src', 'tests')).slice(0, 5);
    expect(sample.length).toBeGreaterThan(0);
    for (const file of sample) expect(tracked.has(file)).toBe(true);
  });
});

describe('反向约定：zzz-* 探针不得入库（P1-30 / .gitignore:70）', () => {
  test('没有已跟踪的 zzz-*.test.js', () => {
    // .gitignore 只约束"未入库"，管不住 `git add .` —— 而那批探针当初就是这么进去的
    // （8 个文件 / 591 行 / 51 test / 0 expect：全是调试脚手架，0 个断言）
    const strays = [...tracked].filter((f) => /[/\\]zzz-.*\.test\.js$/.test(f));
    expect(strays.map((f) => path.relative(ROOT, f)).join('\n')).toBe('');
  });
});
