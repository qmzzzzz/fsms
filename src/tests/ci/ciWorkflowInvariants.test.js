/**
 * ci.yml 结构不变量（安全审计 #9：CI 最小权限口径不一致）
 *
 * 为什么要有这个文件：仓库「run 内零 ${{ }} 插值」的不变量此前只有
 * deployWorkflow.test.js 在扫 deploy.yml——ci.yml 同样消费外部上下文值
 * （gitleaks 的 github.event.before 曾被直接写进 run，是脚本注入面），却没人扫。
 * 本文件把对 ci.yml 的同类不变量补齐，并顺带钉住 #9 的其余修复面：
 *   ① 工作流级顶层 permissions: contents: read 只读兜底（job 级覆盖是唯一放大途径）；
 *   ② 每个 checkout 都 persist-credentials: false（GITHUB_TOKEN 不留在 .git/config）；
 *   ③ 所有 uses 钉到不可变 commit SHA（可变 tag 是供应链劫持面）；
 *   ④ e2e-browser 不再上传 playwright-report（失败 trace 嵌管理员界面 DOM 与
 *      localStorage 里的 JWT，公开仓 workflow artifact 匿名即可下载）。
 *
 * 能力边界（与 deployWorkflow.test.js 同口径）：静态断言不证明工作流能跑通，
 * 证明的是「改了就会出事」的结构不再静默漂移。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const WF = path.join(ROOT, '.github/workflows/ci.yml');

const src = fs.readFileSync(WF, 'utf8');
// ci.yml 是 CRLF 行尾：一律按 /\r?\n/ 切，别让 \r 混进匹配
const lines = src.split(/\r?\n/);

/** 剥掉整行注释与行尾注释，只留真正会生效的内容（与 ciGateWiring.test.js 同款） */
const stripComments = (text) =>
  text
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .map((line) => line.replace(/\s+#(?![^'"]*').*$/, ''))
    .join('\n');

/**
 * 收集某段 YAML 文本里所有 run 的行：块式（`run: |` / `run: >`）取块体，
 * 行内（`run: <cmd>`，ci.yml 大量步骤是这个形态）取该行本身——只扫块式会漏掉
 * 一半注入面。含注释行与空行，由调用方自行剔除（与 deployWorkflow.test.js
 * 的 allRunLines 同口径：注释不执行，不能当证据）。
 */
const runLinesOf = (text) => {
  const out = [];
  let inRun = false;
  let runIndent = 0;
  for (const line of text.split(/\r?\n/)) {
    const block = /^(\s*)(?:-\s+)?run:\s*([|>])/.exec(line);
    if (block) {
      inRun = true;
      runIndent = block[1].length;
      continue;
    }
    if (inRun) {
      if (line.trim() === '') {
        out.push(line);
        continue;
      }
      if (line.match(/^\s*/)[0].length <= runIndent) {
        // 块到这里结束；但这行本身可能是下个步骤的行内 `run: <cmd>`，
        // 不能 continue 掉——落到下面的行内分支继续判（实测漏过一次）。
        inRun = false;
      } else {
        out.push(line);
        continue;
      }
    }
    const inline = /^\s*(?:-\s+)?run:\s+(\S.*)$/.exec(line);
    if (inline) out.push(inline[1]);
  }
  return out;
};

const executableRunLines = () =>
  runLinesOf(src)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

/** 取某个 job 的文本块（从 `  <name>:` 到下个顶层 job），用于「断言它在该 job 内」 */
const jobBlock = (text, name) => {
  const start = text.indexOf(`\n  ${name}:`);
  if (start < 0) throw new Error(`未找到 job：${name}`);
  const rest = text.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:/);
  return next < 0 ? rest : rest.slice(0, next + 1);
};

describe('ci.yml：run 脚本零插值不变量（安全审计 #9）', () => {
  test('前提自证：run 扫描确实覆盖到脚本行（否则零插值断言是空集假绿）', () => {
    // 实测 140 行（含行内 run）。阈值 30 只防「扫描器坏掉返回空集」，不是精确计数。
    expect(executableRunLines().length).toBeGreaterThan(30);
  });

  // GitHub 的 ${{ }} 是文本级替换、先于 shell 解析与任何引号校验：写进 run 就是
  // 脚本注入面（deployWorkflow.test.js 对 deploy.yml 的同款判据；此前没人扫 ci.yml，
  // gitleaks 的 github.event.before 正是从这里漏进去的）。
  test('所有 run 可执行行零 ${{ }} 插值：外部值一律经 env 进入', () => {
    const interpolated = executableRunLines().filter((l) => l.includes('${{'));
    expect(interpolated).toEqual([]);
  });

  test('扫描器可证伪：块式与行内两处插值都必须真的被抓到（不是恒真的空扫）', () => {
    const synthetic = [
      'jobs:',
      '  a:',
      '    steps:',
      '      - run: |',
      '          ref="${{ github.event.before }}"',
      '      - run: echo "${{ steps.x.outputs.y }}"',
    ].join('\n');
    const caught = runLinesOf(synthetic)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && l.includes('${{'));
    expect(caught).toHaveLength(2);
  });

  test('gitleaks base ref 步骤的 env 形态存在：github.event.before 只经 env 进 run', () => {
    // env 赋值是唯一安全通道（env 值不参与 shell 文本展开）——正向锁住修复本身，
    // 而不是只锁「没有旧写法」（后者把表达式改成别的插值也能绿）。
    expect(src).toMatch(/GITHUB_BEFORE_SHA:\s*\$\{\{\s*github\.event\.before\s*\}\}/);
    const joined = executableRunLines().join('\n');
    expect(joined).toContain('ref="$GITHUB_BEFORE_SHA"');
    // run 里不得再出现原始上下文引用：env: 行不在 run 块里，
    // 它出现在任何可执行行都说明有人把插值又搬了回去
    expect(joined).not.toContain('github.event.before');
  });
});

describe('ci.yml：最小权限与供应链钉版（安全审计 #9）', () => {
  test('工作流级顶层 permissions: contents: read 兜底（声明在 jobs 之前）', () => {
    const head = src.slice(0, src.indexOf('\njobs:'));
    expect(head).toMatch(/permissions:\s+contents:\s*read/);
  });

  test('需要写权限的 job 在 job 级覆盖，且顶层兜底不被放大成 contents: write', () => {
    // build：GHCR 推送（packages）+ cosign keyless 签名（id-token）
    const build = stripComments(jobBlock(src, 'build'));
    expect(build).toMatch(/packages:\s*write/);
    expect(build).toMatch(/id-token:\s*write/);
    // secret-scan：gitleaks 在 pull_request 事件下要读 PR commits 推导扫描范围
    expect(stripComments(jobBlock(src, 'secret-scan'))).toMatch(/pull-requests:\s*read/);
    // 全文件（剥注释后）不得出现更高档的作用域：job 级覆盖是显式评审过的白名单
    const stripped = stripComments(src);
    expect(stripped).not.toMatch(/contents:\s*write/);
    expect(stripped).not.toMatch(/write-all/);
  });

  test('每个 checkout 都 persist-credentials: false（GITHUB_TOKEN 不留在 .git/config）', () => {
    const checkouts = [];
    lines.forEach((line, i) => {
      if (/^\s*-\s+uses:\s*actions\/checkout@/.test(line)) checkouts.push(i);
    });
    // 前提自证：确实扫到了 checkout（步骤全被删/改名时这里先红，而不是恒绿）
    expect(checkouts.length).toBeGreaterThan(0);
    for (const i of checkouts) {
      const dashIndent = lines[i].match(/^\s*/)[0].length;
      const attrs = [];
      for (let j = i + 1; j < lines.length; j += 1) {
        const l = lines[j];
        if (l.trim() === '') continue;
        if (l.match(/^\s*/)[0].length <= dashIndent) break;
        attrs.push(l);
      }
      expect(attrs.join('\n')).toMatch(/persist-credentials:\s*false/);
    }
  });

  test('所有 uses 钉到不可变 commit SHA，行尾注释保留版本号', () => {
    const uses = lines.filter((l) => /^\s*(?:-\s+)?uses:\s*\S/.test(l));
    // 前提自证：确实扫到了 action 引用（ci.yml 实测 21 处）
    expect(uses.length).toBeGreaterThan(10);
    const mutable = [];
    for (const line of uses) {
      const ref = /uses:\s*([^\s#]+)/.exec(line)[1];
      // 可变 tag（@v5）与移动分支（@main）都不合格：只有 40 位十六进制 commit SHA
      if (!/^[^@\s]+@[0-9a-f]{40}$/.test(ref)) mutable.push(ref);
      // 钉 SHA 的同时必须留人读的版本注释（行尾 # vN.N.N），否则升级无从对账
      expect(line).toMatch(/#\s*v\d/);
    }
    expect(mutable).toEqual([]);
  });
});

describe('ci.yml：e2e 工件不再外泄（安全审计 #9）', () => {
  const e2eBrowser = jobBlock(src, 'e2e-browser');

  test('e2e-browser 不再上传 playwright-report（Upload 步骤已删）', () => {
    expect(e2eBrowser).not.toMatch(/Upload Playwright report/);
    expect(e2eBrowser).not.toMatch(/actions\/upload-artifact/);
  });

  test('删除原因注释仍在：失败 trace 嵌管理员会话态，公开仓工件匿名可下载', () => {
    // 注释不是装饰——它记录着「为什么不能为了排查方便把上传加回来」。
    // 把关键内容逐条钉住：将来这段被当死注释清掉，上传步骤就会无人拦截地回来。
    expect(e2eBrowser).toMatch(/刻意不上传 playwright-report/);
    expect(e2eBrowser).toMatch(/trace: retain-on-failure/);
    expect(e2eBrowser).toMatch(/JWT/);
    expect(e2eBrowser).toMatch(/npx playwright show-report/);
    // 注释的前提必须仍是真的：trace 仍是失败留痕模式（playwrightConfig.test.js
    // 单独守 trace 语义，这里只对账「注释说了什么、配置是不是什么」）
    const config = require(path.join(ROOT, 'playwright.config.js'));
    expect(config.use.trace).toBe('retain-on-failure');
  });
});
