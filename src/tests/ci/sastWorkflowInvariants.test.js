/**
 * 私有仓 SAST 工作流的不变量（改坏任何一条判据，本文件就红）
 *
 * 【为什么需要本文件】`.github/workflows/sast.yml` 是"私有仓没有静态分析"这条缺口的唯一补法，
 * 但它自己不被任何既有门禁盯着：ci.yml 的几条不变量用例只读 ci.yml，`gateLayerExistence` 只判
 * "文件存在 + 有 jobs: 段"。把 `--error` 删掉、把 `--metrics=off` 拿掉、把 `--config` 指向远端、
 * 把镜像的 digest 去掉——四种改法都"文件仍在、没有任何东西会红"。
 *
 * 【与既有判据的分工】`imageReferenceInventory` 判"钉的 digest 与期望表同值"；本文件判"这条引用
 * 出现在这里、这样写、与规则绑在一起"；`workflowShellSyntax` 判 run 块的 shell 语法。三者不重叠。
 *
 * 【核心是"零命中"】规则包敢开 `--error` 的前提是它在**当前树**上零命中：一条第一次跑就红的规则
 * 会被 `continue-on-error` 或注释消化掉。本文件用规则包里的同一批正则复算零命中，并且要求每条规则
 * 对自己的违反样例必须命中——否则规则退化成永不匹配，扫描"成功"却什么都没看。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n?/g, '\n');

/**
 * 剥掉整行注释与行尾注释，只留真正会生效的内容（与 ciWorkflowInvariants.test.js 同款）。
 * 凡「数某个键出现几次」「某属性必须在」这类判据都必须跑在这个视图上：注释行在 YAML 里
 * 不生效，按原始文本计数时 `# persist-credentials: false` 会把一处失效属性数成一处有效属性。
 */
const stripComments = (text) =>
  text
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .map((line) => line.replace(/\s+#(?![^'"]*').*$/, ''))
    .join('\n');

const wf = read('.github/workflows/sast.yml');
const rules = read('.github/semgrep/rules.yml');
const doc = read('docs/security-dependency-watch.md');

/** 规则 id 的清单：新增/删除规则都必须改这里（否则"到底哪些规则在盯代码"没人说得清） */
const RULE_IDS = [
  'fsms-jwt-verify-without-algorithms',
  'fsms-tls-verification-disabled',
  'fsms-md5-hash',
  'fsms-dynamic-code-execution',
  'fsms-child-process-shell',
  'fsms-mongo-where-operator',
  'fsms-open-redirect',
];
/** 规则包的排除面：规则包与本文件必须点名同一批目录，否则"本地复算的零命中"与 semgrep 跑的
 *  不是同一批文件——两边分叉时，本文件会替一条真跑起来就红的规则背书。 */
const EXCLUDES = ['.github/semgrep/**', 'src/tests/**', 'web-admin/src/tests/**', 'e2e/**'];
/** 本地复算的扫描面：与工作流给的 scan 目标一致，后缀取**超集**（含 .vue）
 *  ⇒ semgrep 真的会扫的文件一定落在本文件的文件集里，"本地零命中"才推得出"扫描也零命中"。 */
const SCAN_ROOTS = ['src', 'scripts', 'migrations', 'e2e', 'web-admin/src'];
const SCAN_EXT = /\.(js|jsx|cjs|mjs|ts|tsx|vue)$/;

/** `run:` 的两种形态：块标量（后续更深缩进的行）与内联（同一行冒号之后的内容） */
function runLinesOf(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    const m = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const inline = m[2].trim();
    if (inline && !/^[|>]/.test(inline)) {
      out.push({ line: i + 1, text: inline });
      continue;
    }
    for (let j = i + 1; j < lines.length; j += 1) {
      if (lines[j].trim() === '') continue;
      if (lines[j].search(/\S/) <= indent) break;
      out.push({ line: j + 1, text: lines[j].trim() });
    }
  }
  return out;
}

const ruleIds = () => [...rules.matchAll(/^\s*-\s+id:\s*(\S+)\s*$/gm)].map((m) => m[1]);
/** YAML 单引号标量里的 `''` 是一个字面单引号（规则文件头有说明），这里如实还原 */
const rulePatterns = () =>
  [...rules.matchAll(/^\s*pattern-regex:\s*'(.+)'\s*$/gm)].map((m) => m[1].replace(/''/g, "'"));

function ruleExcludes() {
  const lines = rules.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!/^\s*exclude:\s*$/.test(lines[i])) continue;
    const indent = lines[i].search(/\S/);
    for (let j = i + 1; j < lines.length; j += 1) {
      if (lines[j].trim() === '') continue;
      if (lines[j].search(/\S/) <= indent) break;
      const item = /^\s*-\s+'([^']+)'\s*$/.exec(lines[j]);
      expect(item).toBeTruthy();
      out.push(item[1]);
    }
  }
  return out;
}

function scanFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(ROOT, abs).split(path.sep).join('/');
      if (
        EXCLUDES.some(
          (x) => rel === x.replace(/\/\*\*$/, '') || rel.startsWith(x.replace(/\/\*\*$/, '') + '/')
        )
      )
        continue;
      if (e.isDirectory()) {
        if (e.name !== 'node_modules') walk(abs);
      } else if (SCAN_EXT.test(e.name)) out.push(abs);
    }
  };
  for (const r of SCAN_ROOTS) walk(path.join(ROOT, r));
  return out;
}

describe('私有仓 SAST（Semgrep）工作流的不变量', () => {
  test('1 触发面与"私有仓唯一 SAST"这条职责：不得再加 private/public 条件把自己关掉', () => {
    // codeql.yml 的第一层判据是 repository.private == false ⇒ 私有仓上一个静态分析器都没有。
    // 本工作流是那条缺口的唯一补法：一旦有人给它也加上 public 条件，判据即红。
    expect(wf).toMatch(/^on:/m);
    expect(wf).toMatch(/^jobs:/m);
    // 判据只看**可执行行**：文件头的说明里就写着 codeql.yml 的那条条件（剥注释与不剥注释
    // 会得出相反结论，这正是本仓装闸时踩过的一类坑）。
    const code = wf
      .split('\n')
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    expect(code).not.toMatch(/repository\.private/);
    for (const t of ['pull_request:', 'push:', 'workflow_dispatch:', 'schedule:'])
      expect(wf).toContain(t);
  });

  test('2 权限只读、声明在 jobs 之前；run 行不含任何 Actions 表达式', () => {
    const jobsAt = wf.indexOf('\njobs:');
    expect(jobsAt).toBeGreaterThan(0);
    expect(wf.slice(0, jobsAt)).toMatch(/^permissions:\n\s+contents: read\s*$/m);
    expect(wf).not.toMatch(/contents:\s*write/);
    expect(wf).not.toContain('${{');
    expect(runLinesOf(wf).length).toBeGreaterThan(0);
  });

  test('3 每个 uses 都钉 40 位 commit 且带版本注释；唯一的 checkout 不带持久凭据', () => {
    const usesLines = wf.split('\n').filter((l) => /^\s*(?:-\s+)?uses:/.test(l));
    expect(usesLines.length).toBeGreaterThan(0);
    for (const l of usesLines) {
      const ref = /uses:\s*(\S+)/.exec(l)[1];
      expect({ line: l.trim(), ok: /^[^@\s]+@[0-9a-f]{40}$/.test(ref) }).toEqual({
        line: l.trim(),
        ok: true,
      });
      expect(l).toMatch(/#\s*v\d+/);
    }
    // 数「生效了几处」必须剥注释：按原始文本计数时，把唯一那处前置 `#` 之后
    // 正则仍能数到 1，与 checkouts 相等 ⇒ 假绿。属性实际已退回默认值 true，
    // 而这是本工作流唯一一道「GITHUB_TOKEN 不留在 .git/config」的判据。
    const eff = stripComments(wf);
    const checkouts = eff.split('\n').filter((l) => /uses: actions\/checkout@/.test(l)).length;
    expect(checkouts).toBe(1);
    expect((eff.match(/persist-credentials: false/g) || []).length).toBe(checkouts);
  });

  test('4 容器镜像：写在 image: 位置（可被镜像面账看见）且与期望表同一个 digest', () => {
    // 写进 docker run 的 run 行里也能跑，但那样的引用**全仓镜像面账看不见**
    // （refValueOf 只认 FROM/image: 两个位置）⇒ 钉了 digest 却没人对账。这里把位置也钉住。
    const { EXPECTED } = require('../../../scripts/verify-image-digests.js');
    expect(wf).toMatch(/^\s+container:\n\s+image: \S+$/m);
    const value = /^\s*image:\s*(\S+)\s*$/m.exec(wf)[1];
    const parsed = /^(semgrep\/semgrep):([^@]+)@sha256:([0-9a-f]{64})$/.exec(value);
    expect(parsed).toBeTruthy();
    const entry = EXPECTED.find((e) => e.ref === parsed[1] + ':' + parsed[2]);
    expect(entry).toBeTruthy();
    expect(entry.digest).toBe(parsed[3]);
  });

  test('5 扫描步骤：fail-closed 的开关一个不少，且规则只从仓库内的规则包来', () => {
    const scan = runLinesOf(wf).find((l) => /semgrep scan/.test(l.text) && /--error/.test(l.text));
    expect(scan).toBeTruthy();
    const line = scan.text;
    // 命中即失败（不是"报告一下"）：`--error`
    expect(line).toContain('--config .github/semgrep/rules.yml');
    expect(line).toContain('--sarif');
    expect(line).toContain('--output sast.sarif');
    // 私有源码不出 runner：关遥测、不查更新、规则取自本地包
    expect(line).toContain('--metrics=off');
    expect(line).toContain('--disable-version-check');
    expect(line).not.toMatch(/--config (auto|p\/|r\/|https?:)/);
    // 目标目录必须与本用例的复算面一致（漂了就等于"本地零命中"证明的不是扫描面）
    const targets = line.split(/\s+/).filter((t) => SCAN_ROOTS.includes(t));
    expect(targets).toEqual(SCAN_ROOTS);
    // 规则包先跑 --validate：规则写坏时 semgrep 会以非 0 退出，但"扫 0 条规则后报绿"必须被排除
    const validate = runLinesOf(wf).find((l) => /--validate/.test(l.text));
    expect(validate).toBeTruthy();
    expect(validate.text).toContain('--config .github/semgrep/rules.yml');
  });

  test('6 结果落制品（私有仓不能交给 code scanning），且制品缺失时不是静默绿', () => {
    expect(wf).toMatch(/uses: actions\/upload-artifact@[0-9a-f]{40}/);
    expect(wf).toMatch(/name: semgrep-sarif/);
    expect(wf).toMatch(/path: sast\.sarif/);
    expect(wf).toMatch(/if-no-files-found: error/);
    expect(wf).toMatch(/if: always\(\)/);
    // 任何"让失败不那么显眼"的开关都不许出现
    expect(wf).not.toContain('continue-on-error');
  });

  test('7 规则包：id 清单、必备字段、正则可编译、排除面与本用例同源', () => {
    expect(ruleIds()).toEqual(RULE_IDS);
    const blocks = rules.split(/^\s*-\s+id:/m).slice(1);
    expect(blocks).toHaveLength(RULE_IDS.length);
    for (const b of blocks) {
      expect(b).toMatch(/^\s*languages:\s*\[[^\]]*javascript[^\]]*\]\s*$/m);
      expect(b).toMatch(/^\s*severity:\s*ERROR\s*$/m);
      expect(b).toMatch(/^\s*message:/m);
      expect(b).toMatch(/^\s*pattern-regex:/m);
    }
    expect(rulePatterns()).toHaveLength(RULE_IDS.length);
    for (const p of rulePatterns()) expect(() => new RegExp(p)).not.toThrow();
    expect(ruleExcludes()).toEqual(RULE_IDS.flatMap(() => EXCLUDES));
  });

  test('8 零命中 + 非空转：每条规则在真实文件集上零命中，对自己的违反样例必须命中', () => {
    const samples = {
      'fsms-jwt-verify-without-algorithms': '  jwt.verify(token, SECRET);',
      'fsms-tls-verification-disabled': '  const a = { rejectUnauthorized: false };',
      'fsms-md5-hash': "  const h = crypto.createHash('md5');",
      'fsms-dynamic-code-execution': "  const r = eval('1+1');",
      'fsms-child-process-shell': '  const o = { shell: true };',
      'fsms-mongo-where-operator': "  await User.find({ $where: 'this.a == 1' });",
      'fsms-open-redirect': '  return res.redirect(req.query.next);',
    };
    const files = scanFiles();
    // 扫描面自证：文件集退化（列不到文件）时，下面的"零命中"是空转，必须先红在这里
    expect(files.length).toBeGreaterThan(300);
    const boxed = rulePatterns().map((p, i) => ({ id: RULE_IDS[i], re: new RegExp(p) }));
    for (const { id, re } of boxed) {
      // ①② 非空转：规则必须真的能命中它要抓的形态
      expect({ id, sample: samples[id], hit: re.test(samples[id]) }).toEqual({
        id,
        sample: samples[id],
        hit: true,
      });
      // ③ 当前树零命中：命中即说明"第一次跑就是红的"（或者有人新写了这类代码，该出豁免/修代码）
      const hits = files
        .filter((f) => re.test(fs.readFileSync(f, 'utf8')))
        .map((f) => path.relative(ROOT, f).split(path.sep).join('/'));
      expect({ id, hits }).toEqual({ id, hits: [] });
    }
  });

  test('9 文档与工作流互指：缺口的登记、规则包与工作流的路径都要能被读到', () => {
    expect(doc).toContain('.github/workflows/sast.yml');
    expect(doc).toContain('.github/semgrep/rules.yml');
    expect(doc).toContain('deployment/dependency-sla.json');
  });
});
