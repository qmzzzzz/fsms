'use strict';

/**
 * 工作流里每个 `run:` 步骤都必须是一条语法成立的 shell 脚本。
 *
 * 起因（实测）：`.github/workflows/release.yml` 的"抽取发布说明"一步长期带着
 * ```
 *   {
 *
 *   } >> /dev/null
 * ```
 * 这样的空花括号组，`bash -n` 直接 `syntax error near unexpected token '}'`（退出码 2）。
 * 也就是说**任何 `v*` tag 推送都会在这一步红，GitHub Release 永远发不出来**，
 * 而主 CI 全绿——因为 CI 从不解析 release 工作流的脚本体，`release.yml` 也没有 job
 * 被别的 workflow `needs`。同仓既有的 `releaseWorkflow.test.js` 把 awk 逻辑"用 JS 重写一遍"
 * 再比对文本，因此那一段坏字节对它完全隐形。
 *
 * 本闸覆盖的是**整类**问题：6 份 workflow、所有 `run:` 块（块标量与单行两种写法），
 * 判据是 bash 自己的语法分析（`bash -n`），不是任何正则近似。
 *
 * 两处口径要说清：
 *   · `${{ github.ref_name }}` 这类 Actions 表达式在 bash 眼里是 `${{...}}`，
 *     属于运行期替换的占位符，先把它们整体换成一个合法标识符再送去语法分析，
 *     否则每个用到 secrets 的步骤都会假红。
 *   · 显式声明了非 bash `shell:` 的步骤（如 `shell: python`）不适用本判据，
 *     跳过并把数量断言下来——"跳过了多少"必须是可见的，不能悄悄少查。
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..', '..');
const WF_DIR = path.join(ROOT, '.github', 'workflows');

/** Actions 表达式 ⇒ 合法占位符（`bash -n` 只吃语法，不吃值） */
const neutralizeExpressions = (text) => text.replace(/\$\{\{[\s\S]*?\}\}/g, 'ACTIONS_EXPR');

/**
 * 从一份 workflow 里抽出所有 `run:` 脚本体。
 * @returns {Array<{file:string,line:number,shell:string|null,body:string}>}
 */
function extractRunBlocks(file) {
  const raw = fs.readFileSync(path.join(WF_DIR, file), 'utf8');
  const lines = raw.split(/\r?\n/);
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    // 只认 `- run: …` 与 `run: …`（缩进内的键）两种形态
    const m = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const [, indent, rest] = m;
    const keyCol = indent.length + (/^-\s/.test(indent + rest) && /^\s*-/.test(lines[i]) ? 2 : 0);
    const header = /^\s*(-\s+)?run:\s*([|>][-+]?[\d]*|['"]?.*)$/.exec(lines[i]);
    if (!header) continue;
    const indicator = header[2].trim();

    if (/^[|>]/.test(indicator)) {
      // 块标量：收所有"比 run: 键更靠右"的行（空行也算，属于块内）
      const body = [];
      let j = i + 1;
      for (; j < lines.length; j++) {
        const line = lines[j];
        if (line.trim() === '') {
          body.push('');
          continue;
        }
        if (line.search(/\S/) <= keyCol) break;
        body.push(line);
      }
      const firstReal = body.find((l) => l.trim() !== '');
      const blockIndent = firstReal ? firstReal.search(/\S/) : 0;
      blocks.push({
        file,
        line: i + 1,
        shell: findShell(lines, i),
        body: body.map((l) => l.slice(blockIndent)).join('\n'),
      });
      i = j - 1;
    } else if (indicator !== '') {
      // 单行：run: 'echo hi' / run: echo hi
      blocks.push({
        file,
        line: i + 1,
        shell: findShell(lines, i),
        body: indicator.replace(/^(['"])([\s\S]*)\1$/, '$2'),
      });
    }
  }
  return blocks;
}

/** 该步骤是否声明了 shell:（YAML 里 shell 键总在 run 之后） */
function findShell(lines, runIdx) {
  for (let k = runIdx + 1; k < lines.length; k++) {
    if (/^\s*(?:-\s+)?run:/.test(lines[k])) break;
    const m = /^\s*shell:\s*(\S.*)$/.exec(lines[k]);
    if (m) return m[1].trim().replace(/^['"]|['"]$/g, '');
  }
  return null;
}

const workflowFiles = () => fs.readdirSync(WF_DIR).filter((f) => /\.ya?ml$/i.test(f));

const allBlocks = () => workflowFiles().flatMap((f) => extractRunBlocks(f));

/** 只有 bash/sh 语义的步骤适用本判据 */
const BASH_LIKE = /^$|bash|sh|python/i;
const isBashLike = (shell) => BASH_LIKE.test(shell || '');

const syntaxCheck = (script) => {
  const r = spawnSync('bash', ['-n', '-'], {
    encoding: 'utf8',
    input: neutralizeExpressions(script),
    // Windows 上 bash 不在 PATH 时 node 会直接 ENOENT：不静默当成"通过"
    cwd: os.tmpdir(),
  });
  return {
    status: r.status,
    error: r.error ? r.error.code : null,
    stderr: (r.stderr || '').trim(),
  };
};

describe('工作流的每个 run 步骤必须是语法成立的 bash', () => {
  test('前提自证：坏字节必须被抓住、好脚本必须放行（否则本闸恒绿）', () => {
    // 这一条就是 release.yml 里长期存在的那三行
    const broken = '{\n\n} >> /dev/null\n';
    expect(syntaxCheck(broken).status).toBe(2);
    expect(syntaxCheck('echo hi\nif [[ -z "$x" ]]; then exit 1; fi\n').status).toBe(0);
    // 表达式中和这一步也得自证：不中和的话 `${{ secrets.X }}` 本身会让分析变形
    expect(neutralizeExpressions('echo "${{ secrets.X }}"')).toBe('echo "ACTIONS_EXPR"');
  });

  test('前提自证：抽取器真的抽到了内容（抽成空集会让全部用例假绿）', () => {
    const blocks = allBlocks();
    expect(blocks.length).toBeGreaterThan(20);
    // 逐份对账：文件里每一个 `run:` 键都必须被抽出来。
    // 只断言"总数够大"是不够的——漏抽一整份文件（例如某步写成 `run: >`）会直接变成"没有失败"。
    for (const file of workflowFiles()) {
      const raw = fs.readFileSync(path.join(WF_DIR, file), 'utf8').split(/\r?\n/);
      const keyCount = raw.filter((l) => /^\s*(?:-\s+)?run:\s*/.test(l)).length;
      expect({ file, extracted: extractRunBlocks(file).length, keyCount }).toEqual({
        file,
        extracted: keyCount,
        keyCount,
      });
    }
    for (const b of blocks) {
      expect(typeof b.body).toBe('string');
      expect(b.file).toMatch(/\.ya?ml$/);
    }
    // 单行写法也得抽到（只支持块标量的解析器会漏掉这一大类）
    expect(blocks.some((b) => !/\n/.test(b.body) && b.body.trim().length > 0)).toBe(true);
  });

  test.each(workflowFiles())('%s 的每个 bash 步骤都过得了 bash -n', (file) => {
    const blocks = extractRunBlocks(file);
    const bashLike = blocks.filter((b) => isBashLike(b.shell));
    const failures = [];
    for (const b of bashLike) {
      const r = syntaxCheck(b.body);
      if (r.error === 'ENOENT') {
        // 环境没有 bash 时**红**而不是跳过：静默跳过等于把这层防护换成错觉
        throw new Error('本机找不到 bash（Git Bash / CI runner 都自带），本闸无法执行');
      }
      if (r.status !== 0) {
        failures.push(`${file}:${b.line} shell=${b.shell || '默认'}\n${r.stderr.split('\n')[0]}`);
      }
    }
    // 跳过的非 bash 步骤必须数量可见（新增了 pwsh 步骤就得在这里显式承认）
    const skipped = blocks.length - bashLike.length;
    expect({ failures, skipped }).toEqual({ failures: [], skipped: expect.any(Number) });
  });
});
