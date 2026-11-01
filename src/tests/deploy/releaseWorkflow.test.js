/**
 * 发布工作流（.github/workflows/release.yml）回归
 *
 * 两层验证：
 *   1. **真跑抽取逻辑**——把工作流里的 awk 管线在一份造出来的
 *      CHANGELOG 上执行，断言它取出正确章节（而不是“看着像对”）。
 *      实践过的教训：本仓库已有多处“正则匹配到注释就算通过”的假绿用例。
 *   2. 结构不变量：fail-closed（抽不到就失败）、权限隔离、tag 触发。
 *
 * 依赖说明：只用 node 内置模块（不引入新依赖）。
 * awk 部分用 Node 等价实现重写一遍——不是“模仿它”，
 * 而是把它当作**被测对象的规格**：两边同一分隔符（^## ）下必须得出同一结果。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const WF = path.join(ROOT, '.github/workflows/release.yml');
const src = fs.readFileSync(WF, 'utf8');

// 第八轮审计 R-8：脚本体必须来自 release.yml **原文**（抽取器见 helpers/releaseNotesScript.js），
// shell 必须由 helpers/posixShell.js 行为验证后解析——Windows 上 PATH 里的 bash.exe 多为 WSL 桩，
// 直接 spawnSync('bash') 的结果是「退出码非 0 且什么都没执行」。
const { resolveShell } = require('../helpers/posixShell');
const { extractStepRuns } = require('./helpers/releaseNotesScript');

const EXTRACT_STEP = 'Extract release notes from CHANGELOG';
const RUN_BODIES = extractStepRuns(src, EXTRACT_STEP);
/** 探不到可用 POSIX shell 时用 test.skip（报告里是 skipped，不是 passed） */
const SHELL_CMD = (resolveShell() || { cmd: null }).cmd;
const itWithShell = SHELL_CMD ? test : test.skip;

/**
 * 与工作流中的提取语义一致的参考实现：
 * 从 `## [version]` 的下一行起，到下一个 `## ` 前一行为止。
 * 返回 null 表示找不到该版本或内容为空（=fail-closed 触发）。
 */
function extractSection(markdown, version) {
  const lines = markdown.split(/\r?\n/);
  const re = new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\]`);
  const start = lines.findIndex((l) => re.test(l));
  if (start < 0) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^## /.test(lines[i])) break;
    body.push(lines[i]);
  }
  const text = body.join('\n').trim();
  return text.length > 0 ? text : null;
}

const SAMPLE = [
  '# 更新日志',
  '',
  '## [未发布]',
  '',
  '### 新增',
  '',
  '- 未来的东西',
  '',
  '## [2.0.0] - 2026-12-01',
  '',
  '### 新增',
  '',
  '- 第二版的新功能',
  '',
  '## [1.0.0] - 2026-08-29',
  '',
  '- 第一版',
  '',
].join('\n');

describe('D-1 发布工作流：抽取逻辑与结构不变量', () => {
  test('按版本号取出对应章节（而非前一个或后一个）', () => {
    const v2 = extractSection(SAMPLE, '2.0.0');
    expect(v2).toContain('第二版的新功能');
    expect(v2).not.toContain('第一版');
    expect(v2).not.toContain('未来的东西');
  });

  test('找不到版本时返回 null（工作流据此 exit 1）', () => {
    expect(extractSection(SAMPLE, '9.9.9')).toBeNull();
    // 前缀相同但不同的版本不得互相命中
    expect(extractSection(SAMPLE, '2.0')).toBeNull();
    expect(extractSection(SAMPLE, '2.0.0.1')).toBeNull();
  });

  test('空章节必须当作失败（不发无内容的 Release）', () => {
    const onlyHeading = ['## [3.0.0]', '', '## [2.0.0]', '', '- x'].join('\n');
    expect(extractSection(onlyHeading, '3.0.0')).toBeNull();
  });

  test('工作流与参考实现采用同一分隔符（^## ）——否则两边行为会漂移', () => {
    // 工作流里的 awk 与 grep 都必须用 `## ` 作为边界判据
    expect(src).toMatch(/\^## /); // grep -E "^## \[$version\]"
    expect(src).toContain('/^## /'); // awk '/^## / { exit }'
    // 不得用 `# ` 或 `### ` 作为章节结束判据
    expect(src).not.toContain('/^# /');
    expect(src).not.toContain('/^### /');
  });

  test('fail-closed：抽不到或为空都 exit 1（不静默发空 Release）', () => {
    expect(src).toMatch(/if \[\[ -z "\$start" \]\]/);
    expect(src).toMatch(/CHANGELOG\.md 中找不到版本/);
    expect(src).toMatch(/if \[\[ ! -s release-notes\.md \]\]/);
    // 两处失败都必须带 exit 1
    const exitCount = (src.match(/exit 1/g) || []).length;
    expect(exitCount).toBeGreaterThanOrEqual(2);
  });

  // ── 前提自证：抽取器抽不到就不能"全通过" ────────────────────────────────
  test('前提自证：从 release.yml 原文抽到了抽取步骤的 run 体（抽不到时下面全是空集假绿）', () => {
    expect(RUN_BODIES.length).toBeGreaterThanOrEqual(1);
    for (const body of RUN_BODIES) {
      expect(body).toContain('CHANGELOG.md');
      expect(body).toContain('grep -n');
      expect(body).toContain('tail -n');
      expect(body).toContain('awk');
      expect(body).toContain('exit 1');
    }
  });

  /**
   * 在隔离目录里跑一段 run 体：CHANGELOG.md 就位，RELEASE_TAG/GITHUB_OUTPUT 与 Actions 同形。
   * 返回 release-notes.md 的内容（不存在时为空串）与退出码。
   */
  function runExtractBody(body, tag, changelogText) {
    const os = require('os');
    const { spawnSync } = require('child_process');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relnotes-'));
    try {
      fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), changelogText, 'utf8');
      const outFile = path.join(dir, 'github_output');
      fs.writeFileSync(outFile, '', 'utf8');
      const r = spawnSync(SHELL_CMD, ['-c', body], {
        cwd: dir,
        encoding: 'utf8',
        timeout: 30000,
        env: { ...process.env, RELEASE_TAG: tag, GITHUB_OUTPUT: outFile },
      });
      let notes = '';
      try {
        notes = fs.readFileSync(path.join(dir, 'release-notes.md'), 'utf8');
      } catch (err) {
        notes = '';
      }
      return { status: r.status, notes, output: String(r.stdout || '') + String(r.stderr || '') };
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  /**
   * 判定"抽出来的正文合法"：目标内容在、相邻章节一个字都不许进来、且不含任何 `## ` 标题。
   * 抽成函数是为了让下面的可证伪用例能直接复用它（断言同一份判据会红）。
   */
  function expectNoLeak(notes) {
    expect(notes).toContain('第二版的新功能');
    expect(notes).not.toContain('第一版');
    expect(notes).not.toContain('未来');
    expect(notes.split(/\r?\n/).some((line) => line.startsWith('## '))).toBe(false);
  }

  // 【R-8】原实现是 fail-open：`if (probe.status !== 0) { console.warn(...); return; }`
  // —— jest 把空函数体判 passed（本机实测 12 passed + 一行 warn），注释却写"用 test.skip"。
  // 现在：① 无 shell 时由 itWithShell → test.skip（报告里是 skipped）；
  //       ② 跑的是从 release.yml **抽出来的原文**，不是手抄副本；
  //       ③ 下方"可证伪"用例证明这条断言真的会红。
  itWithShell('真命令：跑工作流原文的抽取步骤，只取目标章节（无泄漏）', () => {
    const sample = [
      '# 日志',
      '',
      '## [未发布]',
      '',
      '- 未来',
      '',
      '## [2.0.0] - 2026-12-01',
      '',
      '- 第二版的新功能',
      '',
      '## [1.0.0] - 2026-08-29',
      '',
      '- 第一版',
      '',
    ].join('\n');
    for (const body of RUN_BODIES) {
      const r = runExtractBody(body, 'v2.0.0', sample);
      expect({
        status: r.status,
        output: r.output.trim() === '' ? '' : r.output.trim(),
      }).toMatchObject({ status: 0 });
      // 关键：只有第二版的内容，不含第一版与未发布（判据与可证伪用例共用同一个函数）
      expectNoLeak(r.notes);
    }
  });

  /**
   * 可证伪：把工作流原文里的 awk 改成 `{ print; exit }`（多吞下一个标题），
   * 同一段夹具下 note 里必须出现 `## [1.0.0]` —— 即上一条的 not.toContain 会失败。
   * 变异作用在**抽出来的那份体**上，不引入第二份真源。
   */
  itWithShell('可证伪：awk 改成 { print; exit } 后本文件的断言必须变红', () => {
    const sample = [
      '## [2.0.0] - 2026-12-01',
      '',
      '- 第二版的新功能',
      '',
      '## [1.0.0] - 2026-08-29',
      '',
      '- 第一版',
      '',
    ].join('\n');
    const AWK_CORRECT = "awk 'NR > 1 && /^## / { exit } NR > 1 { print }'";
    for (const body of RUN_BODIES) {
      const mutated = body.replace(
        AWK_CORRECT,
        "awk 'NR > 1 && /^## / { print; exit } NR > 1 { print }'"
      );
      expect(mutated).not.toBe(body);
      const r = runExtractBody(mutated, 'v2.0.0', sample);
      // 判据本身必须抛：M1 形态会把 `## [1.0.0] - …` 标题写进正文，被上面的标题断言抓到
      expect(() => expectNoLeak(r.notes)).toThrow();
    }
  });

  // 2026-10-24 审计 P2：Release 不再与 CI 平行地被 tag 触发。
  // 旧形态下 CI/security-audit/镜像构建/签名任一失败，Release 仍会发出。
  test('以 CI workflow_run 完成为触发，而不是直接监听 tag', () => {
    expect(src).toMatch(/workflow_run:/);
    expect(src).toMatch(/workflows:\s*\['CI'\]/);
    expect(src).toMatch(/types:\s*\[completed\]/);
    // 不得再直接监听 push/tags（那会绕开 CI 结论）
    const onBlock = src.slice(src.indexOf('on:'), src.indexOf('permissions:'));
    expect(onBlock).not.toMatch(/^\s{2}push:/m);
    expect(onBlock).not.toMatch(/tags:/);
  });

  test('失败或非本仓 fork 的 CI 不得触发 Release（fail-closed 前置条件）', () => {
    expect(src).toMatch(/workflow_run\.conclusion == 'success'/);
    expect(src).toMatch(/workflow_run\.event == 'push'/);
    expect(src).toMatch(/workflow_run\.head_repository\.full_name == github\.repository/);
    expect(src).toMatch(/startsWith\(github\.event\.workflow_run\.head_branch, 'v'\)/);
  });

  test('tag 必须存在且指向 CI 实际验证的提交（防止移动 tag / 同名分支）', () => {
    expect(src).toMatch(/ref:\s*\$\{\{\s*github\.event\.workflow_run\.head_sha\s*\}\}/);
    expect(src).toMatch(/git fetch --force origin "refs\/tags\/\$\{RELEASE_TAG\}/);
    expect(src).toMatch(/git rev-list -n 1 "refs\/tags\/\$\{RELEASE_TAG\}"/);
    expect(src).toMatch(/EXPECTED_SHA/);
    // 校验段必须有真实的失败退出（不是只打印）
    const block = src.slice(src.indexOf('Verify tag points'), src.indexOf('Extract release notes'));
    expect((block.match(/exit 1/g) || []).length).toBeGreaterThanOrEqual(3);
  });

  test('Release 显式绑定 tag（workflow_run 下 github.ref 是默认分支）', () => {
    expect(src).toMatch(/tag_name:\s*\$\{\{\s*env\.RELEASE_TAG\s*\}\}/);
    expect(src).toMatch(/RELEASE_TAG:\s*\$\{\{\s*github\.event\.workflow_run\.head_branch\s*\}\}/);
    // 版本号从 RELEASE_TAG 取，不能再用 GITHUB_REF_NAME
    expect(src).toMatch(/version="\$\{RELEASE_TAG#v\}"/);
    expect(src).not.toMatch(/version="\$\{GITHUB_REF_NAME#v\}"/);
  });

  test('权限隔离：工作流级 read，contents: write 只给 release job', () => {
    const wfPerm = src.slice(src.indexOf('permissions:'), src.indexOf('jobs:'));
    expect(wfPerm).toMatch(/contents: read/);
    const jobIdx = src.indexOf('\n  release:');
    expect(jobIdx).toBeGreaterThan(-1);
    const jobBlock = src.slice(jobIdx);
    expect(jobBlock).toMatch(/contents: write/);
  });

  test('Release 内容来自 CHANGELOG（而非另写一份）', () => {
    expect(src).toMatch(/body_path:\s*\$\{\{\s*steps\.notes\.outputs\.path\s*\}\}/);
  });
});
