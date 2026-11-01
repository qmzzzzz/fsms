'use strict';

/**
 * 发布说明抽取管线（release.yml 的 "Extract release notes from CHANGELOG" 步骤）的语义闸门
 *
 * 起因（第八轮审计 R-8）：releaseWorkflow.test.js 的"真命令"用例跑的是**手抄副本**，
 * 从不对 .github/workflows/release.yml 的 run 体执行一次。本机实测：把 awk 改成多吞一节、
 * tail 的 +1 改 +2、awk 后接 head -n 3、把"空章节 exit 1"降级为 warning，那 12 条用例全绿。
 * 本文件补上这一半：**从 YAML 原文抽 run 体并真跑**。
 *
 * 四条纪律：
 *  1. 脚本体从 YAML 抽取（js-yaml——本仓 scripts/config-drift-check.js 已在用同一库），
 *     不手抄第二份真源；否则测的是副本，与被测对象再次脱钩。
 *  2. shell 由 helpers/posixShell.js 行为验证后解析（Windows 上 PATH 里的 bash.exe 多是
 *     未装发行版的 WSL 桩：退出码非 0 且什么都不执行，直接 spawnSync('bash') 必假绿）。
 *  3. 前提自证：抽不到 run 体、或体里缺 awk / tail -n / CHANGELOG.md ⇒ 红。
 *     "没抽到所以全部通过"是这类闸门最常见的假绿形态。
 *  4. 判据是**契约**而不是退出码：管线可能 exit 0 却把相邻章节写进正文（M1/M2 实测如此），
 *     所以"正文泄漏 / 正文为空 / fail-closed 失效"都算违约。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { resolveShell } = require('../helpers/posixShell');
const { extractStepRuns } = require('./helpers/releaseNotesScript');

const ROOT = path.resolve(__dirname, '../../..');
const WORKFLOW = path.join(ROOT, '.github', 'workflows', 'release.yml');
const STEP_NAME = 'Extract release notes from CHANGELOG';

const BASH = (resolveShell() || { cmd: null }).cmd;
const group = BASH ? describe : describe.skip;

if (!BASH && process.env.CI) {
  // 同 ciProvisionFailurePropagation.test.js 的口径：CI ubuntu 必有 bash，探不到即为探测失效 ⇒ 红。
  describe('release.yml 抽取步骤的平台前提（CI 上缺 POSIX shell）', () => {
    test('CI 上 resolveShell 必须解析到可用的 POSIX shell，否则本文件全部覆盖都是假的', () => {
      expect(BASH).toBeTruthy();
    });
  });
}
if (!BASH) {
  console.warn(
    '[跳过] 未找到可用的 POSIX shell：release.yml 抽取管线的语义判据无法执行（CI 会跑）'
  );
}

const SOURCE = fs.readFileSync(WORKFLOW, 'utf8');
const BODIES = extractStepRuns(SOURCE, STEP_NAME);

/** 夹具：目标版本夹在"未发布"与更旧版本之间——任何多吞/少吞都会立刻体现在正文里 */
const FIXTURE_SAMPLE = [
  '# 更新日志',
  '',
  '## [未发布]',
  '',
  '- 未来的东西',
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

/** 夹具：前缀冲突版本号（2.0.0.1 在 2.0.0 之前）——钉住 grep 的 `\]` 不是装饰 */
const FIXTURE_COLLIDE = [
  '# 更新日志',
  '',
  '## [2.0.0.1] - 2026-12-02',
  '',
  '- 旧候选不应被选中',
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

/** 夹具：目标版本章节存在但正文为空——必须 fail-closed（exit 1），不许发空 Release */
const FIXTURE_EMPTY = [
  '# 更新日志',
  '',
  '## [3.0.0]',
  '',
  '## [2.0.0] - 2026-12-01',
  '',
  '- 第二版的新功能',
  '',
].join('\n');

const TARGET_LINE = '第二版的新功能';
/** 相邻章节的特征行：正文里出现任意一条即为泄漏 */
const ADJACENT = /第一版|未来的东西|旧候选不应被选中/;

/**
 * 在隔离目录里真跑一段 run 体。
 * RELEASE_TAG / GITHUB_OUTPUT 与 Actions 里的取值同形（tag 名带 v 前缀，输出走文件）。
 */
function runPipeline(body, changelog, tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relnotes-'));
  try {
    fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), changelog, 'utf8');
    const outputFile = path.join(dir, 'github_output');
    fs.writeFileSync(outputFile, '', 'utf8');
    const r = spawnSync(BASH, ['-c', body], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, RELEASE_TAG: tag, GITHUB_OUTPUT: outputFile },
    });
    let notes = '';
    try {
      notes = fs.readFileSync(path.join(dir, 'release-notes.md'), 'utf8');
    } catch (err) {
      notes = '';
    }
    return {
      status: r.status,
      notes,
      output: String(r.stdout || '') + String(r.stderr || ''),
      outputFile,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * 契约判定：返回**违约清单**（空数组＝合规）。
 * 注意它比"退出码非 0"更严：M1/M2 实测 exit 0 但正文多出相邻章节。
 */
function violations(result) {
  const out = [];
  if (result.status !== 0) out.push('退出码 ' + result.status + '（期望 0）');
  const notes = result.notes || '';
  if (!notes.includes(TARGET_LINE)) out.push('正文缺目标内容');
  const lines = notes.split(/\r?\n/);
  const headings = lines.filter((line) => line.startsWith('## '));
  if (headings.length > 0) out.push('正文含章节标题：' + headings.join(' | '));
  const leaked = lines.filter((line) => ADJACENT.test(line));
  if (leaked.length > 0) out.push('正文含相邻章节内容：' + leaked.join(' | '));
  return out;
}

// ── 变异：全部作用在**从 YAML 抽出来的那份体**上，不抄第二份真源 ─────────────
const AWK_CORRECT = "awk 'NR > 1 && /^## / { exit } NR > 1 { print }'";

/** grep 版本正则去掉右方括号（`[2.0.0]` 于是也能命中 `[2.0.0.1]`） */
function looseBracket(body) {
  const needle = '-E "^## \\\\[${version}\\\\]"';
  return body.includes(needle) ? body.replace(needle, '-E "^## \\[${version}"') : null;
}

/** 把"空章节 ⇒ exit 1"这一档降级为警告（fail-closed 变 fail-open） */
function downgradeEmptyGate(body) {
  const lines = body.split('\n');
  const at = lines.findIndex((line) => line.includes('! -s release-notes.md'));
  if (at < 0) return null;
  for (let i = at + 1; i < Math.min(at + 6, lines.length); i += 1) {
    const m = /^(\s*)exit 1\s*$/.exec(lines[i]);
    if (!m) continue;
    lines[i] = m[1] + 'echo "::warning::空章节（已降级为警告，继续发布）"';
    return lines.join('\n');
  }
  return null;
}

const MUTATIONS = [
  {
    id: 'M1 awk { print; exit }：把下一个 ## 标题也写进正文',
    fixture: 'sample',
    tag: 'v2.0.0',
    mutate: (body) =>
      body.includes(AWK_CORRECT)
        ? body.replace(AWK_CORRECT, "awk 'NR > 1 && /^## / { print; exit } NR > 1 { print }'")
        : null,
  },
  {
    id: 'M2 awk { next }：边界判定失效，尾部整段进正文',
    fixture: 'sample',
    tag: 'v2.0.0',
    mutate: (body) =>
      body.includes(AWK_CORRECT)
        ? body.replace(AWK_CORRECT, "awk 'NR > 1 && /^## / { next } NR > 1 { print }'")
        : null,
  },
  {
    id: 'M3 grep 去掉右方括号：前缀冲突版本号互相命中',
    fixture: 'collide',
    tag: 'v2.0.0',
    mutate: looseBracket,
  },
  {
    id: 'M4 空章节 exit 1 降级为 warning：fail-closed 失效',
    fixture: 'empty',
    tag: 'v3.0.0',
    mutate: downgradeEmptyGate,
  },
];

const FIXTURES = { sample: FIXTURE_SAMPLE, collide: FIXTURE_COLLIDE, empty: FIXTURE_EMPTY };

group('release.yml 抽取发布说明：从 YAML 原文抽 run 体真跑', () => {
  test('前提自证：真的抽到了 run 体，且体里是那条 grep/tail/awk 管线', () => {
    expect(BODIES.length).toBeGreaterThanOrEqual(1);
    for (const body of BODIES) {
      expect(body).toContain('CHANGELOG.md');
      expect(body).toContain('grep -n');
      expect(body).toContain('tail -n');
      expect(body).toContain("awk '");
      expect(body).toContain('/^## /');
    }
  });

  test('正向对照：目标版本只取本节正文，不含未发布/更旧版本', () => {
    for (const body of BODIES) {
      const r = runPipeline(body, FIXTURE_SAMPLE, 'v2.0.0');
      expect({ status: r.status, violations: violations(r) }).toEqual({
        status: 0,
        violations: [],
      });
      expect(r.notes).toContain(TARGET_LINE);
      expect(r.notes).not.toContain('第一版');
      expect(r.notes).not.toContain('未来的东西');
    }
  });

  test('前缀冲突对照：2.0.0.1 章节存在时仍只取 2.0.0（钉住 grep 的右方括号）', () => {
    for (const body of BODIES) {
      const r = runPipeline(body, FIXTURE_COLLIDE, 'v2.0.0');
      expect({ status: r.status, violations: violations(r) }).toEqual({
        status: 0,
        violations: [],
      });
      expect(r.notes).not.toContain('旧候选不应被选中');
    }
  });

  test('fail-closed 对照：章节存在但正文为空 ⇒ 非零退出（不发空 Release）', () => {
    for (const body of BODIES) {
      const r = runPipeline(body, FIXTURE_EMPTY, 'v3.0.0');
      expect(r.status).not.toBe(0);
      expect(r.output).toContain('章节为空');
    }
  });

  // ── 语义反例：把变异作用在抽出来的那份体上，每一条都必须被判违约 ──────────
  // 变异必须**真的改动**了体（changed 断言），否则本组会退化成"没变异所以全通过"。
  test.each(MUTATIONS.map((m) => [m.id, m]))('语义反例 %s', (id, mutation) => {
    expect(BODIES.length).toBeGreaterThanOrEqual(1);
    for (const body of BODIES) {
      const mutated = mutation.mutate(body);
      expect(mutated).not.toBeNull();
      expect(mutated).not.toBe(body);
      const r = runPipeline(mutated, FIXTURES[mutation.fixture], mutation.tag);
      const v = violations(r);
      // M4 的形态是"本应 exit 1 却 exit 0"：违约清单里必须出现退出码条目
      expect(v.length).toBeGreaterThan(0);
      if (mutation.fixture === 'empty') expect(r.status).toBe(0);
    }
  });
});
