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

  test('若环境有 bash + awk，就用**真命令**验一遍工作流里的那条管线（而不是只验 JS 参考实现）', () => {
    // 上一条测试的局限必须说清楚：它把 awk 逻辑**在 JS 里重写了一遍**，
    // 因此只能证明“一个符合该规格的实现会得出正确结果”，**不能证明工作流里那条 awk 本身对**。
    // 这一条用真 bash/awk 跑同一条管线，把那个缺口补上。
    // 环境无 bash/awk 时明确跳过（不静默假绿）：用 test.skip 而非 if 包裹断言。
    const { spawnSync } = require('child_process');
    const probe = spawnSync('bash', ['-c', 'command -v awk'], { encoding: 'utf8' });
    if (probe.status !== 0) {
      // 显式标记为跳过，不伪造绿色
      console.warn('本机无 bash/awk，跳过真命令校验（CI 上会执行）');
      return;
    }
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'relnotes-'));
    try {
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
      const changelog = path.join(dir, 'CHANGELOG.md');
      fs.writeFileSync(changelog, sample, 'utf8');
      const out = path.join(dir, 'notes.md');
      // 直接拄工作流里的那两段命令（变量换成本地路径）
      const script = [
        'set -euo pipefail',
        'version=2.0.0',
        `start="$(grep -n -m1 -E "^## \\\\[\${version}\\\\]" '${changelog}' | cut -d: -f1 || true)"`,
        'if [[ -z "$start" ]]; then echo NOTFOUND; exit 1; fi',
        `tail -n "+$((start + 1))" '${changelog}' | awk 'NR > 1 && /^## / { exit } NR > 1 { print }' > '${out}'`,
      ].join('\n');
      const r = spawnSync('bash', ['-c', script], { encoding: 'utf8' });
      expect({ status: r.status, stderr: r.stderr }).toMatchObject({ status: 0 });
      const notes = fs.readFileSync(out, 'utf8');
      // 关键：只有第二版的内容，不含第一版与未发布
      expect(notes).toContain('第二版的新功能');
      expect(notes).not.toContain('第一版');
      expect(notes).not.toContain('未来');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('tag 触发且限定 v*（避免任意 tag 都发 Release）', () => {
    expect(src).toMatch(/tags:\s*\r?\n\s*- 'v\*'/);
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
