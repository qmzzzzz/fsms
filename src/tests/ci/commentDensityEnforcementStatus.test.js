'use strict';

/**
 * 注释密度脚本的"强制状态声明 vs 事实"对账闸（第 23 轮，低-1）
 *
 * 缺口：`node scripts/commentDensity.js` 无参跑只打印总量并**恒 exit 0**，
 * 在 CI 里看起来像"检查通过"，其实是"没在检查"——没有任何 npm script / workflow 引用它。
 *
 * 处置：不接线，但让脚本自己声明状态（scripts/commentDensity.js 的 ENFORCEMENT），
 * 再由本闸与事实对账：
 *   · 未接线 ⇔ enforced:false（声明与事实必须一致，谁改一边都得改另一边）；
 *   · 声明里必须写清理由与启用方式（不是一句"暂不强制"）；
 *   · --check 的退出码语义必须与 evaluate() 的判定一致。
 *
 * 反向对照：同一个"是否被接线"判据对一个**确实接线**的脚本必须能找到引用
 * （scripts/lint-ratchet.js），否则这条判据是恒空的。
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const cd = require(path.join(ROOT, 'scripts', 'commentDensity.js'));

/** 某个脚本文件是否被 npm script 或 workflow 真正引用 */
function wiringRefs(scriptFile) {
  const refs = [];
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  for (const [name, cmd] of Object.entries(pkg.scripts || {})) {
    if (String(cmd).includes(scriptFile)) refs.push('package.json:scripts.' + name);
  }
  const wfDir = path.join(ROOT, '.github', 'workflows');
  if (fs.existsSync(wfDir)) {
    for (const f of fs.readdirSync(wfDir)) {
      if (!/\.ya?ml$/.test(f)) continue;
      if (fs.readFileSync(path.join(wfDir, f), 'utf8').includes(scriptFile)) {
        refs.push('.github/workflows/' + f);
      }
    }
  }
  return refs;
}

describe('注释密度脚本的强制状态声明', () => {
  test('反向对照：接线判据不是恒空（确实接线的脚本必须找到引用）', () => {
    expect(wiringRefs('lint-ratchet.js').length).toBeGreaterThan(0);
  });

  test('声明与事实一致：未接线且声明为非强制', () => {
    const refs = wiringRefs('commentDensity.js');
    const wired = refs.length > 0;
    expect({ wired, enforced: cd.ENFORCEMENT.enforced }).toEqual({ wired, enforced: wired });
    // 现状钉住：谁把它接进 CI，这条就红——那时要做的是"接线 + 翻开关 + 改理由"，而不是改判据。
    expect(refs).toEqual([]);
  });

  test('理由与启用方式必须写着（理由不少于 40 字，启用方式给出可执行命令）', () => {
    expect(cd.ENFORCEMENT.rationale.length).toBeGreaterThanOrEqual(40);
    expect(cd.ENFORCEMENT.enable).toMatch(/--check/);
  });

  test('--check 的退出码与 evaluate() 判定一致（今天实测 exit 1：确有回退）', () => {
    const baseline = JSON.parse(fs.readFileSync(cd.BASELINE_PATH, 'utf8'));
    const verdict = cd.evaluate(baseline, cd.production());
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'scripts', 'commentDensity.js'), '--check'],
      { cwd: ROOT, encoding: 'utf8' }
    );
    expect({ ok: verdict.ok, exit: r.status }).toEqual({
      ok: verdict.ok,
      exit: verdict.ok ? 0 : 1,
    });
    expect(r.status === 0 ? r.stdout : r.stderr).toMatch(/注释密度检查/);
  });

  test('evaluate() 判据不是恒真：合成一条回归必须 ok:false，干净基线必须 ok:true', () => {
    const current = { 'src/x.js': { comment: 5, code: 10, ratio: 0.33 } };
    const dirty = cd.evaluate(
      { files: { 'src/x.js': { comment: 4 } }, total: { comment: 4, code: 10 } },
      current
    );
    expect(dirty.ok).toBe(false);
    expect(dirty.regressions.map((x) => x.file)).toEqual(['src/x.js']);
    const clean = cd.evaluate(
      { files: { 'src/x.js': { comment: 5 } }, total: { comment: 5, code: 10 } },
      current
    );
    expect(clean.ok).toBe(true);
  });
});
