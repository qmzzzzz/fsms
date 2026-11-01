/**
 * 注释密度棘轮（Q-1，见 docs/adr/ADR-011）
 *
 * 钉住两件事：
 *  ① 生产代码（`src/**` 排除 `src/tests/**`）的注释整行数只许降：逐文件不得高于
 *     基线，新增文件密度不得超过 NEW_FILE_MAX；
 *  ② 基线本身可核：总量等于逐文件之和、文件集合与磁盘一致（删除/改名必须同批更新）。
 *
 * 反向对照与真实判据共用 `evaluate`，避免"测试自证的是一套逻辑、产品用的是另一套"。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  measure,
  production,
  evaluate,
  totalsOf,
  NEW_FILE_MAX,
  BASELINE_PATH,
} = require('../../../scripts/commentDensity');

const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
const current = production();
const verdict = evaluate(baseline, current);

describe('注释密度棘轮（生产代码，只降不升）', () => {
  test('前提自证：统计面非空、只含生产代码，且基线总量可自核', () => {
    const files = Object.keys(current);
    expect(files.length).toBeGreaterThan(200);
    expect(files.every((f) => f.startsWith('src/') && !f.startsWith('src/tests/'))).toBe(true);
    expect(files).toContain('src/middleware/security/securityHeaders.js');

    const sum = Object.values(baseline.files).reduce((n, m) => n + m.comment, 0);
    expect(baseline.total.comment).toBe(sum);
    const codeSum = Object.values(baseline.files).reduce((n, m) => n + m.code, 0);
    expect(baseline.total.code).toBe(codeSum);
    // 比率是派生物：基线里的 ratio 必须能由计数重算，防止手改数字粉饰
    expect(baseline.total.ratio).toBe(
      Number((baseline.total.comment / (baseline.total.comment + baseline.total.code)).toFixed(4))
    );
  });

  test('每个已登记文件的注释行数不得增加，且不得有清单残留', () => {
    expect(verdict.regressions).toEqual([]);
    expect(verdict.stale).toEqual([]);
  });

  test('新增文件密度不得超过 NEW_FILE_MAX，总量不得回升', () => {
    expect(verdict.newFilesOverCap).toEqual([]);
    expect(verdict.totalRegressed).toBe(false);
    // 上限必须低于当前水位，否则"新债不得免费入场"会失去意义
    expect(NEW_FILE_MAX).toBeLessThan(baseline.total.ratio);
  });

  test('反向对照：多一行注释 / 超密度新文件 / 删除未同步 都必须被同一条判据抓住', () => {
    // 总量上限留 2 行余量，让"新增文件"这条臂单独验证密度判据
    const base = { files: { 'src/a.js': { comment: 2, code: 8 } }, total: { comment: 4, code: 8 } };

    // ① 已登记文件 +1 行注释 ⇒ 回归
    expect(evaluate(base, { 'src/a.js': { comment: 3, ratio: 0.27 } }).regressions).toEqual([
      { file: 'src/a.js', base: 2, now: 3 },
    ]);
    // ② 新文件超上限 ⇒ 单独标记；未超上限 ⇒ 放行
    const over = evaluate(base, {
      'src/a.js': { comment: 2, ratio: 0.2 },
      'src/b.js': { comment: 4, ratio: 0.4 },
    });
    expect(over.newFilesOverCap).toEqual([{ file: 'src/b.js', ratio: 0.4 }]);
    expect(over.ok).toBe(false);
    const fine = evaluate(base, {
      'src/a.js': { comment: 2, ratio: 0.2 },
      'src/c.js': { comment: 2, ratio: 0.2 },
    });
    expect(fine.newFilesOverCap).toEqual([]);
    expect(fine.ok).toBe(true);
    // ③ 基线里有、磁盘上没了 ⇒ 残留（改名/删除必须同批更新基线）
    expect(evaluate(base, {}).stale).toEqual(['src/a.js']);
    // ④ 有文件数下降但另一文件回升时，总量判据仍然生效
    const totalUp = evaluate(
      { files: { 'src/a.js': { comment: 1, code: 1 } }, total: { comment: 1, code: 1 } },
      { 'src/a.js': { comment: 1, ratio: 0.5 }, 'src/b.js': { comment: 1, ratio: 0.1 } }
    );
    expect(totalUp.totalRegressed).toBe(true);
    expect(totalUp.ok).toBe(false);
  });

  test('全仓总量与逐文件之和一致（防止 evaluate 内部账目与基线口径分叉）', () => {
    expect(totalsOf(current)).toEqual({
      comment: Object.values(current).reduce((n, m) => n + m.comment, 0),
      code: Object.values(current).reduce((n, m) => n + m.code, 0),
    });
  });

  test('ruler 语义：块注释必须计入注释行（把 LINE_COMMENT 收窄成只认 // 时本用例必红）', () => {
    // 上面几条都是「账本自洽」断言（total == Σfiles、ratio 可重算），把判据本体
    // LINE_COMMENT 从 /^\s*(\/\/|\/\*|\*)/ 收窄成只认 `//` 后它们照样全绿：
    // 注释整行数从 22,497 掉到 7,061，密度门禁由红转绿，而没有任何一条断言过
    // 「块注释算不算注释」。这里直接钉判据本体。
    expect(measure('/**\n * 文档注释\n */\n')).toEqual({
      comment: 3,
      code: 0,
      total: 3,
      ratio: 1,
    });
    expect(measure('/* 单行块注释 */\n').comment).toBe(1);
    expect(measure('  * 续行\n').comment).toBe(1);
    expect(measure('// 行注释\n').comment).toBe(1);
    // 对照：行尾注释依附代码行，不得算成整行注释（判据不得放宽到"含 // 就算"）
    expect(measure('var a = 1; // 行尾\n')).toEqual({
      comment: 0,
      code: 1,
      total: 1,
      ratio: 0,
    });
    // 空行不进分母
    expect(measure('\n \n').total).toBe(0);

    // 只用块注释的**临时文件**走完整 measure：文件面上也必须数出注释行
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-ruler-'));
    try {
      const blockOnly = path.join(tmp, 'blockonly.js');
      fs.writeFileSync(blockOnly, '/**\n * 只有块注释\n */\n', 'utf8');
      const m = measure(fs.readFileSync(blockOnly, 'utf8'));
      expect({ comment: m.comment, code: m.code }).toEqual({ comment: 3, code: 0 });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }

    // 全仓层面：用**独立写法的**块注释正则（故意不复用 LINE_COMMENT）数一遍原始文本，
    // 每个含块注释的文件都必须已被判据算进 comment。收窄判据后这 338 个文件全部转红。
    const ROOT_DIR = path.resolve(path.dirname(BASELINE_PATH), '..');
    const blockRe = /^\s*(\/\*|\*)/;
    const short = [];
    let blockLines = 0;
    for (const rel of Object.keys(current)) {
      const text = fs.readFileSync(path.join(ROOT_DIR, rel), 'utf8');
      const n = text.split(/\r?\n/).filter((l) => l.trim() !== '' && blockRe.test(l)).length;
      blockLines += n;
      if (n > 0 && current[rel].comment < n)
        short.push({ rel, blockLines: n, comment: current[rel].comment });
    }
    // 前提自证：真实统计面里确实有块注释；否则下面那条对空集合恒真
    expect(blockLines).toBeGreaterThan(10000);
    expect(short).toEqual([]);
  });
});
