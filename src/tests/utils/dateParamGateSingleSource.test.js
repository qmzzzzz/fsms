'use strict';

/**
 * 「日期参数裸判据」全仓只允许出现在 helpers.isValidDateParam 内部
 *
 * 缺陷形状（F-157）：入口写 `startDate && isNaN(new Date(startDate).getTime())`，
 * 这条判据对**纯数字串**放行——`'123'` / `'2026'` 都能被 Date 解析，
 * 于是参数写错不会报错，而是被 parseDateBoundary 静默翻译成"公元 0122 年"的窗口，
 * 返回 200 + 一个窄到看不见的结果集（报表/统计/审计列表同病）。
 * 本仓的权威口径是 `helpers.isValidDateParam`（reportController 四处已在用），
 * 它拒非字符串、拒纯数字串；判例注释就在 helpers.js 的 JSDoc 里。
 *
 * 本文件是**漂移守卫**：扫生产代码里"裸 Date 解析当入口判据"的写法，
 * 命中的文件必须只有 helpers.js 一处（即那份单一实现自己）。
 * 扫描前剥注释：文本判据在注释上假绿过本仓前科，所以第 1 条用例先自证
 * 提取器"抓得到合成脏样本、不误伤合法写法、注释里的不算"。
 *
 * 扫描面 = src 下除 tests 外的全部 .js（与 writeMethodSingleSource 同一口径）。
 */

const fs = require('fs');
const path = require('path');

const SRC_ROOT = path.join(__dirname, '..', '..');
const CANONICAL = 'src/utils/helpers.js';
/** 裸判据的三个变体：isNaN / Number.isNaN 包 new Date(...)，或 Date.parse(...) */
const RAW_DATE_GATE = /(?:Number\.)?isNaN\(\s*new Date\(|Date\.parse\(/;

const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const walkJs = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (path.basename(full) === 'tests' || path.basename(full) === 'node_modules') continue;
      walkJs(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

const rawGateHits = (code) => stripComments(code).match(RAW_DATE_GATE) || [];

describe('日期参数判据的单一事实来源（F-157）', () => {
  test('提取器自证：抓得到脏样本，不误伤合法写法，注释里的不算', () => {
    // 三个脏形态都要抓得到——漏一个就等于给对应的复制粘贴留了后门
    expect(rawGateHits('if (a && isNaN(new Date(a).getTime())) throw 0;').length).toBe(1);
    expect(rawGateHits('return Number.isNaN(new Date(v).getTime());').length).toBe(1);
    expect(rawGateHits('if (Number.isNaN(Date.parse(v))) bad();').length).toBe(1);
    // 权威实现引用的是 helpers 的导出口 ⇒ 合法，不该命中
    expect(rawGateHits('if (!isValidDateParam(v)) return 400;').length).toBe(0);
    // 构造日期（不是拿 Date 解析当判据）⇒ 本守卫不管，交给 helpers 自己的用例
    expect(rawGateHits('const d = new Date(ts);').length).toBe(0);
    // 只出现在注释里 ⇒ 不算（否则守卫会被文档措辞牵着红）
    expect(
      rawGateHits('// 原写法 isNaN(new Date(x)) 会放行 123\nconst ok = isValidDateParam(v);').length
    ).toBe(0);
    expect(rawGateHits('/* isNaN(new Date(x)) 是缺陷 */\nconst ok = 1;').length).toBe(0);
  });

  test('全仓生产代码里，裸 Date 解析判据只存在于 helpers.js', () => {
    const hits = [];
    for (const file of walkJs(SRC_ROOT)) {
      const rel = path.relative(path.join(SRC_ROOT, '..'), file).split(path.sep).join('/');
      const n = rawGateHits(fs.readFileSync(file, 'utf8')).length;
      if (n > 0) hits.push(`${rel}×${n}`);
    }
    // 只允许那份单一实现自己；任何新复制点都会在这里现形
    expect(hits).toEqual([expect.stringContaining(CANONICAL)]);
  });

  test('四处消费方引用的是 helpers 的导出口（写法门禁，不看值相等）', () => {
    const consumers = [
      'controllers/alarmController.js',
      'controllers/inspectionController.js',
      'utils/auditQuery.js',
      'controllers/reportController.js',
    ];
    for (const rel of consumers) {
      const code = stripComments(fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8'));
      // 判据必须是"从 helpers 解构导入"，而不是本文件另写一份同名实现
      expect(code).toEqual(
        expect.stringMatching(
          /const\s*\{[^}]*\bisValidDateParam\b[^}]*\}\s*=\s*require\(['"][^'"]*helpers['"]\)/
        )
      );
      expect(code).not.toEqual(expect.stringMatching(/(const|function)\s+isValidDateParam\s*[=(]/));
    }
  });
});
