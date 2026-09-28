'use strict';

/**
 * "写操作"名单全仓只有一份
 *
 * 同一份四个方法名此前有**三处**字面量：`originCheck`（CSRF 来源闸）、
 * `security.auditLog` 的默认 `operations`（全局审计记哪些方法）、
 * `behaviorBaseline` 的 writes 聚合（行为基线算哪些是写）。
 * 三条判据在语义上必须同进同退——任一处单独加一个方法，就会出现
 * "被 CSRF 拦下但没进审计"或"基线把某类写当读"的静默口径分叉。
 * 现由 `originCheck.WRITE_METHODS` 作单一事实来源（且冻结，才能安全当默认值共享）。
 *
 * 本文件是**漂移守卫**：扫描源码里"元素集合恰好等于这四个方法"的字符串数组字面量，
 * 命中的声明点必须只有 originCheck.js 一处。
 * 注意扫描前先剥掉注释：文本判据在注释上假绿过两次（本仓前科），
 * 所以第 1 条用例先自证提取器"抓得到合成脏样本、不误伤合法样本、注释里的不算"。
 */

const fs = require('fs');
const path = require('path');
const { WRITE_METHODS } = require('../../middleware/originCheck');

const SRC_ROOT = path.join(__dirname, '..', '..');
const CANONICAL = 'src/middleware/originCheck.js';
const WRITE_SET = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/** 抽出所有"纯字符串字面量数组"，返回元素集合数组 */
const literalStringArrays = (code) => {
  const out = [];
  const re = /\[\s*(['"])[^'"]*\1(?:\s*,\s*(['"])[^'"]*\2)*/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const items = m[0]
      .slice(1)
      .split(',')
      .map((s) => s.trim().slice(1, -1));
    out.push(new Set(items));
  }
  return out;
};

const writeMethodLiteralsIn = (code) =>
  literalStringArrays(stripComments(code)).filter(
    (set) => set.size === WRITE_SET.size && [...set].every((x) => WRITE_SET.has(x))
  );

const walkJs = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // tests 目录里的合成样本与夹具是**测试数据**，不参与"生产代码只有一份"的判据
      if (path.basename(full) === 'tests' || path.basename(full) === 'node_modules') continue;
      walkJs(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

describe('写操作名单的单一事实来源', () => {
  test('提取器自证：抓得到合成脏样本，不误伤合法样本，注释里的不算', () => {
    expect(writeMethodLiteralsIn("const a = ['POST', 'PUT', 'DELETE', 'PATCH'];").length).toBe(1);
    // 顺序不同也一样命中（比的是集合，不是字面串）
    expect(writeMethodLiteralsIn("const a = ['PATCH','DELETE','POST','PUT'];").length).toBe(1);
    // 不是那四个 ⇒ 不算
    expect(writeMethodLiteralsIn("const a = ['GET', 'POST'];").length).toBe(0);
    expect(writeMethodLiteralsIn("const a = ['POST', 'PUT', 'PATCH'];").length).toBe(0);
    expect(
      writeMethodLiteralsIn("const a = ['POST', 'PUT', 'PATCH', 'DELETE', 'GET'];").length
    ).toBe(0);
    // 只出现在注释里 ⇒ 不算（否则守卫会被文档措辞牵着红）
    expect(
      writeMethodLiteralsIn("// 原来是 ['POST','PUT','DELETE','PATCH']\nconst a = 1;").length
    ).toBe(0);
  });

  test('全仓生产代码里，写操作字面量只允许出现在 originCheck.js', () => {
    const hits = [];
    for (const file of walkJs(SRC_ROOT)) {
      const rel = path.relative(path.join(SRC_ROOT, '..'), file).split(path.sep).join('/');
      for (const set of writeMethodLiteralsIn(fs.readFileSync(file, 'utf8'))) hits.push(rel, set);
    }
    const files = [...new Set(hits.filter((h) => typeof h === 'string'))];
    expect(files).toEqual([CANONICAL]);
  });

  test('那份名单本身：四个方法、顺序稳定、且冻结到无法就地改写', () => {
    expect([...WRITE_SET].every((m) => WRITE_METHODS.includes(m))).toBe(true);
    expect(WRITE_METHODS).toHaveLength(4);
    expect(Object.isFrozen(WRITE_METHODS)).toBe(true);
    expect(() => WRITE_METHODS.push('GET')).toThrow();
    expect(WRITE_METHODS).toHaveLength(4);
  });

  test('两个消费方都改为引用它（默认 operations 与基线 writes 不再各写一份）', () => {
    const securitySrc = stripComments(
      fs.readFileSync(path.join(SRC_ROOT, 'middleware/security.js'), 'utf8')
    );
    const baselineSrc = stripComments(
      fs.readFileSync(path.join(SRC_ROOT, 'services/behaviorBaseline.js'), 'utf8')
    );
    expect(securitySrc).toMatch(/require\('\.\/originCheck'\)/);
    expect(securitySrc).toMatch(/operations = WRITE_METHODS/);
    expect(baselineSrc).toMatch(/require\('\.\.\/middleware\/originCheck'\)/);
    expect(baselineSrc).toMatch(/\$in: \['\$method', WRITE_METHODS]/);
  });
});
