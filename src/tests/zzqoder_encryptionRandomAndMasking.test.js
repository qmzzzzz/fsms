'use strict';

/**
 * （2026-09-19）：encryption.js 的两条"按名字理解会出错"的缺陷
 *
 * `HashUtils.randomString`：base64 取完后 `.replace(/[^A-Za-z0-9]/g,'')` 把
 *   `+ / =` 删掉却不补位 ⇒ 长度**静默变短**。实测 500 次 `randomString(32)`：
 *   314 次（63%）短于 32，最短 27；`randomString(16)` 43% 偏短。
 *   既有测试还把这件事写成契约（`toBeLessThanOrEqual(32)` + 注释"可能略短"），
 *   已在 pureModules.test.js 里改成"恰好等于"。
 * `DataMasking.maskPhone` / `maskIdCard`：`String.replace` 未命中时返回**原串**，
 *   于是"认不出的形态"被当成"不需要脱敏"。实测 15 位老式身份证（1999 年前签发）
 *   与 4 位短号整串明文返回。
 */

const { HashUtils, DataMasking } = require('../../src/utils/encryption');

describe('zzqoder randomString 长度承诺', () => {
  test('每个请求长度都必须精确成立（旧实现 63% 的调用偏短）', () => {
    for (const len of [1, 4, 8, 12, 16, 24, 32, 48, 64]) {
      for (let i = 0; i < 60; i += 1) {
        const s = HashUtils.randomString(len);
        if (s.length !== len) {
          throw new Error(`randomString(${len}) 返回了 ${s.length} 位：${JSON.stringify(s)}`);
        }
      }
    }
  });

  test('字符集只有字母与数字（不再有 base64 的 + / =，也不做取模）', () => {
    const joined = Array.from({ length: 200 }, () => HashUtils.randomString(16)).join('');
    expect(joined).toMatch(/^[A-Za-z0-9]+$/);
    expect(joined).toHaveLength(200 * 16);
  });

  test('相邻调用不重复（熵源未被固定种子短路）', () => {
    const a = HashUtils.randomString(32);
    const b = HashUtils.randomString(32);
    expect(a).not.toBe(b);
  });
});

describe('zzqoder 脱敏函数绝不回显原文', () => {
  // 覆盖"正则认不出"的所有形态：短号、非数字、老式 15 位、残缺 16/17 位、超长串
  const SHAPES = [
    '1',
    '12',
    '1234',
    '12 45',
    'n/a',
    'abcdefghijk',
    '110101900307775', // 老式 15 位身份证
    '1101019003077757', // 16 位（录入残缺）
    '11010190030777578', // 17 位（录入残缺）
    '110101199003077758', // 18 位标准
    '12345678901234567890', // 20 位纯数字：非锚定正则只改前 18 位，尾部会漏明文
    '9'.repeat(30),
  ];

  test.each(SHAPES)('maskPhone(%s) 不得原样返回且必须含掩码', (input) => {
    const out = DataMasking.maskPhone(input);
    expect(out).not.toBe(input);
    expect(out).toContain('*');
    // 兜底必须覆盖整串：出现 7 位以上连续数字说明只改了前缀、尾部漏了明文
    expect(out).not.toMatch(/\d{7}/);
  });

  test.each(SHAPES)('maskIdCard(%s) 不得原样返回且必须含掩码', (input) => {
    const out = DataMasking.maskIdCard(input);
    expect(out).not.toBe(input);
    expect(out).toContain('*');
    expect(out).not.toMatch(/\d{7}/);
  });

  test('被识别的标准形态仍然保留可读首尾（修兜底不得把正常脱敏改成全黑）', () => {
    expect(DataMasking.maskPhone('13812345678')).toBe('138****5678');
    expect(DataMasking.maskPhone('12345')).toBe('12***45');
    expect(DataMasking.maskIdCard('110101199003077758')).toBe('110101********7758');
    expect(DataMasking.maskIdCard('1234567')).toBe('1234***67');
    // 15 位老式证：保留前 6 位（行政区划）+ 后 4 位，中间一律打码且长度不变
    const legacy = DataMasking.maskIdCard('110101900307775');
    expect(legacy).toBe('110101*****7775');
    expect(legacy).toHaveLength(15);
  });

  test('空值契约不变（空串与 null/undefined 仍返回空串，不被兜底变成 ****）', () => {
    expect(DataMasking.maskPhone('')).toBe('');
    expect(DataMasking.maskPhone(null)).toBe('');
    expect(DataMasking.maskPhone(undefined)).toBe('');
    expect(DataMasking.maskIdCard('')).toBe('');
    expect(DataMasking.maskIdCard(null)).toBe('');
  });

  test('_maskMiddle 在输入短于头尾保留位数时整串打码（绝不回显）', () => {
    expect(DataMasking._maskMiddle('ab', 6, 4)).toBe('**');
    expect(DataMasking._maskMiddle('', 6, 4)).toBe('');
    expect(DataMasking._maskMiddle('1234567890', 2, 2)).toBe('12******90');
  });

  test('唯一保留的"原样返回"例外是 maskEmail 的非邮箱形态（既有契约，明确记档）', () => {
    // 这一条不是缺陷放行，而是把"我们讨论过并决定不改"的那个决定钉住：
    // 邮箱列里的非邮箱值没有可脱敏的结构，先前实现选择原样返回并写了测试。
    // 若哪天要改成统一打码，必须连带改 src/tests/utils/pureModules.test.js 的对应断言。
    expect(DataMasking.maskEmail('not-an-email')).toBe('not-an-email');
    expect(DataMasking.maskEmail('abcdef@example.com')).toMatch(/^a\*{4}f@example\.com$/);
  });
});
