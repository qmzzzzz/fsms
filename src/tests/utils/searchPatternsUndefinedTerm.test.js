/**
 * U6 回归：upperCodePrefixPattern 对 undefined/null 与 substringPattern 同口径
 *
 * 原实现 term.toUpperCase() 是三个构造器里唯一不设防的一个：undefined 直接
 * TypeError。调用点当前都先经 normalizeSearchTerm（返回 ''），所以这是**契约
 * 一致性**修复而不是线上事故修复——但同文件三个函数一个口径才算收敛。
 */

'use strict';

const {
  substringPattern,
  prefixPattern,
  upperCodePrefixPattern,
} = require('../../utils/searchPatterns');

describe('U6 三个构造器对空值的口径一致', () => {
  test('undefined/null 不抛错', () => {
    for (const fn of [substringPattern, prefixPattern, upperCodePrefixPattern]) {
      expect(() => fn(undefined)).not.toThrow();
      expect(() => fn(null)).not.toThrow();
    }
  });

  test('undefined 与空串产出同一个模式', () => {
    expect(upperCodePrefixPattern(undefined).source).toBe(upperCodePrefixPattern('').source);
    expect(prefixPattern(undefined).source).toBe(prefixPattern('').source);
    expect(substringPattern(undefined).source).toBe(substringPattern('').source);
  });

  test('正向对照：正常词仍然锚定前缀且大写归一', () => {
    expect(upperCodePrefixPattern('dev-01').source).toBe('^DEV-01');
    expect(upperCodePrefixPattern('dev-01').test('DEV-011')).toBe(true);
    expect(upperCodePrefixPattern('dev-01').test('XDEV-01')).toBe(false);
  });

  test('元字符仍被转义（口径一致不等于放弃 escapeRegExp）', () => {
    expect(upperCodePrefixPattern('(a+)+$').test('a'.repeat(2000))).toBe(false);
  });
});
