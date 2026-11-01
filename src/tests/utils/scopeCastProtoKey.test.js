/**
 * U3 回归：castScopeObjectIds 对 __proto__ 键必须落成自身数据属性
 *
 * 原实现 out[k] = v 在 k === '__proto__' 时走的是原型 setter：
 * 键从 Object.keys 与 JSON.stringify 里消失，值却成了**结果对象的原型**
 * （实测出对象能读到 a === '1'，而 Object.keys(out) 为 []）。
 * 与 helpers.stripControlCharsDeep 的落键口径对齐后用 defineProperty，三个观测面都钉住。
 */

'use strict';

const { castScopeObjectIds } = require('../../utils/scopeCast');

describe('U3 __proto__ 作为自身数据属性保留', () => {
  const input = JSON.parse('{"__proto__":{"a":"1"},"b":"x"}');

  test('键不丢：Object.keys 与 JSON.stringify 都能看见它', () => {
    const out = castScopeObjectIds(input);
    expect(Object.keys(out).sort()).toEqual(['__proto__', 'b']);
    expect(JSON.parse(JSON.stringify(out))).toEqual(JSON.parse('{"__proto__":{"a":"1"},"b":"x"}'));
    expect(Object.getOwnPropertyDescriptor(out, '__proto__').enumerable).toBe(true);
  });

  test('不污染：结果对象原型仍是 Object.prototype，全局未被污染', () => {
    const out = castScopeObjectIds(input);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(out.a).toBeUndefined();
    expect({}.a).toBeUndefined();
    expect(Object.prototype.a).toBeUndefined();
  });

  test('回归对照：普通键照旧递归 cast（ObjectId 字符串仍被归一）', () => {
    const hex = '507f1f77bcf86cd799439011';
    const out = castScopeObjectIds({ userId: hex, list: [hex] });
    expect(String(out.userId)).toBe(hex);
    expect(out.userId).not.toBe(hex);
    expect(String(out.list[0])).toBe(hex);
  });
});
