'use strict';

/**
 * 口令字典特征派生（P2 情报的第一级）：三个字段怎么算、以及**绝不能**算出什么。
 *
 * 本文件测的是 `constants/credentialShape`，它是画像唯一的取值来源；画像（聚合面）的判据在
 * tests/ci/stuffingProfileContract.test.js。分开是因为失败面不同：这里是「派生错」，
 * 那里是「聚合出口泄漏判据」。
 *
 * 红线（ADR-013 P2 第 1 条）：口令明文绝不落库，哈希也不行。所以判据不能只测「字段对」，
 * 还要反证「输出里没有口令」——正反两半各有用例，缺一半就等于只测了功能没测边界。
 */
const {
  CHARSET_FLAGS,
  CREDENTIAL_SHAPE_FIELDS,
  LENGTH_BOUNDARIES,
  LENGTH_BUCKETS,
  charsetClassOf,
  credentialShapeOf,
  lengthBucketOf,
} = require('../../constants/credentialShape');
const { isBreachedPassword } = require('../../utils/helpers');

describe('口令字典特征派生：三字段的形状与红线', () => {
  test('字段集合是冻结的三元组：增删字段必须回来改判据（反向也钉住）', () => {
    expect(CREDENTIAL_SHAPE_FIELDS).toEqual([
      'credentialStemHits',
      'lengthBucket',
      'charsetClass',
    ]);
    expect(Object.isFrozen(CREDENTIAL_SHAPE_FIELDS)).toBe(true);
    const shape = credentialShapeOf('Passw0rd!x');
    expect(Object.keys(shape).sort()).toEqual([...CREDENTIAL_SHAPE_FIELDS].sort());
  });

  test('长度档：边界逐点取实测，不抄一份期望表', () => {
    const bounds = [...LENGTH_BOUNDARIES];
    const expected = (size) => {
      const at = bounds.findIndex((lower) => size < lower);
      return at === -1 ? LENGTH_BUCKETS[LENGTH_BUCKETS.length - 1] : LENGTH_BUCKETS[at];
    };
    for (let size = 0; size <= 40; size += 1) {
      expect([size, lengthBucketOf('a'.repeat(size))]).toEqual([size, expected(size)]);
    }
    expect(lengthBucketOf('a'.repeat(7))).toBe('lt8'); // 人类可读的锚点：7 在 min 之下
    expect(lengthBucketOf('a'.repeat(8))).toBe('8-11'); // 恰好落到下一档
    expect(lengthBucketOf('a'.repeat(400))).toBe('20plus'); // 超长不越界
  });

  test('字符集类：按固定序输出，符号走补集判据（不在三条区间里就算符号）', () => {
    expect(charsetClassOf('abc')).toBe('l');
    expect(charsetClassOf('abcXYZ')).toBe('lu');
    expect(charsetClassOf('abcXYZ123')).toBe('lud');
    expect(charsetClassOf('Password1!')).toBe('luds');
    expect(charsetClassOf('!!!')).toBe('s');
    expect(charsetClassOf('中文')).toBe('s'); // 非 ASCII 也不静默算成「无字符」
    expect(charsetClassOf('')).toBe('');
    // 序固定：同一组字符的不同书写顺序不得改变分类串（否则聚合面的众数会随输入顺序漂移）
    expect(charsetClassOf('1aZ!')).toBe(charsetClassOf('Za!1'));
    // 反证：把任一标志位改名后分类串必须跟着变——证明这三条不是摆设
    expect(CHARSET_FLAGS.map((item) => item[0])).toEqual(['l', 'u', 'd']);
  });

  test('命中词干表 ⇒ 1，未命中 ⇒ 0；判据与 isBreachedPassword 同源，不另造词表', () => {
    const hit = credentialShapeOf('Password123');
    expect(hit.credentialStemHits).toBe(isBreachedPassword('Password123') ? 1 : 0);
    expect(credentialShapeOf('x7$Kq2mZ!vRt9wLp').credentialStemHits).toBe(0);
  });

  test('红线反证：输出里没有明文、没有哈希、没有长度原值', () => {
    const secret = 'Sup3rSecret!x9';
    const shape = credentialShapeOf(secret);
    const serialized = JSON.stringify(shape);
    expect(serialized).not.toContain(secret);
    for (const piece of [secret.slice(0, 6), secret.slice(3, 9), secret]) {
      expect(serialized).not.toContain(piece);
    }
    // 长度原值也不得出现：lengthBucket 只能是档位词表里的一个
    expect(LENGTH_BUCKETS).toContain(shape.lengthBucket);
    expect(serialized).not.toContain(String(secret.length));
    expect(serialized).not.toMatch(/[0-9a-f]{16,}/i); // 没有十六进制长串 = 没有哈希痕迹
    // 值域封闭：任何取值都必须是 0/1、档位词、或固定序字符集串——不许出现自由文本
    expect([0, 1]).toContain(shape.credentialStemHits);
    expect(shape.charsetClass).toMatch(/^(?=[luds]*$)(?:l?u?d?s?)$/);
  });

  test('空与非字符串输入：返回 null（不产出一个「空口令画像」），且不抛', () => {
    for (const bad of ['', undefined, null, 0, false, {}, []]) {
      expect([bad, credentialShapeOf(bad)]).toEqual([bad, null]);
    }
  });
});
