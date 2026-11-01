/**
 * U2 回归：username 的类型必须在**参数校验阶段**收敛
 *
 * 原实现把「同名字段重复两次（qs 解析成数组）」与「方括号操作符（解析成对象）」
 * 原样拼进 { $gte: who, $lt: who + '\uFFFF' }，直到 mongoose cast 才抛
 * CastError ⇒ 参数写错变成 500。判据是「在 buildAuditQuery 里就抛带 status=400 的
 * 业务错误」，并显式反向对照：正常字符串照常通过、条件形状不变。
 */

'use strict';

const { buildAuditQuery } = require('../../utils/auditQuery');

const catchOf = (query) => {
  try {
    buildAuditQuery({ query });
    return null;
  } catch (e) {
    return e;
  }
};

describe('U2 username 非字符串必须当场 400（不是留给 mongoose 的 CastError）', () => {
  test('数组形态（同名字段重复）', () => {
    const err = catchOf({ username: ['a', 'b'] });
    expect(err).toBeDefined();
    expect(err.name).not.toBe('CastError');
    expect(err.status).toBe(400);
    expect(err.message).toContain('username');
  });

  test('对象形态（方括号操作符）', () => {
    const err = catchOf({ username: { $ne: 'x' } });
    expect(err).toBeDefined();
    expect(err.name).not.toBe('CastError');
    expect(err.status).toBe(400);
    expect(err.message).toContain('username');
  });

  test('数字/布尔形态同样拒（不是只有数组对象两种）', () => {
    expect(catchOf({ username: 123 }).status).toBe(400);
    expect(catchOf({ username: true }).status).toBe(400);
  });

  test('正向对照：正常字符串照常通过，前缀区间形状不变', () => {
    const built = buildAuditQuery({ query: { username: 'ad' } });
    expect(built.query.username).toEqual({ $gte: 'ad', $lt: 'ad\uFFFF' });
    expect(built.usernamePrefix).toBe(true);
  });

  test('正向对照：未传 username 时不得凭空多出条件', () => {
    const built = buildAuditQuery({ query: {} });
    expect(built.query.username).toBeUndefined();
    expect(built.usernamePrefix).toBe(false);
  });
});
