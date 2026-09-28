/**
 * run-rollback-drill BSON 类型往返回归
 * 纯逻辑，不触发破坏性 IIFE（脚本以 require.main 守卫），不连库。
 */
const mongoose = require('mongoose');
const { toSerializable, fromSerializable } = require('../../scripts/run-rollback-drill');

describe('rollback-drill 快照编解码保留 ObjectId / Date（含嵌套）', () => {
  test('顶层 / 数组 / 子文档里的 ObjectId 与 Date 往返无损', () => {
    const oid = new mongoose.Types.ObjectId('507f1f77bcf86cd799439011');
    const doc = {
      _id: oid,
      timestamp: new Date(0),
      roles: [oid],
      nested: { updatedBy: oid, when: new Date(1234) },
      plain: 'x',
      n: 5,
      isTrue: true,
      nil: null,
    };
    const back = fromSerializable(JSON.parse(JSON.stringify(toSerializable(doc))));

    expect(back._id instanceof mongoose.Types.ObjectId).toBe(true);
    expect(back._id.toString()).toBe(oid.toString());
    expect(back.timestamp instanceof Date).toBe(true);
    expect(back.timestamp.getTime()).toBe(0);
    expect(back.roles[0] instanceof mongoose.Types.ObjectId).toBe(true);
    expect(back.nested.updatedBy instanceof mongoose.Types.ObjectId).toBe(true);
    expect(back.nested.when instanceof Date).toBe(true);
    expect(back.nested.when.getTime()).toBe(1234);
    expect(back.plain).toBe('x');
    expect(back.n).toBe(5);
    expect(back.isTrue).toBe(true);
    expect(back.nil).toBe(null);
  });

  test('反证旧缺陷：裸 JSON.stringify 会把 ObjectId/Date 退化为字符串（正是被修掉的坑）', () => {
    const doc = {
      _id: new mongoose.Types.ObjectId('507f1f77bcf86cd799439011'),
      timestamp: new Date(0),
    };
    const viaPlain = JSON.parse(JSON.stringify(doc));
    expect(typeof viaPlain._id).toBe('string'); // 若无 toSerializable，回灌将写入 String _id
    expect(typeof viaPlain.timestamp).toBe('string');
  });

  test('无 BSON 类型的普通文档原样往返（编解码不误伤标量/嵌套）', () => {
    const doc = {
      _id: 'plain-string-id',
      username: 'alice',
      count: 7,
      active: true,
      nothing: null,
      tags: ['a', 'b'],
      meta: { level: 3, ok: false },
    };
    const round = fromSerializable(JSON.parse(JSON.stringify(toSerializable(doc))));
    expect(round).toEqual(doc);
  });
});
