/**
 * 审计索引对账判据的回归
 *
 * 为什么单独测这几个纯函数：`sync-audit-indexes.js` 的判据此前只能在**真实 Mongo** 上跑
 * 才能观察（脚本一被 require 就连库），所以"key 相同但 TTL 不同算不算一致"这种
 * 真正决定会不会误删 TTL 索引的口径，没有任何测试钉住。
 * 现已把差集逻辑抽成 `diffIndexes` 并加了 require.main 守卫，可在无库条件下断言。
 *
 * 判据错一次的代价是不对称的：把"选项不一致"误判成"一致" ⇒ TTL 静默漂移（审计留存天数失真）；
 * 把"一致"误判成"不一致" ⇒ 运维白跑一趟；把 needsAction 误判成 redundant ⇒ **dropIndex 删掉在用索引**。
 */

const mongoose = require('mongoose');
const {
  keySignature,
  fullSignature,
  diffIndexes,
  verdictLine,
  OPTION_KEYS,
  describeFatalError,
} = require('../../scripts/sync-audit-indexes');

/** 造一条"模型声明"，形状与脚本内部一致 */
const decl = (key, options = {}) => ({
  signature: keySignature(key),
  fullSig: fullSignature(key, options),
  key,
  options,
});
/** 造一条"数据库实际索引"（Mongo 的索引描述把选项平铺在顶层） */
const idx = (name, key, extra = {}) => ({ name, key, ...extra });

describe('sync-audit-indexes 的差集判据', () => {
  test('前提自证：require 脚本不得触发连库', () => {
    expect(mongoose.connection.readyState).toBe(0);
    expect(typeof diffIndexes).toBe('function');
    // 参与比对的选项集合本身就是口径，必须显式列出（新增选项要在此登记才会被看见）
    expect(OPTION_KEYS).toEqual(
      expect.arrayContaining(['expireAfterSeconds', 'sparse', 'partialFilterExpression', 'unique'])
    );
  });

  test('模型与库完全一致 ⇒ 三个桶都为空，汇总串与演练验收栏同序', () => {
    const declared = [decl({ timestamp: -1 }, { expireAfterSeconds: 15552000 })];
    const existing = [
      idx('_id_', { _id: 1 }),
      idx('timestamp_-1', { timestamp: -1 }, { expireAfterSeconds: 15552000 }),
    ];
    const d = diffIndexes(declared, existing);
    expect([d.redundant.length, d.missing.length, d.needsAction.length]).toEqual([0, 0, 0]);
    // deployment/rollback-drill-record.md 的验收栏就是按这个顺序写的，不能换序
    expect(verdictLine(d)).toBe('冗余 0 / 缺失 0 / 选项不一致 0');
  });

  test('_id_ 索引永不判冗余（脚本的硬约束）', () => {
    const d = diffIndexes([decl({ category: 1 })], [idx('_id_', { _id: 1 })]);
    expect(d.redundant.map((r) => r.name)).toEqual([]);
  });

  test('未声明的索引 ⇒ 判冗余（这才是 --apply 会删的对象）', () => {
    const d = diffIndexes(
      [decl({ category: 1 })],
      [idx('_id_', { _id: 1 }), idx('legacy_cat', { category: 1, userId: -1 })]
    );
    expect(d.redundant.map((r) => r.name)).toEqual(['legacy_cat']);
    expect(d.needsAction).toEqual([]);
  });

  test('声明了但库里没有 ⇒ 判缺失', () => {
    const d = diffIndexes(
      [decl({ category: 1 }), decl({ 'body.entityId': 1, timestamp: -1 })],
      [idx('_id_', { _id: 1 }), idx('category_1', { category: 1 })]
    );
    expect(d.missing.map((m) => m.signature)).toEqual(['body.entityId:1|timestamp:-1']);
  });

  test('同 key 不同 TTL ⇒ 判"选项不一致"，既不算一致也不能被当成冗余删掉', () => {
    const declared = [decl({ timestamp: -1 }, { expireAfterSeconds: 15552000 })];
    const existing = [
      idx('_id_', { _id: 1 }),
      idx('timestamp_-1', { timestamp: -1 }, { expireAfterSeconds: 86400 }),
    ];
    const d = diffIndexes(declared, existing);
    expect(d.needsAction.length).toBe(1);
    expect(d.needsAction[0].existing.fullSig).toContain('86400');
    expect(d.needsAction[0].declared.fullSig).toContain('15552000');
    // 关键：不能同时出现在 redundant/missing 里——那会让 --apply 去 drop 一个在用索引
    expect(d.redundant).toEqual([]);
    expect(d.missing).toEqual([]);
  });

  test('索引名不同但 key+关键选项相同 ⇒ 视为一致（不能按名字去删重建）', () => {
    const declared = [decl({ category: 1, timestamp: -1 })];
    const existing = [idx('运维手起的名字', { category: 1, timestamp: -1 })];
    expect(verdictLine(diffIndexes(declared, existing))).toBe('冗余 0 / 缺失 0 / 选项不一致 0');
  });

  test('OPTION_KEYS 之外的选项不参与比对（刻意口径，防止把 TTL 索引误判成漂移）', () => {
    const declared = [decl({ category: 1 }, { background: false })];
    const existing = [idx('category_1', { category: 1 }, { background: true })];
    expect(verdictLine(diffIndexes(declared, existing))).toBe('冗余 0 / 缺失 0 / 选项不一致 0');
    // 而参与比对的选项里，哪怕只是稀疏性不同，也必须被抓出来
    const existing2 = [idx('category_1', { category: 1 }, { sparse: true })];
    expect(diffIndexes(declared, existing2).needsAction.length).toBe(1);
  });

  test('partialFilterExpression 不同 ⇒ 判不一致（本仓 用它是为了排除 legacy 行）', () => {
    const declared = [
      decl({ hash: 1 }, { partialFilterExpression: { hash: { $type: 'string' } } }),
    ];
    const existing = [
      idx('hash_1', { hash: 1 }, { partialFilterExpression: { hash: { $exists: true } } }),
    ];
    expect(diffIndexes(declared, existing).needsAction.length).toBe(1);
    const same = [
      idx('hash_1', { hash: 1 }, { partialFilterExpression: { hash: { $type: 'string' } } }),
    ];
    expect(verdictLine(diffIndexes(declared, same))).toBe('冗余 0 / 缺失 0 / 选项不一致 0');
  });

  test('空声明 + 只有 _id_ ⇒ 完全对齐（防"空集恒绿"式假通过：桶长度必须真为 0）', () => {
    const d = diffIndexes([], [idx('_id_', { _id: 1 })]);
    expect(verdictLine(d)).toBe('冗余 0 / 缺失 0 / 选项不一致 0');
    // 同一条数据若无 _id_ 豁免，就会判冗余——这条断言证明豁免分支真的在起作用
    const d2 = diffIndexes([], [idx('other', { _id: 1 })]);
    expect(d2.redundant.length).toBe(1);
  });
});

describe('sync-audit-indexes 的致命错误分类（连错库 ≠ 同步不彻底）', () => {
  const NS_FORMS = [
    ['driver code 26', { code: 26, message: 'ns not found' }],
    ['只有 codeName', { codeName: 'NamespaceNotFound', message: 'x' }],
    ['只有 code（数字）', { code: 26 }],
    ['只有文案', Object.assign(new Error('Cannot query system.indexes: ns not found'), {})],
    ['文案是 NamespaceNotFound 拼写', new Error('NamespaceNotFound on auditlogs')],
  ];

  test.each(NS_FORMS)('%s ⇒ 归入"命名空间缺失"，退出码 2 且说明可操作', (_label, err) => {
    const r = describeFatalError(err);
    expect(r.exitCode).toBe(2);
    expect(r.message).toMatch(/命名空间不存在|未做任何索引变更/);
    expect(r.message).toMatch(/MONGODB_URI/);
  });

  const GENERIC_FORMS = [
    ['重复键 11000（不得被误判）', { code: 11000, message: 'duplicate key' }],
    ['认证失败', Object.assign(new Error('Authentication failed'), { code: 18 })],
    ['权限不足', Object.assign(new Error('not authorized'), { code: 13 })],
    ['网络中断（无 code）', new Error('connection closed')],
  ];

  test.each(GENERIC_FORMS)('%s ⇒ 走通用分支，退出码 1', (_label, err) => {
    const r = describeFatalError(err);
    expect(r.exitCode).toBe(1);
    expect(r.message).toMatch(/^执行失败：/);
  });

  test('两种结局的退出码必须不同（防"一律 1"或"一律 2"把 CI 的重试语义抹平）', () => {
    const ns = describeFatalError({ code: 26 }).exitCode;
    const other = describeFatalError({ code: 11000 }).exitCode;
    expect(ns).not.toBe(other);
    expect([ns, other]).toEqual([2, 1]);
  });

  test('异常本身形状恶劣时也不许抛（分类器再错一次就是把 exit 1 变成 exit undefined）', () => {
    for (const bad of [undefined, null, '', 0, {}, { message: undefined }]) {
      const r = describeFatalError(bad);
      expect(typeof r.message).toBe('string');
      expect(r.message.length).toBeGreaterThan(0);
      expect([1, 2]).toContain(r.exitCode);
    }
  });
});
