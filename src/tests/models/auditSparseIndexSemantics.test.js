/**
 * `sparse: true` 在 AuditLog 哈希链字段上的真实语义（把"省索引空间"这句注释钉死）
 *
 * schema 对 `prevHash`/`hash` 同时写了 `default: null` 与 `sparse: true`，注释曾声称
 * "旧数据（无 prevHash）不占索引空间 / 存量 legacy 记录（hash=null）不挤占索引"。
 * 后半句错，而且错的方向会诱导一次危险的"优化"：
 *
 *   - 稀疏索引排除的是**根本没有这个键**的文档，**不排除值为 `null`** 的文档；
 *   - 本仓所有审计写入都经 `AuditLog.create` / `insertMany`（缓冲路径见 utils/auditBuffer），
 *     `default: null` 保证这类记录**恒带键** ⇒ 对它们 `sparse` 一个条目都省不掉；
 *   - 真正被排除的只有"字段加入 schema 之前"或绕过 schema 直接写进库的存量记录，
 *     这部分确实存在，所以 `sparse` 不是纯装饰——但它省的是存量、不是 null。
 *
 * 为什么不去掉 `sparse`（那半边"优化"）：同一批 key 的索引选项由**两处**声明——
 * schema（`autoIndex` 建）与 migrations/20260831000000-reconcile-audit-index-options.js
 * （`createIndex({sparse:true})` 重建）。索引选项不能原地变更，两边一旦给出不同选项，
 * 就是在最大的集合上反复 drop+重建或直接 `IndexOptionsConflict`。
 * 所以处置是**保留选项、改正口径**，并且把"两处声明必须一致"本身变成断言：
 *   ① 声明侧：schema 对 `{hash:1}`/`{prevHash:1}` 声明了 sparse（删声明即红）；
 *   ② 迁移侧与声明侧对同一 key 的选项**逐字段一致**（任一侧漂移即红），判据复用
 *      scripts/sync-audit-indexes.js 的 `diffIndexes`——不再自造一套"算不算一致"；
 *   ③ 经 schema 构造的记录一定带 `hash`/`prevHash` 键 ⇒ "null 也入索引"落到真实写入上；
 *   ④ 机械守卫：schema 里 `sparse` 与 `default` 并存的字段集合必须还是已知那两个；
 *   ⑤⑥ 服务端语义实测（探针集合）：`null` 进稀疏索引、缺键才被排除。
 *
 * ①② 刻意**不**读数据库的物理索引：tests/migrations/reconcileAuditIndexOptions.test.js
 * 在同一份共享内存 MongoDB（见 tests/globalSetup.js）上对真表 `auditlogs` 做
 * `dropIndexes()` + 按迁移选项重建，物理索引长什么样取决于 jest 的文件调度顺序。
 * 拿它当判据会得到**假绿**——把 schema 的 sparse 删掉，只要那份迁移先跑过，
 * 物理索引照样带 sparse，用例照绿，而这个改动恰恰是会造成线上选项冲突的那一个。
 * ⑤⑥ 只读自建探针集合（不进 `auditlogs`，避免干扰并发的哈希链套件）。
 */
const mongoose = require('mongoose');

const AuditLog = require('../../models/AuditLog');
const migration = require('../../../migrations/20260831000000-reconcile-audit-index-options');
const { keySignature, fullSignature, diffIndexes } = require('../../../scripts/sync-audit-indexes');
const { RETENTION_SECONDS } = require('../../constants/retention');

const PROBE_COLL = 'zzb_probe_sparse_semantics';

/** schema 声明 → sync-audit-indexes 的"声明侧"形状（与脚本 main 里的构造同式） */
const declaredFromSchema = () =>
  AuditLog.schema.indexes().map(([key, options = {}]) => ({
    key,
    options,
    signature: keySignature(key),
    fullSig: fullSignature(key, options),
  }));

const indexName = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}_${v}`)
    .join('__');

/**
 * 把迁移"会发出哪些 createIndex"录下来，不连库：
 * indexes() 一律返回空 ⇒ 三个分支都走"按模型定义创建"，正是全新库首次 migrate 的形态。
 */
const captureMigrationCreateIndex = async (fn) => {
  const created = [];
  const db = {
    collection: () => ({
      indexes: async () => [],
      createIndex: async (key, options = {}) => {
        created.push({ name: indexName(key), key, ...options });
      },
      dropIndex: async () => {},
    }),
    command: async (cmd) => {
      created.push({
        name: indexName(cmd.index.keyPattern),
        key: cmd.index.keyPattern,
        ...cmd.index,
      });
    },
  };
  // 迁移自带进度 console.log，录制造型时静默（同 tests/migrations 那份套件的处置）
  const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
  try {
    await fn(db);
  } finally {
    spy.mockRestore();
  }
  return created;
};

describe('AuditLog 稀疏索引：声明侧口径（无库、与 jest 调度顺序无关）', () => {
  test('① schema 对哈希链两个 key 声明了 sparse（"删掉声明"就是制造选项冲突）', () => {
    const byKey = new Map(
      AuditLog.schema.indexes().map(([key, options = {}]) => [keySignature(key), options])
    );
    for (const sig of ['hash:1', 'prevHash:1', 'sessionId:1']) {
      expect({ [sig]: byKey.get(sig) }).toEqual({
        [sig]: expect.objectContaining({ sparse: true }),
      });
    }
  });

  test('② 迁移与 schema 对同一 key 的选项逐字段一致（diffIndexes 判据）', async () => {
    const built = await captureMigrationCreateIndex(migration.up);
    // 前提自证：录到的必须就是迁移碰过的那三个索引，否则下面的"零不一致"是空集恒真
    expect(built.map((i) => i.name).sort()).toEqual(
      ['hash_1', 'sessionId_1', 'timestamp_-1'].sort()
    );
    const declared = declaredFromSchema();
    const { needsAction, redundant } = diffIndexes(declared, built);
    // needsAction 只遍历"实际存在"的索引 ⇒ 天然限定在上面这三个 key 上；
    // 任一侧改 sparse / TTL 而不改另一侧，这里立刻红（redundant 同理）。
    expect(
      needsAction.map(
        (n) => `${n.existing.name} 声明=${n.declared.fullSig} 实建=${n.existing.fullSig}`
      )
    ).toEqual([]);
    expect(redundant.map((r) => r.name)).toEqual([]);
    // TTL 也走同一道闸：迁移写死秒数、schema 随 AUDIT_RETENTION_DAYS 变化 ⇒ 这里分叉
    expect(built.find((i) => i.name === 'timestamp_-1').expireAfterSeconds).toBe(RETENTION_SECONDS);
  });

  test('③ 经 schema 写入的记录一定带 hash/prevHash 键 ⇒ "null 也入索引"落在真实数据上', () => {
    const obj = new AuditLog({
      userId: new mongoose.Types.ObjectId(),
      action: 'login',
      path: '/api/auth/login',
      ip: '127.0.0.1',
    }).toObject({ virtuals: false });
    // default: null 会显式把键写出来（不是 undefined 被丢弃）
    expect(Object.prototype.hasOwnProperty.call(obj, 'hash')).toBe(true);
    expect(obj.hash).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(obj, 'prevHash')).toBe(true);
    expect(obj.prevHash).toBeNull();
  });

  test('④ 机械守卫：schema 里 sparse 与 default 并存的字段仍是已知那两个', () => {
    const inert = Object.entries(AuditLog.schema.paths)
      .filter(
        ([, p]) =>
          p.options &&
          p.options.sparse === true &&
          Object.prototype.hasOwnProperty.call(p.options, 'default')
      )
      .map(([name]) => name)
      .sort();
    // 每多一个这样的字段，就多一处"对经 schema 写入的数据 sparse 实际无效"的技术债
    expect(inert).toEqual(['hash', 'prevHash']);
  });
});

describe('AuditLog 稀疏索引：服务端语义实测（自建探针集合，不碰 auditlogs）', () => {
  let probe;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    probe = mongoose.connection.db.collection(PROBE_COLL);
    await probe.createIndex({ hash: 1 }, { sparse: true, name: 'hash_1' });
  }, 30000);

  afterAll(async () => {
    if (probe) await probe.drop();
    await mongoose.disconnect();
  });

  /**
   * 两条实测用例共用一个探针集合，而 CI 用 `jest --randomize` 打乱**文件内**用例顺序
   * （F-112 那一族）：⑥ 往同一 _id 空间插一条"缺键"记录，⑤ 却断言
   * `find({hash:null})` 只返回 [1] —— 谁后跑谁污染前者。实测 seed 31337 恰好 ⑥ 在前
   * ⇒ 绿；20260917 与 777001 下 ⑤ 在前 ⇒ 两条一起红，属 CI 阻断。
   * 处置是"每条用例自带前置数据 + 跑前清空"，而不是给用例编号排序（排序只是把耦合
   * 藏到下一个新增用例身上）。
   */
  beforeEach(async () => {
    await probe.deleteMany({});
  });

  test('⑤ null 值进了稀疏索引：对 schema 写入的记录一条也不省', async () => {
    await probe.insertMany([
      { _id: 1, hash: null },
      { _id: 2, hash: 'a'.repeat(64) },
    ]);
    // 同一个查询：集合扫描与走索引都必须看见那条 hash:null 的记录
    const byScan = await probe.find({ hash: null }).sort({ _id: 1 }).toArray();
    const byIndex = await probe.find({ hash: null }).hint('hash_1').sort({ _id: 1 }).toArray();
    expect(byScan.map((d) => d._id)).toEqual([1]);
    expect(byIndex.map((d) => d._id)).toEqual([1]);
  });

  test('⑥ 只有"根本没有这个键"的文档才被稀疏索引排除', async () => {
    // 缺键形态：MongoDB 的 {hash: null} 语义上匹配"值为 null"与"字段缺失"两种
    // ⑤ 的两条记录在这里也必须自己插一遍：断言 [1, 3] 依赖"集合里有一条 hash:null"，
    // 依赖上一条用例等于没测（本文件 ④ 那条机械守卫说过的"空集恒真"是同一个坑）
    await probe.insertMany([
      { _id: 1, hash: null },
      { _id: 2, hash: 'a'.repeat(64) },
    ]);
    await probe.insertOne({ _id: 3, other: 1 });
    const byScan = await probe.find({ hash: null }).sort({ _id: 1 }).toArray();
    const byIndex = await probe.find({ hash: null }).hint('hash_1').sort({ _id: 1 }).toArray();
    expect(byScan.map((d) => d._id)).toEqual([1, 3]);
    // 走索引时缺键那条不在索引里 ⇒ 这才是 sparse 的实际效果
    expect(byIndex.map((d) => d._id)).toEqual([1]);
  });
});
