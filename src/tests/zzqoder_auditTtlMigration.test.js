/**
 * 迁移 20260919000000（TTL 对齐留存声明值）行为测试 + 一条配置不变量
 *
 * 为什么值得单独一条迁移，这里也一并钉住证据：
 *   migrate-mongo 在 useFileHash:false 时**只按文件名**判断"是否已应用"
 *   （node_modules/migrate-mongo/lib/actions/status.js 的匹配条件里 fileHash 缺省即跳过），
 *   所以改动一个已应用过的迁移文件，对存量库永远不会生效。
 *   本测试的最后一条就是把这个前提钉成断言：如果哪天有人把 useFileHash 打开，
 *   存量 changelog 里没有 fileHash 字段 ⇒ 所有历史迁移会被判为 PENDING 并**整体重跑**，
 *   那是一个比原问题严重得多的事故，必须让改配置的人先看到这条红。
 *
 * 隔离说明：另一个迁移测试（src/tests/migrations/reconcileAuditIndexOptions.test.js）
 * 会在共享内存库的 `auditlogs` 集合上删建索引，jest 多 worker 并行时会互相踩。
 * 迁移签名是 up(db)，db 由调用方给，所以这里连**同一个 server 上的另一个 database**，
 * 彻底避免跨文件干扰（也正因为如此，测试里不依赖 mongoose.connection 的全局状态）。
 */

const mongoose = require('mongoose');

const migration = require('../../migrations/20260919000000-reconcile-audit-ttl-to-retention');
const { RETENTION_SECONDS } = require('../constants/retention');

const COLLECTION = 'auditlogs';
const INDEX_NAME = 'timestamp_-1';
// 与既有测试错开的独立库名，避免并行 worker 互相删建索引
const ISOLATED_DB = 'zzqoder_migration_ttl_test';

describe('迁移：auditlogs TTL 对齐留存声明值', () => {
  let conn;
  let db;
  let silenceLog;

  /** 与 constants/retention.js 声明值不同的错误值（模拟"配了别的留存天数却被硬编码盖掉"） */
  const WRONG_SECONDS = RETENTION_SECONDS === 999999 ? 111111 : 999999;

  const getIndex = async () => {
    let list;
    try {
      list = await db.collection(COLLECTION).indexes();
    } catch (err) {
      // 集合压根不存在时驱动是抛错而不是返回 []。`resetIndex('absent')` 只 dropIndexes、
      // 从不建集合，所以本文件的"缺索引"用例是否成立，取决于**前面有没有别的用例先建过集合**
      // ——默认顺序恰好建过，`--randomize` 一打散就红（实测单文件 + seed 31337 即复现）。
      // 与迁移侧同一口径：只认 NamespaceNotFound，其它错误原样抛（宽 catch 会把
      // 真实的连接/权限故障读成"没有索引"，那条用例就成了假绿）。
      if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48)
        return null;
      throw err;
    }
    return list.find((i) => i.name === INDEX_NAME) || null;
  };

  /** 把索引重置成某种漂移形态 */
  const resetIndex = async (options) => {
    await db
      .collection(COLLECTION)
      .dropIndexes()
      .catch(() => {});
    if (options === 'absent') return;
    await db.collection(COLLECTION).createIndex({ timestamp: -1 }, options);
  };

  beforeAll(async () => {
    // 必须 .asPromise()：mongoose 8 的 createConnection() 返回的是"尚未就绪"的连接对象，
    // 直接 await 它不会等打开，conn.db 届时是 undefined（首版就踩了这个坑，
    // 表现为每条用例秒失败 + 收尾 close() 把 jest 挂住）。
    conn = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: ISOLATED_DB,
        // 连不上时快速失败，而不是把整个 run 挂在这里
        serverSelectionTimeoutMS: 5000,
      })
      .asPromise();
    db = conn.db;
    expect(db).toBeDefined();
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    await db
      .collection(COLLECTION)
      .dropIndexes()
      .catch(() => {});
    await conn.close();
  });

  test('★ TTL 已存在但值不对：collMod 原地改为声明值（旧迁移修不到的正是这一档）', async () => {
    await resetIndex({ expireAfterSeconds: WRONG_SECONDS });
    expect((await getIndex()).expireAfterSeconds).toBe(WRONG_SECONDS);

    await migration.up(db);

    const idx = await getIndex();
    expect(idx.expireAfterSeconds).toBe(RETENTION_SECONDS);
    // collMod 是原地改：索引本身不应被重建丢失
    expect(idx.name).toBe(INDEX_NAME);
  });

  test('TTL 完全缺失的库也补齐（与 20260831000000 的判据同向，不构成冲突）', async () => {
    await resetIndex({});
    const before = await getIndex();
    expect(before.expireAfterSeconds).toBeUndefined();

    await migration.up(db);
    expect((await getIndex()).expireAfterSeconds).toBe(RETENTION_SECONDS);
  });

  test('幂等：第二次执行不改选项、不抛错', async () => {
    await resetIndex({ expireAfterSeconds: WRONG_SECONDS });
    await migration.up(db);
    const first = await getIndex();
    await expect(migration.up(db)).resolves.toBeUndefined();
    const second = await getIndex();
    expect(second.expireAfterSeconds).toBe(first.expireAfterSeconds);
    expect(second.expireAfterSeconds).toBe(RETENTION_SECONDS);
  });

  test('索引不存在时不创建（职责不重叠：创建归模型与 20260831000000）', async () => {
    await resetIndex('absent');
    await expect(migration.up(db)).resolves.toBeUndefined();
    expect(await getIndex()).toBeNull();
  });

  test('down 存在且为无害空操作（回滚演练会无条件调用它，缺省会卡住整条链）', async () => {
    await resetIndex({ expireAfterSeconds: WRONG_SECONDS });
    await migration.up(db);
    await expect(migration.down(db)).resolves.toBeUndefined();
    // 回滚后 TTL 必须仍是声明值：把留存改回更短的值是单向有害操作
    expect((await getIndex()).expireAfterSeconds).toBe(RETENTION_SECONDS);
  });
});

describe('留存声明可变：迁移对齐的是声明值，不是写死的 180 天', () => {
  // 的本体就是"迁移里写死 15552000，而模型侧可配 90..3650 天"。
  // 只用默认环境跑，"读常量"和"写死 180"两种实现给出的结果完全一样，测不出区别——
  // 所以必须把 AUDIT_RETENTION_DAYS 改成非默认值再跑一遍，这条才算真证伪。
  let conn365;
  let db365;

  beforeAll(async () => {
    conn365 = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: `${ISOLATED_DB}_365`,
        serverSelectionTimeoutMS: 5000,
      })
      .asPromise();
    db365 = conn365.db;
  });

  afterAll(async () => {
    await db365
      .collection(COLLECTION)
      .dropIndexes()
      .catch(() => {});
    await conn365.close();
  });

  test('AUDIT_RETENTION_DAYS=365 时对齐 31622400s（而不是被改回 180 天）', async () => {
    const prev = process.env.AUDIT_RETENTION_DAYS;
    process.env.AUDIT_RETENTION_DAYS = '365';
    const silence = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      // isolateModules 让迁移与常量都按新 env 重新求值（两者都在模块加载期读 env）
      let migration365;
      let seconds365;
      jest.isolateModules(() => {
        migration365 = require('../../migrations/20260919000000-reconcile-audit-ttl-to-retention');
        seconds365 = require('../constants/retention').RETENTION_SECONDS;
      });
      // 前提自证：env 真的改变了声明值
      expect(seconds365).toBe(365 * 24 * 60 * 60);
      expect(seconds365).not.toBe(RETENTION_SECONDS);

      await db365
        .collection(COLLECTION)
        .dropIndexes()
        .catch(() => {});
      // 模拟"旧版迁移已经把它写成 180 天"的存量库
      await db365
        .collection(COLLECTION)
        .createIndex({ timestamp: -1 }, { expireAfterSeconds: RETENTION_SECONDS });

      await migration365.up(db365);

      const list = await db365.collection(COLLECTION).indexes();
      const idx = list.find((i) => i.name === INDEX_NAME);
      expect(idx.expireAfterSeconds).toBe(seconds365);
    } finally {
      silence.mockRestore();
      if (prev === undefined) delete process.env.AUDIT_RETENTION_DAYS;
      else process.env.AUDIT_RETENTION_DAYS = prev;
    }
  });
});

describe('配置不变量：migrate-mongo 的迁移标识只能是文件名', () => {
  const config = require('../../migrate-mongo-config');

  test('useFileHash 必须为 false，且理由写在这里', () => {
    // true 的语义是"按内容哈希判定是否已应用"。存量 _migrations 文档里没有 fileHash 字段，
    // 一旦打开，所有历史迁移都会被判为 PENDING 并整体重跑一遍。
    // 真要启用哈希，必须先把存量 changelog 补齐 fileHash —— 那是另一个工作量级的事。
    expect(config.useFileHash).toBe(false);
  });

  test('changelog 集合名未被改走（迁移技术文档与回滚演练都按它寻址）', () => {
    expect(config.changelogCollectionName).toBe('_migrations');
    expect(config.migrationsDir).toBe('migrations');
  });
});
