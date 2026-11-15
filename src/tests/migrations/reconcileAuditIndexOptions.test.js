/**
 * 迁移 20260831000000-reconcile-audit-index-options 行为测试
 *
 * 覆盖 up/down 全部分支与幂等性：测试库中先人工构造「选项漂移」的
 * 旧索引（与迁移修复前的线上形态一致），再验证迁移逐项收敛到模型定义。
 * RETENTION_SECONDS 与 constants/retention.js 单一声明对账，防止迁移内
 * 字面量与留存策略声明漂移。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20260831000000-reconcile-audit-index-options');
const { RETENTION_SECONDS } = require('../../constants/retention');

const COLLECTION = 'auditlogs';

/**
 * 专用后缀库隔离（照 deploy/rollbackDrillRestoreVerification.test.js 的先例）：
 * 本套件是唯一在共享 worker 库上反复改写 auditlogs 索引形态的迁移套件
 * （beforeEach dropIndexes + 迁移内 collMod/重建），索引形态是本套件自己的夹具，
 * 不该当跨套件共享状态用。改在同一 mongod 的后缀库上执行：先关旧连接再连
 * （worker 复用时 readyState !== 0 会沿用旧连接，改动又会落回共享库），afterAll 丢库回收。
 */
const DB_SUFFIX = '_reconcile_idx_opts';
const isolatedUri = () => {
  const uri = process.env.MONGODB_URI;
  const qIndex = uri.indexOf('?');
  const base = qIndex === -1 ? uri : uri.slice(0, qIndex);
  const query = qIndex === -1 ? '' : uri.slice(qIndex);
  return base + DB_SUFFIX + query;
};

const getIndex = async (name) => {
  const list = await mongoose.connection.db.collection(COLLECTION).indexes();
  return list.find((i) => i.name === name) || null;
};

describe('迁移：auditlogs 索引选项对齐', () => {
  let coll;
  let silenceLog;

  beforeAll(async () => {
    // worker 进程复用：上个套件若留下未关的连接（指向共享库），先关掉再连专用库
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
    await mongoose.connect(isolatedUri());
    coll = mongoose.connection.db.collection(COLLECTION);
    // 迁移内部用 console.log 输出进度，测试期静默避免噪音
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    if (mongoose.connection.readyState !== 0) {
      // 独立库随连接一起丢弃：索引夹具不留在共享 mongod 上
      await mongoose.connection.db.dropDatabase().catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    // 每例重置为「漂移形态」：无 TTL 的 timestamp、无 sparse 的两索引
    await coll.dropIndexes().catch(() => {});
    await coll.createIndex({ timestamp: -1 });
    await coll.createIndex({ sessionId: 1 });
    await coll.createIndex({ hash: 1 });
  });

  describe('up()', () => {
    test('TTL 缺失 → collMod 原地补齐为留存策略声明值', async () => {
      await migration.up(mongoose.connection.db);
      const idx = await getIndex('timestamp_-1');
      expect(idx.expireAfterSeconds).toBe(RETENTION_SECONDS);
      expect(idx.expireAfterSeconds).toBe(15552000); // 180 天，显式锚点防常量被静默改动
    });

    test('sessionId_1 / hash_1 重建为 sparse', async () => {
      await migration.up(mongoose.connection.db);
      expect((await getIndex('sessionId_1')).sparse).toBe(true);
      expect((await getIndex('hash_1')).sparse).toBe(true);
    });

    test('timestamp_-1 不存在时按模型定义直接创建（含 TTL）', async () => {
      await coll.dropIndex('timestamp_-1');
      await migration.up(mongoose.connection.db);
      const idx = await getIndex('timestamp_-1');
      expect(idx).not.toBeNull();
      expect(idx.expireAfterSeconds).toBe(RETENTION_SECONDS);
    });

    test('幂等：二次执行不改变索引选项', async () => {
      await migration.up(mongoose.connection.db);
      await migration.up(mongoose.connection.db);
      expect((await getIndex('timestamp_-1')).expireAfterSeconds).toBe(RETENTION_SECONDS);
      expect((await getIndex('sessionId_1')).sparse).toBe(true);
      expect((await getIndex('hash_1')).sparse).toBe(true);
    });
  });

  describe('down()', () => {
    test('回滚移除 TTL 与 sparse（恢复为普通索引）', async () => {
      await migration.up(mongoose.connection.db);
      await migration.down(mongoose.connection.db);

      const tsIdx = await getIndex('timestamp_-1');
      expect(tsIdx).not.toBeNull(); // 索引本身保留，仅选项回退
      expect(tsIdx.expireAfterSeconds).toBeUndefined();
      expect((await getIndex('sessionId_1')).sparse).toBeUndefined();
      expect((await getIndex('hash_1')).sparse).toBeUndefined();
    });

    test('幂等：对已是普通索引的库无副作用', async () => {
      await migration.down(mongoose.connection.db);
      expect((await getIndex('timestamp_-1')).expireAfterSeconds).toBeUndefined();
      expect((await getIndex('sessionId_1')).sparse).toBeUndefined();
      expect((await getIndex('hash_1')).sparse).toBeUndefined();
    });
  });

  test('up → down → up 回路收敛结果一致（演练 #1 实证路径）', async () => {
    await migration.up(mongoose.connection.db);
    await migration.down(mongoose.connection.db);
    await migration.up(mongoose.connection.db);

    expect((await getIndex('timestamp_-1')).expireAfterSeconds).toBe(RETENTION_SECONDS);
    expect((await getIndex('sessionId_1')).sparse).toBe(true);
    expect((await getIndex('hash_1')).sparse).toBe(true);
  });
});
