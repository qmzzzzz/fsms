/**
 * 迁移 20261103000000-device-reminder-tiebreak-index 与模型声明的对账（E5）
 *
 * 形态照 src/tests/migrations/filterTiebreakCompoundIndexes.test.js，本迁移只有一条目标：
 * ① 两键目标 `{expiryDate:1,_id:1}` 在 FireDevice schema 里（提醒扫描 expired/expiringSoon
 *    两档的排序键，到期日大量同值 ⇒ 单键等值块内阻塞排序）；
 * ② 被替换的旧单键 `{expiryDate:1}` 不在声明里（autoIndex 只建不删 ⇒ 迁移是唯一回收路径）；
 * ③ 迁移里硬编码的索引名 === mongod 自动生成名（按名判存在，名字算错会建成 typo 名或抛 85）；
 * ④ 真库行为：全新库 up() 建新删旧 / 漂移收敛幂等 / down() 回到旧形态。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20261103000000-device-reminder-tiebreak-index');
const FireDevice = require('../../models/FireDevice');

const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

/** mongod 的自动命名规则：逐字段 `名_方向` 再用 `_` 连接（_id 因此写成 `__id_1`） */
const mongodName = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}_${v}`)
    .join('_');

const declaredSigs = (model) => model.schema.indexes().map(([key]) => keySig(key));

describe('设备提醒到期档平局键复合索引：迁移与声明对账', () => {
  let silenceLog;
  let isolated;

  beforeAll(async () => {
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: `zDevRemIdx${Date.now().toString(36)}p${process.pid}`,
      })
      .asPromise();
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    if (isolated && isolated.readyState !== 0) {
      await isolated.db.dropDatabase().catch(() => {});
      await isolated.close();
    }
  });

  describe('声明侧（无库）', () => {
    test('① 目标两键索引在 schema 声明里，末字段是同向平局键 _id:1', () => {
      expect(migration.REPLACE).toHaveLength(1);
      for (const { coll, key } of migration.REPLACE) {
        expect(coll).toBe(FireDevice.collection.name);
        expect(declaredSigs(FireDevice)).toContain(keySig(key));
        expect(Object.keys(key).pop()).toBe('_id');
        expect(key._id).toBe(1);
      }
    });

    test('② 被替换的旧单键形态不在声明里（留着就是双份写放大）', () => {
      for (const { oldKey } of migration.REPLACE) {
        expect(declaredSigs(FireDevice)).not.toContain(keySig(oldKey));
      }
    });

    test('③ 硬编码索引名 === mongod 自动名（新旧两条都核）', () => {
      for (const { name, key, oldName, oldKey } of migration.REPLACE) {
        expect(name).toBe(mongodName(key));
        expect(oldName).toBe(mongodName(oldKey));
      }
    });
  });

  describe('真库行为（独立库，不当跨套件共享状态）', () => {
    test('④ 全新库 up() 建新删旧；重复 up() 幂等；down() 回到旧形态且可再 up() 收敛', async () => {
      const coll = migration.REPLACE[0].coll;
      // 先把"存量现场"造出来：旧单键索引在场（等同升级前的库）
      await isolated.db.collection(coll).createIndex(migration.REPLACE[0].oldKey, {
        name: migration.REPLACE[0].oldName,
      });

      await migration.up(isolated.db);
      let indexes = await isolated.db.collection(coll).indexes();
      expect(indexes.some((i) => i.name === migration.REPLACE[0].name)).toBe(true);
      expect(indexes.some((i) => i.name === migration.REPLACE[0].oldName)).toBe(false);

      await migration.up(isolated.db); // 幂等：重复执行不再抛、形态不漂
      indexes = await isolated.db.collection(coll).indexes();
      expect(indexes.filter((i) => i.name === migration.REPLACE[0].name)).toHaveLength(1);

      await migration.down(isolated.db);
      indexes = await isolated.db.collection(coll).indexes();
      expect(indexes.some((i) => i.name === migration.REPLACE[0].oldName)).toBe(true);
      expect(indexes.some((i) => i.name === migration.REPLACE[0].name)).toBe(false);

      await migration.up(isolated.db); // 回滚后再升级仍收敛
      indexes = await isolated.db.collection(coll).indexes();
      expect(indexes.some((i) => i.name === migration.REPLACE[0].name)).toBe(true);
      expect(indexes.some((i) => i.name === migration.REPLACE[0].oldName)).toBe(false);
    });
  });
});
