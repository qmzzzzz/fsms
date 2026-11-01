/**
 * 迁移 20261021000000-query-performance-indexes 与模型声明的对账
 *
 * 为什么要有本套件：这条迁移此前**没有任何对账用例**（2026-10-31 实测：
 * `git grep 20261021000000 -- src/tests` 与 `git grep nextCheckDate_1|assignedTo_1|status_1`
 * 在 src/tests 下均为空），而它是 firedevices/inspections/firealarms 三条复合索引的
 * **唯一**补齐路径（`scripts/sync-audit-indexes.js` 只对账 auditlogs），也是
 * `usersessions.status_1` 冗余索引的唯一回收路径（autoIndex 从不删存量）。
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 迁移碰的集合名必须就是模型的物理集合名 —— 集合名在迁移里是硬编码字符串
 *    （migrate-mongo 上下文不 require 模型），模型改 collection: 就没人报警；
 * ② 迁移建的复合索引 key 必须与 schema 声明逐字段一致 —— 只声明不迁迁移，
 *    存量库永远缺索引（autoIndex 只在新库生效）；
 * ③ 索引名必须与 mongod 自动生成名一致 —— 迁移按名字判存在，名字算错会走到
 *    createIndex：目标名已被同 key 占用时抛 **85 IndexOptionsConflict**
 *    （86 IndexKeySpecsConflict 是「同名不同 key」，mongod 8.0.34 实测）；
 * ④ 真库行为：全新库 up() 不抛 / 漂移形态 up() 收敛且幂等 / down() 回到旧形态。
 *
 * ⑦⑧ 是 2026-10-31 审计新增的两条**形态漂移**用例，形状与 20260928000000（同族）一致：
 *  「名字在就跳过」是本族迁移的共同缺陷 —— 名字对、key 错时被放过（07），
 *  key 对、名字不同时 createIndex 撞 85 让整条 migrate 中断（08）。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20261021000000-query-performance-indexes');

const FireDevice = require('../../models/FireDevice');
const Inspection = require('../../models/Inspection');
const FireAlarm = require('../../models/FireAlarm');
const UserSession = require('../../models/UserSession');

/** 模型侧只从这里取集合名，不抄迁移里的字面量 */
const MODEL_OF = {
  firedevices: FireDevice,
  inspections: Inspection,
  firealarms: FireAlarm,
  usersessions: UserSession,
};

const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => k + ':' + v)
    .join('|');

/** mongod 的自动命名规则：逐字段 名_方向 再用 _ 连接（_id 因此写成 __id_-1） */
const mongodName = (key) =>
  Object.entries(key)
    .map(([k, v]) => k + '_' + v)
    .join('_');

const declaredSigs = (model) => model.schema.indexes().map(([key]) => keySig(key));
const NEW_TARGETS = [...migration.CREATE_ONLY, ...migration.REPLACE_SINGLE];

describe('列表/统计复合索引：迁移与声明对账', () => {
  let silenceLog;
  let isolated;

  beforeAll(async () => {
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    // 执行侧都打在独立库上：up()/down() 会 dropIndex + createIndex，索引形态是这套件自己的
    // 夹具，不该当跨套件共享状态用（同 cursorTiebreakIndexes.test.js 的处置与理由）
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: 'zQueryPerf' + Date.now().toString(36) + 'p' + process.pid,
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

  describe('声明侧（无库，与 jest 调度顺序无关）', () => {
    test('① 新增/替换目标的 key 都在 schema 声明里，旧单字段形态与 status_1 都不在', () => {
      for (const { coll, key } of NEW_TARGETS) {
        expect(declaredSigs(MODEL_OF[coll])).toContain(keySig(key));
      }
      // 被替换的旧单字段：留着就是双份写放大，schema 不该再声明它
      for (const { coll, oldKey } of migration.REPLACE_SINGLE) {
        expect(declaredSigs(MODEL_OF[coll])).not.toContain(keySig(oldKey));
      }
      // usersessions.status_1：全仓 status 查询都同时带 userId/sid，单字段索引恒非最优
      expect(migration.DROP_ONLY.map((d) => d.coll + '.' + d.name)).toContain(
        'usersessions.status_1'
      );
      expect(declaredSigs(UserSession)).not.toContain('status:1');
    });

    test('② 迁移里硬编码的名字/集合名与模型同源（名字算错会撞 85 或静默建 typo 名）', () => {
      for (const entry of NEW_TARGETS) {
        expect(entry.name).toBe(mongodName(entry.key));
        expect(MODEL_OF[entry.coll]).toBeDefined();
      }
      for (const entry of migration.REPLACE_SINGLE) {
        expect(entry.oldName).toBe(mongodName(entry.oldKey));
      }
      // 集合名写死在迁移里，这一格就是那条缝
      expect(Object.keys(MODEL_OF).sort()).toEqual(
        Object.keys(MODEL_OF)
          .map((c) => MODEL_OF[c].collection.name)
          .sort()
      );
      expect(new Set(NEW_TARGETS.map((t) => t.coll)).size).toBeGreaterThan(1);
    });
  });

  describe('执行侧（真库：mongod 自己给索引命名）', () => {
    test('③ 全新库（集合还不存在）跑 up() 不得抛', async () => {
      const fresh = await mongoose
        .createConnection(process.env.MONGODB_URI, {
          dbName: 'zQueryPerfFresh' + Date.now().toString(36),
        })
        .asPromise();
      try {
        // 未捕获的 NamespaceNotFound 会让整条 `migrate-mongo up` 停在半途
        await expect(migration.up(fresh.db)).resolves.toBeUndefined();
      } finally {
        await fresh.db.dropDatabase().catch(() => {});
        await fresh.close();
      }
    });

    /** 造出「迁移之前」的库形态（旧单字段索引 + usersessions.status_1）再跑 up() 收敛 */
    const seedLegacyAndUp = async (db) => {
      const byColl = {};
      for (const e of migration.REPLACE_SINGLE) {
        byColl[e.coll] = byColl[e.coll] || [];
        byColl[e.coll].push(e);
      }
      for (const [coll, entries] of Object.entries(byColl)) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        for (const e of entries) await c.createIndex(e.oldKey, { name: e.oldName });
      }
      for (const d of migration.DROP_ONLY) {
        const c = db.collection(d.coll);
        await c.dropIndexes().catch(() => {});
        await c.createIndex(d.oldKey, { name: d.name });
      }
      for (const t of migration.CREATE_ONLY) {
        await db
          .collection(t.coll)
          .dropIndexes()
          .catch(() => {});
      }
      await migration.up(db);
    };

    test('④ 从漂移形态出发 up() 收敛到声明且幂等（旧索引与 status_1 已回收）', async () => {
      const db = isolated.db;
      await seedLegacyAndUp(db);
      // 幂等：跑第二遍不得因为「名字算错 ⇒ 再建一次同 key 异名」而抛 85
      await expect(migration.up(db)).resolves.toBeUndefined();

      for (const { coll, key, name } of NEW_TARGETS) {
        const list = await db.collection(coll).indexes();
        const fresh = list.find((i) => keySig(i.key) === keySig(key));
        expect(fresh).toBeTruthy();
        expect(fresh.name).toBe(name);
      }
      for (const { coll, oldKey, oldName } of migration.REPLACE_SINGLE) {
        const list = await db.collection(coll).indexes();
        expect(list.find((i) => keySig(i.key) === keySig(oldKey))).toBeFalsy();
        expect(list.find((i) => i.name === oldName)).toBeFalsy();
      }
      for (const d of migration.DROP_ONLY) {
        expect((await db.collection(d.coll).indexes()).find((i) => i.name === d.name)).toBeFalsy();
      }
    });

    test('⑤ down() 回到旧形态：删新索引、把旧单字段与 status_1 建回，且幂等', async () => {
      const db = isolated.db;
      await seedLegacyAndUp(db);
      // 前提自证：down() 要撤销的新索引必须真的在
      for (const { coll, key } of NEW_TARGETS) {
        expect(
          (await db.collection(coll).indexes()).find((i) => keySig(i.key) === keySig(key))
        ).toBeTruthy();
      }
      await migration.down(db);
      await expect(migration.down(db)).resolves.toBeUndefined();

      for (const { coll, key } of NEW_TARGETS) {
        expect(
          (await db.collection(coll).indexes()).find((i) => keySig(i.key) === keySig(key))
        ).toBeFalsy();
      }
      for (const { coll, oldKey, oldName } of migration.REPLACE_SINGLE) {
        const list = await db.collection(coll).indexes();
        const old = list.find((i) => keySig(i.key) === keySig(oldKey));
        expect(old).toBeTruthy();
        expect(old.name).toBe(oldName);
      }
      for (const d of migration.DROP_ONLY) {
        const list = await db.collection(d.coll).indexes();
        const back = list.find((i) => i.name === d.name);
        expect(back).toBeTruthy();
        expect(keySig(back.key)).toBe(keySig(d.oldKey));
      }
    });

    test('⑦ 同名但 key 漂移（反序）⇒ up() 必须纠正到声明的 key', async () => {
      const db = isolated.db;
      for (const { coll, name, key, oldName, oldKey } of migration.REPLACE_SINGLE) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        // 名字对、key 错（反序）：只按名字判存在会把它当已对齐放过，
        // 而 REPLACE_SINGLE 还会把旧单字段删掉 ⇒ 结果既没有对的索引，也没了旧索引
        await c.createIndex(Object.fromEntries(Object.entries(key).reverse()), { name });
        if (oldName) await c.createIndex(oldKey, { name: oldName });
      }
      for (const { coll, name, key } of migration.CREATE_ONLY) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        await c.createIndex(Object.fromEntries(Object.entries(key).reverse()), { name });
      }
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of NEW_TARGETS) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(keySig(named.key)).toBe(keySig(key));
      }
    });

    test('⑧ 同 key 不同名（85 形态）⇒ up() 不抛且收敛到声明名一条', async () => {
      const db = isolated.db;
      for (const { coll, name, key } of NEW_TARGETS) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        // 声明的 key 已被别的名字占着：迁移再 createIndex(声明名) 必撞
        // 85 IndexOptionsConflict（mongod 8.0.34 实测：'Index already exists with a different name'）
        await c.createIndex(key, { name: 'legacy_' + name });
      }
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of NEW_TARGETS) {
        const list = await db.collection(coll).indexes();
        const declared = list.filter((i) => keySig(i.key) === keySig(key));
        expect(declared).toHaveLength(1);
        expect(declared[0].name).toBe(name);
        expect(list.find((i) => i.name === 'legacy_' + name)).toBeFalsy();
      }
    });
    test('⑨ 同名且 key 对，但整 spec 漂移（unique:true）⇒ up() 必须重建', async () => {
      const db = isolated.db;
      for (const { coll, name, key } of NEW_TARGETS) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        await c.createIndex(key, { name, unique: true });
      }
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of NEW_TARGETS) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(keySig(named.key)).toBe(keySig(key));
        expect(named.unique).toBeFalsy();
      }
    });

    test('⑩ 同名且 key 对，但 collation 漂移（caseLevel）⇒ up() 必须重建', async () => {
      const db = isolated.db;
      for (const { coll, name, key } of NEW_TARGETS) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        await c.createIndex(key, {
          name,
          collation: { locale: 'en', strength: 2, caseLevel: true },
        });
      }
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name } of NEW_TARGETS) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(named.collation).toBeUndefined();
      }
    });

    test('⑪ 异名 twin 带语义差异（unique:true）⇒ up() 不得删它', async () => {
      const db = isolated.db;
      // 每个集合只清一次：firedevices / inspections 各有两个目标，逐条清会把前一条的 twin 抹掉
      for (const coll of new Set(NEW_TARGETS.map((t) => t.coll))) {
        await db
          .collection(coll)
          .dropIndexes()
          .catch(() => {});
      }
      for (const { coll, name, key } of NEW_TARGETS) {
        await db.collection(coll).createIndex(key, { name: 'legacy_' + name, unique: true });
      }
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name } of NEW_TARGETS) {
        const list = await db.collection(coll).indexes();
        const twin = list.find((i) => i.name === 'legacy_' + name);
        expect(twin).toBeTruthy();
        expect(twin.unique).toBe(true);
        expect(list.find((i) => i.name === name)).toBeTruthy();
      }
    });
  });
});
