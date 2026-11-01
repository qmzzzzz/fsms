/**
 * 迁移 20261101000000-filter-tiebreak-compound-indexes 与模型声明的对账（D6）
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 六条「等值筛选 + 时间倒序」声明必须都在 schema 里且**带 `_id:-1`** —— 缺它时等值块内
 *    仍要阻塞排序（大集合撞内存排序上限；mongod 8.0.34 实测
 *    `internalQueryMaxBlockingSortMemoryUsageBytes=104857600`，即 100 MiB）。跨页漏/重只在
 *    排序**不带** `_id` 时发生；现行调用点都带 `_id:-1`，阻塞排序会把平局排正，不会漂移。
 * ② 被替换的旧二键形态必须**不在** schema 里 —— 留着就是双份写放大。`scripts/sync-audit-indexes.js`
 *    **只对账 auditlogs**，firealarms/inspections 没有任何对账器会报/删它 ⇒ 迁移是唯一回收路径；
 * ③ 迁移里硬编码的索引名必须等于 mongod 的自动生成名 —— 迁移按名字判存在，名字算错会走到
 *    createIndex：目标名已被同 key 占用时抛 **85 IndexOptionsConflict**（86 IndexKeySpecsConflict
 *    是"同名不同 key"）；目标名尚不存在时会**静默建成 typo 名**，防拼错靠 ④ 的字面量对比；
 * ④ 真库行为：全新库 up() 不抛 / 漂移形态 up() 收敛且幂等 / down() 回到旧形态。
 *
 * 原范式是 20261021000000 建的 `level_1_occurredAt_-1__id_-1`（第一条就有 `_id:-1`），
 * 本迁移把其余五条与 inspections 的 status 一条补齐到同一形状。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20261101000000-filter-tiebreak-compound-indexes');

const FireAlarm = require('../../models/FireAlarm');
const Inspection = require('../../models/Inspection');

/** 模型侧只从这里取集合名，不抄迁移里的字面量 */
const MODEL_OF = { firealarms: FireAlarm, inspections: Inspection };

const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

/** mongod 的自动命名规则：逐字段 `名_方向` 再用 `_` 连接（_id 因此写成 `__id_-1`） */
const mongodName = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}_${v}`)
    .join('_');

const declaredSigs = (model) => model.schema.indexes().map(([key]) => keySig(key));

describe('列表筛选平局键复合索引：迁移与声明对账', () => {
  let silenceLog;
  let isolated;

  beforeAll(async () => {
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    // 执行侧都打在独立库上：up()/down() 会 dropIndex + createIndex，索引形态是这套件自己的夹具，
    // 不该当跨套件共享状态用（同 cursorTiebreakIndexes.test.js 的处置与理由）
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: `zFilterIdx${Date.now().toString(36)}p${process.pid}`,
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
    test('① 六条目标索引都在 schema 声明里，且末字段是同向平局键 _id:-1', () => {
      expect(migration.REPLACE).toHaveLength(6);
      for (const { coll, key } of migration.REPLACE) {
        const sigs = declaredSigs(MODEL_OF[coll]);
        expect(sigs).toContain(keySig(key));
        // 末字段必须是同向平局键：不是 _id:-1 就等于没补（等值块内仍阻塞排序）
        expect(Object.keys(key).pop()).toBe('_id');
        expect(key._id).toBe(-1);
      }
    });

    test('② 被替换的旧二键形态不在声明里（留着就是双份写放大）', () => {
      for (const { coll, oldKey } of migration.REPLACE) {
        expect(declaredSigs(MODEL_OF[coll])).not.toContain(keySig(oldKey));
      }
    });

    test('③ 范式对照：level 那条早就带 _id:-1，且 firealarms 不再有任何二键时间序筛选索引', () => {
      const sigs = declaredSigs(FireAlarm);
      expect(sigs).toContain('level:1|occurredAt:-1|_id:-1');
      // 只按时间倒序的查询形状由 {occurredAt:-1,_id:-1} 承担；任何 <field>:1|occurredAt:-1
      // 二键形态都意味着某条筛选路径仍需块内阻塞排序
      const twoKey = sigs.filter((s) => /^[^|]+:1\|occurredAt:-1$/.test(s));
      expect(twoKey).toEqual([]);
    });

    test('④ 迁移里硬编码的名字/集合名与模型同源（名字算错会在 createIndex 上撞同名不同 key）', () => {
      for (const entry of migration.REPLACE) {
        expect(entry.name).toBe(mongodName(entry.key));
        expect(entry.oldName).toBe(mongodName(entry.oldKey));
        expect(MODEL_OF[entry.coll]).toBeDefined();
      }
      expect(new Set(migration.REPLACE.map((e) => e.coll))).toEqual(
        new Set(['firealarms', 'inspections'])
      );
      // 集合名写死在迁移里，这一格就是那条缝：模型改 collection: 必须让本用例红
      expect(Object.keys(MODEL_OF).sort()).toEqual(['firealarms', 'inspections']);
    });
  });

  describe('执行侧（真库：mongod 自己给索引命名）', () => {
    test('⑤ 全新库（集合还不存在）跑 up() 不得抛', async () => {
      const fresh = await mongoose
        .createConnection(process.env.MONGODB_URI, {
          dbName: `zFilterFresh${Date.now().toString(36)}`,
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

    /** 造出漂移形态（只有旧二键索引）再跑 up() 收敛——⑥ 与 ⑦ 共用的前置，各自调用且自证前提 */
    const seedDriftAndUp = async (db) => {
      for (const { coll, oldKey, oldName } of migration.REPLACE) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        await c.createIndex(oldKey, { name: oldName });
      }
      await migration.up(db);
    };

    test('⑥ 从漂移形态出发 up() 收敛到声明且幂等（新索引名 == mongod 自动名，旧索引已回收）', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 幂等：跑第二遍不得因为"名字算错 ⇒ 再建一次同 key 异名"而抛 85 IndexOptionsConflict
      await expect(migration.up(db)).resolves.toBeUndefined();

      for (const { coll, key, oldKey } of migration.REPLACE) {
        const list = await db.collection(coll).indexes();
        const fresh = list.find((i) => keySig(i.key) === keySig(key));
        expect(fresh).toBeTruthy();
        // ③ 的本体：迁移按这个名字判存在，名字必须是 mongod 的生成形态
        expect(fresh.name).toBe(mongodName(key));
        expect(list.find((i) => keySig(i.key) === keySig(oldKey))).toBeFalsy();
      }
    });

    test('⑦ down() 回到旧形态：删三键、把被替换的二键建回，且幂等', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 前提自证：down() 要撤销的三键索引必须真的在，否则下面两类断言在空库上各对一半
      for (const { coll, key } of migration.REPLACE) {
        expect(
          (await db.collection(coll).indexes()).find((i) => keySig(i.key) === keySig(key))
        ).toBeTruthy();
      }

      await migration.down(db);
      await expect(migration.down(db)).resolves.toBeUndefined();

      for (const { coll, key, oldKey, oldName } of migration.REPLACE) {
        const list = await db.collection(coll).indexes();
        expect(list.find((i) => keySig(i.key) === keySig(key))).toBeFalsy();
        const old = list.find((i) => keySig(i.key) === keySig(oldKey));
        expect(old).toBeTruthy();
        expect(old.name).toBe(oldName);
      }
    });

    /** 逐集合只 drop 一次再铺夹具：多个条目共用 firealarms，逐条 dropIndexes 会把前一条的夹具一起清掉 */
    const seedByColl = async (db, makeIndex) => {
      const byColl = {};
      for (const e of migration.REPLACE) {
        byColl[e.coll] = byColl[e.coll] || [];
        byColl[e.coll].push(e);
      }
      for (const [coll, entries] of Object.entries(byColl)) {
        const c = db.collection(coll);
        await c.dropIndexes().catch(() => {});
        for (const e of entries) await makeIndex(c, e);
      }
    };

    test('⑧ 同名但 key 漂移（反序）⇒ up() 必须纠正到声明的三键形态', async () => {
      const db = isolated.db;
      await seedByColl(db, (c, { name, key }) =>
        c.createIndex(Object.fromEntries(Object.entries(key).reverse()), { name })
      );
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of migration.REPLACE) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        // 「名字在就跳过」会把这条名字对、key 错的索引当已对齐放过，等值块内仍阻塞排序
        expect(keySig(named.key)).toBe(keySig(key));
      }
    });

    test('⑨ 同 key 不同名（85 形态）⇒ up() 不抛且收敛到声明名一条', async () => {
      const db = isolated.db;
      await seedByColl(db, (c, { name, key }) => c.createIndex(key, { name: `legacy_${name}` }));
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of migration.REPLACE) {
        const list = await db.collection(coll).indexes();
        const declared = list.filter((i) => keySig(i.key) === keySig(key));
        expect(declared).toHaveLength(1);
        expect(declared[0].name).toBe(name);
        expect(list.find((i) => i.name === `legacy_${name}`)).toBeFalsy();
      }
    });
    test('⑩ 同名且 key 对，但整 spec 漂移（unique:true）⇒ up() 必须重建', async () => {
      const db = isolated.db;
      await seedByColl(db, (c, { name, key }) => c.createIndex(key, { name, unique: true }));
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name, key } of migration.REPLACE) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(keySig(named.key)).toBe(keySig(key));
        expect(named.unique).toBeFalsy();
      }
    });

    test('⑪ 同名且 key 对，但 collation 漂移（caseLevel）⇒ up() 必须重建', async () => {
      const db = isolated.db;
      await seedByColl(db, (c, { name, key }) =>
        c.createIndex(key, { name, collation: { locale: 'en', strength: 2, caseLevel: true } })
      );
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name } of migration.REPLACE) {
        const named = (await db.collection(coll).indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(named.collation).toBeUndefined();
      }
    });

    test('⑫ 异名 twin 带语义差异（unique:true）⇒ up() 不得删它', async () => {
      const db = isolated.db;
      await seedByColl(db, (c, { name, key }) =>
        c.createIndex(key, { name: `legacy_${name}`, unique: true })
      );
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { coll, name } of migration.REPLACE) {
        const list = await db.collection(coll).indexes();
        const twin = list.find((i) => i.name === `legacy_${name}`);
        expect(twin).toBeTruthy();
        expect(twin.unique).toBe(true);
        expect(list.find((i) => i.name === name)).toBeTruthy();
      }
    });
  });
});
