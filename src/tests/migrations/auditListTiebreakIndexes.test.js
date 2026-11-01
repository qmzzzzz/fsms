/**
 * 迁移 20261201000000-audit-list-tiebreak-indexes 与模型声明的对账（第十一轮 F2）
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 七条「等值筛选 + 时间倒序」声明必须都在 schema 里且**带 `_id:-1`** —— 缺它时索引只能供
 *    filter 这一段，时间与 _id 两段仍要阻塞排序，优化器于是干脆不用它（实测 keys=全表）。
 * ② 被替换的旧二键形态必须**不在** schema 里 —— 留着就是双份写放大；autoIndex 只创建不删除，
 *    迁移是旧二键的确定性回收路径。
 * ③ 迁移里硬编码的索引名必须等于 mongod 的自动生成名 —— 迁移按名字判存在，名字算错会走到
 *    createIndex：目标名已被同 key 占用时抛 85 IndexOptionsConflict（86 是"同名不同 key"）；
 *    目标名尚不存在时会**静默建成 typo 名**，防拼错靠 ④ 的字面量对比。
 * ④ 真库行为：全新库 up() 不抛 / 漂移形态 up() 收敛且幂等 / down() 回到旧形态 /
 *    异名 twin 的 85 形态被收敛、语义不同的 twin 不被删。
 *
 * 为什么不能只断言 schema 里有这条声明：声明只说明「有这条索引」，而退化形态是
 * 「声明在、查询选不中」。执行计划层面由 src/tests/models/auditListTiebreakExplain.test.js 锁。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20261201000000-audit-list-tiebreak-indexes');
const AuditLog = require('../../models/AuditLog');

const keySig = (key) =>
  Object.keys(key)
    .map((k) => k + ':' + key[k])
    .join('|');

/** mongod 的自动命名规则：逐字段 `名_方向` 再用 `_` 连接（_id 因此写成 `__id_-1`） */
const mongodName = (key) =>
  Object.keys(key)
    .map((k) => k + '_' + key[k])
    .join('_');

const declaredSigs = (model) => model.schema.indexes().map(([key]) => keySig(key));

describe('审计列表筛选平局键复合索引：迁移与声明对账（F2）', () => {
  let silenceLog;
  let isolated;

  beforeAll(async () => {
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    // 执行侧打在独立库上：up()/down() 会 dropIndex + createIndex，索引形态是这套件自己的夹具，
    // 不该当跨套件共享状态用（同 cursorTiebreakIndexes.test.js 的处置与理由）
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: `zAuditTiebreak${Date.now().toString(36)}p${process.pid}`,
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
    test('① 七条目标索引都在 schema 声明里，且末字段是同向平局键 _id:-1', () => {
      expect(migration.REPLACE).toHaveLength(7);
      for (const { key } of migration.REPLACE) {
        expect(declaredSigs(AuditLog)).toContain(keySig(key));
        // 末字段必须是同向平局键：不是 _id:-1 就等于没补（等值块内仍阻塞排序）
        expect(Object.keys(key).pop()).toBe('_id');
        expect(key._id).toBe(-1);
      }
    });

    test('② 被替换的旧二键形态不在声明里（留着就是双份写放大）', () => {
      for (const { oldKey } of migration.REPLACE) {
        expect(declaredSigs(AuditLog)).not.toContain(keySig(oldKey));
      }
    });

    test('③ 迁移里硬编码的名字与集合名与模型同源（名字算错会在 createIndex 上撞同名不同 key）', () => {
      for (const entry of migration.REPLACE) {
        expect(entry.name).toBe(mongodName(entry.key));
        expect(entry.oldName).toBe(mongodName(entry.oldKey));
        // 集合名写死在迁移里，这一格就是那条缝：模型改 collection: 必须让本用例红
        expect(entry.coll).toBe(AuditLog.collection.name);
      }
      expect(new Set(migration.REPLACE.map((e) => e.coll))).toEqual(new Set(['auditlogs']));
    });
  });

  describe('执行侧（真库：mongod 自己给索引命名）', () => {
    test('④ 全新库（集合还不存在）跑 up() 不得抛', async () => {
      const fresh = await mongoose
        .createConnection(process.env.MONGODB_URI, {
          dbName: `zAuditTiebreakFresh${Date.now().toString(36)}`,
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

    /** 造出漂移形态（只有旧二键索引）再跑 up() 收敛——⑤⑥ 共用的前置，各自调用且自证前提 */
    const seedDriftAndUp = async (db) => {
      const c = db.collection('auditlogs');
      await c.dropIndexes().catch(() => {});
      for (const { oldKey, oldName } of migration.REPLACE) {
        await c.createIndex(oldKey, { name: oldName });
      }
      await migration.up(db);
    };

    test('⑤ 从漂移形态出发 up() 收敛到声明且幂等（新索引名 == mongod 自动名，旧索引已回收）', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 幂等：跑第二遍不得因为"名字算错 ⇒ 再建一次同 key 异名"而抛 85 IndexOptionsConflict
      await expect(migration.up(db)).resolves.toBeUndefined();

      const list = await db.collection('auditlogs').indexes();
      for (const { key, oldKey } of migration.REPLACE) {
        const fresh = list.find((i) => keySig(i.key) === keySig(key));
        expect(fresh).toBeTruthy();
        expect(fresh.name).toBe(mongodName(key));
        expect(list.find((i) => keySig(i.key) === keySig(oldKey))).toBeFalsy();
      }
    });

    test('⑥ down() 回到旧形态：删三键、把被替换的二键建回，且幂等', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 前提自证：down() 要撤销的三键索引必须真的在，否则下面两类断言在空库上各对一半
      const before = await db.collection('auditlogs').indexes();
      for (const { key } of migration.REPLACE) {
        expect(before.find((i) => keySig(i.key) === keySig(key))).toBeTruthy();
      }

      await migration.down(db);
      await expect(migration.down(db)).resolves.toBeUndefined();

      const list = await db.collection('auditlogs').indexes();
      for (const { key, oldKey, oldName } of migration.REPLACE) {
        expect(list.find((i) => keySig(i.key) === keySig(key))).toBeFalsy();
        const old = list.find((i) => keySig(i.key) === keySig(oldKey));
        expect(old).toBeTruthy();
        expect(old.name).toBe(oldName);
      }
    });

    test('⑦ 同名但 key 漂移（漏 _id）⇒ up() 必须纠正到声明的三键形态', async () => {
      const db = isolated.db;
      const c = db.collection('auditlogs');
      await c.dropIndexes().catch(() => {});
      for (const { name, oldKey } of migration.REPLACE) await c.createIndex(oldKey, { name });
      await expect(migration.up(db)).resolves.toBeUndefined();
      for (const { name, key } of migration.REPLACE) {
        const named = (await c.indexes()).find((i) => i.name === name);
        expect(named).toBeTruthy();
        // 「名字在就跳过」会把这条名字对、key 错的索引当已对齐放过，等值块内仍阻塞排序
        expect(keySig(named.key)).toBe(keySig(key));
      }
    });

    test('⑧ 同 key 不同名（85 形态）⇒ up() 不抛且收敛到声明名一条', async () => {
      const db = isolated.db;
      const c = db.collection('auditlogs');
      await c.dropIndexes().catch(() => {});
      for (const { name, key } of migration.REPLACE)
        await c.createIndex(key, { name: `legacy_${name}` });
      await expect(migration.up(db)).resolves.toBeUndefined();
      const list = await c.indexes();
      for (const { name, key } of migration.REPLACE) {
        const declared = list.filter((i) => keySig(i.key) === keySig(key));
        expect(declared).toHaveLength(1);
        expect(declared[0].name).toBe(name);
        expect(list.find((i) => i.name === `legacy_${name}`)).toBeFalsy();
      }
    });

    test('⑨ 同名且 key 对，但整 spec 漂移（unique:true）⇒ up() 必须重建', async () => {
      const db = isolated.db;
      const c = db.collection('auditlogs');
      await c.dropIndexes().catch(() => {});
      for (const { name, key } of migration.REPLACE)
        await c.createIndex(key, { name, unique: true });
      await expect(migration.up(db)).resolves.toBeUndefined();
      const list = await c.indexes();
      for (const { name, key } of migration.REPLACE) {
        const named = list.find((i) => i.name === name);
        expect(named).toBeTruthy();
        expect(keySig(named.key)).toBe(keySig(key));
        expect(named.unique).toBeFalsy();
      }
    });

    test('⑩ 异名 twin 带语义差异（unique:true）⇒ up() 不得删它', async () => {
      const db = isolated.db;
      const c = db.collection('auditlogs');
      await c.dropIndexes().catch(() => {});
      for (const { name, key } of migration.REPLACE)
        await c.createIndex(key, { name: `legacy_${name}`, unique: true });
      await expect(migration.up(db)).resolves.toBeUndefined();
      const list = await c.indexes();
      for (const { name } of migration.REPLACE) {
        const twin = list.find((i) => i.name === `legacy_${name}`);
        expect(twin).toBeTruthy();
        expect(twin.unique).toBe(true);
        expect(list.find((i) => i.name === name)).toBeTruthy();
      }
    });
  });
});
