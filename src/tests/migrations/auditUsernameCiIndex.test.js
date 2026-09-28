/**
 * 迁移 20260928000000-audit-username-ci-index 与模型声明的对账
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 迁移碰的集合名必须就是模型的物理集合名 —— 集合名在迁移里是硬编码字符串
 *    （migrate-mongo 上下文不 require 模型），模型改 `collection:` 就没人报警；
 * ② 迁移建的索引 key 必须与 schema 声明逐字段一致 —— 只声明不迁迁移，
 *    存量库永远缺索引（autoIndex 只在新库生效）；
 * ③ 索引名必须与 schema 声明一致 —— 迁移按名字判存在，名字算错会走到 createIndex，
 *    同 key 不同名直接 IndexKeySpecsConflict，部署停在半途；
 * ④ **collation 必须一致** —— 这是本迁移与其它索引迁移最大的不同：带 collation 的索引
 *    **只能**被带同一 collation 的查询命中。迁移若漏了 collation（或 strength 不同），
 *    查询侧带着 collation 来反而命中不了它，表现为"索引明明在、却仍走 COLLSCAN"；
 *    反之代码侧若漏挂 collation，前缀范围在默认二进制比较下还会**漏掉大小写变体**
 *    （本机实测：不带 collation 时 `ADMIN` 不落在 `[adm, adn)` 内）。
 *
 * 行为面（带 / 不带 collation 的命中差异）由
 * `src/tests/controllers/auditUsernamePrefixIndex.test.js` 钉。
 *
 * 执行侧一律打在**独立库**上（同 tests/migrations 那份套件的处置）：`up()/down()` 会
 * dropIndex + createIndex，而 jest 套件并发跑在同一个 mongod 上，索引形态是这套件
 * 自己的夹具，不该当跨套件的共享状态用。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20260928000000-audit-username-ci-index');
const AuditLog = require('../../models/AuditLog');

const ISOLATED_DB = `zUsrCiIdx${Date.now().toString(36)}p${process.pid}`;
let isolated;
let silenceLog;

const indexesOf = async (db, coll) => db.collection(coll).indexes();
const findIndex = async (db, coll, name) =>
  (await indexesOf(db, coll)).find((i) => i.name === name) || null;

const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

/** schema 侧声明的那条索引（不抄迁移里的字面量） */
const declared = AuditLog.schema
  .indexes()
  .find(([keys]) => keys.username === 1 && keys.timestamp === -1);

describe('迁移 20260928000000 与模型声明的对账', () => {
  beforeAll(async () => {
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, { dbName: ISOLATED_DB })
      .asPromise();
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    if (isolated && isolated.readyState !== 0) {
      await isolated.db.dropDatabase().catch(() => {});
      await isolated.close();
    }
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('声明侧（无库，与 jest 调度顺序无关）', () => {
    test('① 集合名与模型的物理集合名一致', () => {
      expect(migration.COLLECTION).toBe(AuditLog.collection.name);
    });

    test('② 索引 key 与 schema 声明逐字段一致', () => {
      expect(declared).toBeDefined();
      expect(keySig(migration.KEY)).toBe(keySig(declared[0]));
      expect(migration.KEY).toEqual({ username: 1, timestamp: -1 });
    });

    test('③ 索引名与 schema 声明一致', () => {
      expect(migration.INDEX_NAME).toBe(declared[1].name);
      expect(migration.INDEX_NAME).toBe('username_ci_timestamp');
    });

    test('④ collation 与 schema 声明、模型 statics 三处一致', () => {
      expect(migration.COLLATION).toEqual(declared[1].collation);
      expect(migration.COLLATION).toEqual(AuditLog.AUDIT_USERNAME_COLLATION);
      expect(migration.COLLATION).toEqual({ locale: 'en', strength: 2 });
    });
  });

  describe('执行侧（独立库）', () => {
    test('up()：索引建成且带 collation', async () => {
      await migration.up(isolated.db);
      const idx = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(idx).not.toBeNull();
      expect(idx.key).toEqual({ username: 1, timestamp: -1 });
      expect(idx.collation.locale).toBe('en');
      expect(idx.collation.strength).toBe(2);
    });

    test('up() 幂等：再跑一次不重建、不报错，形态不变', async () => {
      const before = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      await migration.up(isolated.db);
      const after = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(after.name).toBe(before.name);
      expect(after.key).toEqual(before.key);
      expect(after.collation.strength).toBe(before.collation.strength);
    });

    test('collation 不一致时 up() 会删掉重建（否则查询侧命中不了它）', async () => {
      const coll = isolated.db.collection(migration.COLLECTION);
      await coll.dropIndex(migration.INDEX_NAME);
      // 故意造成"同名同 key 但无 collation"的漂移形态
      await coll.createIndex({ username: 1, timestamp: -1 }, { name: migration.INDEX_NAME });
      const drifted = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(drifted.collation).toBeUndefined();

      await migration.up(isolated.db);
      const fixed = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(fixed.collation.strength).toBe(2);
    });

    test('down()：索引被删除', async () => {
      await migration.down(isolated.db);
      expect(await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME)).toBeNull();
    });

    test('down() 幂等：索引已不存在时不报错', async () => {
      await expect(migration.down(isolated.db)).resolves.toBeUndefined();
    });

    test('up() 在空库（集合不存在）上也能建（首次 migrate 路径）', async () => {
      await isolated.db
        .collection(migration.COLLECTION)
        .drop()
        .catch(() => {});
      await migration.up(isolated.db);
      const idx = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(idx).not.toBeNull();
      expect(idx.collation.strength).toBe(2);
    });
  });
});
