/**
 * 迁移 20260928000000-audit-username-ci-index 与模型声明的对账
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 迁移碰的集合名必须就是模型的物理集合名 —— 集合名在迁移里是硬编码字符串
 *    （migrate-mongo 上下文不 require 模型），模型改 `collection:` 就没人报警；
 * ② 迁移建的索引 key 必须与 schema 声明逐字段一致 —— 只声明不迁迁移，
 *    存量库永远缺索引（autoIndex 只在新库生效）；
 * ③ 索引名必须与 schema 声明一致 —— 迁移按名字判存在，名字算错会走到 createIndex，
 *    同 key 不同名抛 85 IndexOptionsConflict（86 IndexKeySpecsConflict 是同名不同 key）；
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
    // 本 describe 的用例操作**同一个** isolated.db，而状态只有"索引在不在"这一个布尔量。
    // 原实现靠声明顺序串起来（up 建 → 幂等 → 漂移 → down 删 → down 幂等），
    // `--randomize` 打乱后必然互相踩：实测 CI #72 的 seed 2/3 里「collation 不一致时 up()
    // 会删掉重建」跑到了「down()：索引被删除」之后 ⇒ dropIndex 抛
    // `MongoServerError: index not found with name [username_ci_timestamp]`。
    // 改为每条用例**自证前置**：需要索引存在就先 up()，需要不存在就先 drop。
    /** 前置：索引已建成且形态正确（up 本身幂等，重复调用安全） */
    const ensureIndexPresent = () => migration.up(isolated.db);
    /** 前置：索引不存在（集合不存在时 dropIndex 会抛，同样视作"不存在"） */
    const ensureIndexAbsent = async () => {
      await isolated.db
        .collection(migration.COLLECTION)
        .dropIndex(migration.INDEX_NAME)
        .catch(() => {});
    };

    test('up()：索引建成且带 collation', async () => {
      await ensureIndexAbsent(); // 自证前置：不依赖"上一条用例刚建过"
      await migration.up(isolated.db);
      const idx = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(idx).not.toBeNull();
      expect(idx.key).toEqual({ username: 1, timestamp: -1 });
      expect(idx.collation.locale).toBe('en');
      expect(idx.collation.strength).toBe(2);
    });

    test('up() 幂等：再跑一次不重建、不报错，形态不变', async () => {
      await ensureIndexPresent(); // 自证前置：before 必须真的存在，否则断言在比 null
      const before = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(before).not.toBeNull();
      await migration.up(isolated.db);
      const after = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
      expect(after.name).toBe(before.name);
      expect(after.key).toEqual(before.key);
      expect(after.collation.strength).toBe(before.collation.strength);
    });

    test('collation 不一致时 up() 会删掉重建（否则查询侧命中不了它）', async () => {
      await ensureIndexPresent(); // 自证前置：dropIndex 需要索引存在
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
      await ensureIndexPresent(); // 自证前置：先建出来，才谈得上"被删掉"
      await migration.down(isolated.db);
      expect(await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME)).toBeNull();
    });

    test('down() 幂等：索引已不存在时不报错', async () => {
      await ensureIndexAbsent(); // 自证前置：本用例要的就是"已不存在"这个状态
      await expect(migration.down(isolated.db)).resolves.toBeUndefined();
    });

    // ── M-3：key 漂移（第八轮审计补的判据）─────────────────────────────────
    //
    // 现状（登记项 M-1）：迁移 sameCollation 只比 locale/strength，up() **从不比较 KEY**，
    // 于是"同名 + collation 一致 + key 漂移"会被判成"已存在，跳过"。下面三条用例断言的是
    // **正确行为**（漂移必须被纠正），因此对着当前迁移**必然是红的**——红即证据：
    // 说明这套判据真的在设防，而不是"跑绿了所以没事"。
    // 实测危害（真实 mongod 8.0.34，见 work/audit-round8-compose-migrations.md §3.3）：
    //   · 反序 key 漂移 ⇒ 查询计划从 IXSCAN 退化为 COLLSCAN（20k 条 4000→20000 docs）；
    //   · 缺 timestamp ⇒ 排序只能走内存（200k 条 304ms 阻塞排序）；
    //   · caseLevel 类细项漂移 ⇒ 同上退化为 COLLSCAN。

    /** 清掉本集合上除 _id_ 外的所有索引（含"同 key 不同名"的残留），让每条用例从干净态起跑 */
    const clearAuditIndexes = async () => {
      const coll = isolated.db.collection(migration.COLLECTION);
      const existing = await indexesOf(isolated.db, migration.COLLECTION).catch(() => []);
      for (const idx of existing) {
        if (idx.name === '_id_') continue;
        await coll.dropIndex(idx.name).catch(() => {});
      }
    };

    /**
     * 用例包装：跑前跑后都清索引。必须在用例内 finally 清 —— 本 describe 里的
     * 其它用例只认"名字为 INDEX_NAME 的那条在不在"，同名/同 key 的残留会让它们的
     * up() 抛 85（--randomize 打乱顺序时尤其致命），所以不能只靠 afterAll。
     */
    const withCleanIndexes = (fn) => async () => {
      await clearAuditIndexes();
      try {
        await fn();
      } finally {
        await clearAuditIndexes();
      }
    };

    test(
      '[M-3/S2] key 漂移（同名同 collation、key 少 timestamp）必须被 up() 纠正',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        // 自证前置：同名、同 collation、key 只有 username —— 正是实测里被"静默跳过"的形态
        await coll.createIndex(
          { username: 1 },
          { name: migration.INDEX_NAME, collation: migration.COLLATION }
        );
        const pre = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(pre).not.toBeNull();
        expect(keySig(pre.key)).toBe('username:1');
        expect(pre.collation).toMatchObject({ locale: 'en', strength: 2 });

        await migration.up(isolated.db);

        const post = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(post).not.toBeNull();
        expect(post.key).toEqual({ username: 1, timestamp: -1 });
        expect(post.collation).toMatchObject({ locale: 'en', strength: 2 });
      })
    );

    test(
      '[M-3/S3] key 漂移（同名同 collation、key 顺序反了）必须被 up() 纠正',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        await coll.createIndex(
          { timestamp: -1, username: 1 },
          { name: migration.INDEX_NAME, collation: migration.COLLATION }
        );
        const pre = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(pre).not.toBeNull();
        // 顺序是 key 的一部分：反序对本查询（username 等值 + timestamp 排序）不可用
        expect(keySig(pre.key)).toBe('timestamp:-1|username:1');

        await migration.up(isolated.db);

        const post = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(post).not.toBeNull();
        expect(keySig(post.key)).toBe('username:1|timestamp:-1');
        expect(post.collation).toMatchObject({ locale: 'en', strength: 2 });
      })
    );

    test(
      '[M-3/S10] 同 key 同 collation 但名字不同（username_1_timestamp_-1）⇒ up() 不得抛 85，且收敛到一条',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        // 自证前置：正是会触发 85 IndexOptionsConflict 的形态（实测原文：
        // "Index already exists with a different name: username_1_timestamp_-1"）
        await coll.createIndex({ username: 1, timestamp: -1 }, { collation: migration.COLLATION });
        const pre = await findIndex(isolated.db, migration.COLLECTION, 'username_1_timestamp_-1');
        expect(pre).not.toBeNull();
        expect(keySig(pre.key)).toBe('username:1|timestamp:-1');
        expect(await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME)).toBeNull();

        // 现状会抛 85 ⇒ 迁移中断；正确行为是收敛（复用同名或收敛到声明名），且不抛
        await expect(migration.up(isolated.db)).resolves.toBeUndefined();

        const named = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(named).not.toBeNull();
        expect(named.key).toEqual({ username: 1, timestamp: -1 });
        // 收敛后同 key 的索引只应剩一条：重复索引是纯粹的写放大
        const sameKey = (await indexesOf(isolated.db, migration.COLLECTION)).filter(
          (i) => i.key.username === 1 && i.key.timestamp === -1
        );
        expect(sameKey).toHaveLength(1);
      })
    );

    test(
      '[W3-1] 同名同 key 但整 spec 漂移（unique:true）⇒ up() 必须重建（唯一约束消失）',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        await coll.createIndex(
          { username: 1, timestamp: -1 },
          { name: migration.INDEX_NAME, collation: migration.COLLATION, unique: true }
        );
        const pre = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        // 自证前置：漂移真的造出了'凭空多出的唯一约束'
        expect(pre.unique).toBe(true);
        await migration.up(isolated.db);
        const post = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(post).not.toBeNull();
        expect(post.unique).toBeFalsy();
        expect(post.collation.strength).toBe(2);
      })
    );

    test(
      '[W3-2] 同名同 key 同 locale/strength 但 collation.caseLevel 漂移 ⇒ up() 必须重建',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        await coll.createIndex(
          { username: 1, timestamp: -1 },
          {
            name: migration.INDEX_NAME,
            collation: { locale: 'en', strength: 2, caseLevel: true },
          }
        );
        const pre = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        // 自证前置：只比 locale/strength 的判据会把它当'已对齐'放过
        expect(pre.collation.caseLevel).toBe(true);
        await migration.up(isolated.db);
        const post = await findIndex(isolated.db, migration.COLLECTION, migration.INDEX_NAME);
        expect(post.collation.caseLevel).toBe(false);
      })
    );

    test(
      '[W4] 异名 twin 带语义差异（unique:true）⇒ up() 不得删它（删了就是静默丢唯一约束）',
      withCleanIndexes(async () => {
        const coll = isolated.db.collection(migration.COLLECTION);
        await coll.createIndex(
          { username: 1, timestamp: -1 },
          { name: 'legacy_username_uniq', collation: migration.COLLATION, unique: true }
        );
        await expect(migration.up(isolated.db)).resolves.toBeUndefined();
        const list = await indexesOf(isolated.db, migration.COLLECTION);
        const twin = list.find((i) => i.name === 'legacy_username_uniq');
        expect(twin).toBeTruthy();
        expect(twin.unique).toBe(true);
        // 声明的那条也建出来了（两者并存合法）
        expect(list.find((i) => i.name === migration.INDEX_NAME)).toBeTruthy();
      })
    );
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
