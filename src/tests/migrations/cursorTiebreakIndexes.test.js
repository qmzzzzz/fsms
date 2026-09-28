/**
 * 迁移 20260926000000-cursor-tiebreak-compound-indexes 与模型声明的对账
 *
 * 钉住四件彼此独立、任一分叉都会在线上出事的事：
 * ① 迁移碰的集合名必须就是模型的物理集合名 —— 集合名在迁移里是硬编码字符串
 *    （migrate-mongo 上下文不 require 模型），模型改 `collection:` 就没人报警；
 * ② 迁移建的复合索引 key 必须与 schema 声明逐字段一致 —— 只声明不迁迁移，
 *    存量库永远缺索引（autoIndex 只在新库生效）；只迁不声明，
 *    `scripts/sync-audit-indexes.js --apply` 会把它当"模型未声明的冗余索引"删掉；
 * ③ 索引名必须与 mongod 自动生成的名字一致 —— 迁移按名字判存在，名字算错会
 *    走到 createIndex，同 key 不同名直接 IndexKeySpecsConflict，部署停在半途；
 * ④ auditlogs 的 `{timestamp:-1}` 单字段索引不能删：它挂着 TTL，而 mongod 6.0.14
 *    实测拒绝在复合索引上挂 expireAfterSeconds（TTL indexes are single-field indexes）。
 *
 * 行为面（等值块跨页不重不漏）由 src/tests/services/cursorTiebreakPagination.test.js 钉。
 */

const mongoose = require('mongoose');
const migration = require('../../../migrations/20260926000000-cursor-tiebreak-compound-indexes');
const { RETENTION_SECONDS } = require('../../constants/retention');

const FireAlarm = require('../../models/FireAlarm');
const Inspection = require('../../models/Inspection');
const AuditLog = require('../../models/AuditLog');

/** 与被测迁移同一批目标，但集合名/字段名**取自模型**，不抄迁移里的字面量 */
const TARGETS = [
  { model: FireAlarm, field: 'occurredAt', replaceSingle: true },
  { model: Inspection, field: 'planStartTime', replaceSingle: true },
  { model: AuditLog, field: 'timestamp', replaceSingle: false },
];

const keySig = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

/**
 * 执行侧一律打在**独立库**上，不打在 `mongoose.connection.db` 上。
 * 理由：`up()/down()` 会 dropIndex + createIndex，而 jest 的套件并发跑在同一个
 * mongod 上——索引形态是这套件自己的夹具，不该当跨套件的共享状态用（原来还要
 * 在 afterAll 里把共享库"回写成已对齐"才不拖累别人，那正是共享状态的代价）。
 *
 * 顺带记一条取证纪律：这套件与 `cursorTiebreakPagination.test.js` 并跑时出现过
 * "对面 4 条用例全挂在夹具阶段、重跑即绿"，第一反应是索引串扰——**错的**。
 * 同形态复现 12 次抓到一次，报错是
 * `SyntaxError: src/utils/encryption.js: Unexpected token`（babel 读到了另一条线
 * 正在写入的半截文件）。串扰是猜的，半截文件是打印出来的证据；结论也按证据写：
 * 那条红与本套件的索引改动无关，独立库是预防，不是它的修复。
 */
const ISOLATED_DB = `zTieIdx${Date.now().toString(36)}p${process.pid}`;
let isolated; // beforeAll 里建立的独立连接

const indexesOf = async (coll) => isolated.db.collection(coll).indexes();

/**
 * 造出"漂移形态"（只剩被替换掉的旧单字段索引）再跑 up() 收敛——⑤ 与 ⑥ 共用的前置状态。
 *
 * 这段原先只长在 ⑤ 里面，而 ⑥ 直接 `migration.down(db)` 后断"单字段索引必须在"，
 * 等于把前置状态写成了一条**有序用例**：`--randomize --seed=777001` 下 ⑥ 先跑，
 * 此时每次运行新建的独立库里连集合都不存在（down() 对 replaceSingle:false 的目标不建任何东西），
 * 报的是 `ns does not exist: ….auditlogs`。更糟的是"如果集合恰好被别的用例建过"，
 * ⑥ 会以"回滚没建回单字段"的错因红——错因还是假的。
 * 搬成两边各自调用的前置，且调用后自证前提，才既顺序无关又不吞真缺陷。
 */
const seedDriftAndUp = async (db) => {
  for (const { model, field, replaceSingle } of TARGETS) {
    const coll = db.collection(model.collection.name);
    await coll.dropIndexes().catch(() => {});
    // auditlogs 的旧单字段带着 TTL（前一道迁移的产物），造数口径必须一致，
    // 否则 ⑥ 断"TTL 还在"就是断一个从来没挂上的东西
    await coll.createIndex(
      { [field]: -1 },
      replaceSingle ? {} : { expireAfterSeconds: RETENTION_SECONDS }
    );
  }
  await migration.up(db);
};

describe('游标平局裁决复合索引：迁移与声明对账', () => {
  let silenceLog;

  beforeAll(async () => {
    // 迁移自带进度 console.log，录制造型时静默（同 tests/migrations 那份套件的处置）
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    isolated = await mongoose
      .createConnection(process.env.MONGODB_URI, { dbName: ISOLATED_DB })
      .asPromise();
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    if (isolated && isolated.readyState !== 0) {
      // 独立库随连接一起丢弃：不回写共享库，也不留索引
      await isolated.db.dropDatabase().catch(() => {});
      await isolated.close();
    }
  });

  describe('声明侧（无库，与 jest 调度顺序无关）', () => {
    test('① 每个目标的复合索引都在 schema 声明里（否则对账脚本会把它当冗余删掉）', () => {
      for (const { model, field } of TARGETS) {
        const sigs = model.schema.indexes().map(([key]) => keySig(key));
        expect(sigs).toContain(`${field}:-1|_id:-1`);
      }
    });

    test('② 被替换的两条单字段索引确实不在声明里（留着就是双份写放大）', () => {
      for (const { model, field, replaceSingle } of TARGETS) {
        const sigs = model.schema.indexes().map(([key]) => keySig(key));
        expect(sigs.includes(`${field}:-1`)).toBe(!replaceSingle);
      }
    });

    test('③ auditlogs 的 TTL 仍挂在单字段 timestamp 上（复合索引挂不了 TTL）', () => {
      const ttl = AuditLog.schema.indexes().find(([, opts]) => opts && opts.expireAfterSeconds);
      expect(ttl[0]).toEqual({ timestamp: -1 });
      expect(ttl[1].expireAfterSeconds).toBe(RETENTION_SECONDS);
    });
  });

  describe('执行侧（真库：mongod 自己给索引命名）', () => {
    test('④ 迁移里硬编码的集合名与模型物理集合名同源', () => {
      expect(migration.TARGETS.map((t) => t.coll).sort()).toEqual(
        TARGETS.map((t) => t.model.collection.name).sort()
      );
      // 集合名写死在迁移里（migrate-mongo 上下文不 require 模型），这一格就是那条缝
      expect(TARGETS.map((t) => t.model.collection.name).sort()).toEqual(
        ['firealarms', 'inspections', 'auditlogs'].sort()
      );
    });

    test('④b 全新库（集合还不存在）跑 up() 不得抛', async () => {
      const fresh = await mongoose
        .createConnection(process.env.MONGODB_URI, {
          dbName: `zFresh${Date.now().toString(36)}`,
        })
        .asPromise();
      try {
        // 未捕获的 NamespaceNotFound 会让整条 `migrate-mongo up` 停在半途
        await expect(migration.up(fresh.db)).resolves.toBeUndefined();
      } finally {
        await fresh.close();
      }
    });

    test('⑤ 从漂移形态（只有旧单字段索引）出发，up() 收敛到声明且幂等', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 幂等：跑第二遍不得因为"名字算错 ⇒ 再建一次同名 key"而抛 IndexKeySpecsConflict
      await expect(migration.up(db)).resolves.toBeUndefined();

      for (const { model, field, replaceSingle } of TARGETS) {
        const list = await indexesOf(model.collection.name);
        const compound = list.find((i) => keySig(i.key) === `${field}:-1|_id:-1`);
        expect(compound).toBeTruthy();
        // ③ 的本体：名字必须是 mongod 的自动生成形态，迁移按这个名字判存在
        expect(compound.name).toBe(`${field}_-1__id_-1`);
        const single = list.find((i) => keySig(i.key) === `${field}:-1`);
        if (replaceSingle) {
          expect(single).toBeFalsy();
        } else {
          // auditlogs：单字段那条必须在，且 TTL 没被本迁移碰掉
          expect(single.expireAfterSeconds).toBe(RETENTION_SECONDS);
        }
      }
    });

    test('⑥ down() 回到漂移形态：删复合、把被替换的单字段建回', async () => {
      const db = isolated.db;
      await seedDriftAndUp(db);
      // 前提自证：down() 要撤销的复合索引必须真的在。缺了这一段，"集合根本没建出来"
      // 会让下面"复合不在 / 单字段在"两类断言在空库上各对一半——真缺陷反而看不出来。
      for (const { model, field } of TARGETS) {
        const seeded = await indexesOf(model.collection.name);
        expect(seeded.find((i) => keySig(i.key) === `${field}:-1|_id:-1`)).toBeTruthy();
      }

      await migration.down(db);
      for (const { model, field } of TARGETS) {
        const list = await indexesOf(model.collection.name);
        expect(list.find((i) => keySig(i.key) === `${field}:-1|_id:-1`)).toBeFalsy();
        // 回滚后单字段索引必须在：两个被替换的由 down() 建回，
        // auditlogs 那条从头到尾没被动过（它挂着 TTL）
        expect(list.find((i) => keySig(i.key) === `${field}:-1`)).toBeTruthy();
      }
      // auditlogs 的单字段索引在 down() 里也不该被删：它带着留存策略
      const audit = await indexesOf('auditlogs');
      expect(audit.find((i) => keySig(i.key) === 'timestamp:-1').expireAfterSeconds).toBe(
        RETENTION_SECONDS
      );
    });
  });
});
