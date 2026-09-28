/**
 * 迁移 20260830000000-backfill-token-version 的回滚射程测试
 *
 * 修的是"回滚做掉了它没写过的数据"：
 *   up()   只补 `{tokenVersion: {$exists: false}}` 的存量裸文档；
 *   down() 原来撤的是 `{tokenVersion: 0}` —— 而 User schema 对该字段有 `default: 0`，
 *          于是每一个经 Mongoose 建档、没被吊销过的用户都是显式 0。
 *   ⇒ 一次 `npm run migrate:down` 会把绝大多数用户的 tokenVersion 整个抹掉。
 * 现在 down() 改成有意空操作（详见迁移文件注释）。本文件把两件事钉住：
 *   ① up() 的作用域严格限于"字段缺失"；
 *   ② down() 一个字段都不许弄掉（尤其是它没写过的显式 0）。
 *
 * 隔离：连**同一 server 的另一个 database**（迁移签名是 `up(db)`/`down(db)`，
 * 不依赖 Mongoose 的默认连接），避免与并行会话在 `users` 上的测试互踩。
 */

const mongoose = require('mongoose');
const migration = require('../../migrations/20260830000000-backfill-token-version');
const User = require('../models/User');

const TAG = `zzbftv_${Date.now()}`;
const mkUser = (name, extra) => ({
  username: `${TAG}_${name}`,
  email: `${TAG}_${name}@example.com`,
  password: 'Zz!1234567890abcdef',
  ...extra,
});

describe('迁移：tokenVersion 补齐与其回滚射程', () => {
  let conn;
  let db;
  let coll;
  let silenceLog;

  beforeAll(async () => {
    const uri = process.env.MONGODB_URI;
    conn = await mongoose.createConnection(uri, { dbName: `${TAG}_db` }).asPromise();
    db = conn.db;
    // 前提自证：连接真的就绪。Mongoose 8 的 createConnection() 不 await 打开，
    // 少了 asPromise() 时 db 是 undefined，每条用例会秒失败、afterAll 的 close() 再把 jest 挂住。
    expect(db).toBeDefined();
    coll = db.collection('users');
    silenceLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterAll(async () => {
    silenceLog.mockRestore();
    if (conn) await conn.close();
  });

  beforeEach(async () => {
    await coll.deleteMany({ username: new RegExp(`^${TAG}_`) });
    // 三类形态：字段缺失（本迁移的目标）/ 显式 0（schema 默认值，绝大多数用户）/ 显式 1（被吊销过）
    await coll.insertMany([
      mkUser('missing', {}),
      mkUser('zero', { tokenVersion: 0 }),
      mkUser('one', { tokenVersion: 1 }),
    ]);
  });

  afterEach(async () => {
    await coll.deleteMany({ username: new RegExp(`^${TAG}_`) });
  });

  const get = async (name) => coll.findOne({ username: `${TAG}_${name}` });

  test('前提自证：schema 默认值就是 0 ⇒ 显式 0 是本迁移没写过的存量常态', () => {
    const path = User.schema.path('tokenVersion');
    // Mongoose 8：`path.default` 是设置器（函数），取值用 `defaultValue`
    // ——首版照抄 `typeof path.default === 'function' ? path.default() : ...` 拿到 undefined。
    expect(typeof path.default).toBe('function');
    expect(path.defaultValue).toBe(0);
  });

  test('up() 只补字段缺失的文档，显式 0 / 显式 1 一律不动', async () => {
    await migration.up(db);

    expect((await get('missing')).tokenVersion).toBe(0);
    expect((await get('zero')).tokenVersion).toBe(0);
    expect((await get('one')).tokenVersion).toBe(1);
    // 只应写一条：证明确实按 $exists 过滤，而不是"把所有版本都按 0 刷一遍"
    expect(silenceLog.mock.calls.flat().join('\n')).toMatch(/匹配 1 条，更新 1 条/);
  });

  test('up() 幂等：二跑不再匹配任何文档', async () => {
    await migration.up(db);
    silenceLog.mockClear();
    await migration.up(db);
    expect(silenceLog.mock.calls.flat().join('\n')).toMatch(/匹配 0 条，更新 0 条/);
    expect((await get('one')).tokenVersion).toBe(1);
  });

  test('★ down() 不得抹掉任何用户的 tokenVersion（原实现会连 schema 默认值的 0 一起撤）', async () => {
    await migration.up(db);
    await migration.down(db);

    for (const name of ['missing', 'zero', 'one']) {
      const doc = await get(name);
      expect(doc.tokenVersion).toBeDefined();
    }
    // 显式 0 是"绝大多数用户"的代表形态：它被弄掉就说明回滚射程越过了 up() 的写入范围
    expect((await get('zero')).tokenVersion).toBe(0);
    expect(await coll.countDocuments({ tokenVersion: { $exists: false } })).toBe(0);
  });

  test('down() 必须存在（migrate-mongo v14 的 down 动作对每条迁移无条件调用 down()）', async () => {
    expect(typeof migration.down).toBe('function');
    await expect(migration.down(db)).resolves.toBeUndefined();
  });
});
