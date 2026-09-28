'use strict';

/**
 * scripts/fix-token-blacklist-index.js 的「动手」路径行为契约
 *
 * 这个脚本此前只有两类测试：护栏校验顺序（拒绝必须早于 connect）与一条
 * 「默认演练」的源码文本契约。也就是说，`--apply` 之后到底删没删对东西、
 * 有没有多删，从来没有被跑起来验证过。而它恰好是一个 dropIndex + deleteMany
 * 的破坏性脚本。
 *
 * 本轮改动补的是「报告失真」：原实现把动手之前清点的 orphan 数当成删除成果打印，
 * deleteMany 的返回值与 dropIndex 的实际效果都不看，一律 exit 0。
 * 于是「一条没删成」和「全删干净」在日志与退出码上完全同形——而这个脚本存在的
 * 理由就是消除 refresh 的 E11000 症状，报告失真的代价是运维带着未修复的库离开。
 * 现在删除数取自驱动，且收尾必须回库复核（残留孤儿 / 遗留索引仍在 → exit 1）。
 *
 * 判据因此分三层，每层都不采信脚本自报的数字：
 * ① 独立回读集合与索引（该删的删了、不该动的一个没动）；
 * ② stdout 里的条数必须等于库里量出来的条数；
 * ③ 护栏仍然生效：未获准的 --apply 不得产生任何数据变更。
 */

const path = require('path');
const mongoose = require('mongoose');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'fix-token-blacklist-index.js');
const COLL = 'tokenblacklists';
const stamp = `tbfc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

const dbNameFrom = (uri) => {
  const noQuery = uri.split('?')[0];
  return noQuery.slice(noQuery.lastIndexOf('/') + 1);
};

/** 遗留单键索引的判据与脚本一致：只有 token 一个键 */
const isLegacySingleKey = (idx) => {
  const keys = Object.keys(idx.key || {});
  return keys.length === 1 && keys[0] === 'token';
};

describe('fix-token-blacklist-index.js --apply 的实际效果', () => {
  let dbName;
  let coll;

  const orphanFilter = { tokenHash: { $exists: false } };

  /**
   * 旧 schema 的文档长这样：有明文 token、没有 tokenHash。
   * token_1 建成 unique+sparse 是为了能同时摆下新格式文档：
   * 新文档没有 token 字段，非 sparse 的唯一索引会把它们全索引成 null，
   * 第二条起就是 E11000——那是本脚本要修的线上症状，不是这里的判据。
   */
  const seed = async () => {
    await coll.drop().catch(() => {});
    await coll.insertMany([
      { token: `${stamp}-legacy-a` },
      { token: `${stamp}-legacy-b` },
      { tokenHash: `${stamp}-h1`, expiryDate: new Date() },
      { tokenHash: `${stamp}-h2`, expiryDate: new Date() },
      { tokenHash: `${stamp}-h3`, expiryDate: new Date() },
    ]);
    await coll.createIndex({ token: 1 }, { unique: true, sparse: true, name: 'token_1' });
    // 复合索引是诱饵：脚本只准删「仅含 token 单键」的索引
    await coll.createIndex({ token: 1, expiryDate: 1 }, { name: 'token_and_expiry' });
  };

  const readback = async () => ({
    orphans: await coll.countDocuments(orphanFilter),
    valid: await coll.countDocuments({ tokenHash: { $exists: true } }),
    legacyIndexes: (await coll.indexes()).filter(isLegacySingleKey).map((i) => i.name),
    allIndexes: (await coll.indexes()).map((i) => i.name).sort(),
  });

  const run = (flags, extraEnv = {}) =>
    spawnSync(process.execPath, [SCRIPT, ...flags], {
      cwd: ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        MONGODB_URI: process.env.MONGODB_URI,
        ALLOWED_SOURCE_DB: dbName,
        ...extraEnv,
      },
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    dbName = dbNameFrom(process.env.MONGODB_URI);
    coll = mongoose.connection.db.collection(COLL);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await coll.drop().catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('1 默认演练：报告待处理项，但库与索引一个字节都不动', async () => {
    await seed();
    const before = await readback();
    expect(before.orphans).toBe(2);
    expect(before.legacyIndexes).toEqual(['token_1']);

    const r = run([]);

    expect(r.status).toBe(0);
    expect(r.stdout).toContain('DRY-RUN');
    expect(r.stdout).toContain('删除 token_1');
    expect(r.stdout).toContain('删除 2 条无 tokenHash');
    expect(await readback()).toEqual(before);
  });

  test('2 --apply：该删的两样都删掉，报告条数等于库里量出来的条数', async () => {
    await seed();

    const r = run(['--apply']);

    expect(r.status).toBe(0);
    expect(r.stdout).toContain('已删除遗留索引：token_1');
    expect(r.stdout).toContain('已清理 2 条');
    // 收尾复核必须真的跑过，而不是无条件打印「处理完成」
    expect(r.stdout).toContain('复核');

    const after = await readback();
    expect(after.orphans).toBe(0);
    expect(after.valid).toBe(3);
    expect(after.legacyIndexes).toEqual([]);
    expect(after.allIndexes).toContain('_id_');
    expect(after.allIndexes).toContain('token_and_expiry');
    expect(after.allIndexes).not.toContain('token_1');
  });

  test('3 有效会话（带 tokenHash）不在删除范围内', async () => {
    await seed();
    const keptBefore = await coll.find({ tokenHash: { $exists: true } }).toArray();

    expect(run(['--apply']).status).toBe(0);

    const keptAfter = await coll.find({ tokenHash: { $exists: true } }).toArray();
    expect(keptAfter.map((d) => d.tokenHash).sort()).toEqual(
      keptBefore.map((d) => d.tokenHash).sort()
    );
  });

  test('4 幂等：修好之后再跑一次报「无需处理」，且不再触碰数据', async () => {
    await seed();
    expect(run(['--apply']).status).toBe(0);
    const settled = await readback();

    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('无需处理');
    expect(await readback()).toEqual(settled);

    const again = run(['--apply']);
    expect(again.status).toBe(0);
    expect(await readback()).toEqual(settled);
  });

  test('5 缺 ALLOWED_SOURCE_DB 的 --apply：退出码 2 且孤儿一条没少', async () => {
    await seed();
    const before = await readback();

    const r = run(['--apply'], { ALLOWED_SOURCE_DB: '' });

    expect(r.status).toBe(2);
    expect(r.stderr).toContain('ALLOWED_SOURCE_DB');
    expect(await readback()).toEqual(before);
  });

  test('6 库名不在白名单内：拒绝执行且孤儿一条没少', async () => {
    await seed();
    const before = await readback();

    const r = run(['--apply'], { ALLOWED_SOURCE_DB: `zz_not_${stamp}` });

    expect(r.status).toBe(2);
    expect(r.stderr).toContain('不在 ALLOWED_SOURCE_DB 白名单中');
    expect(await readback()).toEqual(before);
  });

  // 脚本 `:58-70` 的注释声称「原生驱动对集合不存在返回 []，不会抛错」，
  // 而 catch 分支又专门为 NamespaceNotFound 写了良性出口——两处只能对一个。
  // 本用例不裁决哪句是真的，只钉住**行为**：空库上必须 exit 0 并走「不存在，无需处理」
  // 那条日志，而不是把 serverSelection / 鉴权类故障也一起读成良性（那是 §3 判过的假绿）。
  test('7 空库（集合不存在）：exit 0 且报「无需处理」，不是崩溃也不是走完成功分支', async () => {
    await coll.drop().catch(() => {});

    const r = run(['--apply']);

    expect(r.status).toBe(0);
    expect(r.stdout).toContain('无需处理');
    // 良性出口必须停在"无需处理"，不能一路穿到"处理完成"的复核报告
    expect(r.stdout).not.toContain('处理完成');
    expect(await mongoose.connection.db.listCollections({ name: COLL }).toArray()).toHaveLength(0);
  });
});
