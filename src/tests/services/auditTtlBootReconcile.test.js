/**
 * 审计留存 TTL 的启动期常驻对账（改档后唯一能落到物理索引的地方）
 *
 * 缺陷形态（读码 + migrate-mongo 判据核实，不是猜测）：
 *   `migrate-mongo-config.js:88` 是 `useFileHash: false`，迁移标识**只有文件名**。
 *   所以任何跑过 `20260831000000` / `20260919000000` 的库，改这两个文件的内容
 *   都不会重放（后者本身就是为补前者的可达性而追加的一次性迁移，自己也一样一次性）；
 *   而模型侧 `createIndexes` 遇同名不同选项只抛 IndexOptionsConflict，不改选项。
 *   ⇒ `AUDIT_RETENTION_DAYS` 从 180 改到 365 之后，物理 TTL 仍按 180 天删审计记录。
 *   constants/retention.js 自己把这类偏差定性为「对外声明留存 N 天、实际留得更少」。
 *
 * 修法复用仓内既有形态（reconcileUserIndexes / reconcileTokenBlacklistIndexes）：
 * 启动时比对 `timestamp_-1` 的 expireAfterSeconds 与声明值，不一致就 collMod 原地更正。
 *
 * 本文件刻意用**独立数据库**：对账断言的本质是物理索引状态，而共享库上别的套件
 * 会在 beforeEach 删 auditlogs 的索引（这条口径来自批次 61 的同族教训：
 * 依赖索引存在性的断言放共享库＝偶发红）。这里也不 require AuditLog 模型，
 * 免得 autoIndex 先把索引建出来、把"索引尚不存在"那一档测成假绿。
 */
const mongoose = require('mongoose');

const { reconcileAuditTtlIndex } = require('../../services/initData');
const { RETENTION_SECONDS } = require('../../constants/retention');
const logger = require('../../utils/logger');

const DB_NAME = 'zzb_ttl_reconcile';
const INDEX_NAME = 'timestamp_-1';
const STALE = RETENTION_SECONDS + 7 * 24 * 3600;

const coll = () => mongoose.connection.collection('auditlogs');
const nsExists = async () =>
  (await mongoose.connection.db.listCollections({ name: 'auditlogs' }).toArray()).length > 0;
/** 保证"集合在"这一前提由用例自己造（48/NamespaceExists＝前提已满足） */
const ensureCollection = async () => {
  await mongoose.connection.db.createCollection('auditlogs').catch((e) => {
    if (e.codeName === 'NamespaceExists' || e.code === 48) return;
    throw e;
  });
  expect(await nsExists()).toBe(true);
};
const indexesNow = async () => {
  let list;
  try {
    list = await coll().indexes();
  } catch (e) {
    if (e.codeName === 'NamespaceNotFound' || e.code === 26) return [];
    throw e;
  }
  return list;
};
const ttlOf = async () => {
  const idx = (await indexesNow()).find((i) => i.name === INDEX_NAME);
  return idx ? idx.expireAfterSeconds : undefined;
};

/** 把 timestamp_-1 造给定的物理形态（null = 建索引但不带 TTL；false = 不建该索引） */
const forceIndex = async (expireAfterSeconds) => {
  const existing = (await indexesNow()).find((i) => i.name === INDEX_NAME);
  if (existing) await coll().dropIndex(INDEX_NAME);
  if (expireAfterSeconds === false) return;
  await coll().createIndex(
    { timestamp: -1 },
    {
      name: INDEX_NAME,
      ...(expireAfterSeconds === null ? {} : { expireAfterSeconds }),
    }
  );
};

/** 只挑出会改动 auditlogs 索引形态的写命令，用于区分"发了 collMod"与"什么都没发"。
 *  实测（驱动 7.5.0）：`collection.dropIndex()/createIndex()` 走 executeOperation，
 *  **不经过 db.command**——所以"删重建"在这里留不下 dropIndexes/createIndexes 痕迹，
 *  它表现为 issued() 变空。因此判据必须是"恰好一条 collMod"，不是"没有别的写命令"：
 *  只断后者会让删重建的改动从这条用例静默溜过去（变异臂 M5 实测到此）。 */
const spyCollMod = () => {
  const spy = jest.spyOn(mongoose.connection.db, 'command');
  const issued = () =>
    spy.mock.calls
      .map(([cmd]) => cmd)
      .filter(
        (c) =>
          c &&
          (c.collMod === 'auditlogs' ||
            c.createIndexes === 'auditlogs' ||
            c.dropIndexes === 'auditlogs')
      );
  return { spy, issued };
};

/** 对账应当发出的唯一一条写命令（原地 collMod） */
const COLL_MOD_CMD = {
  collMod: 'auditlogs',
  index: { keyPattern: { timestamp: -1 }, expireAfterSeconds: RETENTION_SECONDS },
};

describe('auditlogs TTL 的启动期对账', () => {
  beforeAll(async () => {
    const base = process.env.MONGODB_URI;
    const [head, query] = base.split('?');
    const uri = `${head.replace(/\/[^/]*$/, `/${DB_NAME}`)}${query ? `?${query}` : ''}`;
    await mongoose.connect(uri);
    // 自证 URI 改写真的换了库：否则上面那段"独立库"的前提是空的
    expect(mongoose.connection.name).toBe(DB_NAME);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await coll()
      .drop()
      .catch(() => {});
    await mongoose.connection.close().catch(() => {});
  });

  test('不一致 → 发一条 collMod 把 TTL 原地对齐到声明值', async () => {
    await forceIndex(STALE);
    expect(await ttlOf()).toBe(STALE); // 前提：物理索引此刻停在旧档位
    const { spy, issued } = spyCollMod();

    await reconcileAuditTtlIndex();

    // 正向对照：证明 collMod 真的走 db.command 这条路（否则下面那条"未发写命令"是空断言）
    expect(issued()).toEqual([COLL_MOD_CMD]);
    spy.mockRestore();
    expect(await ttlOf()).toBe(RETENTION_SECONDS);
  });

  test('对齐是原地的：不删重建、不改名、不改键形', async () => {
    await forceIndex(STALE);
    const { issued } = spyCollMod();
    await reconcileAuditTtlIndex();
    // "原地"必须看写命令形态：删重建的净结果与 collMod 相同（同名、同键、同 TTL），
    // 只有"这条改动是一次 collMod"能把它区分开。
    expect(issued()).toEqual([COLL_MOD_CMD]);
    const idx = (await indexesNow()).find((i) => i.name === INDEX_NAME);
    expect({ name: idx.name, key: idx.key }).toEqual({ name: INDEX_NAME, key: { timestamp: -1 } });
  });

  test('反向对照：已等于声明值时一条写命令都不发', async () => {
    await forceIndex(RETENTION_SECONDS);
    const { issued } = spyCollMod();

    await reconcileAuditTtlIndex();

    expect(issued()).toEqual([]);
    expect(await ttlOf()).toBe(RETENTION_SECONDS);
  });

  test('回滚后遗症：down() 留下的无 TTL 索引被补回声明值', async () => {
    await forceIndex(null);
    expect(await ttlOf()).toBeUndefined();

    await reconcileAuditTtlIndex();

    expect(await ttlOf()).toBe(RETENTION_SECONDS);
  });

  test('索引尚不存在 → 不创建（创建是模型声明与 20260831000000 的职责）', async () => {
    // 本档的场景是"集合在、TTL 索引不在"。前提必须自己造：`--randomize` 把
    // 「集合不存在」那一档排到前面时，独立库整个被 drop 掉，而 forceIndex(false)
    // 只删不建 ⇒ 这一档会在"根本没有集合"的空档上恒绿（那测的是另一件事，且已被它自己那档覆盖）。
    await ensureCollection();
    await forceIndex(false);
    const { issued } = spyCollMod();

    await reconcileAuditTtlIndex();

    expect(issued()).toEqual([]);
    expect((await indexesNow()).map((i) => i.name)).not.toContain(INDEX_NAME);
  });

  test('对账失败（非「集合不存在」）→ 告警落日志且不阻断启动，物理状态不被改坏', async () => {
    await forceIndex(STALE);
    // 只在 collMod 这一步注入失败，其余命令原样放行：否则「读索引」先炸也会走到
    // catch 分支，本用例就会因为错误的原因变绿（或因为同样的原因假绿）。
    const passThrough = mongoose.connection.db.command.bind(mongoose.connection.db);
    const attempted = [];
    const cmd = jest
      .spyOn(mongoose.connection.db, 'command')
      .mockImplementation(async (command, ...rest) => {
        if (command && command.collMod === 'auditlogs') {
          attempted.push('collMod');
          const boom = new Error('not authorized on zzb_ttl_reconcile to execute command collMod');
          boom.code = 13;
          boom.codeName = 'Unauthorized';
          throw boom;
        }
        return passThrough(command, ...rest);
      });
    const warn = jest.spyOn(logger, 'warn');

    await expect(reconcileAuditTtlIndex()).resolves.toBeUndefined();

    expect(attempted).toEqual(['collMod']); // 前提：确实走到了更正这一步
    // 宽口径 catch 的反面：把权限不足读成"没有这个索引"就是假静默——
    // 启动看起来正常而留存档位永远对不齐，且无人知道。
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('auditlogs TTL 对账跳过');
    expect(warn.mock.calls[0][0]).toContain('not authorized');
    expect(await ttlOf()).toBe(STALE);
    cmd.mockRestore();
  });

  test('集合不存在 → 静默跳过，且不顺手把集合建出来', async () => {
    // 前提是"这里真的没有集合"，所以起点必须由本用例自己造，不能借前几档的副作用：
    // 原注释写的"前几档的 createIndex 已把集合留在这里"就是一条有序用例假设——
    // `--randomize --seed=777001` 把「索引尚不存在」（forceIndex(false) 只删不建）
    // 排到本档之前时，独立库里根本没有 auditlogs，裸 drop() 抛
    // `ns does not exist` ⇒ 用例死在断言之前，红的原因还不是本档要测的那件事。
    // 只放过 26/NamespaceNotFound（＝前提已满足），其余错误必须冒泡：
    // 把 Unauthorized 读成"集合本就不存在"会让这条整档假绿。口径与 indexesNow 同源。
    await coll()
      .drop()
      .catch((e) => {
        if (e.codeName === 'NamespaceNotFound' || e.code === 26) return;
        throw e;
      });
    // 前提自证：drop 之后必须真的没有集合，否则"静默跳过"这条断言是在测另一个场景
    expect(await nsExists()).toBe(false);
    // 实测（mongodb 驱动 7.5.0）：集合缺失时 `indexes()` 抛 NamespaceNotFound/26，
    // 不是返回 []——所以下面这次「静默跳过」走的是 catch 分支而不是空列表分支。
    const { issued } = spyCollMod();

    await expect(reconcileAuditTtlIndex()).resolves.toBeUndefined();

    expect(issued()).toEqual([]);
    expect(await nsExists()).toBe(false);
  });
});
