/**
 * TTL 对齐迁移在「空库 / 非命名空间错误」两种情况下的行为
 * （migrations/20260919000000-reconcile-audit-ttl-to-retention.js）
 *
 * 为什么要单独测这条：部署编排里 `migrate-up` 排在容器切换**之前**
 * （scripts/deployPolicy.js 的步骤顺序），而 `auditlogs` 集合要等应用启动期
 * 由模型初始化才创建。于是全新环境第一次部署时，迁移面对的就是「集合不存在」。
 * 驱动在这种情况下是**抛 NamespaceNotFound**（不是返回空数组），
 * 未捕获会让整条 `migrate-mongo up` 失败退出——部署停在"迁移未执行"这一步。
 *
 * 两条用例成对，缺一都会留缝：
 *  ① 空库必须**安静跳过**（走「索引不存在，本迁移不创建」分支）；
 *  ② 非命名空间类错误必须**照样抛出**——这条是防止有人把 catch 写成宽口径：
 *     权限不足/网络抖动被读成「索引不存在」时，迁移会打印成功却什么都没对齐，
 *     那是比崩溃更坏的假绿（同形状的坑已在 scripts/fix-token-blacklist-index.js 判过一次）。
 */

const mongoose = require('mongoose');
// 两条审计索引迁移**都要**测：migrate-mongo 按时间戳顺序执行，
// 20260831000000 在前——只修后面那条，空库首次部署仍会在第一条上中断整条链。
const MIGRATIONS = {
  '20260831000000-reconcile-audit-index-options': require('../../../migrations/20260831000000-reconcile-audit-index-options'),
  '20260919000000-reconcile-audit-ttl-to-retention': require('../../../migrations/20260919000000-reconcile-audit-ttl-to-retention'),
};

const ISOLATED_DB = 'zzqA_ttl_migration_emptydb';

describe('TTL 对齐迁移的集合缺失分支', () => {
  let conn;

  beforeAll(async () => {
    // 必须 .asPromise()：mongoose 8 的 createConnection() 返回尚未就绪的连接对象
    conn = await mongoose
      .createConnection(process.env.MONGODB_URI, {
        dbName: ISOLATED_DB,
        serverSelectionTimeoutMS: 5000,
      })
      .asPromise();
  });

  afterAll(async () => {
    if (conn) {
      // 只清自己这个库，不碰其它套件共用的内存库
      await conn.dropDatabase().catch(() => {});
      await conn.close().catch(() => {});
    }
  });

  test('前提自证：这个库里确实没有 auditlogs 集合', async () => {
    const names = (await conn.db.listCollections().toArray()).map((c) => c.name);
    expect(names).not.toContain('auditlogs');
  });

  test('空库（集合不存在）：两条迁移都必须正常返回，不得抛错中断整条 migrate-up 链', async () => {
    for (const [name, mig] of Object.entries(MIGRATIONS)) {
      await conn.db
        .collection('auditlogs')
        .drop()
        .catch(() => {});
      let err = null;
      try {
        await mig.up(conn.db);
      } catch (e) {
        err = e;
      }
      expect({ migration: name, error: err && err.message }).toEqual({
        migration: name,
        error: null,
      });
    }
  });

  test('TTL 迁移在空库下走的是「不创建、交给模型声明」分支（不是静默跳过真实漂移）', async () => {
    await conn.db
      .collection('auditlogs')
      .drop()
      .catch(() => {});
    const logs = [];
    const orig = console.log;
    console.log = (...a) => logs.push(a.join(' '));
    try {
      await MIGRATIONS['20260919000000-reconcile-audit-ttl-to-retention'].up(conn.db);
    } finally {
      console.log = orig;
    }
    expect(logs.join('\n')).toContain('不存在');
  });

  test('非命名空间错误必须原样抛出（防 catch 被放宽成假绿）', async () => {
    const boom = new Error('not authorized on auditlogs');
    boom.codeName = 'Unauthorized';
    boom.code = 13;
    for (const [name, mig] of Object.entries(MIGRATIONS)) {
      const fakeDb = {
        collection: () => ({
          indexes: async () => {
            throw boom;
          },
        }),
        command: jest.fn(),
      };
      await expect(mig.up(fakeDb)).rejects.toBe(boom);
      // 关键：不得因为"拿不到索引"就当成"索引不存在"走下去并打印成功
      expect(fakeDb.command).not.toHaveBeenCalled();
      void name;
    }
  });

  test('命名空间错误按 code 识别也要放过（不同服务端版本 codeName 不完全一致）', async () => {
    for (const [name, mig] of Object.entries(MIGRATIONS)) {
      const err = new Error('ns does not exist');
      err.code = 48;
      const fakeDb = {
        collection: () => ({
          indexes: async () => {
            throw err;
          },
        }),
        command: jest.fn(),
      };
      let thrown = null;
      try {
        await mig.up(fakeDb);
      } catch (e) {
        thrown = e;
      }
      // 断言的是「命名空间缺失不得作为失败冒出来」：getIndex 必须把它吞成"没有索引"。
      // 后面 up() 可能因为这个极简替身缺少 createIndex 等而抛别的错——那不是本用例要管的事
      // （真实空库路径由上面那条用例覆盖）。
      expect({ migration: name, isNamespaceError: thrown === err }).toEqual({
        migration: name,
        isNamespaceError: false,
      });
    }
  });
});
