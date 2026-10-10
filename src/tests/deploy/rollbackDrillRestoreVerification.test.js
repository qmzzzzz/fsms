'use strict';

/**
 * 回滚演练脚本必须自查「回灌后库里到底有多少条」
 *   scripts/run-rollback-drill.js --apply-source
 *
 * 原实现把 `restoreCollection()` 的返回值直接丢弃，manifest 里的 `documents` 是
 * **清空之前**的读数，然后无条件 `console.log(...)` + 退出码 0。于是这三件事
 * 全都长得像「演练通过」：
 *   · 回灌中途少写了一批（bulkWrite 部分失败、_id 冲突、文件被截断）；
 *   · 快照与清空之间被并发写入的文档被 deleteMany 抹掉，再也没人写回来；
 *   · 集合本来就是空的（新库演练），清空了个寂寞。
 * 演练脚本的唯一产物就是「回滚这条路走得通」这个结论，它不自证就是假绿灯。
 *
 * 本套件用真实子进程 + 真实内存 MongoDB 跑完整链路，判据分三层：
 * ① 脚本自己的报告（restored 逐集合等于 documents、restoreVerified 为真）；
 * ② **测试独立**回读数据库的条数（脚本报告与库不一致时，以库为准判红）；
 * ③ 落盘的 manifest 文件与 stdout 报告同口径（演练记录是留给人的证据）。
 * 另外钉住两条护栏在参数改造后仍然成立：未知参数与白名单不匹配时
 * 必须退出码 2 且**一条数据都没动**。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'run-rollback-drill.js');
const COLLECTIONS = ['users', 'roles', 'permissions', 'auditlogs'];

/** 每个集合造多少条：互不相同且非 1，避免「只有一条」时的巧合绿 */
const SEED_COUNTS = { users: 3, roles: 2, permissions: 4, auditlogs: 5 };

const dbNameFrom = (uri) => {
  const noQuery = uri.split('?')[0];
  return noQuery.slice(noQuery.lastIndexOf('/') + 1);
};

/**
 * 专用库隔离（2026-10-10，随机顺序门禁实测红后的修法）：
 * globalSetup 全局只起一个内存 mongod，所有套件共用同一个库名；而本套件的
 * seed()（以及受测脚本本身）会对目标库 deleteMany({}) 清空四个集合并回灌。
 * jest --randomize 固定 seed 门禁实测：与 security/chainResignPrecheck 并发
 * 执行时，后者的夹具行（action=zzq_a1..a3）被这里的清空抹掉，snapshot 从
 * 3 行变 0 行 ⇒ 假红（seed 20260917 复现一次；默认顺序与另两个种子当时
 * 未重叠，属时序性偶发，不是每次必红）。修法与 models/auditSparseIndexSemantics
 * .test.js 同族（该文件头记载了同一族竞态）：不碰共享库——在同一 mongod 上
 * 开后缀库，清空/回灌/断言全部只发生在专用库内。受测脚本按 URI 里的库名
 * 作业（run-rollback-drill.js 的 dbNameFromUri），故隔离对断言零影响。
 */
const DRILL_DB_SUFFIX = '_rollback_drill';
const drillUri = () => {
  const uri = process.env.MONGODB_URI;
  const qIndex = uri.indexOf('?');
  const base = qIndex === -1 ? uri : uri.slice(0, qIndex);
  const query = qIndex === -1 ? '' : uri.slice(qIndex);
  return base + DRILL_DB_SUFFIX + query;
};

describe('run-rollback-drill.js --apply-source 的自查与护栏', () => {
  let backupDir;
  let dbName;

  const seed = async () => {
    const db = mongoose.connection.db;
    for (const name of COLLECTIONS) {
      await db.collection(name).deleteMany({});
      const docs = Array.from({ length: SEED_COUNTS[name] }, (_, i) => ({
        marker: `${name}_${i}`,
      }));
      await db.collection(name).insertMany(docs);
    }
  };

  const countAll = async () => {
    const db = mongoose.connection.db;
    const out = {};
    for (const name of COLLECTIONS) out[name] = await db.collection(name).countDocuments({});
    return out;
  };

  const run = (flags, extraEnv = {}) =>
    spawnSync(process.execPath, [SCRIPT, ...flags], {
      cwd: ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        MONGODB_URI: drillUri(),
        ALLOWED_SOURCE_DB: dbName,
        ...extraEnv,
      },
    });

  /** stdout 末尾的 JSON 报告（前面混有 >>> 与日志行） */
  const report = (stdout) => {
    const start = stdout.indexOf('{\n  "uri"');
    expect(start).toBeGreaterThanOrEqual(0);
    return JSON.parse(stdout.slice(start));
  };

  beforeAll(async () => {
    // worker 进程复用：上个套件若留下未关的连接（指向共享库），先关掉再连
    // 专用库——否则 readyState !== 0 时会复用旧连接，清空又落回共享库。
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
    await mongoose.connect(drillUri());
    dbName = dbNameFrom(drillUri());
    backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdr-verify-'));
  });

  afterAll(async () => {
    if (backupDir) fs.rmSync(backupDir, { recursive: true, force: true });
    if (mongoose.connection.readyState !== 0) {
      for (const name of COLLECTIONS) {
        await mongoose.connection.db
          .collection(name)
          .deleteMany({})
          .catch(() => {});
      }
      await mongoose.connection.close();
    }
  });

  test('1 清空+回灌后：脚本报告的 restored 逐集合等于快照数，库内实际条数一致', async () => {
    await seed();
    const r = run(['--apply-source', '--yes', '--backup-dir', backupDir]);

    expect(r.status).toBe(0);
    const rep = report(r.stdout);
    expect(rep.applySource).toBe(true);
    expect(rep.restoreVerified).toBe(true);
    for (const name of COLLECTIONS) {
      expect(rep.collections[name].documents).toBe(SEED_COUNTS[name]);
      expect(rep.collections[name].restored).toBe(SEED_COUNTS[name]);
    }
    // ② 独立回读：不采信脚本自报的任何数字
    expect(await countAll()).toEqual({
      users: 3,
      roles: 2,
      permissions: 4,
      auditlogs: 5,
    });
  });

  test('2 落盘 manifest 与 stdout 同口径（演练记录要能事后复核）', async () => {
    await seed();
    const r = run(['--apply-source', '--yes', '--backup-dir', backupDir]);
    expect(r.status).toBe(0);

    const files = fs
      .readdirSync(backupDir)
      .filter((f) => f.startsWith('manifest-'))
      .sort();
    expect(files.length).toBeGreaterThanOrEqual(1);
    const latest = JSON.parse(
      fs.readFileSync(path.join(backupDir, files[files.length - 1]), 'utf8')
    );
    expect(latest.restoreVerified).toBe(true);
    // 快照数与回灌数都必须在文件里——只有 documents 的 manifest 无法自证
    for (const name of COLLECTIONS) {
      expect(latest.collections[name].restored).toBe(SEED_COUNTS[name]);
    }
    expect(latest.totalSnapshotDocuments).toBe(14);
  });

  test('3 未知参数：退出码 2、不写任何产物、数据一条没动', async () => {
    await seed();
    const before = await countAll();
    const dirBefore = fs.readdirSync(backupDir).length;

    const r = run(['--apply-source', '--yes', '--backup-di', backupDir]);

    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--backup-di');
    expect(fs.readdirSync(backupDir).length).toBe(dirBefore);
    expect(await countAll()).toEqual(before);
  });

  test('4 库名白名单仍是硬闸：不在 ALLOWED_SOURCE_DB 内则拒绝且不清空', async () => {
    await seed();
    const r = run(['--apply-source', '--yes', '--backup-dir', backupDir], {
      ALLOWED_SOURCE_DB: 'zz_not_in_allow_list',
    });

    expect(r.status).toBe(2);
    expect(r.stderr).toContain('ALLOWED_SOURCE_DB');
    // 拒绝必须发生在 deleteMany 之前
    expect(await countAll()).toEqual({ users: 3, roles: 2, permissions: 4, auditlogs: 5 });
  });

  test('5 不带 --yes 的 --apply-source 仍然落不了斧（护栏没有被新解析器绕开）', async () => {
    await seed();
    const r = run(['--apply-source', '--backup-dir', backupDir]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--yes');
    expect(await countAll()).toEqual({ users: 3, roles: 2, permissions: 4, auditlogs: 5 });
  });
});
