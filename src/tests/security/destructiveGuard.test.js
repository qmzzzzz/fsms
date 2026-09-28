/**
 * 破坏性脚本护栏测试（M-08）
 *
 * 背景：仓库内多个脚本会批量改写/删除数据，护栏口径原先不一致——
 * run-rollback-drill 需双标志 + 库名白名单，而 resign-audit-hmac /
 * fix-token-blacklist-index / migrate-mfa-secret 只需单个 --apply，
 * 且默认回退本地库 URI。更严重的是 run-rollback-drill 的白名单本身
 * 是 fail-open 的（未设置 ALLOWED_SOURCE_DB 时条件恒假 = 白名单不存在）。
 *
 * 本文件锁定共享护栏（scripts/destructiveGuard.js）的 fail-closed 语义。
 *
 * 【本批追加的第二道洞：只比库名挡不住同名库】
 * 护栏原先只比对库名，而**回退库与生产库同名**（`docker-compose.yml` 的
 * `MONGO_INITDB_DATABASE`、`.env.example` 的 `ALLOWED_SOURCE_DB` 都是
 * `fire_safety_db`）。于是这条路径全程没有一道闸：
 *   `ssh -L 27017:mongo.prod:27017 <prod>` 把生产库打到本机 27017，
 *   而 `MONGODB_URI` 忘了 export ⇒ 脚本用回退串连上 127.0.0.1:27017，
 *   实际就是生产库 ⇒ dbName 命中白名单 ⇒ `dropIndex` / `deleteMany` 落在生产。
 * 主机段从头到尾没被比较过。收口方式两条（都只朝"拒绝"方向收紧）：
 *   ① `isFallback && apply` 直接拒绝（回退出来的库不许做破坏性写）；
 *   ② `ALLOWED_SOURCE_DB` 支持 `host:port/db` 全限定条目，想收紧到指定机器就能表达。
 */

const {
  LOCAL_FALLBACK_URI,
  dbNameFromUri,
  hostFromUri,
  resolveMongoUri,
  assertApplyAllowed,
} = require('../../../scripts/destructiveGuard');

describe('destructiveGuard（M-08 破坏性脚本护栏）', () => {
  const ORIG = {};
  const KEYS = ['MONGODB_URI', 'ALLOWED_SOURCE_DB'];
  let origExitCode;

  beforeEach(() => {
    KEYS.forEach((k) => {
      ORIG[k] = process.env[k];
      delete process.env[k];
    });
    origExitCode = process.exitCode;
    process.exitCode = undefined;
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    KEYS.forEach((k) => {
      if (ORIG[k] === undefined) delete process.env[k];
      else process.env[k] = ORIG[k];
    });
    process.exitCode = origExitCode;
    jest.restoreAllMocks();
  });

  describe('dbNameFromUri', () => {
    test.each([
      ['mongodb://127.0.0.1:27017/fire_safety_db', 'fire_safety_db'],
      ['mongodb://user:pw@host:27017/mydb', 'mydb'],
      ['mongodb://host:27017/mydb?retryWrites=true', 'mydb'],
      ['mongodb+srv://cluster.example.net/appdb', 'appdb'],
      ['mongodb://host:27017/mydb/', 'mydb'],
      ['mongodb://host:27017', ''],
      ['', ''],
      [null, ''],
      [undefined, ''],
    ])('%p → %p', (uri, expected) => {
      expect(dbNameFromUri(uri)).toBe(expected);
    });
  });

  describe('hostFromUri（白名单要比的第二维）', () => {
    test.each([
      ['mongodb://127.0.0.1:27017/fire_safety_db', '127.0.0.1:27017'],
      ['mongodb://user:pw@10.0.0.9:27017/fire_safety_db', '10.0.0.9:27017'],
      ['mongodb://USER:PW@HostA:27017/db?retryWrites=true', 'hosta:27017'],
      ['mongodb+srv://cluster.example.net/appdb', 'cluster.example.net'],
      ['mongodb://host:27017/mydb/', 'host:27017'],
      ['mongodb://127.0.0.1:27017', '127.0.0.1:27017'],
      ['', ''],
      [null, ''],
      [undefined, ''],
    ])('%p → %p', (uri, expected) => {
      expect(hostFromUri(uri)).toBe(expected);
    });

    test('密码里含 @ 时不能把主机段切成「ss@prod-mongo:27017」', () => {
      expect(hostFromUri('mongodb://user:p@ss@prod-mongo:27017/fire_safety_db')).toBe(
        'prod-mongo:27017'
      );
    });
  });

  describe('resolveMongoUri', () => {
    test('已设置 MONGODB_URI 时直接采用，且不告警', () => {
      process.env.MONGODB_URI = 'mongodb://prod-host:27017/prod_db';
      const r = resolveMongoUri({ scriptName: 'x.js' });
      expect(r.uri).toBe('mongodb://prod-host:27017/prod_db');
      expect(r.dbName).toBe('prod_db');
      expect(r.host).toBe('prod-host:27017');
      expect(r.isFallback).toBe(false);
      expect(console.warn).not.toHaveBeenCalled();
    });

    test('未设置时回退本地库并显式告警（不再静默回退）', () => {
      const r = resolveMongoUri({ scriptName: 'x.js' });
      expect(r.uri).toBe(LOCAL_FALLBACK_URI);
      expect(r.dbName).toBe('fire_safety_db');
      expect(r.host).toBe('127.0.0.1:27017');
      expect(r.isFallback).toBe(true);
      expect(console.warn).toHaveBeenCalled();
    });
  });

  describe('assertApplyAllowed（fail-closed 白名单）', () => {
    test('演练模式（apply=false）一律放行，不校验白名单', () => {
      // 即便未设置白名单也不拦截：演练不改数据，应能正常出报告
      expect(assertApplyAllowed({ scriptName: 'x.js', dbName: 'any', apply: false })).toBe(true);
      expect(process.exitCode).toBeUndefined();
    });

    // ---- 核心：M-08 的 fail-open → fail-closed ----
    test('apply=true 但未设置 ALLOWED_SOURCE_DB → 拒绝（原先静默放行）', () => {
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        apply: true,
      });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
      expect(console.error).toHaveBeenCalled();
    });

    test('apply=true 且目标库在白名单内 → 放行', () => {
      process.env.ALLOWED_SOURCE_DB = 'fire_safety_db';
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        apply: true,
      });
      expect(ok).toBe(true);
      expect(process.exitCode).toBeUndefined();
    });

    test('apply=true 但目标库不在白名单内 → 拒绝', () => {
      process.env.ALLOWED_SOURCE_DB = 'drill_db';
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        apply: true,
      });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
    });

    test('白名单支持多库（逗号分隔，含空格）', () => {
      process.env.ALLOWED_SOURCE_DB = 'drill_db, shadow_db , fire_safety_db';
      expect(assertApplyAllowed({ scriptName: 'x.js', dbName: 'shadow_db', apply: true })).toBe(
        true
      );
      expect(assertApplyAllowed({ scriptName: 'x.js', dbName: 'other_db', apply: true })).toBe(
        false
      );
    });

    test('空白串白名单视为未设置 → 拒绝', () => {
      process.env.ALLOWED_SOURCE_DB = '   ,  , ';
      const ok = assertApplyAllowed({ scriptName: 'x.js', dbName: 'any_db', apply: true });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
    });

    test('无法解析库名时拒绝（不因库名为空而放行）', () => {
      process.env.ALLOWED_SOURCE_DB = 'fire_safety_db';
      const ok = assertApplyAllowed({ scriptName: 'x.js', dbName: '', apply: true });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
    });

    // ---- 核心：回退库与生产库同名，只比库名挡不住隧道到本地的生产库 ----
    test('回退库 + apply → 拒绝（即便库名命中白名单：主机段从未被比较）', () => {
      // 复现的正是这条路径：ssh -L 27017:mongo.prod:27017 prod + 忘记 export MONGODB_URI
      process.env.ALLOWED_SOURCE_DB = 'fire_safety_db';
      const r = resolveMongoUri({ scriptName: 'x.js' });
      expect(r.isFallback).toBe(true);
      expect(r.dbName).toBe('fire_safety_db');
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: r.dbName,
        host: r.host,
        isFallback: r.isFallback,
        apply: true,
      });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('回退'));
    });

    test('回退库 + 演练（apply=false）→ 仍放行（本地开发要能出报告）', () => {
      // 这条与上一条成对：收紧只作用在"写"这一侧，不作用在"读"这一侧
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        host: '127.0.0.1:27017',
        isFallback: true,
        apply: false,
      });
      expect(ok).toBe(true);
      expect(process.exitCode).toBeUndefined();
    });

    // ---- 全限定白名单条目：把放行面收紧到"某台机器上的某个库" ----
    test('条目为 host:port/db 且主机与库名都命中 → 放行', () => {
      process.env.ALLOWED_SOURCE_DB = 'mongo.prod.internal:27017/fire_safety_db';
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        host: 'mongo.prod.internal:27017',
        apply: true,
      });
      expect(ok).toBe(true);
      expect(process.exitCode).toBeUndefined();
    });

    test('条目为 host:port/db 而实际主机不同 → 拒绝（同名库不再是放行理由）', () => {
      process.env.ALLOWED_SOURCE_DB = 'mongo.prod.internal:27017/fire_safety_db';
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        host: '127.0.0.1:27017',
        apply: true,
      });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
    });

    test('条目为 host:port/db 但调用方没传 host → 拒绝（不静默降级成只比库名）', () => {
      process.env.ALLOWED_SOURCE_DB = 'mongo.prod.internal:27017/fire_safety_db';
      const ok = assertApplyAllowed({ scriptName: 'x.js', dbName: 'fire_safety_db', apply: true });
      expect(ok).toBe(false);
      expect(process.exitCode).toBe(2);
    });

    test('全限定条目：主机段忽略大小写、库名段区分大小写', () => {
      // 主机段按 DNS 语义不敏感；Mongo 库名本身敏感，整条 toLowerCase 会把
      // 'firesafetydb' 也判为命中（本文件对这条写了反向断言）
      process.env.ALLOWED_SOURCE_DB = 'MONGO.Prod.Internal:27017/FireSafetyDb';
      expect(
        assertApplyAllowed({
          scriptName: 'x.js',
          dbName: 'FireSafetyDb',
          host: 'mongo.prod.internal:27017',
          apply: true,
        })
      ).toBe(true);
      expect(process.exitCode).toBeUndefined();
      expect(
        assertApplyAllowed({
          scriptName: 'x.js',
          dbName: 'firesafetydb',
          host: 'mongo.prod.internal:27017',
          apply: true,
        })
      ).toBe(false);
    });

    test('裸库名条目保持原语义（.env.example 的写法不因新增维度而失效）', () => {
      process.env.ALLOWED_SOURCE_DB = 'fire_safety_db';
      const ok = assertApplyAllowed({
        scriptName: 'x.js',
        dbName: 'fire_safety_db',
        host: 'whatever:27017',
        apply: true,
      });
      expect(ok).toBe(true);
      expect(process.exitCode).toBeUndefined();
    });
  });
});
