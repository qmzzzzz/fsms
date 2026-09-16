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
 */

const {
  LOCAL_FALLBACK_URI,
  dbNameFromUri,
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

  describe('resolveMongoUri', () => {
    test('已设置 MONGODB_URI 时直接采用，且不告警', () => {
      process.env.MONGODB_URI = 'mongodb://prod-host:27017/prod_db';
      const r = resolveMongoUri({ scriptName: 'x.js' });
      expect(r.uri).toBe('mongodb://prod-host:27017/prod_db');
      expect(r.dbName).toBe('prod_db');
      expect(r.isFallback).toBe(false);
      expect(console.warn).not.toHaveBeenCalled();
    });

    test('未设置时回退本地库并显式告警（不再静默回退）', () => {
      const r = resolveMongoUri({ scriptName: 'x.js' });
      expect(r.uri).toBe(LOCAL_FALLBACK_URI);
      expect(r.dbName).toBe('fire_safety_db');
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
  });
});
