/**
 * immutable 档位（改配置需配套数据迁移）的启动期告警
 *
 * 守护的不变式：
 *   1. 只要配置组合满足「pepper 存在 + 历史深度 > 0」，启动期**必须**推一条
 *      password_history_pepper_rotation 告警——这是运维唯一能在启动日志里
 *      看见「口令复用防线因轮换而归零」的位置；
 *   2. 该告警必须同时计入 incSecurityAlert（"可检测 ≠ 已告警"，同 legacyCbcGuard）;
 *   3. 告警是**附加**的，不得挤掉 collectProductionWarnings 既有的任何一条
 *      （把 immutable 的 push 写进 CBC 的 if 块里，就会变成"只在开关开启时才告警"——
 *      这是本文件第 3 组用例专门盯的失效形态）；
 *   4. 指标端不可用时只保留日志文案，不影响启动（与 legacyCbcGuard 同口径）。
 *
 * 为什么不能只断言「warnings 里有这条」：
 *   第 3 条那种失效（把 push 塞进 CBC 的 if 里）在 CBC 开关**关闭**时会让告警消失，
 *   但若测试恰好把 CBC 打开，就会漏杀。故用例显式把 CBC 关掉再断言 immutable 仍然告警。
 */

const ORIGINAL_ENV = process.env;

const loadGuard = () => require('../../config/immutableConfigGuard');

describe('immutable 档位启动期告警（口令历史 pepper 轮换）', () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    // 显式关掉 CBC 开关：本文件测的是 immutable 这条**独立**告警，
    // 不能让它依赖另一条判据的开关状态。
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  describe('判据：hasPasswordHistoryToInvalidate', () => {
    test('默认（未配 PASSWORD_HISTORY_DEPTH）时历史深度 > 0 ⇒ 需要告警', () => {
      delete process.env.PASSWORD_HISTORY_DEPTH;
      const { hasPasswordHistoryToInvalidate } = loadGuard();
      expect(hasPasswordHistoryToInvalidate()).toBe(true);
    });

    test('显式配置正整数时同样需要告警', () => {
      process.env.PASSWORD_HISTORY_DEPTH = '10';
      const { hasPasswordHistoryToInvalidate } = loadGuard();
      expect(hasPasswordHistoryToInvalidate()).toBe(true);
    });

    test('passwordHistory 模块不可加载时判为 false（不告警、不抛）', () => {
      // 判据是"没有历史可归零就不报警"——避免纯噪声。
      // 用 jest.isolateModules + doMock 把 mock 限制在这一条用例内：
      // 直接 jest.doMock 会污染后续用例（实测过：doMock('../../utils/passwordHistory')
      // 会让后面所有用例的 collectInvariantWarnings 恒返回空数组，6 条用例连带变红）。
      jest.isolateModules(() => {
        jest.doMock('../../utils/passwordHistory', () => {
          throw new Error('module unavailable');
        });
        const { hasPasswordHistoryToInvalidate } = require('../../config/immutableConfigGuard');
        expect(() => hasPasswordHistoryToInvalidate()).not.toThrow();
        expect(hasPasswordHistoryToInvalidate()).toBe(false);
      });
      jest.dontMock('../../utils/passwordHistory');
    });
  });

  describe('文案：passwordHistoryRotationMessage', () => {
    test('必须点名 pepper、历史归零、无重签工具三件事', () => {
      const msg = loadGuard().passwordHistoryRotationMessage();
      // 这三个是运维据此判断"我撞上了哪个窗口"的最小信息集
      expect(msg).toMatch(/HMAC_SECRET/);
      expect(msg).toMatch(/pepper/);
      expect(msg).toMatch(/归零/);
      // "没有配套重签工具"必须写明——否则会被误认为跑一下 resign-audit-hmac 就好
      expect(msg).toMatch(/没有配套重签工具/);
      // 要指向操作手册，否则运维不知道下一步做什么
      expect(msg).toMatch(/secret-rotation\.md/);
    });
  });

  describe('收集：collectInvariantWarnings', () => {
    test('满足前提时产出一条告警', () => {
      const warnings = loadGuard().collectInvariantWarnings();
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('HMAC_SECRET');
    });

    test('必须同时计入 incSecurityAlert（"可检测 ≠ 已告警"）', () => {
      const metrics = require('../../utils/metrics');
      const spy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
      loadGuard().collectInvariantWarnings();
      expect(spy).toHaveBeenCalledWith('password_history_pepper_rotation', 'medium');
      spy.mockRestore();
    });

    test('指标端不可用时只保留文案，不向外抛（导出 API 契约）', () => {
      const metrics = require('../../utils/metrics');
      const spy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {
        throw new Error('metrics not ready');
      });
      expect(() => loadGuard().collectInvariantWarnings()).not.toThrow();
      // 文案仍在——这是"指标端挂了也不能静默"的落实
      expect(loadGuard().collectInvariantWarnings()).toHaveLength(1);
      spy.mockRestore();
    });
  });

  describe('接线：必须出现在 collectProductionWarnings 的出口里', () => {
    /** 生产环境下除待测项外全部合法，使 validateConfig 能走到告警阶段 */
    const setValidProdEnv = () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
      process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
      process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
      process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
      process.env.CORS_ORIGIN = 'https://example.com';
      process.env.ENABLE_HTTPS = 'true';
      process.env.ALLOWED_HOSTS = 'api.example.com';
      process.env.TRUST_PROXY_HOPS = '1';
      process.env.REDIS_URL = 'redis://prod-server:6379';
    };

    test('collectProductionWarnings 必须包含 immutable 告警', () => {
      setValidProdEnv();
      const warnings = require('../../config/validate').collectProductionWarnings();
      expect(warnings.some((w) => w.includes('HMAC_SECRET'))).toBe(true);
    });

    // —— 本组最关键的一条 ——
    // 变异：把 `warnings.push(...cbcAndInvariantWarnings())` 换成
    //       `if (reportLegacyCbcDecryptIfEnabled()) warnings.push(legacyCbcWarningMessage());`
    // （即 immutable 的 push 被写进 CBC 的 if 块里）⇒ 本条必须变红。
    // 因为此处 CBC 开关是**关闭**的，那条路径下 immutable 告警会整条消失。
    test('CBC 开关关闭时 immutable 告警仍必须出现（两者不许共用同一 if）', () => {
      setValidProdEnv();
      delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
      const warnings = require('../../config/validate').collectProductionWarnings();
      expect(warnings.some((w) => w.includes('ALLOW_LEGACY_CBC_DECRYPT'))).toBe(false);
      expect(warnings.some((w) => w.includes('HMAC_SECRET'))).toBe(true);
    });

    test('CBC 开启时两条告警都要在（不许互相顶掉）', () => {
      setValidProdEnv();
      process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
      const warnings = require('../../config/validate').collectProductionWarnings();
      expect(warnings.some((w) => w.includes('ALLOW_LEGACY_CBC_DECRYPT'))).toBe(true);
      expect(warnings.some((w) => w.includes('HMAC_SECRET'))).toBe(true);
    });
  });

  // ==========================================================================
  // PII 轮换旧钥残留（2026-09-30 追加）
  //
  // 守护的不变式：
  //   1. 生产环境 + PII_ROTATION_OLD_AES_KEY 非空 ⇒ **必须**推
  //      pii_rotation_old_key_lingering 告警并计入 incSecurityAlert；
  //   2. **反向**：变量不存在 / 为空串 / 非生产环境 ⇒ **不得**告警
  //      （没有这两条，`if (true)` 恒真的实现也能让第 1 条通过）；
  //   3. 空串必须判为「无残留」——`.env` 写 `KEY=`、compose 传空值是常见的
  //      unset 等价写法，判成残留会造成恒真误报。
  // ==========================================================================
  describe('PII 轮换旧钥残留（pii_rotation_old_key_lingering）', () => {
    const OLD_KEY = 'pii-rotation-old-aes-key-32-chars-min!!';

    beforeEach(() => {
      delete process.env.PII_ROTATION_OLD_AES_KEY;
      delete process.env.NODE_ENV;
    });

    describe('判据：hasPiiOldKeyLingering', () => {
      test('变量存在且非空 ⇒ true', () => {
        process.env.PII_ROTATION_OLD_AES_KEY = OLD_KEY;
        const { hasPiiOldKeyLingering } = loadGuard();
        expect(hasPiiOldKeyLingering()).toBe(true);
      });

      test('变量不存在 ⇒ false', () => {
        const { hasPiiOldKeyLingering } = loadGuard();
        expect(hasPiiOldKeyLingering()).toBe(false);
      });

      test('空串 / 纯空白 ⇒ false（unset 的等价物，不得误报）', () => {
        const g1 = loadGuard();
        process.env.PII_ROTATION_OLD_AES_KEY = '';
        expect(g1.hasPiiOldKeyLingering()).toBe(false);
        process.env.PII_ROTATION_OLD_AES_KEY = '   ';
        expect(g1.hasPiiOldKeyLingering()).toBe(false);
      });
    });

    describe('收集：collectInvariantWarnings', () => {
      test('生产环境 + 旧钥残留 ⇒ 告警出现且计入 incSecurityAlert', () => {
        process.env.NODE_ENV = 'production';
        process.env.PII_ROTATION_OLD_AES_KEY = OLD_KEY;
        const incSecurityAlert = jest.fn();
        jest.isolateModules(() => {
          jest.doMock('../../utils/metrics', () => ({ incSecurityAlert }));
          const m = require('../../config/immutableConfigGuard');
          const ws = m.collectInvariantWarnings();
          expect(ws.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(true);
          expect(incSecurityAlert).toHaveBeenCalledWith('pii_rotation_old_key_lingering', 'medium');
        });
        jest.dontMock('../../utils/metrics');
      });

      // —— 本组最关键的反向断言 ——
      // 变异：把 `process.env.NODE_ENV === 'production' && hasPiiOldKeyLingering()`
      // 的任一条件去掉（或整体写成恒真）⇒ 本条必须变红。
      test('生产环境但无旧钥 ⇒ 不得出现该告警（反向断言，防恒真）', () => {
        process.env.NODE_ENV = 'production';
        const { collectInvariantWarnings } = loadGuard();
        const ws = collectInvariantWarnings();
        expect(ws.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(false);
      });

      test('有旧钥但非生产环境 ⇒ 不得出现该告警（开发机/CI 演练是正常的）', () => {
        process.env.NODE_ENV = 'development';
        process.env.PII_ROTATION_OLD_AES_KEY = OLD_KEY;
        const { collectInvariantWarnings } = loadGuard();
        const ws = collectInvariantWarnings();
        expect(ws.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(false);
      });

      test('生产环境 + 空串旧钥 ⇒ 不得出现该告警（unset 等价物不误报）', () => {
        process.env.NODE_ENV = 'production';
        process.env.PII_ROTATION_OLD_AES_KEY = '';
        const { collectInvariantWarnings } = loadGuard();
        const ws = collectInvariantWarnings();
        expect(ws.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(false);
      });

      test('指标端不可用时不抛，文案仍产出', () => {
        process.env.NODE_ENV = 'production';
        process.env.PII_ROTATION_OLD_AES_KEY = OLD_KEY;
        jest.isolateModules(() => {
          jest.doMock('../../utils/metrics', () => {
            throw new Error('metrics unavailable');
          });
          const m = require('../../config/immutableConfigGuard');
          expect(() => m.collectInvariantWarnings()).not.toThrow();
          expect(
            m.collectInvariantWarnings().some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))
          ).toBe(true);
        });
        jest.dontMock('../../utils/metrics');
      });
    });

    describe('接线：collectProductionWarnings 必须带上这条', () => {
      const setValidProdEnv = () => {
        process.env.NODE_ENV = 'production';
        process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
        process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
        process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
        process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
        process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
        process.env.CORS_ORIGIN = 'https://example.com';
        process.env.ENABLE_HTTPS = 'true';
        process.env.ALLOWED_HOSTS = 'api.example.com';
        process.env.TRUST_PROXY_HOPS = '1';
        process.env.REDIS_URL = 'redis://prod-server:6379';
        delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
      };

      test('生产环境 + 旧钥残留 ⇒ 经合并出口出现在告警列表里', () => {
        setValidProdEnv();
        process.env.PII_ROTATION_OLD_AES_KEY = OLD_KEY;
        const warnings = require('../../config/validate').collectProductionWarnings();
        expect(warnings.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(true);
      });

      test('生产环境无残留 ⇒ 该告警不得出现，且不得顶掉既有告警', () => {
        setValidProdEnv();
        const warnings = require('../../config/validate').collectProductionWarnings();
        expect(warnings.some((w) => w.includes('PII_ROTATION_OLD_AES_KEY'))).toBe(false);
        expect(warnings.some((w) => w.includes('HMAC_SECRET'))).toBe(true);
      });
    });
  });
});
