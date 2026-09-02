/**
 * 配置校验测试
 */

describe('Config Validation', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('validateConfig', () => {
    test('should not throw in development mode', () => {
      process.env.NODE_ENV = 'development';
      // 重新加载模块
      const { validateConfig } = require('../../config/validate');
      expect(() => validateConfig()).not.toThrow();
    });

    test('should throw in production with missing JWT_SECRET', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = '';
      process.env.AES_SECRET_KEY = 'test-aes-key-32-chars-minimum!!';
      process.env.HMAC_SECRET = 'test-hmac';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';

      const { validateConfig } = require('../../config/validate');

      // validateConfig 调用 process.exit，需要 mock
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit called');
      });
      const mockConsole = jest.spyOn(console, 'error').mockImplementation(() => {});

      expect(() => validateConfig()).toThrow('process.exit called');

      mockExit.mockRestore();
      mockConsole.mockRestore();
    });

    test('should throw in production with short AES key', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
      process.env.AES_SECRET_KEY = 'short';
      process.env.HMAC_SECRET = 'test-hmac';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';

      const { validateConfig } = require('../../config/validate');

      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit called');
      });
      const mockConsole = jest.spyOn(console, 'error').mockImplementation(() => {});

      expect(() => validateConfig()).toThrow('process.exit called');

      mockExit.mockRestore();
      mockConsole.mockRestore();
    });

    test('should pass in production with all valid config', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
      process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
      process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
      // HMAC_SECRET 与其他密钥同口径：>=32 字符（审计修复后不再接受 16 字符弱值）
      process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';
      process.env.TRUST_PROXY_HOPS = '1';

      const { validateConfig } = require('../../config/validate');

      expect(() => validateConfig()).not.toThrow();
    });
  });

  describe('TRUST_PROXY_HOPS 值域校验（AUX-01）', () => {
    /** 生产环境下除 TRUST_PROXY_HOPS 外全部配置合法 */
    const setValidProdEnv = () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
      process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
      process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
      process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';
      process.env.ALLOWED_HOSTS = 'api.example.com';
    };

    /** 以指定 TRUST_PROXY_HOPS 跑校验，返回收集到的错误消息 */
    const runWith = (value) => {
      setValidProdEnv();
      if (value === undefined) delete process.env.TRUST_PROXY_HOPS;
      else process.env.TRUST_PROXY_HOPS = value;

      const { validateConfig } = require('../../config/validate');
      const logger = require('../../utils/logger');
      const messages = [];
      const mockError = jest
        .spyOn(logger, 'error')
        .mockImplementation((m) => messages.push(String(m)));
      jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit called');
      });

      let exited = false;
      try {
        validateConfig();
      } catch (e) {
        exited = e.message === 'process.exit called';
      }

      mockError.mockRestore();
      mockExit.mockRestore();
      return { exited, messages: messages.join('\n') };
    };

    test.each([
      ['非数字（原先静默退化为不信任代理）', 'abc'],
      ['小数', '1.5'],
      ['负数', '-1'],
      ['零（等于不信任代理，但配置意图不明）', '0'],
      ['超出上限（过大会允许 XFF 伪造轮换 IP）', '99'],
      ['空白字符串', '   '],
    ])('%s → 启动致命错误', (_label, value) => {
      const { exited, messages } = runWith(value);
      expect(exited).toBe(true);
      expect(messages).toContain('TRUST_PROXY_HOPS');
    });

    test('缺失 → 启动致命错误', () => {
      const { exited, messages } = runWith(undefined);
      expect(exited).toBe(true);
      expect(messages).toContain('TRUST_PROXY_HOPS');
    });

    test.each([
      ['1（单层 Nginx，最常见）', '1'],
      ['3', '3'],
      ['5（上限）', '5'],
    ])('%s → 通过校验', (_label, value) => {
      const { exited } = runWith(value);
      expect(exited).toBe(false);
    });
  });

  describe('collectProductionWarnings (G6)', () => {
    test('未配置 ALLOWED_HOSTS 时产出告警', () => {
      delete process.env.ALLOWED_HOSTS;
      const { collectProductionWarnings } = require('../../config/validate');
      const warnings = collectProductionWarnings();
      expect(warnings.some((w) => w.includes('ALLOWED_HOSTS'))).toBe(true);
    });

    test('ALLOWED_HOSTS 为空白字符串时同样告警', () => {
      process.env.ALLOWED_HOSTS = '   ';
      const prevHttps = process.env.ENABLE_HTTPS;
      const restoreHttps = () => {
        if (prevHttps === undefined) delete process.env.ENABLE_HTTPS;
        else process.env.ENABLE_HTTPS = prevHttps;
      };
      process.env.ENABLE_HTTPS = 'true'; // 隔离 M-2 的 TLS 告警，只测 ALLOWED_HOSTS
      const { collectProductionWarnings } = require('../../config/validate');
      const warnings = collectProductionWarnings();
      restoreHttps();
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('ALLOWED_HOSTS');
    });

    test('已配置 ALLOWED_HOSTS 且启用 HTTPS 时无告警', () => {
      process.env.ALLOWED_HOSTS = 'api.example.com,api.example.com:443';
      const prevHttps = process.env.ENABLE_HTTPS;
      const restoreHttps = () => {
        if (prevHttps === undefined) delete process.env.ENABLE_HTTPS;
        else process.env.ENABLE_HTTPS = prevHttps;
      };
      process.env.ENABLE_HTTPS = 'true';
      const { collectProductionWarnings } = require('../../config/validate');
      const warnings = collectProductionWarnings();
      restoreHttps();
      expect(warnings).toHaveLength(0);
    });

    test('M-2：未启用 ENABLE_HTTPS 时告警（TLS 必须由某层终结）', () => {
      process.env.ALLOWED_HOSTS = 'api.example.com';
      const prevHttps = process.env.ENABLE_HTTPS;
      const restoreHttps = () => {
        if (prevHttps === undefined) delete process.env.ENABLE_HTTPS;
        else process.env.ENABLE_HTTPS = prevHttps;
      };
      delete process.env.ENABLE_HTTPS;
      const { collectProductionWarnings } = require('../../config/validate');
      const warnings = collectProductionWarnings();
      restoreHttps();
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('ENABLE_HTTPS');
      expect(warnings[0]).toContain('TLS');
    });

    test('生产环境缺失加固项只告警不退出', () => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
      process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
      process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
      process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
      process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
      process.env.CORS_ORIGIN = 'https://example.com';
      process.env.TRUST_PROXY_HOPS = '1';
      delete process.env.ALLOWED_HOSTS;

      const { validateConfig } = require('../../config/validate');
      const logger = require('../../utils/logger');
      const mockWarn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit called');
      });

      expect(() => validateConfig()).not.toThrow();
      expect(mockWarn).toHaveBeenCalledWith(expect.stringContaining('ALLOWED_HOSTS'));
      expect(mockExit).not.toHaveBeenCalled();

      mockWarn.mockRestore();
      mockExit.mockRestore();
    });
  });
});
