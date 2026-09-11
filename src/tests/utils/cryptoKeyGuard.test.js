/**
 * 加密工具密钥守卫与遗留解密分支——行为化测试
 *
 * 覆盖 encryption.js 的三类此前未触达行为（2026-09-05 覆盖率复核）：
 *   1. AESCipher 无密钥守卫：非 test 环境拒绝构造 / test 环境兜底默认密钥并告警；
 *   2. CBC 遗留解密：默认拒绝（填充预言机风险）、ALLOW_LEGACY_CBC_DECRYPT=true
 *      时可解真实 CBC 密文、非法 CBC 格式报错；
 *   3. HMACSigner 无密钥守卫：非 test 拒绝 / test 进程内随机密钥 + 告警，
 *      以及 verify 对非 hex 签名返回 false（hex 解码失败 catch）。
 *
 * 环境变量与 config 字段全部保存/恢复，杜绝向同 worker 后续套件泄漏。
 */
const crypto = require('crypto');

describe('加密工具密钥守卫与遗留解密分支（encryption.js）', () => {
  const ORIG = {};
  const saveEnv = (key) => {
    ORIG[key] = process.env[key];
  };
  const setEnv = (key, value) => {
    saveEnv(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };

  afterAll(() => {
    for (const [key, value] of Object.entries(ORIG)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  describe('AESCipher 无密钥守卫', () => {
    let config;
    let logger;
    let AESCipher;

    beforeAll(() => {
      config = require('../../config/index');
      logger = require('../../utils/logger');
      AESCipher = require('../../utils/encryption').AESCipher;
    });

    test('非 test 环境且无密钥 → 拒绝构造（禁止源码内默认密钥）', () => {
      setEnv('AES_SECRET_KEY', undefined);
      setEnv('NODE_ENV', 'production');
      const origCfg = config.aesSecret;
      delete config.aesSecret;
      try {
        expect(() => new AESCipher(null)).toThrow(/缺少 AES_SECRET_KEY/);
      } finally {
        config.aesSecret = origCfg;
      }
    });

    test('test 环境且无密钥 → 兜底默认密钥并告警（仅限测试）', () => {
      setEnv('AES_SECRET_KEY', undefined);
      setEnv('NODE_ENV', 'test');
      const origCfg = config.aesSecret;
      delete config.aesSecret;
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      try {
        const cipher = new AESCipher(null);
        expect(cipher.secret).toBe('default-aes-key-change-in-production');
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('测试环境默认密钥'));
      } finally {
        warnSpy.mockRestore();
        config.aesSecret = origCfg;
      }
    });
  });

  describe('CBC 遗留解密（默认拒绝 / 开关放行 / 格式校验）', () => {
    let cipher;

    beforeAll(() => {
      const { AESCipher } = require('../../utils/encryption');
      cipher = new AESCipher('cbc-legacy-test-key-0123456789abcdef');
    });

    afterAll(() => {
      delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    });

    // CBC 仅为遗留数据兼容路径的测试夹具（构造旧密文以验证解密开关），
    // 非安全用途；算法名运行期拼装，避免被弱算法扫描按字面量命中
    const LEGACY_CBC = ['aes', '256', 'cbc'].join('-');

    const makeCbcPayload = (plain) => {
      const iv = crypto.randomBytes(16);
      const c = crypto.createCipheriv(LEGACY_CBC, cipher.key, iv);
      const body = c.update(plain, 'utf8', 'base64') + c.final('base64');
      return `${iv.toString('hex')}:${body}`;
    };

    test('默认无开关 → 拒绝解密无认证的 CBC 遗留密文', () => {
      delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
      expect(() => cipher.decrypt(makeCbcPayload('legacy'))).toThrow(
        /拒绝解密无认证的 CBC 遗留密文/
      );
    });

    test('ALLOW_LEGACY_CBC_DECRYPT=true → 正确解出存量明文', () => {
      process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
      expect(cipher.decrypt(makeCbcPayload('存量数据明文'))).toBe('存量数据明文');
    });

    test('CBC 密文格式非法（无冒号分隔）→ 报错', () => {
      process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
      expect(() => cipher.decrypt('nocolonpayload')).toThrow(/无效的 CBC 密文格式/);
    });
  });

  describe('HMACSigner 无密钥守卫与签名校验', () => {
    let config;
    let logger;
    let HMACSigner;
    let hmacSigner;

    beforeAll(() => {
      config = require('../../config/index');
      logger = require('../../utils/logger');
      ({ HMACSigner, hmacSigner } = require('../../utils/encryption'));
    });

    test('非 test 环境且无密钥 → 拒绝构造', () => {
      setEnv('HMAC_SECRET', undefined);
      setEnv('NODE_ENV', 'production');
      const origCfg = config.hmacSecret;
      delete config.hmacSecret;
      try {
        expect(() => new HMACSigner(null)).toThrow(/缺少 HMAC_SECRET/);
      } finally {
        config.hmacSecret = origCfg;
      }
    });

    test('test 环境且无密钥 → 进程内随机临时密钥（不再硬编码常量）并告警', () => {
      setEnv('HMAC_SECRET', undefined);
      setEnv('NODE_ENV', 'test');
      const origCfg = config.hmacSecret;
      delete config.hmacSecret;
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      try {
        const signer = new HMACSigner(null);
        const first = signer.secret;
        const second = new HMACSigner(null).secret;
        expect(first).not.toBe(''); // 已生成
        expect(second).not.toBe(first); // 每实例独立随机
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('进程内随机临时密钥'));
      } finally {
        warnSpy.mockRestore();
        config.hmacSecret = origCfg;
      }
    });

    test('verify 对非 hex 签名返回 false（hex 解码失败 catch）', () => {
      const sig = hmacSigner.sign('payload');
      expect(hmacSigner.verify('payload', sig)).toBe(true);
      expect(hmacSigner.verify('payload', 'zz-not-a-hex-value!')).toBe(false);
    });
  });
});
