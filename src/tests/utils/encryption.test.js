/**
 * 加密工具函数测试 — 补齐 GCM 完整性校验、CBC 兼容路径、HMAC 时序安全
 */

describe('Encryption Utils', () => {
  let aesCipher, hmacSigner;

  beforeAll(() => {
    process.env.AES_SECRET_KEY = 'test-aes-key-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'test-hmac-secret';

    const encryption = require('../../utils/encryption');
    aesCipher = new encryption.AESCipher();
    hmacSigner = new encryption.HMACSigner();
  });

  describe('AES-GCM encrypt/decrypt', () => {
    test('should encrypt and decrypt text correctly', () => {
      const text = 'Hello World';
      const encrypted = aesCipher.encrypt(text);
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe(text);
    });

    test('should produce different ciphertext for same plaintext (random IV)', () => {
      const text = 'Hello World';
      const encrypted1 = aesCipher.encrypt(text);
      const encrypted2 = aesCipher.encrypt(text);
      expect(encrypted1).not.toBe(encrypted2);
    });

    test('should handle empty string', () => {
      const encrypted = aesCipher.encrypt('');
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe('');
    });

    test('should handle Chinese characters', () => {
      const text = '你好世界';
      const encrypted = aesCipher.encrypt(text);
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe(text);
    });

    // 密文格式是 `gcm:<ivHex>:<tagHex>:<cipherB64>`，decrypt 先切掉 'gcm:' 前缀，
    // 再按 3 段解析。原两条"篡改"用例把 payload 当成了 `iv:tag:cipher`（实际它
    // 只是 ivHex 一段），造出来的串分别是 2 段和"tag 段为空"，于是抛的是
    // 「无效的 GCM 密文格式」/ ERR_CRYPTO_INVALID_AUTH_TAG —— 两条都在**抵达
    // 认证判定之前**就抛了。实测：删掉 `decipher.setAuthTag(authTag)` 整行，
    // 旧用例仍全绿，即"GCM 完整性校验"当时零防护。
    const splitGcm = (encrypted) => {
      const [prefix, ivHex, tagHex, cipherB64] = encrypted.split(':');
      expect(prefix).toBe('gcm');
      expect(ivHex).toMatch(/^[0-9a-f]{24}$/);
      expect(tagHex).toMatch(/^[0-9a-f]{32}$/);
      expect(cipherB64).toBeTruthy();
      return { ivHex, tagHex, cipherB64 };
    };
    // GCM 认证失败的报错文案（Node/OpenSSL）；据此区分"认证没通过"与"输入不合格式"
    const AUTH_FAILURE = /Unsupported state|unable to authenticate|bad decrypt|auth tag/i;

    test('GCM: 同格式同长度的 authTag 被改 → 必须是认证失败而非格式错误', () => {
      const { ivHex, tagHex, cipherB64 } = splitGcm(aesCipher.encrypt('sensitive data'));
      // 逐字保持合法：仍是 16 字节十六进制，只翻转第一个字节
      const flipped = (tagHex[0] === '0' ? '1' : '0') + tagHex.slice(1);
      expect(flipped).toHaveLength(tagHex.length);
      expect(() => aesCipher.decrypt(`gcm:${ivHex}:${flipped}:${cipherB64}`)).toThrow(AUTH_FAILURE);
    });

    test('GCM: 密文被改（tag 保持原值）→ 必须是认证失败', () => {
      const text = 'sensitive data for gcm';
      const { ivHex, tagHex, cipherB64 } = splitGcm(aesCipher.encrypt(text));
      const buf = Buffer.from(cipherB64, 'base64');
      buf[0] ^= 0x01;
      const tampered = buf.toString('base64');
      expect(tampered).not.toBe(cipherB64);
      expect(Buffer.from(tampered, 'base64')).toHaveLength(buf.length);
      expect(() => aesCipher.decrypt(`gcm:${ivHex}:${tagHex}:${tampered}`)).toThrow(AUTH_FAILURE);
    });

    test('GCM: 未被篡改的原样密文仍可解密（上面三条的前置对照）', () => {
      const encrypted = aesCipher.encrypt('sensitive data');
      expect(aesCipher.decrypt(encrypted)).toBe('sensitive data');
    });

    // P3-27 把 CBC 解密改成"默认拒绝"（无认证 → 填充预言机面）。这条安全控制
    // 此前完全没有用例：把 decrypt 的 `ALLOW_LEGACY_CBC_DECRYPT !== 'true'` 判断
    // 删掉，让所有历史格式默认可解，全仓无人变红。
    test('CBC 遗留格式默认拒绝解密，仅显式开关可放行（P3-27）', () => {
      expect(() => aesCipher.decrypt('aabbccddeeff00112233445566778899:Zm9vYmFy')).toThrow(
        /拒绝解密无认证的 CBC 遗留密文/
      );

      const previous = process.env.ALLOW_LEGACY_CBC_DECRYPT;
      process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
      try {
        // 开关打开后进入 CBC 分支：密钥/IV 不匹配会抛密码学错误，
        // 但不得再抛"拒绝解密"——那才是本条要钉的行为差异
        expect(() => aesCipher.decrypt('aabbccddeeff00112233445566778899:Zm9vYmFy')).not.toThrow(
          /拒绝解密无认证的 CBC 遗留密文/
        );
      } finally {
        if (previous === undefined) delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
        else process.env.ALLOW_LEGACY_CBC_DECRYPT = previous;
      }
    });
  });

  describe('HMAC sign/verify', () => {
    test('should sign and verify correctly', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      expect(hmacSigner.verify(data, signature)).toBe(true);
    });

    test('should reject wrong signature', () => {
      const data = 'important data';
      expect(hmacSigner.verify(data, 'wrongsignature')).toBe(false);
    });

    test('should reject signature with different length', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      // 截断签名
      expect(hmacSigner.verify(data, signature.slice(0, 10))).toBe(false);
    });

    // 上面两条都在 verify 的**长度早退分支**结束（实测 'wrongsignature' 的 hex
    // 解码长度为 0、截断 10 字符解码长度为 5，而真签名是 32 字节），
    // 于是"等长但内容不同"这条唯一真正走 timingSafeEqual 的输入从未被覆盖：
    // 把 `return crypto.timingSafeEqual(sigBuffer, expectedBuffer)` 改成
    // `return true`，本文件当时 10 个用例全绿。
    test('HMAC: 等长但内容不同的签名必须为 false（唯一抵达 timingSafeEqual 的输入）', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      expect(signature).toMatch(/^[0-9a-f]{64}$/);

      const flipped = (signature[0] === '0' ? '1' : '0') + signature.slice(1);
      expect(flipped).toHaveLength(signature.length);
      expect(Buffer.from(flipped, 'hex')).toHaveLength(Buffer.from(signature, 'hex').length);
      expect(hmacSigner.verify(data, flipped)).toBe(false);

      // 数据侧同长度改动同样必须为 false（签名与数据必须绑定）
      expect(hmacSigner.verify(`${data} `, signature)).toBe(false);
    });

    test('HMAC: 大写十六进制等价的签名仍判等（长度比较不得因大小写误判）', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      expect(hmacSigner.verify(data, signature.toUpperCase())).toBe(true);
    });

    test('should reject null/undefined signature', () => {
      const data = 'important data';
      expect(hmacSigner.verify(data, null)).toBe(false);
      expect(hmacSigner.verify(data, undefined)).toBe(false);
    });
  });
});
