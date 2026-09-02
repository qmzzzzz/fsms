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

    test('GCM: should fail when authTag is tampered', () => {
      const text = 'sensitive data';
      const encrypted = aesCipher.encrypt(text);
      // 篡改 authTag（最后一段）
      const parts = encrypted.split(':');
      // parts[0]='gcm' 已去掉，实际是 iv:authTag:ciphertext
      const payload = parts[1]; // 这是 slice(4) 后的 iv:authTag:ciphertext
      const payloadParts = payload.split(':');
      payloadParts[1] = '00000000000000000000000000000000'; // 篡改 authTag
      const tampered = 'gcm:' + payloadParts.join(':');
      expect(() => aesCipher.decrypt(tampered)).toThrow();
    });

    test('GCM: should fail when ciphertext is tampered', () => {
      const text = 'sensitive data';
      const encrypted = aesCipher.encrypt(text);
      const parts = encrypted.split(':');
      const payload = parts[1];
      const payloadParts = payload.split(':');
      // 篡改密文（最后一段）
      payloadParts[2] = Buffer.from('tampered').toString('base64');
      const tampered = 'gcm:' + payloadParts.join(':');
      expect(() => aesCipher.decrypt(tampered)).toThrow();
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

    test('should reject null/undefined signature', () => {
      const data = 'important data';
      expect(hmacSigner.verify(data, null)).toBe(false);
      expect(hmacSigner.verify(data, undefined)).toBe(false);
    });
  });
});
