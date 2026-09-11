/**
 * TOTP 工具测试（I-06）
 * 覆盖：Base32 编解码往返、RFC 4226 官方 HOTP 测试向量（HMAC-SHA1 / 6 位）、
 * verifyTotp 正反例、otpauth URI 契约、非法输入容错
 */

const {
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  verifyTotp,
  otpauthUri,
} = require('../../utils/totp');

describe('TOTP 工具（I-06）', () => {
  describe('base32 编解码', () => {
    test('编码结果只含标准字母表字符（RFC 4648，无填充）', () => {
      const secret = generateSecret();
      expect(secret).toMatch(/^[A-Z2-7]+$/);
      expect(secret).toHaveLength(32); // 20 字节 → 160 bit → 32 个 base32 字符
    });

    test('编解码往返一致（含全 0 与全 0xff 边界字节）', () => {
      for (const buf of [
        Buffer.alloc(20),
        Buffer.alloc(20, 0xff),
        Buffer.from([0]),
        Buffer.from('hello mfa 中文混合', 'utf8'),
      ]) {
        const encoded = base32Encode(buf);
        expect(base32Decode(encoded)).toEqual(buf);
      }
    });

    test('解码容忍小写、空白与填充字符', () => {
      const encoded = base32Encode(Buffer.from('abc'));
      expect(base32Decode(encoded.toLowerCase().replace(/(.{4})/g, '$1='))).toEqual(
        Buffer.from('abc')
      );
    });

    test('空串/全非法输入解码抛错（不返回空缓冲被误当有效密钥）', () => {
      expect(() => base32Decode('')).toThrow();
      expect(() => base32Decode('!!!!!')).toThrow();
    });
  });

  describe('HOTP 官方测试向量（RFC 4226 附录 B，HMAC-SHA1）', () => {
    // 标准测试密钥 "12345678901234567890" 的 Base32 表示
    const secretBase32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const secretBuf = base32Decode(secretBase32);

    // RFC 4226 附录 B 的前 10 个 6 位动态口令
    const vectors = [
      [0, '755224'],
      [1, '287082'],
      [2, '359152'],
      [3, '969429'],
      [4, '338314'],
      [5, '254676'],
      [6, '287922'],
      [7, '162583'],
      [8, '399871'],
      [9, '520489'],
    ];

    test.each(vectors)('counter=%i → %s', (counter, expected) => {
      expect(hotp(secretBuf, counter)).toBe(expected);
    });
  });

  describe('verifyTotp', () => {
    const secret = generateSecret();

    test('当前窗口的合法口令验证通过', () => {
      const counter = Math.floor(Date.now() / 1000 / 30);
      const code = hotp(base32Decode(secret), counter);
      expect(verifyTotp(secret, code)).toBe(true);
    });

    test('±1 窗口内（时钟小幅偏移）仍通过', () => {
      const counter = Math.floor(Date.now() / 1000 / 30);
      const prevCode = hotp(base32Decode(secret), counter - 1);
      expect(verifyTotp(secret, prevCode)).toBe(true);
    });

    test('窗口外（±2）口令拒绝', () => {
      const counter = Math.floor(Date.now() / 1000 / 30);
      const farCode = hotp(base32Decode(secret), counter - 2);
      expect(verifyTotp(secret, farCode)).toBe(false);
    });

    test('错误密钥 / 非法输入一律拒绝且不抛错', () => {
      expect(verifyTotp(secret, '000000')).toBeDefined();
      expect(verifyTotp(secret, 'abc12')).toBe(false); // 非 6 位
      expect(verifyTotp(secret, 'abcdef')).toBe(false); // 非数字
      expect(verifyTotp(secret, '')).toBe(false);
      expect(verifyTotp(secret, null)).toBe(false);
      expect(verifyTotp('', '123456')).toBe(false); // 无效密钥
      expect(verifyTotp('!!!', '123456')).toBe(false); // 非法密钥字符
    });
  });

  describe('otpauth URI', () => {
    test('包含标签、secret 与发行方参数，可直接被认证器识别', () => {
      const secret = generateSecret();
      const uri = otpauthUri(secret, 'admin@example.com', '消防管理系统');
      expect(uri).toContain('otpauth://totp/');
      expect(uri).toContain(encodeURIComponent('消防管理系统:admin@example.com'));
      expect(uri).toContain(`secret=${secret}`);
      expect(uri).toContain('digits=6');
      expect(uri).toContain('period=30');
      expect(uri).toContain('algorithm=SHA1');
    });
  });
});
