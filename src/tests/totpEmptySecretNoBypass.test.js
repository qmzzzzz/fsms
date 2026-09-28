'use strict';

/**
 * （2026-09-19）：MFA 口令校验对"退化密钥"必须在**任何**提交码下都拒绝
 *
 * 为什么需要这条：`utils/mfaSecret.js` 的设计是"解密失败 ⇒ 返回空串"，
 * 注释写明"调用方一律走验证码错误分支"。这个前提成立的唯一理由是
 * **空密钥永远算不出可通过的码**。`base32Decode('')` 目前抛错（两处：空输入、
 * 解码结果为空），所以 `verifyTotpDetailed` 的 catch 把它变成 valid:false ✓
 * （本次改动实测确认，未见可绕过路径 ⇒ 记负结果）。
 *
 * 但保证如果只钉在**成因**层就很脆：既有套件靠
 * `expect(() => base32Decode('')).toThrow()`（用例名："不返回空缓冲被误当有效密钥"）
 * 与 `verifyTotp('', '123456') === false` 两条守住。实测（变异：把 `base32Decode('')`
 * 改成返回空缓冲）两套都会红，但后一条红是因为前者——单看 verify 那条，
 * 它只测了一个具体码，空密钥算出的真实码照样能通过。
 * 本用例把保证抬到**判定函数层**：9 种退化密钥 × 攻击者可离线算出的空密钥码，全部必须拒绝。
 */

const {
  verifyTotp,
  verifyTotpDetailed,
  base32Decode,
  base32Encode,
  generateSecret,
  hotp,
} = require('../../src/utils/totp');

const STEP_SECONDS = 30;
const nowCounter = () => Math.floor(Date.now() / 1000 / STEP_SECONDS);

// 一切"拿不到真实密钥"的形态：解密失败给的空串、脏数据、类型漂移
const DEGENERATE_SECRETS = ['', '   ', '====', '-', 'A', '!!!!', undefined, null, 123, {}, []];

describe('zzqoder 退化密钥不得产出可通过的 TOTP', () => {
  test('用空密钥算出的当前窗口码，对任何退化密钥都必须判不通过', () => {
    const counter = nowCounter();
    // 攻击者可离线算出的"空密钥码"：±1 窗口全部试一遍
    const emptyKeyCodes = [counter - 1, counter, counter + 1].map((c) => hotp(Buffer.alloc(0), c));
    expect(emptyKeyCodes.every((c) => /^\d{6}$/.test(c))).toBe(true);

    for (const secret of DEGENERATE_SECRETS) {
      for (const code of emptyKeyCodes) {
        expect({ secret: String(secret), code, verdict: verifyTotpDetailed(secret, code) }).toEqual(
          {
            secret: String(secret),
            code,
            verdict: { valid: false, counter: null },
          }
        );
        expect(verifyTotp(secret, code)).toBe(false);
      }
    }
  });

  test('全 0 到全 9 的极端码也不能靠"空密钥恰好等于某个码"通过', () => {
    const secret = '';
    // 10^6 太大，取结构性样本：空密钥码 + 边界码 + 随机若干
    const counter = nowCounter();
    const codes = [
      hotp(Buffer.alloc(0), counter),
      '000000',
      '999999',
      '123456',
      ...Array.from({ length: 200 }, () =>
        String(Math.floor(Math.random() * 1e6)).padStart(6, '0')
      ),
    ];
    codes.forEach((code) => {
      expect(verifyTotpDetailed(secret, code).valid).toBe(false);
    });
  });

  test('正对照：真实密钥 + 正确码必须通过（否则上面两条是空对空的恒绿）', () => {
    const secret = generateSecret();
    const counter = nowCounter();
    const code = hotp(base32Decode(secret), counter);
    expect(verifyTotpDetailed(secret, code)).toEqual({ valid: true, counter });
    expect(verifyTotp(secret, code)).toBe(true);
    // ±1 窗口内也认，窗口外不认
    expect(verifyTotp(secret, hotp(base32Decode(secret), counter - 1))).toBe(true);
    expect(verifyTotp(secret, hotp(base32Decode(secret), counter - 5))).toBe(false);
  });

  test('base32Decode 的两处空值防护都还在（它们是上面那条判据的成因）', () => {
    expect(() => base32Decode('')).toThrow(/输入为空/);
    expect(() => base32Decode('A')).toThrow(/解码结果为空/); // 4 bit 不足一字节
    expect(() => base32Decode('!!!!')).toThrow(/非法字符/);
    // 往返自证：20 字节密钥编码后能解回同一字节串
    const buf = Buffer.from('0123456789abcdef0123', 'hex');
    expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
  });
});
