/**
 * 最小 TOTP 实现（RFC 6238，E2E 专用）
 *
 * 仅用于自动化登录时生成两步验证码，与后端 notp 口径一致：
 * HMAC-SHA1、30 秒步长、6 位动态码。不引入第三方 OTP 依赖。
 */

const crypto = require('crypto');

/** base32 解码（容忍空白与填充） */
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input).toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`非法 base32 字符：${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 生成当前时刻的 6 位 TOTP 码 */
function generateTotp(secretBase32, { windowOffset = 0 } = {}) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 30000) + windowOffset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
  return code;
}

module.exports = { generateTotp };
