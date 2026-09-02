/**
 * TOTP 工具（RFC 6238）—— MFA 两步验证的核心实现（I-06）
 *
 * 零第三方依赖：HMAC-SHA1 + Base32 用 node:crypto 手工实现。
 * 参数与主流认证器（Google Authenticator / Microsoft Authenticator /
 * 1Password / FreeOTP）默认约定一致：SHA1 / 6 位 / 30 秒周期。
 */

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;
// 允许 ±1 个时间窗（共 90 秒），容忍客户端时钟小幅偏移
const DEFAULT_WINDOW = 1;

/** Buffer → Base32 字符串（RFC 4648，无填充） */
function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Base32 字符串 → Buffer
 *
 * P3-26：非法字符不再静默跳过。原实现 `if (idx === -1) continue` 会把
 * `JBSWY3DPEHPK3PXP!!!!` 与 `JBSWY3DPEHPK3PXP` 解成同一个密钥，
 * 也会把用户误粘贴的整段 URL 解出一个"看起来能用"的密钥——
 * 于是 enroll 阶段的输入错误要到验证阶段才暴露，且无从定位。
 * 空白与 `=` 填充仍然容忍（认证器展示的密钥常带分组空格）。
 *
 * @param {string} str Base32 字符串
 * @returns {Buffer}
 * @throws {Error} 含非 Base32 字母表字符时抛出
 */
function base32Decode(str) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error('Base32 输入为空');
  }
  let bits = 0;
  let value = 0;
  const out = [];
  const normalized = str.toUpperCase().replace(/[=\s-]/g, '');
  for (const ch of normalized) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`Base32 含非法字符：${JSON.stringify(ch)}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  if (out.length === 0) {
    throw new Error('Base32 解码结果为空');
  }
  return Buffer.from(out);
}

/** 生成 160 位随机密钥的 Base32 表示（认证器标准长度） */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/** HOTP（RFC 4226）：counter → 6 位动态口令
 *
 * 算法说明：使用 HMAC-SHA1 系标准强制而非遗留习惯——RFC 4226/6238 规定
 * TOTP 默认且互操作基线为 HMAC-SHA1，Google/Microsoft Authenticator 等
 * 主流认证器仅稳定支持 SHA1。HMAC 构造下 SHA1 的碰撞弱点不可利用，
 * 此处不构成弱加密风险（区别于裸 SHA1 摘要用途）。
 */
function hotp(secretBuf, counter) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * 校验用户提交的 6 位 TOTP 码（时间安全比较，±1 窗口）
 * @param {string} secretBase32 - 用户密钥（Base32）
 * @param {string} code - 用户输入的 6 位数字
 * @param {number} [window] - 允许的时间窗偏移数，默认 1
 * @returns {boolean}
 */
function verifyTotp(secretBase32, code, window = DEFAULT_WINDOW) {
  return verifyTotpDetailed(secretBase32, code, window).valid;
}

/**
 * 校验 TOTP 码并返回匹配的时间窗计数器（L5 重放防护依赖）
 * @returns {{valid: boolean, counter: number|null}} counter 为匹配的 TOTP 时间窗序号
 */
function verifyTotpDetailed(secretBase32, code, window = DEFAULT_WINDOW) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return { valid: false, counter: null };
  }
  try {
    const secretBuf = base32Decode(secretBase32);
    const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
    const submitted = Buffer.from(code, 'utf8');
    // P3-26：改用 crypto.timingSafeEqual 做常量时间比较。
    // Buffer.equals 是逐字节短路比较——首字符不同即立即返回，
    // 耗时随「与正确码的公共前缀长度」变化。理论上可用于逐位猜测口令，
    // 虽然 6 位数字空间小（10^6）且有 MFA 失败计数封顶使其难以实用化，
    // 但校验路径上没有理由保留可测量的时序差异。
    //
    // 关键：不能在匹配后立即 return——那会让「第 1 个窗口命中」与
    // 「第 3 个窗口命中」耗时不同，把泄露从字节级搬到窗口级。
    // 因此遍历全部窗口后再返回结果。
    let matchedCounter = null;
    for (let i = -window; i <= window; i++) {
      const expected = Buffer.from(hotp(secretBuf, counter + i), 'utf8');
      // 长度恒为 DIGITS（6），timingSafeEqual 的等长前提成立
      const hit =
        expected.length === submitted.length && crypto.timingSafeEqual(expected, submitted);
      if (hit && matchedCounter === null) {
        matchedCounter = counter + i;
      }
    }
    return matchedCounter === null
      ? { valid: false, counter: null }
      : { valid: true, counter: matchedCounter };
  } catch (_) {
    return { valid: false, counter: null };
  }
}

/**
 * 生成认证器扫码/手动录入用的 otpauth:// URI
 * @param {string} secretBase32
 * @param {string} account - 用户标识（用户名/邮箱）
 * @param {string} issuer - 发行方名称
 */
function otpauthUri(secretBase32, account, issuer) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  verifyTotp,
  verifyTotpDetailed,
  otpauthUri,
};
