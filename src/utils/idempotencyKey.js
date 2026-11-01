/**
 * 幂等键形态校验、键哈希与载荷指纹（纯函数，无 IO）。设计取舍见 docs/adr/ADR-014。
 */

const crypto = require('crypto');

const KEY_MIN_LENGTH = 8; // 下界防高撞车率键，上界防索引键超限
const KEY_MAX_LENGTH = 64;
// 可见 ASCII 0x21-0x7e：排除空白、控制字符与多字节字符
const KEY_PATTERN = new RegExp('^[\\x21-\\x7e]{' + KEY_MIN_LENGTH + ',' + KEY_MAX_LENGTH + '}$');

function parseIdempotencyKey(raw) {
  // 重复头在 Node 里可能是数组：只认第一个，不接受"任一个合法就用"
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === undefined || value === null || value === '')
    return { ok: false, reason: 'missing' };
  const key = String(value);
  if (!KEY_PATTERN.test(key)) return { ok: false, reason: 'shape' };
  return { ok: true, key };
}

/** 只存哈希（键可能被塞进工号/邮箱）；前缀 scope + userId 作盐 ⇒ 跨端点/跨用户同名键天然不相撞 */
function hashIdempotencyKey({ scope, userId, key }) {
  return crypto
    .createHash('sha256')
    .update(String(scope) + '\u0000' + String(userId) + '\u0000' + String(key))
    .digest('hex');
}

/**
 * 同键不同载荷必须被拒（否则客户端改内容重发即可借用上一次的成功响应）。
 * 只排顶层键：深层排序会把 [{a:1},{a:2}] 与 [{a:2},{a:1}] 判成同一份载荷。
 */
function fingerprintRequestBody(body) {
  const source = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const sorted = {};
  for (const key of Object.keys(source).sort()) sorted[key] = source[key];
  return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

module.exports = {
  KEY_MAX_LENGTH,
  KEY_MIN_LENGTH,
  fingerprintRequestBody,
  hashIdempotencyKey,
  parseIdempotencyKey,
};
