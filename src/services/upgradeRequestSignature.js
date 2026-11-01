/**
 * 升级请求签名（应用与宿主机代理共用）。签名不防「应用被攻陷」（两侧同持一把 HMAC 密钥，攻陷应用即可伪造），它防的是
 * 能写队列目录的本机用户塞入「看起来合法」的升级指令，并把 id/image/requestedAt 与签名绑死（改名或换 digest 都验签失败）。
 * 真正的边界在代理侧：无论签名是否通过都重跑 parseImageRef + assertImageAllowed，且只执行固定脚本、固定参数。
 */

const crypto = require('crypto');

const DOMAIN = 'upgrade-request:v1:';

/** 规范化输入：字段顺序固定，换行分隔，避免 JSON 键序差异导致签名漂移 */
const canonical = ({ id, image, requestedAt, userId }) =>
  [DOMAIN + id, image, requestedAt, userId].join('\n');

function signUpgradeRequest(secret, payload) {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new Error('缺少 HMAC 密钥：无法签发升级请求');
  }
  return crypto.createHmac('sha256', secret).update(canonical(payload)).digest('hex');
}

function verifyUpgradeRequest(secret, payload, signature) {
  if (typeof secret !== 'string' || secret.length < 16) return false;
  if (typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) return false;
  let expected;
  try {
    expected = signUpgradeRequest(secret, payload);
  } catch {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
}

module.exports = { DOMAIN, canonical, signUpgradeRequest, verifyUpgradeRequest };
