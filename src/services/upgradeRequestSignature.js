/**
 * 升级请求签名（应用与宿主机代理共用）。签名不防「应用被攻陷」（两侧同持一把 HMAC 密钥，攻陷应用即可伪造），它防的是
 * 能写队列目录的本机用户塞入「看起来合法」的升级指令，并把 id/image/requestedAt/mode 与签名绑死（改名、换 digest、改模式都验签失败）。
 * 真正的边界在代理侧：无论签名是否通过都重跑 parseImageRef + assertImageAllowed，且只执行固定脚本、固定参数。
 *
 * canonical 按模式分型（不整体升版本域的理由：请求 TTL 只有 30 分钟，而应用镜像与宿主脚本
 * 的发布并不保证同批——分型让 registry 请求的签名格式与历史逐字节相同，滚动期任何一侧
 * 先升级都不会把对方在途的在线请求拒掉；offline 请求本来就只有新版代理能执行）：
 *   · registry（缺省）：[DOMAIN+id, image, requestedAt, userId]              —— 4 段，历史格式
 *   · offline：          [DOMAIN+id, image, requestedAt, userId, 'offline']  —— 5 段
 * 走哪一型由请求里的 mode 唯一决定：mode=offline 的请求绝不接受 4 段签名（在线签名贴到
 * 离线请求上无效），不带 mode 的请求绝不接受 5 段（离线签名被剥掉 mode 后冒充在线也无效）。
 */

const crypto = require('crypto');

const DOMAIN = 'upgrade-request:v1:';

const REGISTRY_MODE = 'registry';
const OFFLINE_MODE = 'offline';
const UPGRADE_MODES = [REGISTRY_MODE, OFFLINE_MODE];

/** mode 归一：只有显式 'offline' 才是离线，其余（含缺省）一律 registry——路由层已用 isIn 挡过一次，这里兜底且不抛 */
function normalizeMode(mode) {
  return mode === OFFLINE_MODE ? OFFLINE_MODE : REGISTRY_MODE;
}

/** 规范化输入：字段顺序固定，换行分隔，避免 JSON 键序差异导致签名漂移 */
const canonical = ({ id, image, requestedAt, userId, mode }) => {
  const lines = [DOMAIN + id, image, requestedAt, userId];
  if (normalizeMode(mode) === OFFLINE_MODE) lines.push(OFFLINE_MODE);
  return lines.join('\n');
};

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

module.exports = {
  DOMAIN,
  UPGRADE_MODES,
  canonical,
  normalizeMode,
  signUpgradeRequest,
  verifyUpgradeRequest,
};
