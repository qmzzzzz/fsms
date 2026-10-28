/**
 * 短期二次验证票据（reauth ticket）
 *
 * 用途：GET 类审计读取无法在请求体里携带口令/动态码，先经 POST /api/security/reauth
 * 完成一次 step-up，再凭短期票据访问受保护读取端点。
 *
 * 设计约束：
 *  - 无状态：HMAC 签名（复用审计链同一把 HMAC_SECRET），多实例天然一致，无需共享存储；
 *  - 绑定会话：票据含 userId 与 access token 的 jti（req.user.sessionId）。换会话即失效，
 *    设备会话被踢后 authenticate 先行拒绝，票据无从单独使用；
 *  - 短期：5 分钟。过期后必须重新验证，不提供续期接口；
 *  - 只放行读取：票据由 requireReauthTicket 校验，仅挂在审计读取端点。
 *
 * 票据是 bearer 凭据：不得写入日志、URL 或 localStorage（前端只放内存）。
 */

const { hmacSigner } = require('./encryption');

const REAUTH_TICKET_TTL_MS = 5 * 60 * 1000;
const REAUTH_TICKET_TTL_SECONDS = Math.floor(REAUTH_TICKET_TTL_MS / 1000);

/**
 * 签名域前缀（domain separation）。
 *
 * 本票据与审计链检查点（services/auditChainCheckpoint.js）共用同一把 HMAC_SECRET，
 * 且双方的签名输入都曾是「裸字节」，没有一个把两条用途隔开的固定前缀。密钥用途
 * 不分离的代价：一旦哪天某处的签名/原文泄漏，两种协议的原语同构，界面上互相
 * "可迁移解读"的空间就变大。加一个固定域前缀后，同一密钥在两条用途上产出的
 * 签名字节流从**输入层面**就不同构——伪造一类凭据的签名不可能在另一类上成立。
 *
 * 前缀只进签名输入、不进线路格式：票据仍是 `body.signature`，body 仍是
 * base64url(JSON)。因此对前端（只当作不透明串透传）与既有用例零影响。
 * 审计链检查点侧未同步改动——它的格式受 CHECKPOINT_VERSION 约束，改签名输入
 * 必须连带升版本并处理存量锚点文件，属独立迁移项（见该模块头注释），不在本次范围。
 */
const REAUTH_TICKET_DOMAIN = 'reauth-ticket:v1:';

const normalizeSid = (sessionId) => (sessionId ? String(sessionId) : null);

const encodePayload = (payload) =>
  Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

/** 参与签名的字节流：域前缀 + 线路体。签发与校验必须共用本函数，避免两处拼法漂移 */
const signedPayload = (body) => REAUTH_TICKET_DOMAIN + body;

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * 签发票据。
 * @param {{userId: string, sessionId?: string|null}} binding
 * @param {number} [now] 仅供测试注入时间
 * @returns {{ticket: string, expiresIn: number}}
 */
function issueReauthTicket({ userId, sessionId = null }, now = Date.now()) {
  if (!userId) throw new Error('issueReauthTicket 缺少 userId');
  const payload = {
    uid: String(userId),
    sid: normalizeSid(sessionId),
    exp: now + REAUTH_TICKET_TTL_MS,
  };
  const body = encodePayload(payload);
  return {
    ticket: `${body}.${hmacSigner.sign(signedPayload(body))}`,
    expiresIn: REAUTH_TICKET_TTL_SECONDS,
  };
}

/**
 * 校验票据：签名 → 结构 → 绑定 → 过期。任一步失败都返回 false（不抛异常）。
 * @param {unknown} ticket
 * @param {{userId: string, sessionId?: string|null}} binding
 * @param {number} [now] 仅供测试注入时间
 * @returns {boolean}
 */
function verifyReauthTicket(ticket, { userId, sessionId = null }, now = Date.now()) {
  if (typeof ticket !== 'string' || !ticket) return false;
  const firstDot = ticket.indexOf('.');
  // 必须恰好一个分隔点：多段/缺失都按无效处理，避免解析歧义
  if (firstDot <= 0 || firstDot !== ticket.lastIndexOf('.')) return false;

  const body = ticket.slice(0, firstDot);
  const signature = ticket.slice(firstDot + 1);
  if (!hmacSigner.verify(signedPayload(body), signature)) return false;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  if (!isPlainObject(payload)) return false;
  if (typeof payload.uid !== 'string' || !payload.uid) return false;
  if (payload.sid !== null && typeof payload.sid !== 'string') return false;
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return false;
  if (payload.exp <= now) return false;

  if (!userId || payload.uid !== String(userId)) return false;
  if (payload.sid !== normalizeSid(sessionId)) return false;
  return true;
}

module.exports = {
  REAUTH_TICKET_TTL_MS,
  REAUTH_TICKET_TTL_SECONDS,
  issueReauthTicket,
  verifyReauthTicket,
};
