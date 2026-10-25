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

const normalizeSid = (sessionId) => (sessionId ? String(sessionId) : null);

const encodePayload = (payload) =>
  Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

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
    ticket: `${body}.${hmacSigner.sign(body)}`,
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
  if (!hmacSigner.verify(body, signature)) return false;

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
