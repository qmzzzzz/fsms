/**
 * 短期二次验证票据（reauth ticket）
 *
 * 用途：GET 类审计读取无法在请求体里携带口令/动态码，先 POST /api/security/reauth 完成一次
 * step-up，再凭短期票据访问受保护读取端点。
 * 设计约束：无状态 HMAC 签名（多实例一致、无需共享存储）；绑定 userId+sid（换会话即失效）；
 * 5 分钟不续期；只放行审计读取；票据是 bearer 凭据，不得写入日志/URL/localStorage（前端只放内存）。
 * 一次性（2026-10-31，审计一-3）：载荷含 jti，消费记录落在 models/ReauthTicketUse 的唯一索引上。
 * 原实现无 jti，同一张票 5 分钟内可无限重放——一次泄漏（前端内存、代理日志里的 X-REAUTH-TICKET
 * 头）就等于整个窗口的审计读取权；无 jti 的旧票一律判无效：宁可让用户重新 step-up，也不留
 * 「没有 jti 就跳过唯一性判据」的旁路。
 */

const crypto = require('crypto');
const { hmacSigner } = require('./encryption');

const REAUTH_TICKET_TTL_MS = 5 * 60 * 1000;
const REAUTH_TICKET_TTL_SECONDS = Math.floor(REAUTH_TICKET_TTL_MS / 1000);

const REAUTH_TICKET_DOMAIN = 'reauth-ticket:v1:'; // 域分离前缀：只进签名输入、不进线路格式（票据仍是 body.signature），对前端与既有用例零影响；审计链检查点的格式受 CHECKPOINT_VERSION 约束，改其签名输入须连带升版本+迁移存量锚点，属独立迁移项

const normalizeSid = (sessionId) => (sessionId ? String(sessionId) : null);

// jti 长度：16 字节随机 ⇒ 32 位 hex。形状判据同时回答"这是不是本版本签出的票"。
const JTI_BYTES = 16;
const JTI_HEX_LENGTH = JTI_BYTES * 2;
const JTI_PATTERN = new RegExp('^[0-9a-f]{' + JTI_HEX_LENGTH + '}$');
const isJti = (value) => typeof value === 'string' && JTI_PATTERN.test(value);

const encodePayload = (payload) =>
  Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

const signedPayload = (body) => REAUTH_TICKET_DOMAIN + body; // 签发与校验共用，避免两处拼法漂移

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * 签发票据。@returns {{ticket: string, expiresIn: number}}（now 仅供测试注入时间）
 */
function issueReauthTicket({ userId, sessionId = null }, now = Date.now()) {
  if (!userId) throw new Error('issueReauthTicket 缺少 userId');
  const payload = {
    uid: String(userId),
    sid: normalizeSid(sessionId),
    exp: now + REAUTH_TICKET_TTL_MS,
    // 一次性消费的标识：随机不可预测（票据本身已签名，jti 防的是重放而不是伪造）
    jti: crypto.randomBytes(JTI_BYTES).toString('hex'),
  };
  const body = encodePayload(payload);
  return {
    ticket: body + '.' + hmacSigner.sign(signedPayload(body)),
    expiresIn: REAUTH_TICKET_TTL_SECONDS,
  };
}

/**
 * 校验票据并取出消费所需的 jti/exp：签名 → 结构 → 绑定 → 过期，任一步失败返回 {valid:false}（不抛）。
 * 与 verifyReauthTicket 分开：布尔接口丢掉了 jti/exp，调用方若自己再解析一遍等于把解析逻辑抄成第二份。
 * @param {unknown} ticket @param {{userId: string, sessionId?: string|null}} binding @param {number} [now]
 * @returns {{valid: false}|{valid: true, jti: string, exp: number}}
 */
function inspectReauthTicket(ticket, { userId, sessionId = null }, now = Date.now()) {
  const invalid = { valid: false };
  if (typeof ticket !== 'string' || !ticket) return invalid;
  const firstDot = ticket.indexOf('.');
  // 必须恰好一个分隔点：多段/缺失都按无效处理，避免解析歧义
  if (firstDot <= 0 || firstDot !== ticket.lastIndexOf('.')) return invalid;

  const body = ticket.slice(0, firstDot);
  const signature = ticket.slice(firstDot + 1);
  if (!hmacSigner.verify(signedPayload(body), signature)) return invalid;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return invalid;
  }
  if (!isPlainObject(payload)) return invalid;
  if (typeof payload.uid !== 'string' || !payload.uid) return invalid;
  if (payload.sid !== null && typeof payload.sid !== 'string') return invalid;
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return invalid;
  if (payload.exp <= now) return invalid;
  // 无 jti / jti 形状不对 ⇒ 无效（不给"没有 jti 就跳过唯一性判据"留旁路）
  if (!isJti(payload.jti)) return invalid;

  if (!userId || payload.uid !== String(userId)) return invalid;
  if (payload.sid !== normalizeSid(sessionId)) return invalid;
  return { valid: true, jti: payload.jti, exp: payload.exp };
}

/**
 * 布尔形态校验（签名/绑定/过期/jti 形状），不含一次性消费判据；消费在 middleware 侧执行，
 * 此处保持无副作用、可单测。
 */
function verifyReauthTicket(ticket, binding, now = Date.now()) {
  return inspectReauthTicket(ticket, binding, now).valid === true;
}

module.exports = {
  REAUTH_TICKET_TTL_MS,
  REAUTH_TICKET_TTL_SECONDS,
  JTI_HEX_LENGTH,
  issueReauthTicket,
  inspectReauthTicket,
  verifyReauthTicket,
};
