/**
 * AuditLog body 脱敏：递归处理嵌套对象与数组，防止深层敏感字段明文入库。
 */

const SENSITIVE_KEYS = [
  'password',
  'currentpassword',
  'newpassword',
  'mfacode',
  'token',
  'refreshtoken',
  'secret',
  'apikey',
];
const MAX_SANITIZE_DEPTH = 6;

const sanitizeAuditBody = (body, depth = 0) => {
  if (depth > MAX_SANITIZE_DEPTH) return '[深度超限]';
  if (body === null || typeof body !== 'object') return body;
  if (Array.isArray(body)) return body.map((value) => sanitizeAuditBody(value, depth + 1));

  const cleaned = {};
  for (const [key, value] of Object.entries(body)) {
    cleaned[key] = SENSITIVE_KEYS.some((sensitive) => key.toLowerCase().includes(sensitive))
      ? '***'
      : sanitizeAuditBody(value, depth + 1);
  }
  return cleaned;
};

module.exports = { sanitizeAuditBody, SENSITIVE_KEYS };
