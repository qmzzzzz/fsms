/**
 * AuditLog 敏感键脱敏：递归处理嵌套对象与数组，防止深层敏感字段明文入库。
 *
 * 判定规则有两条、盲区方向相反，**取并集**用于 query/params：
 *  - 子串名单（SENSITIVE_KEY_SUBSTRINGS）⇒ 能抓 camelCase 的 refreshToken /
 *    accessToken / mfaCode，但抓不到语义同为凭据的裸键 code / otp /
 *    authorization / session / captcha / signature；
 *  - 整键/下划线边界名单（SENSITIVE_QUERY_KEYS）⇒ 能抓上述裸键、且刻意不误伤
 *    postcode/zipcode，但按整键相等/边界判 ⇒ 漏 camelCase
 *    （'refreshtoken' 既不等于 'token' 也不以 '_token' 结尾）。
 * 任一单独使用都会留洞。两份名单与"取并集"这条规则都在 utils/helpers.js 里声明，
 * 本模块只引用；访问日志 URL 打码（redactUrlQuery）用的是同一个并集函数，
 * 这样两条链路对同一个键必然给出同一个结论。
 */

const {
  SENSITIVE_KEY_SUBSTRINGS,
  matchesSensitiveBodyKey,
  isCredentialQueryKey,
} = require('../utils/helpers');

// 对外保留原名（middleware/security.js 与多处测试按此名引用）
const SENSITIVE_KEYS = SENSITIVE_KEY_SUBSTRINGS;

const MAX_SANITIZE_DEPTH = 6;

/** body 名单：子串匹配（camelCase 只有子串抓得住） */
const isBodySensitiveKey = matchesSensitiveBodyKey;

/** query/params 名单：body 名单 ∪ 查询专用名单（补齐 code/otp/authorization 等裸键） */
const isQuerySensitiveKey = isCredentialQueryKey;

/**
 * 通用递归清洗。isSensitive 决定"哪些键算凭据"，其余（含 __proto__ 保真）两条流水线共用。
 */
const walk = (node, isSensitive, depth) => {
  if (depth > MAX_SANITIZE_DEPTH) return '[深度超限]';
  if (node === null || typeof node !== 'object') return node;
  // Date 不是"没有 own  enumerable 键的普通对象"那么无害：走下面的通用分支会被
  // Object.entries() 摊成 {}，于是"审计副本与实际请求体同形"这条本模块的存在理由
  // 对所有时间戳失效（取证时只看到一个空对象，且没有任何痕迹说明它曾经是时间）。
  // 同理 Buffer/Map/Set 也会摊成 {}，但它们不出现在 JSON 请求体里，Date 会
  // （服务端自己组装审计载荷时最容易顺手带上时间戳）。
  // 注：这里刻意不写具体的写入调用样式——audit action 对账用例按源码文本扫描，
  // 注释里出现那种写法会被它当成一个解析不了的写入点而硬失败（本轮实测踩过）。
  if (node instanceof Date) {
    return Number.isNaN(node.getTime()) ? '[无效时间]' : node.toISOString();
  }
  if (Array.isArray(node)) return node.map((value) => walk(value, isSensitive, depth + 1));

  const cleaned = {};
  for (const [key, value] of Object.entries(node)) {
    const safeValue = isSensitive(key.toLowerCase()) ? '***' : walk(value, isSensitive, depth + 1);
    // 必须用 defineProperty：`cleaned[key] = ...` 遇到字面量键 "__proto__"
    // 走的是 Object.prototype 的 setter（JSON.parse / express.json 造出的正是这种
    // own 键），结果该键被**整个丢掉**——攻击探针的载荷就这样从审计副本里消失，
    // 而"审计副本与实际请求体同形"正是这条链路存在的理由。
    // defineProperty 直接建 own 数据属性，绕开 setter，键与值都原样留存。
    Object.defineProperty(cleaned, key, {
      value: safeValue,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return cleaned;
};

const sanitizeAuditBody = (body, depth = 0) => walk(body, isBodySensitiveKey, depth);

/** req.params / req.query 专用：范围比 body 宽，方向只多砍不误砍 */
const sanitizeAuditQuery = (query, depth = 0) => walk(query, isQuerySensitiveKey, depth);

module.exports = {
  sanitizeAuditBody,
  sanitizeAuditQuery,
  SENSITIVE_KEYS,
  isBodySensitiveKey,
  isQuerySensitiveKey,
};
