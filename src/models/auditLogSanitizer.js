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
  stripControlChars,
  stripControlCharsDeep,
  redactUrlQuery,
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
  // 注：这里刻意不写具体的写入调用样式——audit action 对账用例按源码文本扫描，注释里出现那种
  // 写法会被当成解析不了的写入点而硬失败。
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

/**
 * 审计详情采集的封顶口径。
 *
 * 与 forensic 采集（FORENSIC_*_CAP，KB 级、仅对已标记攻击源开启）刻意不同：
 * 审计是**常态开启**的，每条被审计请求都写一份。上限必须小到不会让 append-only
 * 集合的体积和哈希链序列化成本失控，又足以回答"这次请求到底发了什么"。
 */
const MAX_AUDIT_HEADER_VALUE_LENGTH = 512;
const MAX_AUDIT_HEADERS = 64;
const MAX_AUDIT_HEADER_BYTES = 8192;
const MAX_AUDIT_RESPONSE_BODY_BYTES = 8192;
const RESPONSE_BODY_TRUNCATED_MARK = '…[已截断]';

/**
 * 头名归一：HTTP 头名允许 `.` 与 `$`，而 Mongo 中带这两个字符的键既难查询、
 * 也可能被旧版本驱动拒绝。统一替换为 `_` 后再落库（不同原名可能归一成同名，
 * 后者覆盖前者——头名本身就是证据的一部分，宁可少一维也不让整条审计写入失败）。
 */
const normalizeHeaderName = (name) =>
  stripControlChars(String(name), 128).toLowerCase().replace(/[.$]/g, '_');

/**
 * 名字里直接看出凭据语义的头。其余交给 isCredentialQueryKey（与 query 打码、
 * 审计 query 脱敏同一把尺）：`x-xsrf-token` / `x-reauth-ticket` 由子串名单命中。
 * `set-cookie` 整袋掩码而非保留属性摘要：审计不是取证副本，不需要靠它判断会话属性，
 * 而漏掉一个 Set-Cookie 就等于把刚签发的会话令牌写进不可篡改集合。
 */
const CREDENTIAL_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
]);

/** URL 型头：query 里的凭据按单源规则打码（referer 常带着 reset token 原样进来） */
const URL_HEADER_NAMES = new Set(['referer', 'x-original-url']);

const capHeaderValue = (value) => {
  const raw = Array.isArray(value) ? value.map((v) => String(v)).join(', ') : String(value);
  return stripControlChars(raw, MAX_AUDIT_HEADER_VALUE_LENGTH);
};

/**
 * 请求/响应头脱敏 + 封顶。返回可直接落库的对象；无头对象返回 undefined。
 * 总预算按 UTF-8 字节计，超预算的头被丢弃并留下 `__truncated` 计数——
 * 静默丢弃会让事后读到一份"看起来完整"的头袋，错误结论比残缺更危险。
 */
const sanitizeAuditHeaders = (headers) => {
  if (!headers || typeof headers !== 'object') return undefined;
  const out = {};
  let kept = 0;
  let usedBytes = 2;
  let dropped = 0;
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = normalizeHeaderName(rawName);
    if (!name) continue;
    if (kept >= MAX_AUDIT_HEADERS) {
      dropped += 1;
      continue;
    }
    let value;
    if (CREDENTIAL_HEADER_NAMES.has(name) || isCredentialQueryKey(name)) {
      value = '***';
    } else if (URL_HEADER_NAMES.has(name)) {
      value = stripControlChars(redactUrlQuery(String(rawValue)), MAX_AUDIT_HEADER_VALUE_LENGTH);
    } else {
      value = capHeaderValue(rawValue);
    }
    const bytes = Buffer.byteLength(JSON.stringify({ [name]: value }), 'utf8');
    if (usedBytes + bytes > MAX_AUDIT_HEADER_BYTES) {
      dropped += 1;
      continue;
    }
    Object.defineProperty(out, name, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
    kept += 1;
    usedBytes += bytes + 1;
  }
  if (dropped > 0) {
    Object.defineProperty(out, '__truncated', {
      value: { dropped, maxHeaders: MAX_AUDIT_HEADERS, maxBytes: MAX_AUDIT_HEADER_BYTES },
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
};

/** 按 UTF-8 字节截断；截断点落在多字节字符中间时丢掉半个码元，保证输出是合法 UTF-8 */
const capUtf8 = (text, maxBytes) => {
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes <= maxBytes) return { text, truncated: false };
  const markBytes = Buffer.byteLength(RESPONSE_BODY_TRUNCATED_MARK, 'utf8');
  const keep = Math.max(0, maxBytes - markBytes);
  const cut = Buffer.from(text, 'utf8')
    .subarray(0, keep)
    .toString('utf8')
    .replace(/\uFFFD+$/, '');
  return { text: cut + RESPONSE_BODY_TRUNCATED_MARK, truncated: true };
};

/**
 * 响应体采集：返回 { value, truncated, skipped }。
 *
 * `skipped` 是**事实说明**而非失败：stream（write/end 流式响应，正文从未整块到手）、
 * empty（无正文）、binary（Buffer 只记字节数）、unserializable（环形/BigInt 等）。
 * 这些形态必须留下标记，否则详情页会把"没采集到"误读成"响应体为空"。
 *
 * 对象响应先按键脱敏（isQuerySensitiveKey：query 名单 ∪ 子串名单），再封顶。
 * 超过字节上限时退化为可读的 JSON 文本前缀 + truncated=true——继续存完整结构
 * 会让单条审计文档逼近 Mongo 16MB 上限，而"截到哪儿"本身也是需要被记录的事实。
 */
const sanitizeAuditResponseBody = (body, skipped) => {
  if (typeof skipped === 'string' && skipped) {
    return { value: undefined, truncated: false, skipped };
  }
  if (body === undefined) {
    return { value: undefined, truncated: false, skipped: 'empty' };
  }
  if (body === null) return { value: null, truncated: false, skipped: undefined };
  if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
    return {
      value: { __type: 'binary', bytes: body.length },
      truncated: false,
      skipped: 'binary',
    };
  }
  if (typeof body === 'string') {
    const cleaned = stripControlChars(body, MAX_AUDIT_RESPONSE_BODY_BYTES + 1);
    const capped = capUtf8(cleaned, MAX_AUDIT_RESPONSE_BODY_BYTES);
    return { value: capped.text, truncated: capped.truncated, skipped: undefined };
  }
  if (typeof body !== 'object') {
    return { value: body, truncated: false, skipped: undefined };
  }
  let serialized;
  try {
    // walk 先处理 Date/深层结构；stripControlCharsDeep 再清洗所有字符串。
    // 字符串上限必须 >= 正文上限：沿用默认 1024 会在外层字节封顶**之前**就静默
    // 截短长字段，而 truncated 仍是 false —— 详情页会把残缺正文当完整响应。
    serialized = JSON.stringify(
      stripControlCharsDeep(
        walk(body, isQuerySensitiveKey, 0),
        0,
        MAX_AUDIT_RESPONSE_BODY_BYTES + 1
      )
    );
  } catch {
    return { value: undefined, truncated: false, skipped: 'unserializable' };
  }
  if (serialized === undefined) {
    return { value: undefined, truncated: false, skipped: 'unserializable' };
  }
  const capped = capUtf8(serialized, MAX_AUDIT_RESPONSE_BODY_BYTES);
  return {
    value: capped.truncated ? capped.text : JSON.parse(serialized),
    truncated: capped.truncated,
    skipped: undefined,
  };
};

module.exports = {
  sanitizeAuditBody,
  sanitizeAuditQuery,
  sanitizeAuditHeaders,
  sanitizeAuditResponseBody,
  MAX_AUDIT_HEADER_VALUE_LENGTH,
  MAX_AUDIT_HEADERS,
  MAX_AUDIT_HEADER_BYTES,
  MAX_AUDIT_RESPONSE_BODY_BYTES,
  RESPONSE_BODY_TRUNCATED_MARK,
  SENSITIVE_KEYS,
  isBodySensitiveKey,
  isQuerySensitiveKey,
};
