/** 取证捕获的载荷构建（P2）：把请求/响应变成可落库的取证副本——脱敏、PII 掩码、封顶截断、摘要、recordHash 规范化；编排在 forensicCapture.js。
 *  单源纪律（不复制任何实现）：body→auditLogSanitizer.sanitizeAuditBody，PII→logPiiMask.maskPiiText，口令摘要→passwordHistory.digestOf，query/params→sanitizeAuditQuery。 */

const codec = require('./forensicCaptureCodec');
const logger = require('../utils/logger');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const { sanitizeAuditBody, sanitizeAuditQuery } = require('../models/auditLogSanitizer');
const { digestOf } = require('../utils/passwordHistory');
const { maskPiiText, isSensitiveKey } = require('../utils/logPiiMask');

const {
  sha256,
  capText,
  capBag,
  maskHeaders,
  maskResponseHeaders,
  summarizeSetCookie,
  canonicalJson,
  recordHashOf,
  TRUNCATED_MARK,
  REDACTED,
} = codec;

const MAX_SANITIZE_DEPTH = 6;
const DEPTH_EXCEEDED = '[深度超限]';

const num = (name, fallback, integer = false) =>
  readPositiveNumberEnv(name, fallback, {
    integer,
    onInvalid: (n, raw, d) =>
      logger.error(`${n}=${JSON.stringify(raw)} 非法，已按默认 ${d} 处理（取证容量口径必须显式）`),
  });

const REQ_HEADER_CAP = num('FORENSIC_REQ_HEADER_CAP', 8192); // 采集上限（任务书 §2.2 的默认值）。现读 env 而不是写死：压小上限是取证演练的常规手段。
const REQ_BODY_CAP = num('FORENSIC_REQ_BODY_CAP', 16384);
const RES_HEADER_CAP = num('FORENSIC_RES_HEADER_CAP', 4096);
const RES_BODY_CAP = num('FORENSIC_RES_BODY_CAP', 65536);

// 口令短别名 + 一次性口令数组（恢复码整组都是凭据）：单源子串名单只抓 password/passwd/pwd，pass/pw/pin/otp 漏网即明文入库
const PASSWORD_ALIAS_KEYS = new Set(['pass', 'pw', 'pin', 'otp', 'passcode', 'pincode']);
const SECRET_LIST_KEYS = new Set(['recoverycodes', 'backupcodes', 'recoverycode', 'backupcode']);

/** 键名归一（去非字母数字、小写）：两处判定共用同一把尺 */
const normalizeKey = (key) =>
  String(key)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');

/** 口令键：归一（去非字母数字、小写）后含 password/passwd、以 pwd 结尾，或命中短别名 */
const isPasswordKey = (key) => {
  const n = String(key)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
  return (
    n.includes('password') ||
    n.includes('passwd') ||
    n.endsWith('pwd') ||
    PASSWORD_ALIAS_KEYS.has(n)
  );
};

/** 6 层脱敏 + 口令键 {len,hmac}：先由单源 sanitizeAuditBody 产出掩码树，再按原树补回口令摘要（它只给 '***'，拿不到长度）。 */
const sanitizeBodyForForensic = (body, depth = 0) => {
  if (depth > MAX_SANITIZE_DEPTH) return DEPTH_EXCEEDED;
  const masked = sanitizeAuditBody(body);
  const upgrade = (raw, out, level) => {
    if (level > MAX_SANITIZE_DEPTH) return out;
    if (Array.isArray(raw) && Array.isArray(out)) {
      return out.map((v, i) => upgrade(raw[i], v, level + 1));
    }
    if (!raw || typeof raw !== 'object' || !out || typeof out !== 'object') return out;
    const next = Array.isArray(out) ? out.slice() : { ...out };
    for (const key of Object.keys(next)) {
      const rawVal = raw[key];
      // 口令键优先：单源名单不含 passwd/pwd 这类别名，此处按 §1.4 升级成 { len, hmac }（只存长度与带 pepper 的摘要），不是放宽脱敏。
      if (SECRET_LIST_KEYS.has(normalizeKey(key)) && Array.isArray(rawVal)) {
        next[key] = rawVal.map((one) => {
          const text = String(one);
          return { len: text.length, hmac: digestOf(text) };
        });
        continue;
      }
      if ((typeof rawVal === 'string' || typeof rawVal === 'number') && isPasswordKey(key)) {
        const secretText = String(rawVal);
        next[key] = { len: secretText.length, hmac: digestOf(secretText) };
        continue;
      }
      next[key] = upgrade(rawVal, next[key], level + 1);
    }
    return next;
  };
  const upgraded = upgrade(body, masked, 0);
  return JSON.parse(JSON.stringify(upgraded === undefined ? null : upgraded)); // 兜底：单源对深层/异常形态返回原值（例如 Buffer），再过一遍 JSON 语义清洗
};

/** PII 深度掩码：每个字符串过 maskPiiText；键用 defineProperty 落以保住 __proto__ 的 own 属性 */
const maskPiiDeep = (node, depth = 0) => {
  if (depth > MAX_SANITIZE_DEPTH) return DEPTH_EXCEEDED;
  if (typeof node === 'string') return maskPiiText(node);
  if (node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map((v) => maskPiiDeep(v, depth + 1));
  const out = {};
  for (const [key, value] of Object.entries(node)) {
    const scalar = typeof value === 'string' || typeof value === 'number'; // 按键名判定单源 isSensitiveKey（文本正则看不见键名）：令牌/私钥/恢复码只有按名才抓得住
    const masked = scalar && isSensitiveKey(key) ? '***' : maskPiiDeep(value, depth + 1);
    Object.defineProperty(out, key, {
      value: masked,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
};

/** query/params：单源 sanitizeAuditQuery + PII 掩码 */
const sanitizeQueryPayload = (value) => maskPiiDeep(sanitizeAuditQuery(value));

/** 请求体：GET/HEAD 无体；非 JSON 只留元数据；JSON 走单源脱敏 + PII 掩码 + 封顶 */
const captureRequestBody = (req) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return { body: null, bodyBytes: 0, bodyTruncated: false, bodySha256: null };
  }
  const contentType = String((req.headers && req.headers['content-type']) || '');
  if (!/json/i.test(contentType)) {
    const length = Number(req.headers && req.headers['content-length']) || 0;
    if (!length && !req.body)
      return { body: null, bodyBytes: 0, bodyTruncated: false, bodySha256: null };
    return {
      body: { contentType, length },
      bodyBytes: length,
      bodyTruncated: false,
      bodySha256: null,
    };
  }
  const safe = maskPiiDeep(sanitizeBodyForForensic(req.body === undefined ? null : req.body));
  const capped = capText(JSON.stringify(safe), REQ_BODY_CAP);
  return {
    body: capped.truncated ? capped.text : safe,
    bodyBytes: capped.bytes,
    bodyTruncated: capped.truncated,
    bodySha256: capped.sha256,
  };
};

/** 响应体：json/text 存正文（PII 掩码 + 封顶）；二进制与**流式**只留 { contentType, bytes, complete }——半截内容既不是证据也可能未脱敏，而"字节数与是否完整"才是可断言的事实。 */
const buildResponsePart = (capture) => {
  const contentType = String(capture.contentType || '');
  const headers = maskResponseHeaders(capture.headers || {}, RES_HEADER_CAP);
  const base = { status: capture.status, headers, contentType };
  if (capture.streamed || !/json|text/i.test(contentType)) {
    const bytes = capture.bytes || 0;
    return {
      ...base,
      body: { contentType, bytes, complete: capture.complete !== false },
      bodyBytes: bytes,
      bodyTruncated: false,
      bodySha256: null,
    };
  }
  // JSON 响应体同样走**按键**脱敏：accessToken/refreshToken 这类键必须与请求侧同口径掩掉，否则取证副本成了凭据仓库；解析失败 ⇒ 降级为文本级 PII 掩码，不猜结构。
  const raw = String(capture.body || '');
  let masked;
  if (/json/i.test(contentType)) {
    try {
      masked = JSON.stringify(maskPiiDeep(sanitizeBodyForForensic(JSON.parse(raw))));
    } catch {
      masked = maskPiiText(raw);
    }
  } else {
    masked = maskPiiText(raw);
  }
  const capped = capText(masked, RES_BODY_CAP);
  return {
    ...base,
    body: capped.text,
    bodyBytes: capped.bytes,
    bodyTruncated: capped.truncated,
    bodySha256: capped.sha256,
  };
};

/** 响应段字段必须**总是齐备**：模型上 bodyBytes/bodyTruncated/bodySha256 带默认值，残缺入参会被 mongoose 补齐 ⇒ 落库副本与算哈希那刻不同形，复核必报假篡改（P1-7 实测）。默认值必须与 schema 逐字一致。 */
const normalizeResponsePart = (part) => {
  if (!part) return part;
  return {
    ...part,
    bodyBytes: part.bodyBytes === undefined ? 0 : part.bodyBytes,
    bodyTruncated: part.bodyTruncated === undefined ? false : part.bodyTruncated,
    bodySha256: part.bodySha256 === undefined ? null : part.bodySha256,
  };
};

/** 设备字段封顶：攻击者可控的超长头必须在载荷侧截进模型 maxlength（§2.3），否则 mongoose 校验失败会被 insertMany 静默吞掉（P0-3）。 */
const DEVICE_CAPS = {
  ua: 512,
  secChUa: 512,
  acceptLanguage: 512,
  acceptEncoding: 512,
  tlsProtocol: 32,
  tlsCipher: 128,
};

/** 按字符数封顶；null/undefined 原样保留（模型里这些字段可空） */
const fitToMax = (value, max) => {
  if (value === null || value === undefined) return null;
  const text = String(value);
  return text.length <= max ? text : capText(text, max).text;
};

/** 设备指纹字段（parseUserAgent 从不抛；TLS 字段取自反代注入的头） */
const buildDevicePart = (req) => {
  const ua = req.get ? String(req.get('user-agent') || '') : '';
  const uaInfo = require('./sessionService').parseUserAgent(ua) || {};
  const header = (name) => (req.get ? String(req.get(name) || '') || null : null);
  const headerOf = (name, max) => fitToMax(header(name), max);
  return {
    ua: fitToMax(ua, DEVICE_CAPS.ua),
    browser: uaInfo.browser || null,
    os: uaInfo.os || null,
    deviceType: uaInfo.deviceType || null,
    secChUa: headerOf('sec-ch-ua', DEVICE_CAPS.secChUa),
    acceptLanguage: headerOf('accept-language', DEVICE_CAPS.acceptLanguage),
    acceptEncoding: headerOf('accept-encoding', DEVICE_CAPS.acceptEncoding),
    httpVersion: fitToMax(req.httpVersion || null, 16),
    tlsProtocol: headerOf('x-tls-protocol', DEVICE_CAPS.tlsProtocol),
    tlsCipher: headerOf('x-tls-cipher', DEVICE_CAPS.tlsCipher),
  };
};

/** 归属地：ipLocationService.locate 失败/查不出都只留空（增强信息，绝不影响捕获） */
const buildLocationPart = (ip) => {
  let text = null;
  try {
    text = require('./ipLocationService').locate(ip);
  } catch {
    /* 数据文件缺失/畸形 IP ⇒ 留空 */
  }
  return { country: null, province: null, city: null, isp: null, text };
};

/** 网络来源：auditClientAddress 的 clientInfo（空值不落键，与审计哈希口径一致） */
const buildNetPart = (req) => {
  const { clientInfo } = require('../utils/ipUtils').auditClientAddress(req);
  return {
    reportedIp: (clientInfo && clientInfo.reportedIp) || null,
    socketPeer: (clientInfo && clientInfo.socketPeer) || null,
  };
};

/** 头袋取出时补齐默认上限（上限本身住在 payload：它读 env，属于采集口径而非原语） */
const maskHeadersWithCap = (headers, capBytes = REQ_HEADER_CAP) => maskHeaders(headers, capBytes);
const maskResponseHeadersWithCap = (headers, capBytes = RES_HEADER_CAP) =>
  maskResponseHeaders(headers, capBytes);

module.exports = {
  MAX_SANITIZE_DEPTH,
  DEPTH_EXCEEDED,
  TRUNCATED_MARK,
  REDACTED,
  DEVICE_CAPS,
  PASSWORD_ALIAS_KEYS,
  SECRET_LIST_KEYS,
  fitToMax,
  REQ_HEADER_CAP,
  REQ_BODY_CAP,
  RES_HEADER_CAP,
  RES_BODY_CAP,
  isPasswordKey,
  sanitizeBodyForForensic,
  maskPiiDeep,
  sanitizeQueryPayload,
  sha256,
  capText,
  capBag,
  maskHeaders: maskHeadersWithCap,
  summarizeSetCookie,
  maskResponseHeaders: maskResponseHeadersWithCap,
  canonicalJson,
  recordHashOf,
  captureRequestBody,
  buildResponsePart,
  normalizeResponsePart,
  buildDevicePart,
  buildLocationPart,
  buildNetPart,
};
