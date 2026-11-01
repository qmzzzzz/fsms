/**
 * winston 运行日志的 PII 掩码与凭据脱敏（由 logger.js 的 sanitize 阶段调用）
 *
 * 边界：只作用于 winston 运行日志；`models/AuditLog` 不经此处——审计按取证需要保留 username/ip，其访问由 `pii:export` + 二次验证约束。把掩码加到审计库会破坏取证链，必须另立决策。
 *
 * 两类处理：凭据类字段按**键名**整体替换（含对象/数组，覆盖 `credentials: { user, pass }` 形状）；PII 按**值**局部掩码，email 保首字符与域名、手机号保前 3 后 4、身份证保前 6 后 4——保留可辨识形状供排障，
 * 但不足以定位到人。
 *
 * 不做整条 message 的正则替换：`tokenVersion`、"刷新 token 失败" 这类业务词会被一并吃掉，排障信息损失不可控。`LOG_PII_MASK=false` 可关闭（调试核对
 * 原文）；关闭时 logger.js 必须留痕（生产语义用 error），否则会成为静默例外。
 */

'use strict';

const { stripControlChars } = require('./helpers');

const REDACTED = '[REDACTED]';

/**
 * email：保留首字符与 @ 之后的域名，`zhangsan@corp.com` → `z***@corp.com`。前置否定环视是**性能判据**不是语义修饰：首字符组与后续字符类完全重叠，没有左边界时每个
 * 起点都要把整段同字符吃完再失败，无 @ 长串因此退化成 O(n²)（262144 字符实测 79 秒 → 1.1ms）。
 */
const EMAIL_RE =
  /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;

/** 18 位身份证：保留前 6（行政区划）与后 4。必须**先于**手机号执行：18 位里含 11 位连续
 * 数字，顺序反了会挖出 `1***********` 这种既不可读也不合规的残形，且掩码后不再是纯数字 */
const CN_ID_RE = /(?<!\d)(\d{6})\d{8}(\d{3}[\dXx])(?!\d)/g;

/** 中国大陆手机号：`(?<!\d)`/`(?!\d)` 保证不命中长数字串的中段（订单号、时间戳拼接） */
const CN_MOBILE_RE = /(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)/g;

/**
 * 敏感**键名**闭合集（已归一：小写、去掉 `_`/`-`/`.`）。
 *
 * 归一后比较而不是正则匹配，是为了让 `access_token` / `accessToken` / `ACCESS-TOKEN` 落进同一条：三种写法在生产代码里都真实存在。刻意**不含** `tokenversion`（版本号不是凭据）与 `csrf`（前端可读、非机密）。
 */
const SENSITIVE_KEYS = new Set([
  'password',
  'passwd',
  'pwd',
  'oldpassword',
  'newpassword',
  'confirmpassword',
  'passwordhash',
  'secret',
  'clientsecret',
  'mfasecret',
  'hmacsecret',
  'jwtsecret',
  'privatekey',
  'encryptionkey',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'tokenvalue',
  'bearertoken',
  'apikey',
  'authorization',
  'cookie',
  'setcookie',
  'credential',
  'credentials',
  'sessionid',
  'otp',
  'totpcode',
  'recoverycode',
  'recoverycodes',
  'recoverycodesremaining',
]);

/**
 * 结构性键：这些字段即便形态上像 PII 也不掩码。 `requestId`/`userId`/`socketId` 是排障关联键，掩掉等于把日志变成无法串联的碎片；它们本身不是 PII（userId 是内部 ObjectId，不是身份证号）。
 */
const STRUCTURAL_KEYS = new Set([
  'level',
  'timestamp',
  'message',
  'service',
  'hostname',
  'pid',
  'requestid',
  'userid',
  'socketid',
]);

/** 深拷贝的最大深度：日志 meta 再深就没有排障价值，而深递归会拖慢每条日志 */
const MAX_DEPTH = 4;

const MAX_NESTED_CHARS = 1024; // 与 logger.js 的 MAX_LOG_FIELD_CHARS 同值：嵌套字段也是字段

/**
 * 后缀判定（在闭合集之外补的一层）：覆盖 `x-api-key`、`dbPassword`、 `client_api_key` 这类带前缀的写法。
 *
 * 只对**强后缀**开放，不把 `token` 放进后缀集：`tokenVersion`、`tokenCount` 这类业务字段会被误伤，而它们恰恰是排障要看的。宁可让极少数冷门键漏掉，也不要把常规字段批量变成 `[REDACTED]`——那种日志读起来像坏了。
 */
const SENSITIVE_SUFFIXES = [
  'password',
  'passwd',
  'secret',
  'apikey',
  'accesstoken',
  'refreshtoken',
  'privatekey',
  'authorization',
];

function normalizeKey(key) {
  return String(key)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

/** 该键名是否属于"值本身就是凭据" */
function isSensitiveKey(key) {
  const normalized = normalizeKey(key);
  if (SENSITIVE_KEYS.has(normalized)) return true;
  return SENSITIVE_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

/**
 * 对一段文本做 PII 掩码。
 * @param {string} text
 * @returns {string}
 */
function maskPiiText(text) {
  if (typeof text !== 'string' || text === '') return text;
  return text
    .replace(EMAIL_RE, '$1***$2')
    .replace(CN_ID_RE, '$1********$2')
    .replace(CN_MOBILE_RE, '$1****$2');
}

/**
 * 递归掩码一个日志记录（就地修改并返回）。
 *
 * 为什么要递归：winston 的 meta 是**任意对象**，`logger.warn('x', { user: { email } })` 这种写法在仓里大量存在。只处理顶层字符串等于宣布"嵌套里的 PII 不管"——
 * 而那恰好是最常见的形状（请求体片段、实体对象、错误详情）。嵌套串同样先过 1024 长度闸，否则一条超长 blob 就能把正则的扫描量放大成分钟级停顿。
 *
 * 深度上限与循环保护：`serializeMeta` 已经因为循环引用丢过日志（见 logger.js 注释），这里用 WeakSet 保证不会在掩码阶段先抛一次。
 *
 * @param {unknown} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {unknown}
 */
function maskValue(value, depth, seen) {
  if (typeof value === 'string') return maskPiiText(stripControlChars(value, MAX_NESTED_CHARS));
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH) return value;
  if (seen.has(value)) return value;
  seen.add(value);

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) value[i] = maskValue(value[i], depth + 1, seen);
    return value;
  }

  // 只处理普通对象：Date/Buffer/Error/Map 等有各自语义，改写会破坏下游序列化
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return value;

  for (const key of Object.keys(value)) {
    if (isSensitiveKey(key)) {
      value[key] = REDACTED;
      continue;
    }
    if (STRUCTURAL_KEYS.has(normalizeKey(key))) continue;
    value[key] = maskValue(value[key], depth + 1, seen);
  }
  return value;
}

/** 是否启用掩码（每次调用读环境：日志路径不在热循环，且便于测试与临时排查） */
function isMaskEnabled() {
  const raw = process.env.LOG_PII_MASK;
  if (typeof raw !== 'string' || raw.trim() === '') return true; // 默认开启
  return raw.trim().toLowerCase() !== 'false';
}

/**
 * 掩码一条 winston info（就地修改）。
 *
 * 键名判定优先于文本判定：`{ password: 'Abc123' }` 应该整体变 `[REDACTED]`，而不是先跑一遍 PII 规则（那条密码里若恰好有 11 位数字，会得到半掩的残值）。
 *
 * @param {object} info winston 日志对象
 * @returns {object} 同一个对象
 */
function maskLogInfo(info) {
  if (!info || typeof info !== 'object' || !isMaskEnabled()) return info;

  if (typeof info.message === 'string') {
    info.message = maskPiiText(info.message);
  }

  const seen = new WeakSet([info]);
  for (const key of Object.keys(info)) {
    if (key === 'message') continue;
    if (isSensitiveKey(key)) {
      info[key] = REDACTED;
      continue;
    }
    if (STRUCTURAL_KEYS.has(normalizeKey(key))) continue;
    info[key] = maskValue(info[key], 0, seen);
  }
  return info;
}

module.exports = {
  REDACTED,
  SENSITIVE_KEYS,
  STRUCTURAL_KEYS,
  isSensitiveKey,
  isMaskEnabled,
  maskPiiText,
  maskLogInfo,
};
