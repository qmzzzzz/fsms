/** 取证载荷的"编解码原语"：封顶截断、头袋掩码、规范化哈希（从 forensicCapturePayload.js 拆出，max-lines 300 棘轮）。
 *  只认识**字节**、不认识 body 语义；凭据头判定复用 utils/helpers 的 isCredentialQueryKey，不另立名单。 */

const crypto = require('crypto');
const { isCredentialQueryKey, redactUrlQuery } = require('../utils/helpers');
const { errText } = require('../utils/auditWriteFailure');

const TRUNCATED_MARK = '…[FORENSIC_TRUNCATED]';
const REDACTED = '[REDACTED]';

const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

/** 截断：按 UTF-8 字节封顶，超限追加可见标记；摘要与字节数始终取**全文** */
const capText = (text, capBytes) => {
  const full = typeof text === 'string' ? text : JSON.stringify(text);
  const bytes = Buffer.byteLength(full, 'utf8');
  if (bytes <= capBytes) return { text: full, truncated: false, bytes, sha256: sha256(full) };
  // 标记本身不得把输出顶穿 capBytes：极小 cap 时退化为"尾巴被吃掉"的短标记
  const mark = capBytes >= Buffer.byteLength(TRUNCATED_MARK, 'utf8') + 1 ? TRUNCATED_MARK : '…';
  const keep = Math.max(0, capBytes - Buffer.byteLength(mark, 'utf8'));
  let cut = Buffer.from(full, 'utf8').subarray(0, keep).toString('utf8');
  cut = cut.replace(/\uFFFD+$/, ''); // subarray 可能切在多字节字符中间：丢掉末尾的替换符，保证输出是合法 UTF-8
  return { text: cut + mark, truncated: true, bytes, sha256: sha256(full) };
};

/** 头袋封顶：按插入序收，超预算即停并落可见标记（不静默丢）；预算按 **UTF-8 字节**计——按字符计会让 CJK/emoji 头把体积撑到上限的 2–3 倍。 */
const capBag = (bag, capBytes) => {
  const out = {};
  let used = 2;
  let dropped = 0;
  for (const [key, value] of Object.entries(bag)) {
    const piece = JSON.stringify({ [key]: value });
    const bytes = Buffer.byteLength(piece, 'utf8');
    if (used + bytes > capBytes) {
      dropped += 1;
      continue;
    }
    out[key] = value;
    used += bytes + 1;
  }
  if (dropped > 0) out.__truncated = { dropped, capBytes, usedBytes: used };
  return out;
};

/** 名字里直接看出凭据语义的头（其余交给单源判定；手写名单永远比攻击者的头名慢一步） */
const MASKED_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'x-reauth-ticket',
  'x-auth',
  'x-authentication',
]);

/** 头名是否携带凭据：复用 utils/helpers 的单源判定（与审计/访问日志同一把尺） */
const isCredentialHeader = (lower) => MASKED_HEADERS.has(lower) || isCredentialQueryKey(lower);

/** URL 型头：query 里的凭据按单源规则打码（referer 常带着 reset token 原样进来） */
const CREDENTIAL_URL_HEADERS = new Set(['referer', 'x-original-url']);

/** 单值封顶：超限追加可见标记（静默截断会让事后比对头值得出错误结论） */
const capValue = (value) =>
  Array.isArray(value)
    ? value.map((v) => capText(String(v), 1024).text)
    : capText(String(value), 4096).text;

/** 请求头掩码：敏感头整体替换；x-forwarded-for 保留原链（任务书明示，归属地取证需要） */
const maskHeaders = (headers, capBytes) => {
  const bag = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const lower = String(key).toLowerCase();
    if (CREDENTIAL_URL_HEADERS.has(lower)) bag[key] = redactUrlQuery(String(value));
    else bag[key] = isCredentialHeader(lower) ? REDACTED : capValue(value);
  }
  return capBag(bag, capBytes);
};

/** Set-Cookie → 仅属性摘要（name/Max-Age/HttpOnly/Secure/SameSite），绝不存值 */
const summarizeSetCookie = (raw) => {
  const parts = String(raw)
    .split(';')
    .map((p) => p.trim());
  const [pair, ...attrs] = parts;
  const summary = { name: pair.split('=')[0] || '' };
  for (const attr of attrs) {
    const [k, v] = attr.split('=');
    const key = String(k).toLowerCase();
    if (key === 'max-age') summary.maxAge = Number(v);
    else if (key === 'httponly') summary.httpOnly = true;
    else if (key === 'secure') summary.secure = true;
    else if (key === 'samesite') summary.sameSite = v;
  }
  return summary;
};

/** 响应头：set-cookie 摘要化，其余同请求侧掩码 */
const maskResponseHeaders = (headers, capBytes) => {
  const bag = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const lower = String(key).toLowerCase();
    if (lower === 'set-cookie') {
      bag[key] = (Array.isArray(value) ? value : [value]).map(summarizeSetCookie);
      continue;
    }
    bag[key] = isCredentialHeader(lower) ? REDACTED : capValue(value);
  }
  return capBag(bag, capBytes);
};

/** canonicalJSON：键排序、Date→ISO、undefined 丢弃（recordHash 与 P2b 清单链共用同一口径） */
const canonicalJson = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(',')}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
};

/** recordHash = sha256(canonicalJSON(全字段去 recordHash/__walSeq/_id))：seq 属内容、改动必须被哈希抓住；_id 是存储层产物（算哈希那刻还不存在），剔除后落库副本才可能逐字节复算。 */
const recordHashOf = (doc) => {
  const copy = { ...doc };
  delete copy.recordHash;
  delete copy.__walSeq;
  delete copy._id;
  return sha256(canonicalJson(copy));
};

/** 确定性 _id：recordHash 前 24 位十六进制即是合法 ObjectId；非哈希输入无条件回落随机 */
const deterministicId = (hash) => {
  const { Types } = require('mongoose');
  const hex = String(hash || '').slice(0, 24);
  return /^[0-9a-f]{24}$/i.test(hex) ? new Types.ObjectId(hex) : new Types.ObjectId();
};

/** 落库失败后的幂等筛选：把这批里"其实已经写进去了"的剔除，只回填真没进去的 */
const docsNotYetStored = async (Model, docs) => {
  const ids = docs.map((d) => d._id).filter(Boolean);
  if (!ids.length) return docs;
  const found = await Model.find({ _id: { $in: ids } })
    .select('_id')
    .lean();
  const stored = new Set(found.map((r) => String(r._id)));
  return docs.filter((d) => !stored.has(String(d._id)));
};

/** 逐条校验模型（不落库）：null=可写，或 { message }=被拒原因。只有真 mongoose 模型（带 schema.paths）才分流，测试替身一律判可写——否则替身会被全判非法，把"落库失败"类用例的语义整个改掉；构造期 cast 抛错折算成"被拒"，不冒泡成写失败。 */
const validateOne = (Model, doc) => {
  if (!Model || !Model.schema || !Model.schema.paths) return null;
  try {
    const err = new Model(doc).validateSync();
    if (!err) return null;
    const first = Object.values(err.errors || {})[0];
    return { message: (first && first.message) || err.message || 'validation failed' };
  } catch (e) {
    return { message: errText(e) };
  }
};

module.exports = {
  sha256,
  capText,
  capBag,
  capValue,
  maskHeaders,
  maskResponseHeaders,
  summarizeSetCookie,
  canonicalJson,
  recordHashOf,
  deterministicId,
  docsNotYetStored,
  validateOne,
  TRUNCATED_MARK,
  REDACTED,
};
