/** 幂等键形态校验、键哈希与载荷指纹（纯函数，无 IO）。设计取舍见 docs/adr/ADR-014。 */

const crypto = require('crypto');

const KEY_MIN_LENGTH = 8; // 下界防高撞车率键，上界防索引键超限
const KEY_MAX_LENGTH = 64;
// 可见 ASCII 0x21-0x7e：排除空白、控制字符与多字节字符
const KEY_PATTERN = new RegExp('^[\\x21-\\x7e]{' + KEY_MIN_LENGTH + ',' + KEY_MAX_LENGTH + '}$');

function parseIdempotencyKey(raw) {
  const value = Array.isArray(raw) ? raw[0] : raw; // 重复头在 Node 里可能是数组：只认第一个，不接受"任一个合法就用"
  if (value === undefined || value === null || value === '')
    return { ok: false, reason: 'missing' };
  const key = String(value);
  if (!KEY_PATTERN.test(key)) return { ok: false, reason: 'shape' };
  return { ok: true, key };
}

/** 只存哈希（键可能被塞进工号/邮箱）；前缀 scope + userId 作盐 ⇒ 跨端点/跨用户同名键天然不相撞 */
function hashIdempotencyKey({ scope, userId, key }) {
  return crypto
    .createHash('sha256')
    .update(String(scope) + '\u0000' + String(userId) + '\u0000' + String(key))
    .digest('hex');
}

/**
 * 全深度键序无关的规范化：对象按键排序后逐层递归，数组保持原序（[{a:1},{a:2}] 与 [{a:2},{a:1}] 是两份载荷——顺序本身是内容）。只排顶层时，嵌套对象的键序不同会算成两份载荷（JSON.stringify 按插入序输出），客户端/序列化层改写键序即被误判 409。
 * 性能：一次递归 + 每层一次 sort，无字符串改写、无 JSON 往返；req.body 是请求体量级的对象，远小于哈希本体的成本。循环引用防护：req.body 原则上来自 JSON 解析（天然无环），但判据不得因自引用结构抛错/栈溢出——沿路径记祖先（WeakSet，add 后递归、递归完 delete），命中即以占位串收口；用「路径」而不是「见过」是为了放过 DAG 式的同一子树多次引用（那不是环）。
 * 只递归普通对象/无原型对象（Object.prototype 或 null 原型）：Date/Map/Set 等异形对象原样交给 JSON.stringify 的既有语义（Date 仍序列化成 ISO 串，不被误改成 {}）。收集容器用 null 原型：键名可能是 '__proto__'（JSON.parse 可产出同名 own 属性），普通对象赋值会命中原型 setter 丢键，null 原型容器保证它仍是自己的键。
 */
const canonicalizeForFingerprint = (value, ancestors) => {
  if (value === null || typeof value !== 'object') return value;
  if (ancestors.has(value)) return '[Circular]';
  const isPlain =
    Array.isArray(value) ||
    Object.getPrototypeOf(value) === Object.prototype ||
    Object.getPrototypeOf(value) === null;
  if (!isPlain) return value;
  ancestors.add(value);
  let out;
  if (Array.isArray(value)) {
    out = value.map((item) => canonicalizeForFingerprint(item, ancestors));
  } else {
    out = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeForFingerprint(value[key], ancestors);
    }
  }
  ancestors.delete(value);
  return out;
};

/** 同键不同载荷必须被拒（否则客户端改内容重发即可借用上一次的成功响应）。 */
function fingerprintRequestBody(body) {
  const source = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(canonicalizeForFingerprint(source, new WeakSet())))
    .digest('hex');
}

module.exports = {
  KEY_MAX_LENGTH,
  KEY_MIN_LENGTH,
  fingerprintRequestBody,
  hashIdempotencyKey,
  parseIdempotencyKey,
};
