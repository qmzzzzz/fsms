/**
 * IP 地址工具：IPv4/IPv6 归一化与 CIDR 子网匹配（基于 ipaddr.js）
 *
 * 背景：IP 黑白名单以字符串存储并匹配，存在三处等价性缺口：
 *  1) IPv6 有多种等价文本形式（2001:db8::1 与 2001:db8:0:0:0:0:0:1），
 *     纯字符串精确匹配会因写法不同而静默漏拦；
 *  2) IPv4 映射 IPv6 形态（::ffff:1.2.3.4）与纯 IPv4（1.2.3.4）被视为两个不同字符串；
 *  3) CIDR 网段（192.168.0.0/16、2001:db8::/64）无法通过字符串相等判断包含关系。
 * 本模块统一提供：
 *  - parseIP / normalizeIP：单地址解析与归一化（含前导零 IPv4 的规范化）
 *  - parseCIDR / normalizeCIDR：网段解析（前缀范围 IPv4 ≤32 / IPv6 ≤128）与归一化
 *  - ipMatchesEntry：客户端 IP 与名单条目（单地址或 CIDR）的匹配判断
 */

const ipaddr = require('ipaddr.js');

/**
 * 解析单个 IP 地址（不含 CIDR 前缀）
 * @param {string} ip 待解析的 IP 字符串
 * @returns {object|null} ipaddr 地址对象；非法输入返回 null（不抛错）
 */
const parseIP = (ip) => {
  if (typeof ip !== 'string') return null;
  try {
    return ipaddr.parse(ip.trim());
  } catch {
    return null;
  }
};

/**
 * 归一化单地址为规范文本：
 * - IPv4 标准点分十进制（含去除前导零，如 192.168.001.001 → 192.168.1.1）
 * - IPv6 RFC 5952 压缩形式（等价写法统一，如 2001:0DB8:0:0::1 → 2001:db8::1）
 * - IPv4 映射 IPv6 收敛为纯 IPv4（::ffff:1.2.3.4 → 1.2.3.4）
 *   Node 在 IPv6 栈下 req.ip 形如 ::ffff:1.2.3.4，若不收敛会与管理员录入的
 *   1.2.3.4 形成两条指向同一地址的记录（唯一索引按文本判重拦不住）；
 *   注意 ipaddr.parse(...).toString() 会输出 ::ffff:102:304 这类第三种写法，
 *   故必须用 process() 而非 parse() 做归一化
 * @param {string} ip 待归一化的 IP 字符串
 * @returns {string|null} 归一化结果；非法输入返回 null
 */
const normalizeIP = (ip) => {
  if (typeof ip !== 'string') return null;
  try {
    return ipaddr.process(ip.trim()).toString();
  } catch {
    return null;
  }
};

/**
 * 解析 CIDR 网段并校验前缀长度（IPv4 ≤ 32、IPv6 ≤ 128）
 * ipaddr.parseCIDR 自身已拒绝越界前缀（如 /33、/129），此处二次校验兜底
 * @param {string} cidr 形如 192.168.0.0/16 或 2001:db8::/64
 * @returns {{addr: object, bits: number}|null} 解析结果；非法输入返回 null
 */
const parseCIDR = (cidr) => {
  if (typeof cidr !== 'string') return null;
  try {
    const [addr, bits] = ipaddr.parseCIDR(cidr.trim());
    const maxBits = addr.kind() === 'ipv4' ? 32 : 128;
    if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) return null;
    return { addr, bits };
  } catch {
    return null;
  }
};

/**
 * 归一化 CIDR 文本（地址部分压缩、大小写统一），如 2001:0DB8::/64 → 2001:db8::/64
 * @param {string} cidr 待归一化的网段字符串
 * @returns {string|null} 归一化结果；非法输入返回 null
 */
const normalizeCIDR = (cidr) => {
  const parsed = parseCIDR(cidr);
  return parsed ? `${parsed.addr.toString()}/${parsed.bits}` : null;
};

/**
 * 计算名单条目的覆盖宽度（前缀位数）：单地址视为 /32（IPv4）或 /128（IPv6），
 * CIDR 网段取其前缀位数。数值越小覆盖面越宽（/16 宽于 /24，/24 宽于 /32 单地址），
 * 用于多条命中时按「最宽泛优先」排序
 * @param {string} entryIP 名单条目（单地址或 CIDR）
 * @returns {number|null} 前缀位数；无法解析返回 null
 */
const entryPrefixBits = (entryIP) => {
  if (!entryIP || typeof entryIP !== 'string') return null;
  const str = entryIP.trim();
  if (str.includes('/')) {
    const parsed = parseCIDR(str);
    return parsed ? parsed.bits : null;
  }
  const parsed = parseIP(str);
  if (!parsed) return null;
  return parsed.kind() === 'ipv4' ? 32 : 128;
};

/**
 * 将 IP 转为用于比较的地址对象：
 * 使用 process() 把 IPv4 映射 IPv6（::ffff:1.2.3.4）转换为 IPv4，
 * 使其与直接写入的 1.2.3.4 视为同一地址
 * @param {string} ip 客户端 IP 或名单条目
 * @returns {object|null} ipaddr 地址对象；非法输入返回 null
 */
const comparableAddr = (ip) => {
  if (typeof ip !== 'string') return null;
  try {
    return ipaddr.process(ip.trim());
  } catch {
    return null;
  }
};

/**
 * 判断客户端 IP 是否命中名单条目
 * - 快路径：字符串完全相等直接命中（覆盖绝大多数存量记录与自动封禁，零解析开销）
 * - 条目为 CIDR 网段 → 子网包含判断（IPv4/IPv6 均支持，含映射地址转换）
 * - 条目为单地址 → 双方归一化后比较（等价文本形式视为相同）
 * - 任何解析失败返回 false，不影响放行决策的安全性
 * @param {string} clientIP 客户端 IP（通常来自 req.ip）
 * @param {string} entryIP 名单中存储的单地址或 CIDR 网段
 * @returns {boolean} 是否命中
 */
const ipMatchesEntry = (clientIP, entryIP) => {
  if (!clientIP || !entryIP) return false;
  if (String(clientIP) === String(entryIP)) return true;

  const client = comparableAddr(clientIP);
  if (!client) return false;

  const entryStr = String(entryIP).trim();

  // 条目为 CIDR 网段：子网包含判断
  if (entryStr.includes('/')) {
    const parsed = parseCIDR(entryStr);
    if (!parsed) return false;
    if (client.kind() !== parsed.addr.kind()) return false;
    try {
      return client.match(parsed.addr, parsed.bits);
    } catch {
      return false;
    }
  }

  // 条目为单地址：归一化后比较（映射地址与对应 IPv4 等价）
  const entry = comparableAddr(entryStr);
  if (!entry || client.kind() !== entry.kind()) return false;
  return client.toString() === entry.toString();
};

/**
 * 判断名单条目 A 是否完整覆盖条目 B（支持网段 vs 网段）
 * 用于管理面冲突检测：如白名单已有 198.51.100.0/24 时，
 * 应识别出 198.51.100.0/28 与 198.51.100.9 均落在其覆盖范围内。
 * ipMatchesEntry 的语义是「单地址 vs 条目」，客户端侧传入 CIDR 会解析失败，
 * 故网段与网段的包含关系必须由本函数判断。
 * @param {string} outer 可能更宽的条目（单地址或 CIDR）
 * @param {string} inner 被包含的条目（单地址或 CIDR）
 * @returns {boolean} outer 是否覆盖 inner
 */
const entryCovers = (outer, inner) => {
  if (!outer || !inner) return false;
  const outerStr = String(outer).trim();
  const innerStr = String(inner).trim();
  if (outerStr === innerStr) return true;

  // inner 为单地址时退化为标准的「地址是否命中条目」判断
  if (!innerStr.includes('/')) return ipMatchesEntry(innerStr, outerStr);

  // inner 为网段：outer 必须同样是网段且前缀不长于 inner（更宽或等宽），
  // 且 inner 的网络地址落在 outer 内
  const innerCidr = parseCIDR(innerStr);
  if (!innerCidr) return false;

  if (!outerStr.includes('/')) return false;
  const outerCidr = parseCIDR(outerStr);
  if (!outerCidr) return false;

  if (innerCidr.addr.kind() !== outerCidr.addr.kind()) return false;
  if (outerCidr.bits > innerCidr.bits) return false;

  try {
    return innerCidr.addr.match(outerCidr.addr, outerCidr.bits);
  } catch {
    return false;
  }
};

/**
 * 判断名单条目是否为「全网段」（覆盖全部地址的 /0 前缀）
 * 0.0.0.0/0 与 ::/0 会一次性命中所有客户端：
 *  - 加入黑名单 → 全站拒绝服务（含管理员自己，无法再登录解除）
 *  - 加入白名单 → 所有 IP 豁免黑名单与限流，安全策略整体失效
 * 因此此类条目属于高危配置，需在管理面单独做权限收口。
 * @param {string} entry 名单条目（单地址或 CIDR）
 * @returns {boolean} 是否为全网段
 */
const isFullRangeCIDR = (entry) => {
  if (typeof entry !== 'string' || !entry.includes('/')) return false;
  const parsed = parseCIDR(entry);
  return !!parsed && parsed.bits === 0;
};

module.exports = {
  parseIP,
  normalizeIP,
  parseCIDR,
  normalizeCIDR,
  entryPrefixBits,
  ipMatchesEntry,
  entryCovers,
  isFullRangeCIDR,
};
