/**
 * 会话指纹工具
 *
 * 从请求头派生稳定的客户端指纹，用于审计溯源关联：
 * - 同一 sessionId 下指纹突变 → 令牌可能被窃用（换设备/换网络重放）
 * - 跨 sessionId 相同指纹 → 可关联同一攻击者的多次尝试（撞库、多账号爆破）
 *
 * 设计要点：
 * - 只取「相对稳定」的头部：User-Agent、Accept-Language、Accept-Encoding。
 *   不取 Accept（同一客户端不同请求会变）、不取具体 IP（移动网络频繁切换）。
 * - IP 只取网段（IPv4 前三段 / IPv6 前四组），兼顾稳定性与区分度。
 * - 输出取 SHA-256 前 32 位十六进制：碰撞概率足够低，且不含可逆的原始信息，
 *   避免指纹本身成为新的个人信息泄露面。
 */

const crypto = require('crypto');
const { normalizeIP } = require('./ipUtils');

const MAX_HEADER_LEN = 512;

/**
 * 取 IPv6 的前四组（/64 网段）作为稳定网段键
 * 入参须为归一化后的 IPv6 文本；若含 '::' 压缩写法，先展开为完整 8 组再截取，
 * 保证同一地址的任意文本写法（2001:db8::1 与 2001:db8:0:0:0:0:0:1 等）
 * 得到完全相同的网段键，且「前四组」语义始终对应 /64 前缀
 * @param {string} ipv6 归一化后的 IPv6 字符串
 * @returns {string} 前 64 位网段键
 */
const ipv6PrefixGroups = (ipv6) => {
  const halves = ipv6.split('::');
  if (halves.length === 2) {
    // 含压缩点：补零展开为完整 8 组后截取
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves[1] ? halves[1].split(':') : [];
    const missing = Math.max(8 - head.length - tail.length, 0);
    const full = [...head, ...Array(missing).fill('0'), ...tail];
    return full.slice(0, 4).join(':');
  }
  // 无压缩：已是完整 8 组，直接截取
  return ipv6.split(':').slice(0, 4).join(':');
};

/**
 * 提取 IP 网段（降低移动网络下的指纹抖动）
 * @param {string} ip 客户端 IP
 * @returns {string} 网段字符串，无法解析时返回空串
 */
const ipSegment = (ip) => {
  if (typeof ip !== 'string' || !ip) return '';
  // 先归一化、再按族分派。归一化（ipUtils.normalizeIP，内部 ipaddr.process()）已经把两件
  // 事判对了：IPv4-mapped 前缀收敛为 IPv4、以及 RFC 5952 规范写法。
  //
  // 原实现在这里自己 `replace(/^::ffff:/i, '')` 再靠「含不含点」分派——该前缀**只有在后面
  // 接点分四段时**才剥得掉；接十六进制段时（'::ffff:7f00:1' 就是 127.0.0.1）剥完得到
  // '7f00:1'，它已经不是同一个地址，而是另一个不完整的 IPv6 文本，实测 normalizeIP 判非法
  // ⇒ 网段整块丢失（'' ），同一台机器的两种合法写法产出两个指纹，与本文件头声明的
  // 「同一地址的任意文本写法 → 完全相同的网段键」这条不变式相悖。
  // 这类文本在本仓是真实存在的：ipUtils.js:151-165 记录过 normalizeCIDR 会把映射网段
  // 存成 '::ffff:a00:0/104' 这种十六进制写法（同族缺陷，那边已修）。
  //
  // 方向：归一化只会**收窄**产出——'999.999.999.999'、'0177.0.0.1'（前导零，ipUtils
  // 按歧义拒绝）、'1.2.3'（简写）这些过去会产出 '999.999.999' / '0177.0.0' 一类**假网段**
  // 的文本，现在产出 ''（不参与指纹），不会把过去拒绝的输入放进来。唯一新增产出的方向是
  // 十六进制映射写法，而它本来就该解出对应的那个 IPv4 网段。
  const normalized = normalizeIP(ip);
  if (!normalized) return '';

  if (normalized.includes('.')) {
    // 归一化后的 IPv4 恒为点分四段（'1.2.3' 一类简写已被 normalizeIP 判非法，实测 null），
    // 所以这里不再重复判长度
    return normalized.split('.').slice(0, 3).join('.');
  }
  // IPv6：归一化后仍可能带 '::' 压缩，交给 ipv6PrefixGroups 展开成完整 8 组再取前四组（/64）
  return ipv6PrefixGroups(normalized);
};

/**
 * 计算请求的会话指纹
 * @param {import('express').Request} req Express 请求对象
 * @returns {string|null} 32 位十六进制指纹，无任何可用特征时返回 null
 */
const computeFingerprint = (req) => {
  if (!req || typeof req.get !== 'function') return null;

  const ua = String(req.get('user-agent') || '').slice(0, MAX_HEADER_LEN);
  const lang = String(req.get('accept-language') || '').slice(0, MAX_HEADER_LEN);
  const enc = String(req.get('accept-encoding') || '').slice(0, MAX_HEADER_LEN);
  const seg = ipSegment(req.ip);

  // 全部特征为空说明请求头被完全剥离（异常客户端），不产出无意义的固定指纹
  if (!ua && !lang && !enc && !seg) return null;

  // 分隔符必须与内容解耦：`|` 和 `\` 都是这三个外控头里的合法字符，朴素 join('|') 会让
  // ['A|B','C'] 与 ['A','B|C'] 得到同一份 material ⇒ 关联键可被伪造/摊薄。
  // 只转义两个保留字符而**不**整体重编码：不含 | 与 \ 的头 material 逐字节不变，
  // 已落库的指纹在新老记录之间仍然可比（整体重编码会切断跨版本的"同一行为人"关联）。
  const esc = (s) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
  const material = [esc(ua), esc(lang), esc(enc), esc(seg)].join('|');
  return crypto.createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
};

module.exports = {
  computeFingerprint,
  ipSegment,
};
