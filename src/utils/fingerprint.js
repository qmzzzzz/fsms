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
  // 剥离 IPv4-mapped IPv6 前缀，统一按 IPv4 处理
  const bare = ip.replace(/^::ffff:/i, '');

  if (bare.includes('.')) {
    const parts = bare.split('.');
    return parts.length === 4 ? parts.slice(0, 3).join('.') : '';
  }
  if (bare.includes(':')) {
    // 先经 ipUtils.normalizeIP 归一化为 RFC 5952 规范形式：
    // 原始写法直接 split(':').slice(0,4) 会因压缩位置不同（如 :: 在头部/中部）
    // 对同一地址产出不同网段键；归一化 + 展开 '::' 后再截取，结果稳定
    const normalized = normalizeIP(bare);
    if (!normalized || !normalized.includes(':')) return '';
    return ipv6PrefixGroups(normalized);
  }
  return '';
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

  const material = [ua, lang, enc, seg].join('|');
  return crypto.createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
};

module.exports = {
  computeFingerprint,
  ipSegment,
};
