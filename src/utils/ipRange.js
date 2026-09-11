/**
 * IP 访问范围规则：解析、校验与匹配
 *
 * 用于「用户允许登录/访问的 IP 范围」功能。规则文本以 , ; 换行 空格 分隔，
 * 单条规则前加 ! 表示排除（黑名单语义，优先级高于允许项）。
 *
 * 支持的 7 类语法：
 *  1) 单地址          192.168.1.1        / 2001:db8::2003
 *  2) 末段区间        192.168.1.1-254    （仅 IPv4，区间作用于最后一段）
 *  3) CIDR 网段       192.168.1.0/24     / 2001:db8::/96
 *  4) 通配符          192.168.1.*        （* 可出现在任意段；须写满四段）
 *  5) 段区间 + 通配   192.168.1-10.*     （同样须写满四段）
 *  6) 排除            !192.168.1.1       （可作用于上述任意形式）
 *  7) 全量通配        *                  （等价于不限制）
 *
 * P3-28：第 4/5 类（含 * 或段区间的 IPv4 模式）必须写满四段，
 * 三段简写 192.168.* 不受支持，会被 validateRules 判为非法片段并在
 * 用户创建/更新接口回报 400 —— 即配置者能立即看到错误，不存在静默失效。
 * 此处刻意不实现「三段自动补 *」：扩宽访问控制规则的解析语法等于放宽
 * 白名单匹配面，而等价写法 192.168.*.* 已可表达同一意图。
 *
 * 匹配语义（与主流网络设备/OA 系统一致）：
 *  - 规则为空       → 不限制，放行
 *  - 命中任一排除项 → 拒绝（排除优先，不受允许项影响）
 *  - 无允许项       → 仅有排除项时，未被排除即放行
 *  - 有允许项       → 必须命中至少一条才放行
 */

const ipaddr = require('ipaddr.js');
const { normalizeIP, parseCIDR } = require('./ipUtils');

// 规则分隔符：逗号、分号、中文逗号/分号、空白（含换行、制表）
const RULE_SEPARATOR = /[,;，；\s]+/;

// 单条规则最大长度与规则条数上限，防止超长输入造成解析开销
const MAX_RULE_LENGTH = 64;
const MAX_RULE_COUNT = 200;
const MAX_TEXT_LENGTH = 8192;

/**
 * 将规则文本切分为去空、去重后的原始规则数组
 * @param {string} text 规则文本
 * @returns {string[]} 原始规则片段
 */
const splitRules = (text) => {
  if (typeof text !== 'string' || text.trim().length === 0) return [];
  return [
    ...new Set(
      text
        .split(RULE_SEPARATOR)
        .map((s) => s.trim())
        .filter(Boolean)
    ),
  ];
};

/**
 * 解析 IPv4 单段的取值集合定义
 * 支持：具体数字（1）、区间（1-10）、通配（*）
 * @param {string} segment 段文本
 * @returns {{min: number, max: number}|null} 该段允许的取值区间；非法返回 null
 */
const parseIPv4Segment = (segment) => {
  if (segment === '*') return { min: 0, max: 255 };

  const rangeMatch = /^(\d{1,3})-(\d{1,3})$/.exec(segment);
  if (rangeMatch) {
    const min = Number(rangeMatch[1]);
    const max = Number(rangeMatch[2]);
    if (min > 255 || max > 255 || min > max) return null;
    return { min, max };
  }

  if (/^\d{1,3}$/.test(segment)) {
    const value = Number(segment);
    if (value > 255) return null;
    return { min: value, max: value };
  }

  return null;
};

/**
 * 解析「含通配符或段区间」的 IPv4 模式，如 192.168.1.*、192.168.1-10.*、192.168.1.1-254
 * 仅接受写满四段的形式；三段简写（192.168.*）返回 null 由调用方判为非法（见文件头 P3-28）
 * @param {string} pattern 模式文本
 * @returns {{type: 'ipv4-pattern', segments: Array<{min: number, max: number}>}|null}
 */
const parseIPv4Pattern = (pattern) => {
  const parts = pattern.split('.');
  if (parts.length !== 4) return null;

  const segments = [];
  for (const part of parts) {
    const seg = parseIPv4Segment(part);
    if (!seg) return null;
    segments.push(seg);
  }

  return { type: 'ipv4-pattern', segments };
};

/**
 * 解析单条规则（不含 ! 前缀）为可匹配的结构
 * @param {string} rule 规则文本
 * @returns {object|null} 规则结构；非法返回 null
 */
const parseRuleBody = (rule) => {
  // 全量通配
  if (rule === '*') return { type: 'any' };

  // CIDR 网段（IPv4/IPv6 通用）
  if (rule.includes('/')) {
    const cidr = parseCIDR(rule);
    return cidr ? { type: 'cidr', addr: cidr.addr, bits: cidr.bits } : null;
  }

  // 含通配符或段区间：仅 IPv4 支持（IPv6 段区间语义歧义大，统一用 CIDR 表达）
  if (rule.includes('*') || rule.includes('-')) {
    if (rule.includes(':')) return null;
    return parseIPv4Pattern(rule);
  }

  // 单地址（IPv4 / IPv6，映射地址收敛为 IPv4）
  const normalized = normalizeIP(rule);
  return normalized ? { type: 'single', ip: normalized } : null;
};

/**
 * 解析规则文本为结构化规则集
 * @param {string} text 规则文本
 * @returns {{allows: object[], denies: object[], invalid: string[]}}
 *          allows 允许项、denies 排除项、invalid 无法解析的原始片段
 */
const parseRules = (text) => {
  const result = { allows: [], denies: [], invalid: [] };
  if (typeof text !== 'string' || text.length > MAX_TEXT_LENGTH) return result;

  const raws = splitRules(text).slice(0, MAX_RULE_COUNT);

  for (const raw of raws) {
    if (raw.length > MAX_RULE_LENGTH) {
      result.invalid.push(raw);
      continue;
    }

    const isDeny = raw.startsWith('!');
    const body = isDeny ? raw.slice(1).trim() : raw;
    if (!body) {
      result.invalid.push(raw);
      continue;
    }

    const parsed = parseRuleBody(body);
    if (!parsed) {
      result.invalid.push(raw);
      continue;
    }

    (isDeny ? result.denies : result.allows).push({ ...parsed, raw });
  }

  return result;
};

/**
 * 校验规则文本，返回无法识别的片段列表
 * @param {string} text 规则文本
 * @returns {{valid: boolean, invalid: string[], allowCount: number, denyCount: number}}
 */
const validateRules = (text) => {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { valid: true, invalid: [], allowCount: 0, denyCount: 0 };
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return { valid: false, invalid: ['规则文本过长'], allowCount: 0, denyCount: 0 };
  }
  if (splitRules(text).length > MAX_RULE_COUNT) {
    return {
      valid: false,
      invalid: [`规则条数超过上限 ${MAX_RULE_COUNT}`],
      allowCount: 0,
      denyCount: 0,
    };
  }

  const { allows, denies, invalid } = parseRules(text);
  return {
    valid: invalid.length === 0,
    invalid,
    allowCount: allows.length,
    denyCount: denies.length,
  };
};

/**
 * 判断 IP 是否命中单条已解析规则
 * @param {string} ip 客户端 IP（已归一化）
 * @param {object} rule 已解析的规则结构
 * @returns {boolean} 是否命中
 */
const matchRule = (ip, rule) => {
  if (rule.type === 'any') return true;

  if (rule.type === 'single') {
    return ip === rule.ip;
  }

  if (rule.type === 'cidr') {
    let addr;
    try {
      addr = ipaddr.process(ip);
    } catch {
      return false;
    }
    if (addr.kind() !== rule.addr.kind()) return false;
    try {
      return addr.match(rule.addr, rule.bits);
    } catch {
      return false;
    }
  }

  if (rule.type === 'ipv4-pattern') {
    // 模式仅约束 IPv4：客户端为 IPv6（非映射形态）时不匹配
    if (ip.includes(':')) return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return rule.segments.every((seg, i) => {
      const value = Number(parts[i]);
      return Number.isInteger(value) && value >= seg.min && value <= seg.max;
    });
  }

  return false;
};

/**
 * 判断客户端 IP 是否被规则文本允许访问
 * @param {string} clientIp 客户端 IP（可为 ::ffff: 映射形态）
 * @param {string} text 规则文本；空值表示不限制
 * @returns {{allowed: boolean, reason: string, matchedRule: string|null}}
 *          reason 取值：no_rules / denied / allowed / not_in_allowlist / invalid_client_ip
 */
const isIPAllowed = (clientIp, text) => {
  if (typeof text !== 'string' || text.trim().length === 0) {
    return { allowed: true, reason: 'no_rules', matchedRule: null };
  }

  const ip = normalizeIP(clientIp);
  if (!ip) {
    // 客户端 IP 无法解析时，在已配置限制的前提下按拒绝处理（fail-closed）
    return { allowed: false, reason: 'invalid_client_ip', matchedRule: null };
  }

  const { allows, denies } = parseRules(text);

  // 排除项优先：命中即拒绝
  for (const rule of denies) {
    if (matchRule(ip, rule)) {
      return { allowed: false, reason: 'denied', matchedRule: rule.raw };
    }
  }

  // 无允许项（仅配置了排除项）：未被排除即放行
  if (allows.length === 0) {
    return { allowed: true, reason: 'no_rules', matchedRule: null };
  }

  for (const rule of allows) {
    if (matchRule(ip, rule)) {
      return { allowed: true, reason: 'allowed', matchedRule: rule.raw };
    }
  }

  return { allowed: false, reason: 'not_in_allowlist', matchedRule: null };
};

module.exports = {
  splitRules,
  parseRules,
  validateRules,
  isIPAllowed,
  MAX_RULE_LENGTH,
  MAX_RULE_COUNT,
  MAX_TEXT_LENGTH,
};
