/**
 * 名单条目并集的地址族覆盖率判定
 *
 * 独立成文件的理由与 utils/ipUtils.js 的体积棘轮（max-lines 300）有关：
 * 并集判定需要区间换算与合并，直接塞进 ipUtils 会新增一条体积告警。
 *
 * 只判单条 `bits === 0`（ipUtils.isFullRangeCIDR）是可以绕过的：`0.0.0.0/1` 与
 * `128.0.0.0/1` 两条各自都只是半张网，合起来却等价于 `0.0.0.0/0`。白名单
 * 以此方式铺满 IPv4 后，所有地址都豁免黑名单与限流，而两条记录都不会触发
 * 全网段守卫；黑名单侧则等价于把全站封死。故管理面判定必须看**并集**。
 */

const { parseCIDR, parseIP, normalizeIP } = require('./ipUtils');

const FAMILY_BITS = { ipv4: 32, ipv6: 128 };

/** 地址对象的字节序列转整数（BigInt：IPv6 的 128 位超出 Number 安全范围） */
const addrToBigInt = (addr) =>
  addr.toByteArray().reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

/**
 * 把一条名单条目换算成所属地址族的闭区间；非法/不可解析条目返回 null
 * 单地址是宽度为 1 的区间；CIDR 的起始地址按前缀掩码归一（ipaddr 保留主机位）。
 */
const entryToInterval = (entry) => {
  if (typeof entry !== 'string') return null;
  const text = entry.trim();
  if (!text) return null;

  if (text.includes('/')) {
    const parsed = parseCIDR(text);
    if (!parsed) return null;
    const family = parsed.addr.kind();
    if (!FAMILY_BITS[family]) return null;
    const hostBits = BigInt(FAMILY_BITS[family] - parsed.bits);
    const start = addrToBigInt(parsed.addr) & ~((1n << hostBits) - 1n);
    return { family, start, end: start + (1n << hostBits) - 1n };
  }

  // normalizeIP 先把 IPv4 映射形态收敛为 IPv4（::ffff:1.2.3.4 → 1.2.3.4），
  // 与名单落库口径一致；歧义文本返回 null，由 parseIP 一并拒掉。
  const addr = parseIP(normalizeIP(text));
  if (!addr) return null;
  const family = addr.kind();
  if (!FAMILY_BITS[family]) return null;
  const value = addrToBigInt(addr);
  return { family, start: value, end: value };
};

/**
 * 一组名单条目的并集是否覆盖某个地址族的全部地址
 *
 * 判据：把条目落成闭区间，按起点排序后线性合并；第一个区间须从 0 开始，
 * 且合并后的覆盖终点须到该地址族的最大值，中途出现空隙即不覆盖。
 * 无法解析的条目跳过（入站已由归一化拒绝，存量脏数据不可能扩大覆盖面）。
 * @param {string[]} entries 名单条目（单地址或 CIDR）
 * @returns {{ipv4: boolean, ipv6: boolean}} 各地址族是否被完整覆盖
 */
const cidrUnionCoversAll = (entries) => {
  const byFamily = { ipv4: [], ipv6: [] };
  for (const entry of Array.isArray(entries) ? entries : []) {
    const interval = entryToInterval(entry);
    if (interval) byFamily[interval.family].push(interval);
  }

  const covers = (family) => {
    const intervals = byFamily[family];
    if (intervals.length === 0) return false;
    intervals.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    const max = (1n << BigInt(FAMILY_BITS[family])) - 1n;
    let reach = -1n;
    for (const { start, end } of intervals) {
      if (start > reach + 1n) return false; // 与已覆盖段之间有空洞
      if (end > reach) reach = end;
      if (reach >= max) return true;
    }
    return reach >= max;
  };

  return { ipv4: covers('ipv4'), ipv6: covers('ipv6') };
};

/**
 * 删除一条条目后，某个此前被并集完整覆盖的地址族是否**失去**完整覆盖
 *
 * 删除侧的对称约束不能只判被删条目自己的前缀位数：`0.0.0.0/1` 单看只是半张网，
 * 但它与 `128.0.0.0/1` 合起来是 /0。只看单条的删除守卫会允许非超管逐个移除，
 * 把超管配置的全覆盖状态拆掉。反向地，也不能一律禁止「存在全覆盖时删除任何条目」：
 * 全覆盖名单里一条冗余的 /24 被删掉并不改变覆盖结论，拦它只是误伤。
 * 故判据取「删掉这条之后覆盖率是否下降」——只有真正拆掉防线的那一步才需要超管。
 *
 * @param {string[]} entries 当前仍生效的同类型名单条目（**包含**待删条目）
 * @param {string} removedEntry 待删条目的 IP 文本
 * @returns {{ipv4: boolean, ipv6: boolean}} 各地址族是否因删除而失去完整覆盖
 */
const cidrRemovalBreaksFullCoverage = (entries, removedEntry) => {
  const list = Array.isArray(entries) ? entries : [];
  if (!removedEntry) return { ipv4: false, ipv6: false };
  const full = cidrUnionCoversAll(list);
  const remaining = list.filter((entry) => String(entry) !== String(removedEntry));
  const rest = cidrUnionCoversAll(remaining);
  return {
    ipv4: full.ipv4 && !rest.ipv4,
    ipv6: full.ipv6 && !rest.ipv6,
  };
};

module.exports = { cidrUnionCoversAll, cidrRemovalBreaksFullCoverage };
