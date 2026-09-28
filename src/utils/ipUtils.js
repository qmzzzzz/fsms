/**
 * IP 地址工具：IPv4/IPv6 归一化与 CIDR 子网匹配（基于 ipaddr.js）
 *
 * 背景：IP 黑白名单以字符串存储并匹配，存在三处等价性缺口：
 *  1) IPv6 有多种等价文本形式（2001:db8::1 与 2001:db8:0:0:0:0:0:1），
 *     纯字符串精确匹配会因写法不同而静默漏拦；
 *  2) IPv4 映射 IPv6 形态（::ffff:1.2.3.4）与纯 IPv4（1.2.3.4）被视为两个不同字符串；
 *  3) CIDR 网段（192.168.0.0/16、2001:db8::/64）无法通过字符串相等判断包含关系。
 * 本模块统一提供：
 *  - parseIP / normalizeIP：单地址解析与归一化（歧义形态按非法拒绝，见下方 normalizeIP 判据）
 *  - parseCIDR / normalizeCIDR：网段解析（前缀范围 IPv4 ≤32 / IPv6 ≤128）与归一化
 *  - ipMatchesEntry：客户端 IP 与名单条目（单地址或 CIDR）的匹配判断
 *  - isAmbiguousIpText：入站严格性判据（四个解析漏斗共用，管理面入站校验亦可复用）
 *  - parseReadyText：四个漏斗与判据共用的统一入参文本（去空白 + 剥 IPv6 作用域标识）
 */

const ipaddr = require('ipaddr.js');

/**
 * 规范 IPv4 文本判据——拦截 ipaddr 的「宽松数值形态」
 *
 * ipaddr.parse/process/parseCIDR 接受多种非规范写法，并把它们**重解释成另一个地址**
 * （2026-09-19 实测，全部命中 127.0.0.1）：
 *   0177.0.0.1     → 127.0.0.1        八进制
 *   0x7f.0.0.1     → 127.0.0.1        十六进制
 *   017700000001   → 127.0.0.1        单数字（32 位整数）
 *   2130706433     → 127.0.0.1        同上（规范点分写法必含点）
 *   127.1          → 127.0.0.1        短写补零
 *   ::ffff:0177.0.0.1 → 177.0.0.1     映射前缀被吞，连"看起来像谁"都变了
 *
 * 危害方向有两个，都不是"数据脏"：
 *  1) 客户端侧：IP 文本一旦被攻击者影响（开了 trust proxy 的 XFF、WS 握手头），
 *     他就能把自己写成任意规范地址。实测 `ipMatchesEntry('0177.0.0.1','127.0.0.1')`
 *     === true ⇒ 命中白名单即同时豁免黑名单/限流并置信任标记，还能绕过账户级
 *     allowedIPs（两处共用本解析器）。可利用性按真实判据算：默认
 *     `resolveTrustProxyHops()` 非 development 为 0 ⇒ 默认部署不可利用；
 *     ≥2 跳（CDN+nginx，攻击者可控右数第二个元素）或直接暴露却开了 trust proxy 才可利用。
 *  2) 条目侧：管理员写 `127.1` 被封成整个环回段、写 `::ffff:0177.0.0.0/104`
 *     实际存成 `177.0.0.0/8`（一个不相干的公网段）——黑名单静默封错对象 = fail-open。
 *
 * 因此判据放在本文件，且 **四个解析漏斗共用**（parseIP / normalizeIP /
 * comparableAddr / parseCIDR）：只在 normalizeIP 收口是无效的——名单匹配走的是
 * comparableAddr，上面那条 true 仍然成立。判据只针对"会被重解释成另一个地址"的形态；
 * 完全解析不出的文本仍走原有 null → fail-closed 路径，行为不变。
 *
 * 注意：这是**入站严格性**，不是存储格式转换——被判定为歧义的文本一律按非法处理，
 * 不做"帮你改成规范写法"（那等于替攻击者猜意图）。
 */

// 规范 IPv4 的一段：0 或无前导零的十进制，且 ≤ 255
const CANONICAL_OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;

/**
 * 解析前的统一文本：去首尾空白 + 剥掉 IPv6 作用域标识（RFC 4007，如 `fe80::1%eth0`）
 *
 * 这里破例做了本文件对前导零/十六进制刻意不做的"帮你改成规范写法"，理由是作用域标识
 * **不携带任何地址位**，剥掉它不改变"这是哪个地址"——ipaddr 自己的 `match()` 比较 parts
 * 时就已经忽略它。不剥的后果是同一个网块出现两套口径（2026-09-26 实测）：
 *   ipMatchesEntry('fe80::1%eth0', 'fe80::/10') === true    // 走 CIDR，zone 被忽略
 *   ipMatchesEntry('fe80::1%eth0', 'fe80::1')   === false   // 走单地址文本比对，zone 被当真
 * 且 normalizeIP 原样吐出带 %eth0 的文本，违反其"归一化为规范文本"后置条件。真实代价
 * 在记录面而非绕过面：Node 对 link-local 对端的 req.ip 本身就带 %<iface>（无需伪造），
 * 自动封禁遂把带作用域的文本入库，管理员按 fe80::1 查询/解封都对不上那条记录——
 * 与 models/IPBlacklist.js 的 unblockIP 注释为 `::ffff:` 形态立过的"封得住解不开"同一条规矩。
 * 保持原样拒绝的：`1.2.3.4%eth0`（RFC 4007 的作用域标识只存在于 IPv6，不是合法 IPv4 文本）、
 * 以及前缀在后的 `fe80::/10%eth0`（按 '/' 切分，不去吞前缀，仍由 ipaddr 判非法）。
 * @param {unknown} text 原始文本
 * @returns {string} 去空白并剥作用域后的文本；非字符串归一为 ''
 */
const parseReadyText = (text) => {
  const trimmed = typeof text === 'string' ? text.trim() : '';
  if (!trimmed.includes(':')) return trimmed;
  const slash = trimmed.indexOf('/');
  const head = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const at = head.indexOf('%');
  if (at === -1) return trimmed;
  return head.slice(0, at) + (slash === -1 ? '' : trimmed.slice(slash));
};

/**
 * 该文本是否"看起来像 IP、但会被宽松解析器重解释成另一个地址"
 * @param {unknown} text 待判定文本（IP 或 CIDR 均可；`/前缀` 不参与本判据）
 * @returns {boolean} true = 有歧义，必须按非法处理
 */
const isAmbiguousIpText = (text) => {
  if (typeof text !== 'string') return false;
  let trimmed = parseReadyText(text);
  if (!trimmed) return false;

  // 带前缀的写法（CIDR）只看地址部分：`192.168.0.0/16` 是规范网段不是歧义地址，
  // 若把 `/16` 留在最后一段里判，规范网段会被误判成歧义
  // （实测：本仓 CIDR 查询因此错报"格式无效"而不是"仅接受单地址"）。
  // 前缀本身是否越界由 parseCIDR 负责，不在本判据范围内。
  const slash = trimmed.indexOf('/');
  if (slash !== -1) trimmed = trimmed.slice(0, slash);
  if (!trimmed) return false;

  // 纯数字形态：规范点分写法必然含点，故这类文本一律是"被重解释"的风险。
  // 十进制（2130706433）与八进制（017700000001）靠"全是数字"就能抓住，
  // 但十六进制单数字（0x7f000001）含 'x' 会漏网——实测它 amb=false 而
  // normalizeIP 给出 127.0.0.1：客户端侧把自己写成任意规范地址的那条线就是从这儿走的
  // （命中白名单即同时豁免黑名单与限流，并绕过账户 allowedIPs）。
  if (/^[0-9]+$/.test(trimmed)) return true;
  if (/^0x[0-9a-f]+$/i.test(trimmed)) return true;

  // IPv6 可在尾部嵌点分 v4（::ffff:1.2.3.4、64:ff9b::192.0.2.1），只看最后一段
  const tail = trimmed.includes(':') ? trimmed.slice(trimmed.lastIndexOf(':') + 1) : trimmed;
  if (!tail.includes('.')) return false; // 纯 IPv6（含 ::1）不涉及本判据

  const groups = tail.split('.');
  if (groups.length !== 4) return true; // 127.1 / 10.0.1 这类简写会被补成别的地址
  return groups.some((g) => !CANONICAL_OCTET.test(g));
};

/**
 * 「这段歧义文本会被宽松解析器解释成哪个地址」——**仅供人看的提示**（拒答文案）
 *
 * 刻意与 normalizeIP 分开命名并保留 ipaddr 的宽松解释：此后 normalizeIP 对
 * 歧义文本返回 null，而管理面需要告诉运维"你写的 0177.0.0.1 其实会被当成
 * 127.0.0.1"。这个函数只能出现在**文案/日志**里；用在任何匹配或授权判定上，
 * 就是把 重新打开。解析不出时返回 null（调用方自行省略提示）。
 * @param {string} text 歧义 IP 文本
 * @returns {string|null} 宽松解释后的地址文本
 */
const lenientAddressHint = (text) => {
  if (typeof text !== 'string' || !text.trim()) return null;
  try {
    return ipaddr.process(text.trim()).toString();
  } catch {
    return null;
  }
};

/**
 * 解析单个 IP 地址（不含 CIDR 前缀）
 * @param {string} ip 待解析的 IP 字符串
 * @returns {object|null} ipaddr 地址对象；非法或有歧义输入返回 null（不抛错）
 */
const parseIP = (ip) => {
  if (typeof ip !== 'string') return null;
  const trimmed = parseReadyText(ip);
  if (isAmbiguousIpText(trimmed)) return null;
  try {
    return ipaddr.parse(trimmed);
  } catch {
    return null;
  }
};

/**
 * 归一化单地址为规范文本：
 * - IPv4 标准点分十进制。**前导零不再被"规范化"而是按歧义拒绝**：
 *   192.168.001.001 这类文本 ipaddr 按八进制解释（010 → 8），
 *   与"去掉前导零"结果不同 ⇒ 一律返回 null，由调用方走各自的 fail-closed 分支
 * - IPv6 RFC 5952 压缩形式（等价写法统一，如 2001:0DB8:0:0::1 → 2001:db8::1）
 * - IPv4 映射 IPv6 收敛为纯 IPv4（::ffff:1.2.3.4 → 1.2.3.4）
 *   Node 在 IPv6 栈下 req.ip 形如 ::ffff:1.2.3.4，若不收敛会与管理员录入的
 *   1.2.3.4 形成两条指向同一地址的记录（唯一索引按文本判重拦不住）；
 *   注意 ipaddr.parse(...).toString() 会输出 ::ffff:102:304 这类第三种写法，
 *   故必须用 process() 而非 parse() 做归一化
 * @param {string} ip 待归一化的 IP 字符串
 * @returns {string|null} 归一化结果；非法或有歧义输入返回 null
 */
const normalizeIP = (ip) => {
  if (typeof ip !== 'string') return null;
  const trimmed = parseReadyText(ip);
  if (isAmbiguousIpText(trimmed)) return null;
  try {
    return ipaddr.process(trimmed).toString();
  } catch {
    return null;
  }
};

/**
 * 解析 CIDR 网段并校验前缀长度（IPv4 ≤ 32、IPv6 ≤ 128）
 * ipaddr.parseCIDR 自身已拒绝越界前缀（如 /33、/129），此处二次校验兜底。
 *
 * 【IPv4 映射写法的网段必须先收敛成 IPv4，否则该条目永远匹配不上任何客户端】
 * `::ffff:10.0.0.0/104` 这类条目 ipaddr 会解析成 IPv6/104，而 ipMatchesEntry 对
 * 客户端侧一律走 `process()`（映射地址收敛为 IPv4，见 normalizeIP 注释），
 * 于是 `client.kind() !== parsed.addr.kind()` 恒成立 ⇒ 条目命中 0 个地址。
 * 实测（修复前）：ipMatchesEntry('10.0.0.9', '::ffff:10.0.0.0/104') === false，
 * 连客户端也写成 '::ffff:10.0.0.9' 同样是 false。后果按名单类型分两个方向：
 *   - 黑名单：管理员以为封了这个网段，实际一条都不封——**静默 fail-open**；
 *   - 白名单：不豁免，方向安全但同样令人困惑。
 * 且 `normalizeCIDR` 会把它存成第三种写法 `::ffff:a00:0/104`（正是本文件头注释
 * 提醒过的 parse().toString() 形态），运维在界面上根本看不出它是个死条目。
 *
 * 修法：把映射写法的网段**换算**为等价的 IPv4 网段（前缀减去 96 位），而不是直接拒绝——
 * 匹配是运行时按 parseCIDR 结果算的，所以**存量已入库的这类行会自动开始生效**，
 * 无需迁移脚本。前缀小于 /96（如 `::ffff:10.0.0.0/90`）的映射网段横跨了
 * 非 IPv4 地址空间，无法用 IPv4 CIDR 表达，仍按非法拒绝（不猜语义）。
 *
 * @param {string} cidr 形如 192.168.0.0/16 或 2001:db8::/64
 * @returns {{addr: object, bits: number}|null} 解析结果；非法输入返回 null
 */
const parseCIDR = (cidr) => {
  if (typeof cidr !== 'string') return null;
  const text = parseReadyText(cidr);
  // 判据内部只看地址部分，规范网段不会被误判成歧义
  if (isAmbiguousIpText(text)) return null;
  try {
    let [addr, bits] = ipaddr.parseCIDR(text);
    const maxBits = addr.kind() === 'ipv4' ? 32 : 128;
    if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) return null;
    if (
      addr.kind() === 'ipv6' &&
      typeof addr.isIPv4MappedAddress === 'function' &&
      addr.isIPv4MappedAddress()
    ) {
      if (bits < 96) return null; // 横跨 IPv4 之外的地址空间，无法等价表达
      addr = addr.toIPv4Address(); // 注意：ipaddr 的 API 名是 toIPv4Address（无 toIPv4）
      bits -= 96;
    }
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
  const trimmed = parseReadyText(ip);
  if (isAmbiguousIpText(trimmed)) return null;
  try {
    return ipaddr.process(trimmed);
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
  // 快路径只在文本已是规范形态时启用：否则客户端只要照抄条目里那条
  // 存量非规范文本（如 '0177.0.0.1'）就能不经解析直接命中，严格判据被绕过。
  // 落到下面的解析路径后两侧都会被判歧义 ⇒ false，方向是 fail-closed。
  if (String(clientIP) === String(entryIP) && !isAmbiguousIpText(clientIP)) return true;

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

/**
 * 由一个地址推导出它在字符串存储里可能出现的全部等价文本，供 `$in` 检索用。
 *
 * 为什么必须从**地址**推导而不是从输入字符串推导：Node 在 IPv6 栈下 `req.ip` 恒为
 * `::ffff:a.b.c.d`，所以审计日志等按字符串落库的表里，映射形态是默认形态而非边角
 * （实测本地 dev 库同一地址：`::ffff:127.0.0.1` 3553 行 / `127.0.0.1` 2089 行）。
 * 只把 [规范, 原始] 当变体的写法，在"用户贴规范写法查"这一侧会静默漏掉映射入库的行
 * ——检索结果不完整却回 200，比报错危险。
 *
 * IPv4 才补映射形态：`::ffff:2001:db8::1` 不是合法文本，补进去只会引入噪声条件。
 * 返回的每个值归一化后仍等于目标地址 ⇒ 不存在为凑命中而放宽匹配的问题。
 * @param {string} ip 待检索的地址文本（规范或映射形态皆可）
 * @returns {string[]} 变体集合；无法解析时最多返回去空白的原始文本（检索条件退化为匹配不到，fail-closed）
 */
const ipQueryVariants = (ip) => {
  const raw = typeof ip === 'string' ? ip.trim() : '';
  const canon = normalizeIP(ip);
  if (!canon) return raw ? [raw] : [];
  const variants = [canon];
  if (raw && raw !== canon) variants.push(raw);
  const parsed = parseIP(canon);
  if (parsed && parsed.kind() === 'ipv4') variants.push(`::ffff:${canon}`);
  return [...new Set(variants)];
};

/**
 * 把单个地址写成 Mongo 的 ip 过滤条件（单值退化为等值，多值用 $in）。
 * 与 ipQueryVariants 同处本模块，是为了让"查询侧/导出侧同一把尺子"只有一份实现
 * ——两处各写一遍正是 定性过的口径漂移来源。
 * @param {string} ip 待检索的地址文本
 * @returns {string|{$in: string[]}|null} Mongo 条件；无可用变体时返回 null（调用方不落条件）
 */
const ipQueryCondition = (ip) => {
  const variants = ipQueryVariants(ip);
  if (variants.length === 0) return null;
  return variants.length > 1 ? { $in: variants } : variants[0];
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
  isAmbiguousIpText,
  parseReadyText,
  lenientAddressHint,
  ipQueryVariants,
  ipQueryCondition,
};
