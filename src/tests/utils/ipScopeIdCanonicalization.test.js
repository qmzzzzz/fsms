/**
 * IPv6 作用域标识（RFC 4007 `fe80::1%eth0`）归一化收口
 *
 * 缺陷原型（2026-09-26 实测，修复前）：ipaddr 解析带作用域的文本且 toString() 原样保留它，
 * 但 match() 比较 parts 时忽略它 ⇒ 同一个地址在本模块两套口径：
 *   ipMatchesEntry('fe80::1%eth0','fe80::/10') === true   // CIDR 条目命中
 *   ipMatchesEntry('fe80::1%eth0','fe80::1')   === false  // 单地址条目不命中
 *   normalizeIP('fe80::1%eth0') === 'fe80::1%eth0'        // 违反"归一化为规范文本"后置条件
 * 真实触发面不需要伪造：Node 对 link-local 对端给出的 req.ip 本身就带 %<iface>，
 * 于是自动封禁把带作用域的文本入库，管理员按 fe80::1 查询/解封都对不上那条记录。
 *
 * 用例分三层：绝对值（真值表 + 后置条件）、行为（命中口径一致 + 拒绝面不放宽）、
 * 漂移门禁（从源码推导"凡调 ipaddr 者必先过 parseReadyText"）。
 */
const fs = require('fs');
const path = require('path');
const {
  normalizeIP,
  parseIP,
  parseCIDR,
  normalizeCIDR,
  ipMatchesEntry,
  entryCovers,
  isAmbiguousIpText,
  parseReadyText,
  ipQueryVariants,
  ipQueryCondition,
} = require('../../utils/ipUtils');

const SRC_PATH = path.join(__dirname, '..', '..', 'utils', 'ipUtils.js');

describe('parseReadyText：去空白 + 剥 IPv6 作用域标识的真值表', () => {
  it.each([
    ['fe80::1%eth0', 'fe80::1'],
    ['fe80::1%25', 'fe80::1'], // 数字 scope id（RFC 4007 允许 interface-id）
    ['  fe80::1%eth0  ', 'fe80::1'], // 去空白与剥作用域同一处发生
    ['fe80::1%eth0/64', 'fe80::1/64'], // 前缀在 % 之后必须整体留下
    ['2001:db8::5%1', '2001:db8::5'],
    ['fe80::1', 'fe80::1'], // 无 % 时逐字符不变
    ['fe80::/10%eth0', 'fe80::/10%eth0'], // % 落在前缀之后：不剥（剥了会吞掉 '/10'）
    ['1.2.3.4%eth0', '1.2.3.4%eth0'], // 不含 ':'：RFC 4007 的作用域标识只存在于 IPv6
    ['', ''],
    ['   ', ''],
  ])('parseReadyText(%j) === %j', (input, expected) => {
    expect(parseReadyText(input)).toBe(expected);
  });

  it.each([
    [undefined],
    [null],
    [1234],
    [{}],
    [['fe80::1%eth0']],
    [true],
    [Buffer.from('fe80::1%eth0')],
  ])('非字符串输入归一为空串而不是抛错：%j', (input) => {
    expect(parseReadyText(input)).toBe('');
  });
});

describe('绝对值：同一地址的任意写法收敛为同一规范文本', () => {
  const SCOPED = [
    'fe80::1%eth0',
    'fe80::1%25',
    'fe80::1%wlan0',
    ' FE80::0001%eth0 ',
    '::ffff:1.2.3.4%eth0',
  ];

  it.each(SCOPED)('normalizeIP(%j) 不含 %% 且等于"测试自己剥一遍"的oracle', (text) => {
    const got = normalizeIP(text);
    expect(got).not.toBeNull();
    expect(got).not.toContain('%');
    // 独立推导期望值：判据在测试侧重写一次（split 而非复用实现），实现若改成"剥错位置"即红
    expect(got).toBe(normalizeIP(text.split('%')[0].trim()));
  });

  it.each(SCOPED)('归一化幂等：normalizeIP(normalizeIP(%j)) 不变', (text) => {
    const once = normalizeIP(text);
    expect(normalizeIP(once)).toBe(once);
  });

  it('带作用域与不带的两种写法得到同一串（唯一索引按文本判重从此拦得住）', () => {
    expect(normalizeIP('fe80::1%eth0')).toBe(normalizeIP('fe80::1'));
    expect(normalizeIP('::ffff:1.2.3.4%eth0')).toBe('1.2.3.4');
  });

  it('parseIP 与 normalizeIP 对同一文本判据一致（都先过 parseReadyText）', () => {
    const obj = parseIP('fe80::1%eth0');
    expect(obj).not.toBeNull();
    expect(obj.toString()).toBe(normalizeIP('fe80::1%eth0'));
  });

  it('网段侧不被吞前缀：带作用域的 CIDR 与规范 CIDR 归一到同一条目', () => {
    expect(normalizeCIDR('fe80::1%eth0/64')).toBe(normalizeCIDR('fe80::1/64'));
    expect(normalizeCIDR('fe80::1%eth0/64')).toContain('/64');
    expect(parseCIDR('fe80::1%eth0/64').bits).toBe(64);
  });
});

describe('行为：单地址条目与 CIDR 条目口径一致（修复的判据本身）', () => {
  it.each([
    ['fe80::1%eth0', 'fe80::1'],
    ['2001:db8::5%eth0', '2001:db8::5'],
    ['::ffff:1.2.3.4%eth0', '1.2.3.4'],
    ['fe80::1', 'fe80::1%eth0'], // 存量条目带作用域、客户端不带：仍须生效（向后兼容）
    ['fe80::1%eth0', 'fe80::1%eth0'], // 两侧同形走快路径
  ])('ipMatchesEntry(%j, %j) === true', (client, entry) => {
    expect(ipMatchesEntry(client, entry)).toBe(true);
  });

  it('CIDR 与单地址对同一客户端 IP 同时命中（修复前二者相反）', () => {
    const client = 'fe80::1%eth0';
    expect(ipMatchesEntry(client, 'fe80::/10')).toBe(true);
    expect(ipMatchesEntry(client, 'fe80::1')).toBe(true);
  });

  it.each([
    ['fe80::1%eth0', 'fe80::/10'],
    ['fe80::1%eth0', '2001:db8::/32'],
    ['fe80::1%eth0', '10.0.0.1'],
  ])('entryCovers(%j, %j) 与 ipMatchesEntry 同向', (outer, inner) => {
    expect(entryCovers(outer, inner)).toBe(ipMatchesEntry(inner, outer));
  });

  it('剥作用域不会把地址改错：邻近地址仍不命中', () => {
    expect(ipMatchesEntry('fe80::2%eth0', 'fe80::1')).toBe(false);
    expect(ipMatchesEntry('fe80::1%eth0', 'fe80::2')).toBe(false);
    expect(ipMatchesEntry('::ffff:1.2.3.5%eth0', '1.2.3.4')).toBe(false);
  });
});

describe('拒绝面不放宽（防"凡带 % 都放行"）', () => {
  it.each([
    '0177.0.0.1', // 八进制
    '2130706433', // 单数字
    '0x7f000001', // 十六进制单数字
    '127.1', // 短写补零
  ])('歧义形态规范写法仍按非法：%j', (text) => {
    expect(isAmbiguousIpText(text)).toBe(true);
    expect(normalizeIP(text)).toBeNull();
    expect(ipMatchesEntry(text, '127.0.0.1')).toBe(false);
  });

  it.each([
    '0177.0.0.1%eth0', // 歧义形态 + 作用域：剥完仍是歧义形态 ⇒ 仍拒
    '2130706433%eth0',
    '127.1%eth0',
  ])('歧义形态带作用域后缀同样按非法（判据在剥之后仍然生效）：%j', (text) => {
    expect(normalizeIP(text)).toBeNull();
    expect(ipMatchesEntry(text, '127.0.0.1')).toBe(false);
  });

  it('IPv4 文本带 % 后缀仍按非法（作用域标识只存在于 IPv6，不因此放宽）', () => {
    expect(isAmbiguousIpText('1.2.3.4%eth0')).toBe(true);
    expect(normalizeIP('1.2.3.4%eth0')).toBeNull();
  });

  it('前缀在 % 之前的网段保持被拒（不剥则解析不出，剥了会吞前缀）', () => {
    expect(normalizeCIDR('fe80::/10%eth0')).toBeNull();
    expect(parseCIDR('fe80::/10%eth0')).toBeNull();
  });

  it.each([
    ['fe80::1%', 'fe80::1'],
    ['::1%%', '::1'],
  ])('空作用域（%j）剥掉后是合法地址 ⇒ 收敛为 %j：不猜"它想写别的地址"', (text, expected) => {
    expect(normalizeIP(text)).toBe(expected);
  });

  it('非字符串一律 null（四个漏斗的 typeof 守卫不可少）', () => {
    for (const bad of [null, undefined, 123, {}, ['fe80::1%eth0'], true]) {
      expect(normalizeIP(bad)).toBeNull();
      expect(parseIP(bad)).toBeNull();
      expect(parseCIDR(bad)).toBeNull();
    }
  });
});

describe('记录面：查询变体仍能捞到存量带作用域的行', () => {
  it('ipQueryVariants 同时给出规范文本与原始文本', () => {
    const variants = ipQueryVariants('fe80::1%eth0');
    expect(new Set(variants)).toEqual(new Set(['fe80::1', 'fe80::1%eth0']));
  });

  it('ipQueryCondition 多值时用 $in（存量脏行不因修复而查不到）', () => {
    expect(ipQueryCondition('fe80::1%eth0')).toEqual({ $in: ['fe80::1', 'fe80::1%eth0'] });
  });

  it('规范文本只有一个变体（不为凑命中而放宽）', () => {
    expect(ipQueryVariants('fe80::1')).toEqual(['fe80::1']);
  });
});

describe('漂移门禁：凡调用 ipaddr 的解析函数必须先过 parseReadyText', () => {
  // 从源码推导（CRLF 先归一，否则多行锚点匹配不上）。白名单只有一项：
  // lenientAddressHint 是"仅供人看的提示"，刻意保留 ipaddr 的宽松解释，不参与任何判定。
  const LENIENT_ONLY = new Set(['lenientAddressHint']);
  const src = fs.readFileSync(SRC_PATH, 'utf8').replace(/\r\n/g, '\n');
  const bodies = new Map();
  const FN_RE = /^const (\w+) = \([\s\S]*?^\};$/gm;
  for (let m = FN_RE.exec(src); m; m = FN_RE.exec(src)) {
    const name = m[1];
    // 只取赋值右侧到首个行首 '};' 的函数体（顶层箭头函数常量）
    const start = m[0].indexOf('=>') + 2;
    bodies.set(name, m[0].slice(start));
  }

  const ipaddrCallers = [...bodies.keys()].filter((name) => bodies.get(name).includes('ipaddr.'));

  it('定位到函数体（<3 个说明锚点已随重构失效，本门禁本身要先设防）', () => {
    expect(bodies.size).toBeGreaterThanOrEqual(8);
    expect(ipaddrCallers.length).toBeGreaterThanOrEqual(4);
  });

  it.each(ipaddrCallers)('调用 ipaddr 的 %s 先过 parseReadyText', (name) => {
    if (LENIENT_ONLY.has(name)) return;
    expect(bodies.get(name)).toContain('parseReadyText(');
  });

  it('漏斗数量与文件头注释承诺一致（四个解析漏斗共用判据）', () => {
    expect(ipaddrCallers.filter((n) => !LENIENT_ONLY.has(n))).toHaveLength(4);
  });

  it('parseReadyText 本体不反向依赖 ipaddr（否则判据与解析成环）', () => {
    expect(bodies.get('parseReadyText')).toBeDefined();
    expect(bodies.get('parseReadyText')).not.toContain('ipaddr.');
  });
});
