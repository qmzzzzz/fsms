/**
 * IPv4 映射写法的 CIDR 条目契约（2026-09-19 实测缺陷，静默 fail-open）
 *
 * 修复前实测：
 *   ipMatchesEntry('10.0.0.9',        '::ffff:10.0.0.0/104') === false
 *   ipMatchesEntry('::ffff:10.0.0.9', '::ffff:10.0.0.0/104') === false
 *   normalizeCIDR('::ffff:10.0.0.0/104') === '::ffff:a00:0/104'
 * ⇒ 管理员把黑名单写成映射网段时，**一条都封不住**，而 ipListController:142
 *   只要求 normalizeCIDR 不返回 null 就入库，所以界面上看不出这是个死条目。
 * 本文件把「映射写法必须与等价的原生 IPv4 网段完全同效」钉成契约。
 */

const {
  parseCIDR,
  normalizeCIDR,
  ipMatchesEntry,
  entryCovers,
  isFullRangeCIDR,
} = require('../../utils/ipUtils');

describe('ipUtils：IPv4 映射写法的 CIDR 必须收敛为等价 IPv4 网段', () => {
  test('缺陷用例：映射网段条目必须真的命中 IPv4 客户端', () => {
    expect(ipMatchesEntry('10.0.0.9', '::ffff:10.0.0.0/104')).toBe(true);
    // 客户端也写成映射形态时同样命中（req.ip 在 IPv6 栈下就是这个形态）
    expect(ipMatchesEntry('::ffff:10.0.0.9', '::ffff:10.0.0.0/104')).toBe(true);
    // 网段外的地址不得命中（防"修成放行一切"）
    expect(ipMatchesEntry('11.0.0.9', '::ffff:10.0.0.0/104')).toBe(false);
    expect(ipMatchesEntry('10.255.0.9', '::ffff:10.0.0.0/112')).toBe(false);
  });

  test('与等价原生 IPv4 网段逐项同效（映射写法不得是另一套语义）', () => {
    const mapped = '::ffff:10.0.0.0/104';
    const native = '10.0.0.0/8';
    expect(normalizeCIDR(mapped)).toBe(normalizeCIDR(native));
    expect(normalizeCIDR(mapped)).toBe('10.0.0.0/8');
    for (const ip of ['10.0.0.1', '10.255.255.255', '9.255.255.255', '11.0.0.0']) {
      expect(ipMatchesEntry(ip, mapped)).toBe(ipMatchesEntry(ip, native));
    }
  });

  test('冲突检测随之生效：原生 /8 现在覆盖映射写法的 /104', () => {
    // 修复前恒为 false（kind 不同），管理面的"已有更宽白名单"提醒会漏报
    expect(entryCovers('10.0.0.0/8', '::ffff:10.0.0.0/104')).toBe(true);
    expect(entryCovers('::ffff:10.0.0.0/104', '10.0.0.9')).toBe(true);
  });

  test('第二个 fail-open：::ffff:0.0.0.0/96 必须被识别为全网段高危条目', () => {
    // 修复前 bits=96≠0 ⇒ isFullRangeCIDR 为 false，绕过管理面的高危收口，
    // 等价于用映射写法偷偷加一条 0.0.0.0/0（白名单即全站豁免限流与黑名单）
    expect(isFullRangeCIDR('::ffff:0.0.0.0/96')).toBe(true);
    expect(isFullRangeCIDR('0.0.0.0/0')).toBe(true);
    expect(isFullRangeCIDR('::/0')).toBe(true);
    expect(isFullRangeCIDR('10.0.0.0/8')).toBe(false);
    expect(ipMatchesEntry('8.8.8.8', '::ffff:0.0.0.0/96')).toBe(true);
  });

  test('横跨 IPv4 之外的映射前缀按非法拒绝（不猜语义）', () => {
    // /90 的映射网段包含非 ::ffff: 前缀的地址，无法用 IPv4 CIDR 等价表达
    expect(parseCIDR('::ffff:10.0.0.0/90')).toBeNull();
    expect(ipMatchesEntry('10.0.0.9', '::ffff:10.0.0.0/90')).toBe(false);
    expect(normalizeCIDR('::ffff:10.0.0.0/90')).toBeNull();
  });

  test('回归闸：原生 IPv4 / 真 IPv6 网段行为不变', () => {
    expect(normalizeCIDR('192.168.1.0/24')).toBe('192.168.1.0/24');
    // 起前导零形态按歧义拒绝（原先"顺手规范化"成 192.168.1.0/24）：
    // ipaddr 的八进制解释会让 010 变成 8，规范化与重解释无法靠"看着像"区分
    expect(normalizeCIDR('192.168.001.0/24')).toBeNull();
    expect(ipMatchesEntry('192.168.7.7', '192.168.1.0/24')).toBe(false);
    expect(ipMatchesEntry('192.168.1.7', '192.168.1.0/24')).toBe(true);
    expect(normalizeCIDR('2001:0DB8::/64')).toBe('2001:db8::/64');
    expect(ipMatchesEntry('2001:db8::abcd', '2001:db8::/64')).toBe(true);
    expect(ipMatchesEntry('2001:db9::abcd', '2001:db8::/64')).toBe(false);
    // 非映射的 IPv6 网段不得被误转成 IPv4
    expect(parseCIDR('2001:db8::/64').addr.kind()).toBe('ipv6');
    // 单地址（含映射写法）仍走归一化比较，不受本次改动影响
    expect(ipMatchesEntry('::ffff:10.0.0.9', '10.0.0.9')).toBe(true);
    expect(ipMatchesEntry('10.0.0.9', '::ffff:10.0.0.9')).toBe(true);
  });

  test('非法输入仍返回 null / false，不抛错', () => {
    for (const bad of ['10.0.0.0/33', '::1/129', 'not-an-ip/24', '10.0.0.0/', '', null, 123]) {
      expect(parseCIDR(bad)).toBeNull();
    }
    expect(ipMatchesEntry(null, '::ffff:10.0.0.0/104')).toBe(false);
    expect(ipMatchesEntry('10.0.0.9', 'garbage/24')).toBe(false);
  });
});
