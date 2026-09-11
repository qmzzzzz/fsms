/**
 * ipUtils 工具测试：IPv4/IPv6 归一化与 CIDR 子网匹配
 */

const {
  parseIP,
  normalizeIP,
  parseCIDR,
  normalizeCIDR,
  entryPrefixBits,
  ipMatchesEntry,
  entryCovers,
  isFullRangeCIDR,
} = require('../../utils/ipUtils');

describe('ipUtils（ipaddr.js 封装）', () => {
  describe('parseIP / normalizeIP', () => {
    test('合法 IPv4 归一化（含去除首尾空白）', () => {
      expect(normalizeIP(' 192.168.1.1 ')).toBe('192.168.1.1');
      expect(normalizeIP('8.8.8.8')).toBe('8.8.8.8');
      expect(parseIP('0.0.0.0')).not.toBeNull();
    });

    test('IPv4 前导零规范化为标准形式（192.168.001.001 → 192.168.1.1）', () => {
      expect(normalizeIP('192.168.001.001')).toBe('192.168.1.1');
    });

    test('IPv4 映射 IPv6 收敛为纯 IPv4（消除自动封禁与手动录入的重复记录）', () => {
      expect(normalizeIP('::ffff:192.168.1.1')).toBe('192.168.1.1');
      expect(normalizeIP('::ffff:198.51.100.9')).toBe('198.51.100.9');
      // 与直接录入纯 IPv4 归一化结果一致，唯一索引才能正确判重
      expect(normalizeIP('::ffff:8.8.8.8')).toBe(normalizeIP('8.8.8.8'));
    });

    test('IPv6 等价文本形式归一化为同一规范形式', () => {
      expect(normalizeIP('2001:db8::1')).toBe('2001:db8::1');
      expect(normalizeIP('2001:db8:0:0:0:0:0:1')).toBe('2001:db8::1');
      expect(normalizeIP('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
      expect(normalizeIP('2001:DB8::1')).toBe('2001:db8::1');
      expect(normalizeIP('::1')).toBe('::1');
    });

    test('非法文本返回 null（不抛错）', () => {
      expect(normalizeIP('999.999.999.999')).toBeNull();
      expect(normalizeIP('::::')).toBeNull();
      expect(normalizeIP('abc')).toBeNull();
      expect(normalizeIP('')).toBeNull();
      expect(normalizeIP(null)).toBeNull();
      expect(normalizeIP(undefined)).toBeNull();
    });
  });

  describe('parseCIDR / normalizeCIDR', () => {
    test('合法 CIDR 归一化（大小写/压缩形式统一）', () => {
      expect(normalizeCIDR('192.168.0.0/16')).toBe('192.168.0.0/16');
      expect(normalizeCIDR('2001:0DB8::/64')).toBe('2001:db8::/64');
      expect(normalizeCIDR('10.0.0.0/8')).toBe('10.0.0.0/8');
    });

    test('拒绝非法前缀长度（IPv4 >32 / IPv6 >128）', () => {
      expect(parseCIDR('10.0.0.0/33')).toBeNull();
      expect(parseCIDR('2001:db8::/129')).toBeNull();
      expect(normalizeCIDR('10.0.0.0/33')).toBeNull();
    });

    test('拒绝非 CIDR 文本', () => {
      expect(normalizeCIDR('10.0.0.0/')).toBeNull();
      expect(normalizeCIDR('abc')).toBeNull();
      expect(normalizeCIDR('10.0.0.0')).toBeNull();
    });
  });

  describe('entryPrefixBits（覆盖宽度度量）', () => {
    test('单地址视为 /32 或 /128', () => {
      expect(entryPrefixBits('1.2.3.4')).toBe(32);
      expect(entryPrefixBits('2001:db8::1')).toBe(128);
    });

    test('CIDR 取前缀位数（数值越小覆盖面越宽）', () => {
      expect(entryPrefixBits('192.168.0.0/16')).toBe(16);
      expect(entryPrefixBits('192.168.100.0/24')).toBe(24);
      expect(entryPrefixBits('2001:db8::/64')).toBe(64);
      expect(entryPrefixBits('0.0.0.0/0')).toBe(0);
    });

    test('无法解析返回 null', () => {
      expect(entryPrefixBits('::::')).toBeNull();
      expect(entryPrefixBits('')).toBeNull();
      expect(entryPrefixBits(null)).toBeNull();
    });
  });

  describe('ipMatchesEntry', () => {
    test('字符串完全相等快路径', () => {
      expect(ipMatchesEntry('1.2.3.4', '1.2.3.4')).toBe(true);
      expect(ipMatchesEntry('2001:db8::1', '2001:db8::1')).toBe(true);
    });

    test('IPv6 等价文本形式视为同一地址（双向）', () => {
      expect(ipMatchesEntry('2001:db8::1', '2001:db8:0:0:0:0:0:1')).toBe(true);
      expect(ipMatchesEntry('2001:db8:0:0:0:0:0:1', '2001:db8::1')).toBe(true);
    });

    test('IPv4 映射 IPv6 与对应 IPv4 等价（修复 ::ffff: 漏拦）', () => {
      expect(ipMatchesEntry('::ffff:192.168.1.1', '192.168.1.1')).toBe(true);
      expect(ipMatchesEntry('192.168.1.1', '::ffff:192.168.1.1')).toBe(true);
    });

    test('IPv4 CIDR 子网包含判断', () => {
      expect(ipMatchesEntry('192.168.1.5', '192.168.1.0/24')).toBe(true);
      expect(ipMatchesEntry('192.168.1.5', '192.168.0.0/16')).toBe(true);
      expect(ipMatchesEntry('192.168.1.5', '10.0.0.0/8')).toBe(false);
      expect(ipMatchesEntry('192.169.1.5', '192.168.0.0/16')).toBe(false);
      expect(ipMatchesEntry('192.168.1.5', '0.0.0.0/0')).toBe(true);
      expect(ipMatchesEntry('192.168.1.5', '192.168.1.5/32')).toBe(true);
    });

    test('IPv6 CIDR 子网包含判断（/64 轮换防护）', () => {
      expect(ipMatchesEntry('2001:db8:aaaa:bbbb::1234', '2001:db8:aaaa:bbbb::/64')).toBe(true);
      expect(ipMatchesEntry('2001:db8:aaaa:cccc::1234', '2001:db8:aaaa:bbbb::/64')).toBe(false);
      expect(ipMatchesEntry('2001:db8::1', '2001:db8::/48')).toBe(true);
      // 映射 IPv4 客户端命中 IPv4 CIDR
      expect(ipMatchesEntry('::ffff:192.168.1.5', '192.168.0.0/16')).toBe(true);
    });

    test('IPv4 与 IPv6 互不误匹配', () => {
      expect(ipMatchesEntry('1.2.3.4', '::1')).toBe(false);
      expect(ipMatchesEntry('2001:db8::1', '192.168.0.0/16')).toBe(false);
      // /128 精确网段仍按子网语义命中
      expect(ipMatchesEntry('2001:db8::1', '2001:db8::1/128')).toBe(true);
    });

    test('非法条目/非法输入不匹配且不抛错', () => {
      expect(ipMatchesEntry('1.2.3.4', '::::')).toBe(false);
      expect(ipMatchesEntry('1.2.3.4', 'not-an-ip')).toBe(false);
      expect(ipMatchesEntry('not-an-ip', '1.2.3.4')).toBe(false);
      expect(ipMatchesEntry(undefined, '1.2.3.4')).toBe(false);
      expect(ipMatchesEntry('1.2.3.4', undefined)).toBe(false);
      expect(ipMatchesEntry('', '')).toBe(false);
    });
  });

  describe('entryCovers（网段 vs 网段包含判断）', () => {
    test('更宽网段覆盖更窄网段（修复 CIDR 冲突检测被绕过）', () => {
      expect(entryCovers('198.51.100.0/24', '198.51.100.0/28')).toBe(true);
      expect(entryCovers('10.0.0.0/8', '10.1.2.0/24')).toBe(true);
      expect(entryCovers('0.0.0.0/0', '192.168.0.0/16')).toBe(true);
      expect(entryCovers('2001:db8::/32', '2001:db8:aaaa::/48')).toBe(true);
    });

    test('更窄网段不覆盖更宽网段', () => {
      expect(entryCovers('198.51.100.0/28', '198.51.100.0/24')).toBe(false);
      expect(entryCovers('192.168.0.0/16', '10.0.0.0/8')).toBe(false);
    });

    test('不相交网段互不覆盖', () => {
      expect(entryCovers('10.0.0.0/8', '192.168.0.0/16')).toBe(false);
      expect(entryCovers('2001:db8:aaaa::/48', '2001:db8:bbbb::/48')).toBe(false);
    });

    test('inner 为单地址时退化为地址命中判断', () => {
      expect(entryCovers('198.51.100.0/24', '198.51.100.9')).toBe(true);
      expect(entryCovers('198.51.100.0/24', '198.51.101.9')).toBe(false);
      expect(entryCovers('1.2.3.4', '1.2.3.4')).toBe(true);
      expect(entryCovers('::ffff:1.2.3.4', '1.2.3.4')).toBe(true);
    });

    test('单地址条目不覆盖网段', () => {
      expect(entryCovers('198.51.100.9', '198.51.100.0/24')).toBe(false);
    });

    test('IPv4 与 IPv6 互不覆盖；非法输入返回 false 且不抛错', () => {
      expect(entryCovers('2001:db8::/32', '192.168.0.0/16')).toBe(false);
      expect(entryCovers('10.0.0.0/8', 'not-a-cidr/8')).toBe(false);
      expect(entryCovers('bad', '10.0.0.0/8')).toBe(false);
      expect(entryCovers(undefined, '10.0.0.0/8')).toBe(false);
      expect(entryCovers('10.0.0.0/8', undefined)).toBe(false);
    });
  });

  describe('isFullRangeCIDR（全网段识别，用于权限收口）', () => {
    test('/0 前缀被识别为全网段', () => {
      expect(isFullRangeCIDR('0.0.0.0/0')).toBe(true);
      expect(isFullRangeCIDR('::/0')).toBe(true);
      // 非零网络地址配 /0 仍是全网段语义
      expect(isFullRangeCIDR('10.1.2.3/0')).toBe(true);
      expect(isFullRangeCIDR(' 0.0.0.0/0 ')).toBe(true);
    });

    test('非 /0 网段与单地址不算全网段', () => {
      expect(isFullRangeCIDR('0.0.0.0/1')).toBe(false);
      expect(isFullRangeCIDR('10.0.0.0/8')).toBe(false);
      expect(isFullRangeCIDR('192.168.1.1/32')).toBe(false);
      expect(isFullRangeCIDR('2001:db8::/64')).toBe(false);
      expect(isFullRangeCIDR('0.0.0.0')).toBe(false);
      expect(isFullRangeCIDR('192.168.1.1')).toBe(false);
    });

    test('非法输入返回 false 且不抛错', () => {
      expect(isFullRangeCIDR('bad/0')).toBe(false);
      expect(isFullRangeCIDR('10.0.0.0/99')).toBe(false);
      expect(isFullRangeCIDR('')).toBe(false);
      expect(isFullRangeCIDR(null)).toBe(false);
      expect(isFullRangeCIDR(undefined)).toBe(false);
      expect(isFullRangeCIDR(123)).toBe(false);
    });
  });
});
