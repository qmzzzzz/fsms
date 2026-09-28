'use strict';

/**
 * 落地侧判据：严格性必须覆盖**全部四个解析漏斗**，且不得误伤规范网段
 *
 * 与既有测试的分工：
 *  - `clientIpCanonicalForm`（并行会话）钉客户端侧"歧义文本不得命中"；
 *  - `ipQueryAmbiguousRefusal` 钉管理面查询的拒答文案；
 *  - `ipUtils.test.js` / `zzqA_ipUtilsMappedCidr` 钉归一化与映射网段收敛。
 *
 * 本文件钉的是**只有这里会红**的两件事：
 *  1) 判据必须同时住在 parseIP / normalizeIP / comparableAddr / parseCIDR。
 *     技术文档里那版建议只在 normalizeIP 收口，实测不足以关洞：名单匹配走的是
 *     comparableAddr（`ipMatchesEntry('0177.0.0.1','127.0.0.1')` 当时为 true）。
 *     下面每个函数各自打一条，缺哪个漏斗就红哪条。
 *  2) `isAmbiguousIpText` 必须先剥掉 `/前缀` 再判点分。规范网段 `192.168.0.0/16`
 *     的末段是 `0/16`，不剥就会被判成"歧义地址"⇒ 管理面把 CIDR 查询误报成
 *     格式无效（实测由 `ipListBranches` 先抓到，这里补一条不依赖控制器的直判）。
 */

const {
  parseIP,
  normalizeIP,
  parseCIDR,
  normalizeCIDR,
  entryPrefixBits,
  ipMatchesEntry,
  entryCovers,
  isAmbiguousIpText,
  lenientAddressHint,
} = require('../../utils/ipUtils');

const AMBIGUOUS = ['0177.0.0.1', '0x7f.0.0.1', '017700000001', '2130706433', '127.1'];

describe('zzqA 严格判据的漏斗覆盖', () => {
  describe('漏斗 1：comparableAddr（经 ipMatchesEntry / entryCovers）', () => {
    test.each(AMBIGUOUS)('客户端 %s 不得命中规范条目 127.0.0.1', (fake) => {
      expect(ipMatchesEntry(fake, '127.0.0.1')).toBe(false);
    });

    test.each(AMBIGUOUS)('反向：规范客户端 127.0.0.1 也不得命中歧义条目 %s', (entry) => {
      expect(ipMatchesEntry('127.0.0.1', entry)).toBe(false);
    });

    test('字符串快路径不是后门：两侧同写歧义形态也必须 false', () => {
      // 没有 comparableAddr 守卫时，第二行才是攻击者的路；这里连文本相等都不给命中
      expect(ipMatchesEntry('0177.0.0.1', '0177.0.0.1')).toBe(false);
      expect(ipMatchesEntry('127.1', '127.1')).toBe(false);
    });

    test('条目侧同样受控：歧义网段不得覆盖任何地址', () => {
      expect(entryCovers('0177.0.0.0/8', '127.0.0.1')).toBe(false);
      expect(entryCovers('127.0.0.0/8', '0177.0.0.1')).toBe(false);
    });
  });

  describe('漏斗 2：parseIP（经 entryPrefixBits）', () => {
    test('歧义条目的覆盖宽度判不出来 ⇒ null（不得当成 /32 参与排序）', () => {
      expect(entryPrefixBits('127.1')).toBeNull();
      expect(entryPrefixBits('017700000001')).toBeNull();
      expect(parseIP('0x7f.0.0.1')).toBeNull();
      // 正对照
      expect(entryPrefixBits('127.0.0.1')).toBe(32);
      expect(entryPrefixBits('2001:db8::1')).toBe(128);
    });
  });

  describe('漏斗 3：normalizeIP', () => {
    test.each(AMBIGUOUS)('%s ⇒ null', (input) => {
      expect(normalizeIP(input)).toBeNull();
    });
  });

  describe('漏斗 4：parseCIDR（经 normalizeCIDR / isFullRangeCIDR）', () => {
    test('歧义地址部分的网段一律 null', () => {
      expect(normalizeCIDR('0177.0.0.0/8')).toBeNull();
      expect(normalizeCIDR('0x7f.0.0.0/8')).toBeNull();
      expect(normalizeCIDR('::ffff:0177.0.0.0/104')).toBeNull();
    });

    test('歧义形态不得被认成全网段（否则绕过高危配置收口）', () => {
      // 旧实现：017700000000/0 会被 ipaddr 解析后判出 bits===0
      expect(isAmbiguousIpText('0000000000')).toBe(true);
      expect(normalizeCIDR('0177.0.0.0/0')).toBeNull();
    });
  });

  describe('前缀不得干扰点分判据（本次改动实测引入过的回归）', () => {
    test('规范网段不是歧义地址', () => {
      expect(isAmbiguousIpText('192.168.0.0/16')).toBe(false);
      expect(isAmbiguousIpText('10.0.0.0/8')).toBe(false);
      expect(isAmbiguousIpText('2001:db8::/64')).toBe(false);
      expect(parseCIDR('192.168.0.0/16')).not.toBeNull();
    });

    test('歧义网段仍然是歧义（剥前缀不许把判断一起剥掉）', () => {
      expect(isAmbiguousIpText('0177.0.0.0/8')).toBe(true);
      expect(isAmbiguousIpText('192.168.1/24')).toBe(true);
    });
  });

  describe('判据收紧的边界：不误伤合法形态', () => {
    test.each([
      ['127.0.0.1', '127.0.0.1'],
      ['::ffff:127.0.0.1', '127.0.0.1'],
      ['64:ff9b::192.0.2.1', '64:ff9b::c000:201'],
      ['2001:db8::1', '2001:db8::1'],
      ['::1', '::1'],
      ['255.255.255.255', '255.255.255.255'],
      ['0.0.0.0', '0.0.0.0'],
    ])('%s 仍归一化为 %s', (input, expected) => {
      expect(isAmbiguousIpText(input)).toBe(false);
      expect(normalizeIP(input)).toBe(expected);
    });

    test('段值越界（256.x）与垃圾文本一样走 null，但方向不变', () => {
      expect(isAmbiguousIpText('256.1.1.1')).toBe(true);
      expect(normalizeIP('256.1.1.1')).toBeNull();
      expect(isAmbiguousIpText('not-an-ip')).toBe(false);
      expect(normalizeIP('not-an-ip')).toBeNull();
    });
  });

  describe('lenientAddressHint 只许做显示出口', () => {
    test('它保留宽松解释（供拒答文案），而 normalizeIP 已拒绝', () => {
      expect(lenientAddressHint('0177.0.0.1')).toBe('127.0.0.1');
      expect(normalizeIP('0177.0.0.1')).toBeNull();
    });

    test('解析不出时返回 null，不给文案留 "undefined"', () => {
      expect(lenientAddressHint('not-an-ip')).toBeNull();
      expect(lenientAddressHint('')).toBeNull();
      expect(lenientAddressHint(undefined)).toBeNull();
    });
  });
});
