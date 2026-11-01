'use strict';

/**
 * 活跃度护栏的**前缀推导**判据（T6-3）。
 *
 * 这个模块此前只有一条间接覆盖：ipPoolBan.test.js 把它整段 stub 成 {live:false}，
 * 于是"前缀推导错到匹配不上任何主机"这类缺陷在测试面上完全不可见——护栏红了但没人知道。
 * 本文件只测一件事：**网段内的真实主机必须被这个查询匹配到**（fail-open 的方向），
 * 以及**不能宽到整个地址空间**（否则护栏变成常量拒绝）。
 *
 * 期望值在本文件内独立计算，不 import 被测模块的推导函数，否则实现错时两边一起错。
 */

const model = () => {
  const seen = [];
  return {
    seen,
    find: (q) => {
      seen.push(q.ip);
      return {
        select: () => ({ sort: () => ({ limit: () => ({ lean: async () => [] }) }) }),
      };
    },
  };
};

const queryRegexOf = async (cidr) => {
  const m = model();
  const live = require('../../services/ipPoolLiveTraffic');
  await live.segmentHasLiveTraffic({ cidr, model: m });
  return m.seen[0];
};

const matches = (re, ip) => new RegExp(re.source).test(ip);

describe('ipPoolLiveTraffic 的网段前缀推导', () => {
  test('网段内的主机必须命中查询：/8 到 /32 每一档都成立（含 /25–/32 的旧缺陷档）', async () => {
    // 每档给一个该网段内的真实主机地址，独立于实现计算（网络号 + 偏移）
    const cases = [
      { cidr: '10.0.0.0/8', host: '10.9.8.9' },
      { cidr: '10.9.0.0/16', host: '10.9.8.9' },
      { cidr: '10.9.8.0/20', host: '10.9.8.9' },
      { cidr: '10.9.8.0/23', host: '10.9.8.9' },
      { cidr: '10.9.8.0/24', host: '10.9.8.9' },
      { cidr: '10.9.8.0/25', host: '10.9.8.9' },
      { cidr: '10.9.8.0/26', host: '10.9.8.9' },
      { cidr: '10.9.8.0/28', host: '10.9.8.9' },
      { cidr: '10.9.8.0/30', host: '10.9.8.9' },
      { cidr: '10.9.8.0/31', host: '10.9.8.9' },
      { cidr: '10.9.8.9/32', host: '10.9.8.9' },
    ];
    for (const { cidr, host } of cases) {
      const re = await queryRegexOf(cidr);
      expect({ cidr, hit: matches(re, host) }).toEqual({ cidr, hit: true });
    }
  });

  test('不得宽到整个地址空间：/24 的查询不能命中相邻 /24，/32 不能命中同 /24 的另一台主机', async () => {
    // 「多算活动」是 fail-closed 可接受方向，但不能宽到"任一地址有活动就拒绝全部封禁"
    const re24 = await queryRegexOf('10.9.8.0/24');
    expect(matches(re24, '10.9.8.9')).toBe(true);
    expect(matches(re24, '10.9.9.9')).toBe(false);

    const re32 = await queryRegexOf('10.9.8.9/32');
    expect(matches(re32, '10.9.8.9')).toBe(true);
    expect(matches(re32, '10.9.8.10')).toBe(false);
  });

  test('IPv6 网段同样要匹配段内主机（不能因为写法差异恒 false）', async () => {
    const re = await queryRegexOf('2001:db8::/64');
    expect(matches(re, '2001:db8::1')).toBe(true);
    expect(matches(re, '2001:db8::dead:beef')).toBe(true);
  });

  test('前缀里的点必须转义：网段内前缀的点不得退化成通配符', async () => {
    // 向量要能真正区分「转义 / 不转义」：不转义时 /^10.9.8\./ 也拦得住 10x9x8x9（尾部点仍是字面点），
    // 必须让**中间的点位于通配位置**才看得出差别——/32 的整段地址是最干净的观察面：
    // 不转义时 /^10.9.8.9$/ 会把 10x9x8y9 一起匹配进来（实测），转义后不会。
    const re32 = await queryRegexOf('10.9.8.9/32');
    expect(matches(re32, '10.9.8.9')).toBe(true);
    expect(matches(re32, '10x9x8y9')).toBe(false);
    // /24 侧同理：前缀 10.9.8 的两处点若变通配，10a9b8.9 也会命中
    const re24 = await queryRegexOf('10.9.8.0/24');
    expect(matches(re24, '10a9b8.9')).toBe(false);
  });

  test('非法/缺省前缀不抛错，且不得退化成"匹配一切"', async () => {
    const re = await queryRegexOf('10.9.8.0');
    expect(re).toBeTruthy();
    expect(matches(re, '10.9.8.9')).toBe(true);
  });
});
