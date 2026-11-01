'use strict';

/**
 * 活跃度护栏的**取行范围**判据（T6-3）。
 *
 * 这个模块此前只有一条间接覆盖：ipPoolBan.test.js 把它整段 stub 成 {live:false}，
 * 于是"取行范围错到捞不到段内主机"这类缺陷在测试面上完全不可见。
 *
 * 判据不写死期望值，而是**与 ipMatchesEntry 对拍**——本仓库唯一的 CIDR 包含判断。
 * 手写表格正是漏掉 /1–/7 欠扫的原因：表格只覆盖到 /8 起，且 /30、/31 两行的期望值
 * 本身就写错了（10.9.8.9 不在 10.9.8.0/30 里），旧实现过宽反而"通过"。
 */

const { ipMatchesEntry } = require('../../utils/ipUtils');
const live = require('../../services/ipPoolLiveTraffic');

// 假 model 必须**像真库一样按查询条件过滤**：直接回吐全部行会让"取行范围认得哪些写法"
// 这条判据完全测不到——去掉映射写法前缀的变异在那种模型下是绿的（假绿）。
const funnelOf = async (cidr, rows = []) => {
  const seen = [];
  const model = {
    find: (q) => {
      seen.push(q.ip);
      const hit = rows.filter(
        (r) => q.ip.test(r.ip) && q.method.$in.includes(r.method) && r.createdAt >= q.createdAt.$gte
      );
      return {
        select: () => ({ sort: () => ({ limit: () => ({ lean: async () => hit.slice(0, 200) }) }) }),
      };
    },
  };
  const result = await live.segmentHasLiveTraffic({ cidr, model });
  return { re: new RegExp(seen[0], 'i'), result };
};

const row = (ip) => [{ ip, method: 'GET', createdAt: new Date(), action: 'a' }];

const V4_HOSTS = [
  '10.9.8.9', '10.9.9.9', '10.9.15.255', '10.9.16.0', '10.0.0.1', '10.255.255.255',
  '9.0.0.1', '127.0.0.1', '128.0.0.1', '191.255.255.255', '192.168.1.1',
  '200.10.1.1', '203.0.113.129', '255.255.255.255', '0.0.0.0',
];
const V4_CIDRS = [];
for (let w = 0; w <= 32; w += 1) {
  for (const n of ['10.9.8.0', '128.0.0.0', '203.0.113.128', '10.9.8.9', '0.0.0.0', '200.0.0.0']) {
    V4_CIDRS.push(n + '/' + w);
  }
}

describe('ipPoolLiveTraffic 的取行范围', () => {
  test('超集性：ipMatchesEntry 判为段内的主机，取行正则必须全部能捞到（v4 全宽度）', async () => {
    const missed = [];
    for (const cidr of V4_CIDRS) {
      const { re } = await funnelOf(cidr);
      for (const host of V4_HOSTS) {
        if (ipMatchesEntry(host, cidr) && !re.test(host)) missed.push(cidr + ' <- ' + host);
      }
    }
    expect(missed).toEqual([]);
  });

  test('超集性：v6 同样（含压缩写法 2001:db8::1 与 2001:0db8::1）', async () => {
    // 零组必须出现在段内：段里的零组在文本上会被 :: 吞掉（压缩写法），要求字面写出即漏行
    const cidrs = [
      '2001:db8::/32', '2001:db8::/64', '2001:db8::1/128', '2001:db8:0:1::/64',
      '2001:db8:0:0:1::/80', '2001:db8:1:2:3:4:0:1/80', '2001:db8:0:0:0:0:0:1/128',
      'fe80::/10', '::/0',
    ];
    const hosts = [
      '2001:db8::1', '2001:db8::dead:beef', '2001:db8:0:1::5', '2001:db8:1::1',
      '2001:db8::', '2001:0db8::1', '2001:db8:0:0:0:0:0:1', '2001:db8::1:2:3:4',
      '2001:db8:0:0:1::9', '2001:db8:0:0:0:0:0:1', '2001:db8:1:2:3:99::', '::1', 'fe80::1',
    ];
    const missed = [];
    for (const cidr of cidrs) {
      const { re } = await funnelOf(cidr);
      for (const host of hosts) {
        if (ipMatchesEntry(host, cidr) && !re.test(host)) missed.push(cidr + ' <- ' + host);
      }
    }
    expect(missed).toEqual([]);
  });

  test('不得宽到整个地址空间：/24 的范围不能把相邻 /24 一起捞进来', async () => {
    const { re } = await funnelOf('10.9.8.0/24');
    expect(re.test('10.9.8.9')).toBe(true);
    expect(re.test('10.9.9.9')).toBe(false);
    const { re: r30 } = await funnelOf('10.9.8.0/30');
    expect(r30.test('10.9.9.9')).toBe(false);
  });

  test('/30、/31、/32 这些窄段必须精确到段内：段外主机不得被捞进来', async () => {
    const { re: r30 } = await funnelOf('10.9.8.0/30');
    expect(r30.test('10.9.8.1')).toBe(true);
    expect(r30.test('10.9.8.9')).toBe(false);
    const { re: r31 } = await funnelOf('10.9.8.0/31');
    expect(r31.test('10.9.8.1')).toBe(true);
    expect(r31.test('10.9.8.9')).toBe(false);
    const { re: r32 } = await funnelOf('10.9.8.9/32');
    expect(r32.test('10.9.8.9')).toBe(true);
    expect(r32.test('10.9.8.10')).toBe(false);
  });

  test('/1 这类超宽段不得退化成"只能匹配网络地址那一段"（旧实现的欠扫档）', async () => {
    const { re } = await funnelOf('128.0.0.0/1');
    for (const host of ['128.0.0.1', '191.255.255.255', '200.10.1.1']) {
      expect({ host, hit: re.test(host) }).toEqual({ host, hit: true });
    }
    expect(re.test('127.0.0.1')).toBe(false);
  });

  test('前缀里的点必须转义：不得退化成通配符', async () => {
    const { re } = await funnelOf('10.9.8.9/32');
    expect(re.test('10.9.8.9')).toBe(true);
    expect(re.test('10x9x8x9')).toBe(false);
  });

  test('权威判据复核：漏斗命中但不在段内的行不得算作有活跃流量', async () => {
    // v6 的取行范围是超集（/64 的漏斗认到 /32 就停），正好用来构造"命中漏斗但不在段内"
    const { re } = await funnelOf('2001:db8::/64');
    expect(re.test('2001:db8:1::1')).toBe(true);
    expect(ipMatchesEntry('2001:db8:1::1', '2001:db8::/64')).toBe(false);
    const { result } = await funnelOf('2001:db8::/64', [
      { ip: '2001:db8:1::1', method: 'GET', createdAt: new Date(), action: 'a' },
    ]);
    expect(result.live).toBe(false);
    expect(result.sample).toEqual([]);
    expect(result.scanned).toBe(1);
  });

  test('段内主机（含映射写法）算作有活跃流量，并回传样本', async () => {
    const { result } = await funnelOf('10.9.8.0/24', row('10.9.8.9'));
    expect(result.live).toBe(true);
    expect(result.sample.map((s) => s.ip)).toEqual(['10.9.8.9']);

    const mapped = await funnelOf('10.9.8.0/24', row('::ffff:10.9.8.9'));
    expect(mapped.result.live).toBe(true);
  });

  test('候选被截断时必须保守：捞满上限且没复核到段内主机，也不能答"没有活跃流量"', async () => {
    const rows = Array.from({ length: live.CANDIDATE_LIMIT }, (_, i) => ({
      ip: '2001:db8:1::' + (i + 1),
      method: 'GET',
      createdAt: new Date(),
      action: 'a',
    }));
    const { result } = await funnelOf('2001:db8::/64', rows);
    expect(result.live).toBe(true);
    expect(result.reason).toBe('candidates_truncated');
  });

  test('查询异常时保守返回有活动（宁可挡一次封禁）', async () => {
    const boom = {
      find: () => {
        throw new Error('db down');
      },
    };
    const result = await live.segmentHasLiveTraffic({ cidr: '10.9.8.0/24', model: boom });
    expect(result).toMatchObject({ live: true, scanned: 0, reason: 'check_failed' });
  });

  test('缺 cidr 不查库，也不计入拒绝', async () => {
    const before = live.getLiveTrafficStats().refused;
    const result = await live.segmentHasLiveTraffic({ cidr: null });
    expect(result).toMatchObject({ live: false, scanned: 0 });
    expect(live.getLiveTrafficStats().refused).toBe(before);
  });
  test('护栏统计不认「查不到」：异常兜底也是挡下一次封禁，必须计入 refused', async () => {
    live.resetLiveTrafficState();
    const before = live.getLiveTrafficStats();
    const model = {
      find: () => ({
        select: () => ({
          sort: () => ({
            limit: () => ({
              lean: async () => {
                throw new Error('mongo down');
              },
            }),
          }),
        }),
      }),
    };
    const r = await live.segmentHasLiveTraffic({
      cidr: '10.9.8.0/24',
      model,
      now: new Date('2026-01-01T00:00:00Z'),
    });
    expect(r.live).toBe(true);
    expect(r.reason).toBe('check_failed');
    const after = live.getLiveTrafficStats();
    expect(after.checks).toBe(before.checks + 1);
    expect(after.refused).toBe(before.refused + 1);
  });
});
