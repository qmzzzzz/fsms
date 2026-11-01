/** T6-1 IP 池聚类：判据必须是「IP 多、指纹少」才算轮换池；共享出口只报不建议。 */
const cluster = require('../../services/ipPoolCluster');

const row = (segment, hits, ips, fps) => ({
  _id: segment,
  hits,
  ips,
  fps,
  firstSeen: new Date('2026-10-31T00:00:00.000Z'),
  lastSeen: new Date('2026-11-01T00:00:00.000Z'),
});

describe('网段键转 CIDR：只转换，不另起一套算法', () => {
  test('IPv4 前三段 ⇒ /24', () => {
    expect(cluster.cidrOf('203.0.113')).toBe('203.0.113.0/24');
  });

  test('IPv6 前四组 ⇒ /64', () => {
    expect(cluster.cidrOf('2001:db8:0:1')).toBe('2001:db8:0:1::/64');
  });

  test('非法/空段 ⇒ null（宁可漏报，也不产出假 CIDR 去封）', () => {
    expect(cluster.cidrOf('')).toBeNull();
    expect(cluster.cidrOf('999.999.999')).toBeNull();
    expect(cluster.cidrOf(null)).toBeNull();
  });
});

describe('判定：轮换池 vs 共享出口（这条判据决定要不要误伤整栋楼）', () => {
  test('大量 IP 却只有极少数指纹 ⇒ rotate_pool（一台机器在换 IP）', () => {
    expect(cluster.verdictOf({ distinctIps: 12, distinctFingerprints: 2, minIps: 4 })).toBe(
      'rotate_pool'
    );
  });

  test('大量 IP + 大量指纹 ⇒ shared_egress（办公 NAT，封段等于误伤整栋楼）', () => {
    expect(cluster.verdictOf({ distinctIps: 12, distinctFingerprints: 11, minIps: 4 })).toBe(
      'shared_egress'
    );
  });

  test('IP 太少 ⇒ 不给结论（2 个 IP 凑不出「池」）', () => {
    expect(cluster.verdictOf({ distinctIps: 2, distinctFingerprints: 1, minIps: 4 })).toBe(
      'too_few_ips'
    );
  });

  test('临界：IP 数 / 指纹数正好 4:1 判轮换池，3:1 判共享出口（边界可证伪）', () => {
    expect(cluster.verdictOf({ distinctIps: 8, distinctFingerprints: 2, minIps: 4 })).toBe(
      'rotate_pool'
    );
    expect(cluster.verdictOf({ distinctIps: 9, distinctFingerprints: 3, minIps: 4 })).toBe(
      'shared_egress'
    );
  });
});

describe('聚类查询', () => {
  const fakeModel = (rows) => ({ aggregate: async () => rows });

  test('只聚合取证库里有网段的记录，且按命中数排序并封顶', async () => {
    const model = {
      aggregate: jest.fn(async (pipeline) => {
        expect(pipeline[0].$match.ipSegment).toEqual({ $ne: '' });
        expect(pipeline[0].$match.createdAt.$gte).toBeInstanceOf(Date);
        expect(pipeline[2].$match.hits.$gte).toBe(cluster.DEFAULT_MIN_HITS);
        return [row('203.0.113', 40, Array(10).fill('1.2.3.4'), ['f'.repeat(32)])];
      }),
    };
    const r = await cluster.clusterIpPools({ model });
    expect(r.segments).toHaveLength(1);
    expect(r.segments[0]).toMatchObject({ segment: '203.0.113', cidr: '203.0.113.0/24', hits: 40 });
  });

  test('轮换池进 recommended，共享出口不进（自动封禁只认 recommended）', async () => {
    const r = await cluster.clusterIpPools({
      model: fakeModel([
        row('203.0.113', 30, Array(10).fill('a'), ['f'.repeat(32)]),
        row('198.51.100', 30, Array(10).fill('b'), Array(9).fill('g'.repeat(32))),
      ]),
    });
    expect(r.recommended.map((s) => s.segment)).toEqual(['203.0.113']);
    expect(r.segments[1].verdict).toBe('shared_egress');
    expect(r.segments[1].recommendBan).toBe(false);
  });

  test('段解析不出 ⇒ 不给 CIDR 也不建议封（unparsable_segment 不是 rotate_pool）', async () => {
    const r = await cluster.clusterIpPools({
      model: fakeModel([row('999.999.999', 30, Array(10).fill('c'), ['f'.repeat(32)])]),
    });
    expect(r.segments[0].cidr).toBeNull();
    expect(r.segments[0].verdict).toBe('unparsable_segment');
    expect(r.recommended).toEqual([]);
  });

  test('空结果不抛，返回空清单（没有捕获时聚类是常态）', async () => {
    const r = await cluster.clusterIpPools({ model: fakeModel([]) });
    expect(r.segments).toEqual([]);
    expect(r.recommended).toEqual([]);
  });
});
