/**
 * P3：segmentOfIp 改走 ipaddr 解析。
 *
 * 旧实现按 '.'/':' 切分拼前缀，对压缩形态 IPv6（2001:db8::1）会产出非法 CIDR 文本
 * （cidrOf 返回 null ⇒ 该 IP 从网段聚类/活跃度分桶里静默丢失）。现口径：ipaddr 解析
 * 后取 IPv4 /24、IPv6 /64 网络前缀；非法或歧义输入返回 null（宁漏不造）。
 */
const { segmentOfIp } = require('../../services/ipPoolLiveTraffic');

describe('segmentOfIp 的网段收敛（P3）', () => {
  test('压缩形态 IPv6 取 /64 网络前缀', () => {
    // normalizeCIDR 输出 RFC 5952 规范形（零组压缩），与全展开写法同段
    expect(segmentOfIp('2001:db8::1')).toBe('2001:db8::/64');
    expect(segmentOfIp('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
    expect(segmentOfIp('2001:0DB8:0:0:0:0:0:1')).toBe('2001:db8::/64'); // 全展开形态同段
  });

  test('IPv4 取 /24；IPv4 映射写法收敛到同一 v4 网段', () => {
    expect(segmentOfIp('10.9.8.9')).toBe('10.9.8.0/24');
    expect(segmentOfIp('::ffff:10.9.8.9')).toBe('10.9.8.0/24');
  });

  test('非法/歧义输入返回 null（宁漏不造非法 CIDR）', () => {
    expect(segmentOfIp(null)).toBeNull();
    expect(segmentOfIp('')).toBeNull();
    expect(segmentOfIp('not-an-ip')).toBeNull();
    expect(segmentOfIp('::::')).toBeNull();
    expect(segmentOfIp('0x7f.0.0.1')).toBeNull(); // 歧义形态按 ipUtils 判据拒绝
  });
});
