/**
 * 会话指纹工具单测
 */

const { computeFingerprint, ipSegment } = require('../../utils/fingerprint');

const mockReq = (headers = {}, ip = '203.0.113.10') => ({
  ip,
  get: (name) => headers[String(name).toLowerCase()],
});

describe('fingerprint 会话指纹', () => {
  describe('ipSegment 网段提取', () => {
    it('IPv4 取前三段', () => {
      expect(ipSegment('192.168.1.55')).toBe('192.168.1');
    });

    it('IPv4-mapped IPv6 剥离前缀后按 IPv4 处理', () => {
      expect(ipSegment('::ffff:10.0.0.7')).toBe('10.0.0');
    });

    it('IPv6 取前四组', () => {
      expect(ipSegment('2001:db8:85a3:8d3:1319:8a2e:370:7348')).toBe('2001:db8:85a3:8d3');
    });

    it('非法输入返回空串', () => {
      expect(ipSegment('')).toBe('');
      expect(ipSegment(null)).toBe('');
      expect(ipSegment('not-an-ip')).toBe('');
      expect(ipSegment('1.2.3')).toBe('');
    });
  });

  describe('computeFingerprint 指纹计算', () => {
    it('相同请求特征产出相同指纹', () => {
      const headers = {
        'user-agent': 'Mozilla/5.0 Firefox/120.0',
        'accept-language': 'zh-CN,zh;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
      };
      const a = computeFingerprint(mockReq(headers, '203.0.113.10'));
      const b = computeFingerprint(mockReq(headers, '203.0.113.10'));
      expect(a).toBe(b);
      expect(a).toHaveLength(32);
    });

    it('同网段内换末位 IP 指纹保持稳定', () => {
      const headers = { 'user-agent': 'UA-1', 'accept-language': 'en' };
      const a = computeFingerprint(mockReq(headers, '203.0.113.10'));
      const b = computeFingerprint(mockReq(headers, '203.0.113.99'));
      expect(a).toBe(b);
    });

    it('User-Agent 变化导致指纹变化', () => {
      const a = computeFingerprint(mockReq({ 'user-agent': 'UA-1' }));
      const b = computeFingerprint(mockReq({ 'user-agent': 'UA-2' }));
      expect(a).not.toBe(b);
    });

    it('跨网段导致指纹变化', () => {
      const headers = { 'user-agent': 'UA-1' };
      const a = computeFingerprint(mockReq(headers, '203.0.113.10'));
      const b = computeFingerprint(mockReq(headers, '198.51.100.10'));
      expect(a).not.toBe(b);
    });

    it('所有特征为空时返回 null（不产出无意义的固定指纹）', () => {
      expect(computeFingerprint(mockReq({}, ''))).toBeNull();
    });

    it('非法 req 对象返回 null', () => {
      expect(computeFingerprint(null)).toBeNull();
      expect(computeFingerprint({})).toBeNull();
    });

    it('超长请求头被截断，不影响指纹产出', () => {
      const long = 'x'.repeat(5000);
      const fp = computeFingerprint(mockReq({ 'user-agent': long }));
      expect(fp).toHaveLength(32);
    });
  });
});
