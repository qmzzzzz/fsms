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

    it('IPv4-mapped 点分写法按 IPv4 处理（不再依赖手写剥前缀）', () => {
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
    /**
     * ──────────────────────────────────────────────────────────────────
     * F-177：`ipSegment` 的入口必须是 `normalizeIP`，而不是自己剥 '::ffff:'
     *
     * 本文件头声明的不变式是「同一地址的任意文本写法 → 完全相同的网段键」，
     * 而它此前只对 IPv6 的 '::' 压缩写法成立（下面第一条用例钉住的就是那一半）。
     * IPv4-mapped 的另一半被漏掉了：`ip.replace(/^::ffff:/i,'')` 之后靠
     * 「含不含点」分派，点分写法（'::ffff:127.0.0.1'）能过，十六进制写法
     * （'::ffff:7f00:1'，同一个地址）剥完变成 '7f00:1' —— 另一个不完整的
     * IPv6 文本，判非法 ⇒ 网段静默丢失。
     *
     * 关键：**期望值不手写**，而是从本仓唯一的 IP 文本权威 `ipUtils.normalizeIP`
     * 反推。每个等价对先断言两侧归一化结果相同（前提行——若 ipUtils 已经不认为
     * 它们是同一个地址，下面要求网段键相同就没有依据），再要求网段键相同。
     * 这样 ipUtils 的口径若演进，这里会变红而不是悄悄失配。
     * ──────────────────────────────────────────────────────────────────
     */
    const EQUIVALENT_FORMS = [
      ['IPv4-mapped 点分 vs 十六进制（同一个 127.0.0.1）', '::ffff:127.0.0.1', '::ffff:7f00:1'],
      ['IPv4-mapped 点分 vs 十六进制（同一个 10.0.0.9）', '::ffff:10.0.0.9', '::ffff:a00:9'],
      ['IPv4-mapped 点分 vs 十六进制（同一个 0.0.0.1）', '::ffff:0.0.0.1', '::ffff:0:1'],
      ['IPv6 全写 vs :: 压缩（RFC 5952 两种写法）', '2001:db8:0:0:0:0:0:1', '2001:db8::1'],
      ['IPv6 大小写混写', '2001:DB8::1', '2001:db8::1'],
    ];

    it.each(EQUIVALENT_FORMS)('前提（从 ipUtils 反推）：%s 是同一个地址', (_name, a, b) => {
      const { normalizeIP } = require('../../utils/ipUtils');
      expect(normalizeIP(a)).toBeTruthy();
      expect(normalizeIP(a)).toBe(normalizeIP(b));
    });

    it.each(EQUIVALENT_FORMS)('同一地址的任意写法产出同一网段键：%s', (_name, a, b) => {
      expect(ipSegment(a)).toBe(ipSegment(b));
    });

    it('反证：漏掉归一化时十六进制写法会整块丢掉网段（钉住缺陷本体）', () => {
      // 这一条与上一条同向，但它单独存在的原因是：只断言「两者相等」时，
      // 一种「两边都返回 ''」的退化实现也能让它绿。这里显式要求非空。
      expect(ipSegment('::ffff:7f00:1')).toBe('127.0.0');
    });

    it('非法/歧义地址不再产出假网段（归一化只会收窄，不会放宽）', () => {
      const { normalizeIP } = require('../../utils/ipUtils');
      const junk = [
        '999.999.999.999',
        '0177.0.0.1',
        '010.1.1.1',
        '1.2.3.4.5',
        '[::1]',
        '2130706433',
      ];
      for (const ip of junk) {
        // 前提：ipUtils 这侧已经判定它不是可确定的 IP 文本
        expect(normalizeIP(ip)).toBeNull();
        // 结论：网段键必须为空（过去 '999.999.999.999' 会产出 '999.999.999'、
        //       '0177.0.0.1' 会产出 '0177.0.0' —— 拿着假网段参与指纹，等于凭空造区分度）
        expect(ipSegment(ip)).toBe('');
      }
    });

    it('归一化前后向兼容：点分写法与带空格的写法仍按 IPv4 前三段', () => {
      expect(ipSegment('::ffff:127.0.0.1')).toBe('127.0.0');
      expect(ipSegment(' 127.0.0.1 ')).toBe('127.0.0');
      expect(ipSegment('::ffff:169.254.0.1')).toBe('169.254.0');
    });

    it('指纹层面（真正被消费的东西）：同一客户端的两种 IP 写法 → 同一指纹', () => {
      const headers = { 'user-agent': 'UA-1', 'accept-language': 'zh-CN' };
      const a = computeFingerprint(mockReq(headers, '::ffff:203.0.113.10'));
      const b = computeFingerprint(mockReq(headers, '::ffff:cb00:710a'));
      expect(a).toBe(b);
      // 对照臂：同一 /24 之外的地址必须不同（否则上面的相等可以是恒真的）
      const c = computeFingerprint(mockReq(headers, '::ffff:198.51.100.10'));
      expect(a).not.toBe(c);
    });

    it('对照臂：IP 完全不可解析时指纹退化为纯头部指纹（不制造假区分度）', () => {
      const headers = { 'user-agent': 'UA-1', 'accept-language': 'zh-CN' };
      const junk = computeFingerprint(mockReq(headers, '999.999.999.999'));
      const none = computeFingerprint(mockReq(headers, ''));
      // 两个不同的非法地址不得产出两个不同指纹（旧实现会：'999.999.999' vs '0177.0.0'）
      expect(junk).toBe(none);
      expect(computeFingerprint(mockReq(headers, '0177.0.0.1'))).toBe(none);
    });

    /**
     * F-177 自检补上的第二半：**绝对值**。
     * 上面「同一地址的任意写法 → 同一网段键」是关系断言——把 IPv6 分支的 `::` 展开整个
     * 删掉（变异 M3）它也照样 26/26 绿，因为比较的两侧走的是同一条错路。本仓 F-1xx 系列
     * 反复踩过这一点（F-175 的 M1 同形），关系断言必须配一条绝对值断言。
     * 更实际的一点：`ipv6PrefixGroups` 存在的意义就是「同一 /64 内的任意地址收敛到同一个键」,
     * 而这条性质此前只有 IPv4 侧被测过（'同网段内换末位 IP 指纹保持稳定'），
     * IPv6 侧连绝对值都没钉——等于该函数的两条分支一条有闸一条没有。
     */
    it('IPv6 压缩写法必须先展开再取 /64（绝对值，不接受「两边一致」）', () => {
      expect(ipSegment('2001:db8::1')).toBe('2001:db8:0:0');
      expect(ipSegment('2001:db8::ffff')).toBe('2001:db8:0:0');
      expect(ipSegment('fe80::1')).toBe('fe80:0:0:0');
      expect(ipSegment('::1')).toBe('0:0:0:0');
      // 前导零与大小写也在归一化里被吃掉：它与 '2001:db8::1' 是同一个绝对值
      expect(ipSegment('2001:0DB8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8:0:0');
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

    it('IPv6 同一 /64 内换接口标识符，指纹保持稳定（IPv4 侧已有同形态用例）', () => {
      const headers = { 'user-agent': 'UA-1', 'accept-language': 'en' };
      const a = computeFingerprint(mockReq(headers, '2408:8000:1234:5600::11'));
      const b = computeFingerprint(mockReq(headers, '2408:8000:1234:5600::abcd'));
      expect(a).toBe(b);
      // 对照臂：换 /64 必须变（否则上面的相等可以是恒真的）
      const c = computeFingerprint(mockReq(headers, '2408:8000:1234:5678::11'));
      expect(a).not.toBe(c);
      // 对照臂二：/64 之外的截断若被放宽成"整段地址都用上"，这条会立刻变红
      const d = computeFingerprint(mockReq(headers, '2408:8000:1234:5600::beef'));
      expect(a).toBe(d);
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
