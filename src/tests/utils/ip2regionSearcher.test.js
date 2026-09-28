/**
 * ip2regionSearcher 单元测试（xdb 离线检索器）
 *
 * 检索器是归属地展示的底座，缺陷形态是「静默给错答案」：
 * 二分对齐错一位就把 A 城的人标成 B 城（无异常、无日志）。因此除常规
 * 解析分支外，重点用**真实数据文件的稳定事实**做探针断言——这些事实
 * 来自数据生成器的固有语义（公共 DNS 的国家、环回恒为内网），随数据
 * 版本漂移的概率极低，不会把测试变成脆弱的快照。
 */

const fs = require('fs');
const searcher = require('../../utils/ip2regionSearcher');

describe('ip2regionSearcher（xdb 离线检索器）', () => {
  describe('parseIPv4（严格点分十进制解析）', () => {
    test('合法地址解析为无符号 32 位整数', () => {
      expect(searcher.parseIPv4('0.0.0.0')).toBe(0);
      expect(searcher.parseIPv4('255.255.255.255')).toBe(0xffffffff);
      expect(searcher.parseIPv4('127.0.0.1')).toBe(0x7f000001);
    });

    test('八进制/十六进制/十进制整数等歧义写法一律拒绝', () => {
      // 与 ipUtils.isAmbiguousIpText 同一立场：归属地检索不做"帮你猜写法"
      expect(searcher.parseIPv4('0177.0.0.1')).toBeNull();
      expect(searcher.parseIPv4('0x7f000001')).toBeNull();
      expect(searcher.parseIPv4('2130706433')).toBeNull();
      expect(searcher.parseIPv4('127.1')).toBeNull();
    });

    test('越界段/畸形文本/非字符串一律 null（不抛错）', () => {
      expect(searcher.parseIPv4('256.1.1.1')).toBeNull();
      expect(searcher.parseIPv4('1.2.3.4.5')).toBeNull();
      expect(searcher.parseIPv4('::ffff:1.2.3.4')).toBeNull();
      expect(searcher.parseIPv4('abc')).toBeNull();
      expect(searcher.parseIPv4(null)).toBeNull();
      expect(searcher.parseIPv4(123)).toBeNull();
    });
  });

  describe('loadFromBuffer（结构校验）', () => {
    /** 构造一个长度合法、内容可控的"伪 xdb"：头部 + 向量索引区 + 富余尾部 */
    const fakeXdb = () => Buffer.alloc(256 + 256 * 256 * 8 + 128);

    test('非 Buffer / 长度不足直接抛错', () => {
      expect(() => searcher.loadFromBuffer(null)).toThrow(/数据不完整/);
      expect(() => searcher.loadFromBuffer(Buffer.alloc(10))).toThrow(/数据不完整/);
    });

    test('版本号不是 2 抛错（防止新格式静默错读）', () => {
      const buf = fakeXdb();
      buf.writeUInt16LE(3, 0);
      expect(() => searcher.loadFromBuffer(buf)).toThrow(/版本/);
    });

    test.each([
      ['start 指针为 0', (buf) => buf.writeUInt32LE(0, 8)],
      [
        'end 指针小于 start',
        (buf) => {
          buf.writeUInt32LE(600_000, 8);
          buf.writeUInt32LE(500_000, 12);
        },
      ],
      [
        'end 指针越过文件尾',
        (buf) => {
          buf.writeUInt32LE(600_000, 8);
          buf.writeUInt32LE(10_000_000, 12);
        },
      ],
    ])('段索引指针异常（%s）抛错', (_name, mutate) => {
      const buf = fakeXdb();
      buf.writeUInt16LE(2, 0);
      mutate(buf);
      expect(() => searcher.loadFromBuffer(buf)).toThrow(/指针/);
    });
  });

  describe('search / searchRaw（真实数据文件探针）', () => {
    // 数据文件与代码同仓库提交；若被移除，这条前提自检会让下面的探针用例
    // 显示跳过而不是误报失败（CI 与本地克隆都带该文件，正常不会触发）
    if (!fs.existsSync(searcher.DATA_FILE)) {
      test.skip('仓库缺少 src/data/ip2region.xdb（见该目录 README.md 的刷新方式）', () => {});
      return;
    }

    test('公共 DNS 探针：国家判级正确（生成器固有语义，非具体记录快照）', () => {
      expect(searcher.search('223.5.5.5')).toContain('中国'); // 阿里公共 DNS
      expect(searcher.search('8.8.8.8')).toContain('美国'); // Google 公共 DNS
    });

    test('原始串固定为五段「国家|区域|省份|城市|ISP」结构', () => {
      const raw = searcher.search('223.5.5.5');
      expect(raw.split('|')).toHaveLength(5);
    });

    test('保留地址由数据侧统一标为「内网IP」（与业务侧口径一致）', () => {
      for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '100.64.0.1', '169.254.1.1']) {
        expect(searcher.search(ip)).toBe('0|0|0|内网IP|内网IP');
      }
    });

    test('非 IPv4 输入返回 null 而非抛错', () => {
      expect(searcher.search('256.1.1.1')).toBeNull();
      expect(searcher.search('not-an-ip')).toBeNull();
      expect(searcher.search(null)).toBeNull();
    });

    test('懒加载单例：reset 后重新检索仍可用（数据句柄可被重建）', () => {
      const before = searcher.search('223.5.5.5');
      searcher.resetForTest();
      expect(searcher.search('223.5.5.5')).toBe(before);
    });
  });
});
