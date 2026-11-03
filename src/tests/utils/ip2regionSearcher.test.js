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

    // F3（off-by-one 回归，2026-11-03）：构造「通过全部加载校验、末桶 ePtr==buffer.length」
    // 的合成 xdb，桶内尾隙查询不得抛 ERR_OUT_OF_RANGE。
    //
    // 构造法（loadFromBuffer 的校验逐条满足）：
    //   头部 256B（version=2，start=首段偏移、end=末段起始偏移——头部校验要求 end>start，
    //   故放**两条**段索引）+ 向量索引区 65536×8B + 数据区（地区串）+ 文件最末 28B 是
    //   两条段索引（startIp/endIp/dataLen/dataPtr ×2），于是该桶 sPtr=len-28、ePtr=len
    //   ——「末桶 ePtr 允许等于文件尾」正是 loadFromBuffer 注释声明的排他末尾契约，
    //   修复前二分上界取 N（排他），探到 mid=N 时 p 恰好落在 ePtr==buffer.length 处
    //   ⇒ 越文件尾抛 ERR_OUT_OF_RANGE。
    const REGION = 'A|B|C|D|E'; // 五段「国家|区域|省份|城市|ISP」占位串
    const regionOffset = 256 + 256 * 256 * 8;
    const segOffset = regionOffset + REGION.length;
    const syntheticTailGapXdb = () => {
      const totalLen = segOffset + 2 * 14; // 末桶 ePtr 恰为 buffer.length
      const buf = Buffer.alloc(totalLen);
      buf.writeUInt16LE(2, 0); // version
      buf.writeUInt32LE(segOffset, 8); // startIndexPtr（首段）
      buf.writeUInt32LE(segOffset + 14, 12); // endIndexPtr（末段起始，> start）
      // 桶 (203<<8|0) → 203.0.x.x 前缀：sPtr=len-28、ePtr=len（等于文件尾，加载必须放行）
      const bucket = 203 * 256 + 0;
      buf.writeUInt32LE(segOffset, 256 + bucket * 8);
      buf.writeUInt32LE(totalLen, 256 + bucket * 8 + 4);
      buf.write(REGION, regionOffset); // 数据区：地区串（两条段共用）
      const ipOf = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
      const writeSeg = (at, startIp, endIp) => {
        buf.writeUInt32LE(startIp, at);
        buf.writeUInt32LE(endIp, at + 4);
        buf.writeUInt16LE(REGION.length, at + 8);
        buf.writeUInt32LE(regionOffset, at + 10);
      };
      writeSeg(segOffset, ipOf(203, 0, 113, 0), ipOf(203, 0, 113, 255));
      writeSeg(segOffset + 14, ipOf(203, 0, 114, 0), ipOf(203, 0, 114, 255));
      return buf;
    };
    const segBaseOf = (buf) => buf.length - 2 * 14; // 合成数据里段索引区起点（定值，避免魔法数漂移）

    test('合成尾隙（末桶 ePtr==文件尾）：桶内尾隙查询不抛 ERR_OUT_OF_RANGE，按未命中返回空串', () => {
      const buf = syntheticTailGapXdb();
      const handle = searcher.loadFromBuffer(buf); // 全部加载校验通过（含"末桶 ePtr==len"契约）
      // 命中段内：正常返回地区串（对照，证明检索本身没被修坏）
      expect(searcher.searchRaw(handle, '203.0.113.9')).toBe('A|B|C|D|E');
      expect(searcher.searchRaw(handle, '203.0.114.9')).toBe('A|B|C|D|E');
      // 尾隙：203.0.200.1 落在末段终点之后、同桶内。旧上界（high=N）会探到 mid=N ⇒
      // p==ePtr==buffer.length ⇒ readUInt32LE 抛 ERR_OUT_OF_RANGE；修复后按未命中返回 ''
      expect(searcher.searchRaw(handle, '203.0.200.1')).toBe('');
      expect(searcher.searchRaw(handle, '203.0.50.1')).toBe(''); // 段前的桶内隙，同理不抛
    });

    test('N=0 退化（零长桶 ePtr==sPtr）：空桶循环不执行，直接按未命中返回空串', () => {
      const buf = syntheticTailGapXdb();
      // 桶 (10<<8|0)：sPtr=ePtr=段索引区起点（对齐且在界内）⇒ N=0，二分区间 [0,-1]
      const bucket = 10 * 256 + 0;
      buf.writeUInt32LE(segBaseOf(buf), 256 + bucket * 8);
      buf.writeUInt32LE(segBaseOf(buf), 256 + bucket * 8 + 4);
      const handle = searcher.loadFromBuffer(buf);
      expect(searcher.searchRaw(handle, '10.1.2.3')).toBe('');
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
