/**
 * ipLocationService 单元测试（IP 归属地展示服务）
 *
 * 该服务的安全边界是 **fail-soft**：归属地是纯增强信息，任何失败都必须
 * 表现为「字段为 null、界面省略展示」，绝不能让 sessions 接口因此报错。
 * 因此这里的用例重点不在"查得准"（那是检索器测试的职责），而在失败路径
 * 与缓存边界——服务挂掉的典型方式是异常逃逸污染主流程，或缓存把旧的
 * 失败/成功结果串场。
 */

const searcher = require('../../utils/ip2regionSearcher');
const ipLocation = require('../../services/ipLocationService');

describe('ipLocationService（IP 归属地展示）', () => {
  beforeEach(() => {
    // 缓存逐例清空：locate 以原文为键缓存（含失败结果 null），
    // 上一例的结论残留会让下一例测到的是缓存而非分支
    ipLocation.clearCache();
  });

  describe('输入卫生（非法输入一律 null，不抛错）', () => {
    test.each([
      ['null 输入', null],
      ['undefined 输入', undefined],
      ['空串', ''],
      ['纯空白', '   '],
      ['非字符串', 123],
      ['明显不是 IP 的文本', 'not-an-ip'],
      ['歧义八进制写法按非法处理', '0177.0.0.1'],
    ])('%s → null', (_name, input) => {
      expect(ipLocation.locate(input)).toBeNull();
    });

    test('IPv6：公网 v6 无数据返回 null，内网族（回环/链路本地/ULA）标「内网」', () => {
      // v4 数据库不含 v6 归属，公网 v6 只能不展示
      expect(ipLocation.locate('2001:db8::1')).toBeNull();
      // 内网族不能跟着"缺数据"掉进 null：本机/内网 IPv6 会话（::1、fe80::、fc00::）
      // 若与 IPv4 内网口径分裂，后台会表现为"有的 IP 查不到归属地"
      expect(ipLocation.locate('::1')).toBe('内网');
      expect(ipLocation.locate('fe80::1')).toBe('内网');
      expect(ipLocation.locate('fe80::1%eth0')).toBe('内网');
      expect(ipLocation.locate('fd00::1')).toBe('内网');
    });
  });

  describe('成功路径（真实数据）', () => {
    test('公网 IP 输出「国家·省·市·ISP」可读串，占位符 0 被丢弃', () => {
      // 期望值写成「稳定事实的包含断言」而非全串快照：数据更新可能微调
      // 市/ISP 拆分，测试不应因数据版本红掉
      expect(ipLocation.locate('223.5.5.5')).toContain('中国');
      expect(ipLocation.locate('223.5.5.5')).toContain('·');
    });

    test('IPv4 映射形态（::ffff:1.2.3.4）收敛为纯 IPv4 后查询', () => {
      // Node 在 IPv6 栈下 req.ip 常带此前缀；若不收敛，会话里同一地址
      // 会因写法不同查不到归属地
      expect(ipLocation.locate('::ffff:223.5.5.5')).toContain('中国');
    });

    test('首尾空白被裁剪（列表数据手工修补过的历史记录常带空格）', () => {
      expect(ipLocation.locate('  223.5.5.5  ')).toContain('中国');
    });

    test('内网/保留地址统一展示为「内网」', () => {
      for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '100.64.0.1']) {
        expect(ipLocation.locate(ip)).toBe('内网');
      }
    });
  });

  describe('失败语义与缓存', () => {
    test('检索器抛错时 fail-soft 返回 null，不向调用方逃逸', async () => {
      const spy = jest.spyOn(searcher, 'search').mockImplementation(() => {
        throw new Error('数据文件被外力删除');
      });
      expect(ipLocation.locate('223.5.5.5')).toBeNull();
      spy.mockRestore();
    });

    test('同键重复查询命中缓存（结果一致且不再触发底层检索）', () => {
      const spy = jest.spyOn(searcher, 'search');
      const first = ipLocation.locate('223.5.5.5');
      const calls = spy.mock.calls.length;
      expect(ipLocation.locate('223.5.5.5')).toBe(first);
      expect(spy.mock.calls.length).toBe(calls);
      spy.mockRestore();
    });

    test(`缓存容量上限 ${ipLocation.CACHE_LIMIT}：满后淘汰最早一条（FIFO）`, () => {
      const spy = jest.spyOn(searcher, 'search');
      for (let i = 0; i < ipLocation.CACHE_LIMIT; i++) {
        // 生成必然合法（有真实段覆盖）且互不重复的地址
        ipLocation.locate(`1.${Math.floor(i / 256)}.${i % 256}.1`);
      }
      const before = spy.mock.calls.length;
      expect(before).toBe(ipLocation.CACHE_LIMIT);

      // 再查一条：新键触发检索；容量已满，最早缓存的键被淘汰
      ipLocation.locate('8.8.8.8');
      expect(spy.mock.calls.length).toBe(before + 1);

      // 被淘汰的最早键重新查询 → 再次触发检索（证明确实不在缓存里）
      ipLocation.locate('1.0.0.1');
      expect(spy.mock.calls.length).toBe(before + 2);
      spy.mockRestore();
    });
  });
});
