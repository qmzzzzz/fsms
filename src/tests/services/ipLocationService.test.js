/**
 * ipLocationService 单元测试（IP 归属地展示服务）
 *
 * 该服务的安全边界是 **fail-soft**：归属地是纯增强信息，任何失败都必须
 * 表现为「字段为 null、界面省略展示」，绝不能让 sessions 接口因此报错。
 * 因此这里的用例重点不在"查得准"（那是检索器测试的职责），而在失败路径
 * 与缓存边界——服务挂掉的典型方式是异常逃逸污染主流程，或缓存把旧的
 * 失败/成功结果串场。
 *
 * F4（2026-11-03）追加：懒加载独立层的两类失败必须分开——加载失败置哨兵
 * （5 分钟内短路、只告警一次、过期重试）；句柄加载成功后的运行期异常**不置位**
 * 加载闩（逐条降级 + 60s 节流 warn）。混用一个布尔的话，一条畸形输入就能把
 * 整个归属地面杀 5 分钟（或反之：数据文件没了还每条查询重读 11MB）。
 */

const searcher = require('../../utils/ip2regionSearcher');
const ipLocation = require('../../services/ipLocationService');
const logger = require('../../utils/logger');
// 私网展示值取后端码表单例（constants/ipLocationCodes.js）：断言跟着码表走，
// 后端改取值时这里跟着改，不会出现「测试还钉着旧中文、实现已是新码」的假绿
const { IP_LOCATION_CODES } = require('../../constants/ipLocationCodes');
const PRIVATE = IP_LOCATION_CODES.PRIVATE_NETWORK;

describe('ipLocationService（IP 归属地展示）', () => {
  beforeEach(() => {
    // F4：句柄三态与告警闩是模块级状态，逐例复位（缓存清空含在内）
    ipLocation.resetForTest();
    searcher.resetForTest();
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

    test('IPv6：公网 v6 无数据返回 null，内网族（回环/链路本地/ULA）标稳定码 private', () => {
      // v4 数据库不含 v6 归属，公网 v6 只能不展示
      expect(ipLocation.locate('2001:db8::1')).toBeNull();
      // 内网族不能跟着"缺数据"掉进 null：本机/内网 IPv6 会话（::1、fe80::、fc00::）
      // 若与 IPv4 内网口径分裂，后台会表现为"有的 IP 查不到归属地"。取值是稳定码
      // 而非中文文案，英文界面才能本地化（见 constants/ipLocationCodes.js）
      expect(ipLocation.locate('::1')).toBe(PRIVATE);
      expect(ipLocation.locate('fe80::1')).toBe(PRIVATE);
      expect(ipLocation.locate('fe80::1%eth0')).toBe(PRIVATE);
      expect(ipLocation.locate('fd00::1')).toBe(PRIVATE);
    });
  });

  describe('成功路径（真实数据）', () => {
    test('公网 IP 输出数据文本（非稳定码）：占位符 0 被丢弃', () => {
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

    test('内网/保留地址统一展示为稳定码 private（IPv4 数据侧与 IPv6 range 判定同一口径）', () => {
      for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '100.64.0.1']) {
        expect(ipLocation.locate(ip)).toBe(PRIVATE);
      }
    });
  });

  test('私网取值不含中日韩字符（英文界面 i18n 缺口回归）', () => {
    // 修复前私网/环回地址收敛成中文两字「内网」：前端从 API 拿到的已是定型
    // 文案，切到 en-US 也翻不了，界面上挂着中文。现在必须是语言中立的稳定码
    expect(ipLocation.locate('127.0.0.1')).not.toMatch(/[\u4e00-\u9fa5]/);
    expect(ipLocation.locate('::1')).not.toMatch(/[\u4e00-\u9fa5]/);
    expect(ipLocation.locate('fd00::1')).not.toMatch(/[\u4e00-\u9fa5]/);
  });

  describe('失败语义与缓存', () => {
    test('检索器运行期抛错时 fail-soft 返回 null，不向调用方逃逸', async () => {
      const spy = jest.spyOn(searcher, 'searchRaw').mockImplementation(() => {
        throw new Error('段索引被外力改写');
      });
      expect(ipLocation.locate('223.5.5.5')).toBeNull();
      spy.mockRestore();
    });

    test('同键重复查询命中缓存（结果一致且不再触发底层检索）', () => {
      const spy = jest.spyOn(searcher, 'searchRaw');
      const first = ipLocation.locate('223.5.5.5');
      const calls = spy.mock.calls.length;
      expect(ipLocation.locate('223.5.5.5')).toBe(first);
      expect(spy.mock.calls.length).toBe(calls);
      spy.mockRestore();
    });

    test(`缓存容量上限 ${ipLocation.CACHE_LIMIT}：满后淘汰最早一条（FIFO）`, () => {
      const spy = jest.spyOn(searcher, 'searchRaw');
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

  describe('F4 懒加载独立层：加载哨兵与运行期异常两态分开', () => {
    test('加载失败只告警一次且哨兵期内短路：后续查询不再重读 11MB 数据文件', () => {
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const loadSpy = jest.spyOn(searcher, 'loadDataFile').mockImplementation(() => {
        throw new Error('xdb missing');
      });
      try {
        for (let i = 0; i < 10; i += 1) {
          expect(ipLocation.locate(`1.2.${i}.1`)).toBeNull();
        }
        // 10 条查询只真正加载了 1 次：哨兵把其余 9 次短路掉（旧实现每条都重做同步读）
        expect(loadSpy).toHaveBeenCalledTimes(1);
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(warnSpy.mock.calls[0][0]).toContain('IP 归属地数据加载失败');
      } finally {
        loadSpy.mockRestore();
        warnSpy.mockRestore();
      }
    });

    test('哨兵 5 分钟过期重试一次：数据修复后无需进程重启', () => {
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      let healthy = false;
      const loadSpy = jest.spyOn(searcher, 'loadDataFile').mockImplementation(() => {
        if (!healthy) throw new Error('xdb missing');
        return searcher.loadFromBuffer(require('fs').readFileSync(searcher.DATA_FILE));
      });
      try {
        expect(ipLocation.locate('223.5.5.5')).toBeNull();
        // 修复数据后把时钟推过哨兵存续期（LOAD_RETRY_MS）⇒ 下一条查询重试并恢复
        healthy = true;
        const clock = jest
          .spyOn(Date, 'now')
          .mockReturnValue(Date.now() + ipLocation.LOAD_RETRY_MS + 1000);
        try {
          expect(ipLocation.locate('223.5.5.5')).toContain('中国');
        } finally {
          clock.mockRestore();
        }
        // 告警闩在成功后复位：每个故障回合只告警一次，重试成功不算第二回合
        expect(warnSpy).toHaveBeenCalledTimes(1);
      } finally {
        loadSpy.mockRestore();
        warnSpy.mockRestore();
      }
    });

    test('句柄加载成功后的运行期异常不置位加载闩：逐条 warn（节流）返回 null，句柄不失效', () => {
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      // loadDataFile 必须成功（真实文件），失败的是逐条检索
      const loadSpy = jest
        .spyOn(searcher, 'loadDataFile')
        .mockImplementation(() =>
          searcher.loadFromBuffer(require('fs').readFileSync(searcher.DATA_FILE))
        );
      const rawSpy = jest.spyOn(searcher, 'searchRaw').mockImplementation(() => {
        throw new Error('runtime boom');
      });
      try {
        for (let i = 0; i < 5; i += 1) {
          expect(ipLocation.locate(`1.2.3.${i + 1}`)).toBeNull();
        }
        // 每条都还在尝试检索（加载闩没有被置位 ⇒ 句柄没有被判死）
        expect(rawSpy).toHaveBeenCalledTimes(5);
        // loadDataFile 只在首条时跑过一次：运行期异常不得触发重新加载
        expect(loadSpy).toHaveBeenCalledTimes(1);
        // warn 逐条路径但有 60s 节流：5 条只落 1 条
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(warnSpy.mock.calls[0][0]).toContain('IP 归属地检索异常');
      } finally {
        loadSpy.mockRestore();
        rawSpy.mockRestore();
        warnSpy.mockRestore();
      }
    });

    test('成功路径每条查询不重读数据文件：句柄进程内复用', () => {
      const loadSpy = jest
        .spyOn(searcher, 'loadDataFile')
        .mockImplementation(() =>
          searcher.loadFromBuffer(require('fs').readFileSync(searcher.DATA_FILE))
        );
      try {
        for (let i = 0; i < 8; i += 1) ipLocation.locate(`223.5.${i}.1`);
        expect(loadSpy).toHaveBeenCalledTimes(1);
      } finally {
        loadSpy.mockRestore();
      }
    });
  });
});
