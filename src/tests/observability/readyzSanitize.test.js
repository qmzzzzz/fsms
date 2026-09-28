/**
 * M-1 回归：/readyz 就绪探针错误信息脱敏
 *
 * 背景（2026-09-02 综合评估报告 M-1）：/readyz 曾把 Mongo 驱动的原始
 * err.message 直接放进响应体 checks.mongo。该端点不鉴权且被公网 LB 探测，
 * 驱动错误消息可泄露主机/端口/副本集名/认证失败原因等内部拓扑情报。
 *
 * 修复口径：checkMongoReady 返回 { ok, reason, detail } 双轨——
 * reason 为固定枚举供对外暴露，detail 仅入服务端日志。
 * 本套件驱动三条失败路径断言 reason 枚举正确，且枚举值绝不携带
 * 驱动错误消息中的主机/端口等内容。
 */

const mongoose = require('mongoose');
const { checkMongoReady, __resetReadyCacheForTest } = require('../../utils/healthChecks');

describe('M-1 /readyz 错误信息脱敏（checkMongoReady reason 枚举）', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  beforeEach(() => {
    // S-M1 缓存会跨用例复用结果——本套件每用例 mock 不同状态，必须重置
    __resetReadyCacheForTest();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('正常路径：ok + reason=ok', async () => {
    const result = await checkMongoReady();
    expect(result.ok).toBe(true);
    expect(result.reason).toBe('ok');
  });

  test('连接未就绪：reason=disconnected，detail 仅供日志', async () => {
    // 以实例属性遮蔽原型 getter，模拟 readyState !== 1
    Object.defineProperty(mongoose.connection, 'readyState', {
      value: 0,
      configurable: true,
    });
    try {
      const result = await checkMongoReady();
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('disconnected');
      expect(result.detail).toContain('readyState=0');
    } finally {
      delete mongoose.connection.readyState; // 恢复原型 getter
    }
    expect(mongoose.connection.readyState).toBe(1);
  });

  test('ping 驱动错误：reason=unreachable，拓扑细节只留在 detail', async () => {
    const leaked = 'MongoServerSelectionError: connect ECONNREFUSED 10.0.0.5:27017 (rs-prod-01)';
    const spy = jest.spyOn(mongoose.connection.db, 'admin').mockReturnValue({
      ping: () => Promise.reject(new Error(leaked)),
    });
    try {
      const result = await checkMongoReady();
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('unreachable');
      expect(result.reason).not.toContain('10.0.0.5');
      expect(result.reason).not.toContain('rs-prod-01');
      expect(result.detail).toBe(leaked);
    } finally {
      spy.mockRestore();
    }
  });

  test('ping 悬挂：reason=timeout（探针必须快速失败）', async () => {
    const spy = jest.spyOn(mongoose.connection.db, 'admin').mockReturnValue({
      ping: () => new Promise(() => {}), // 永不 resolve
    });
    try {
      const started = Date.now();
      const result = await checkMongoReady(50);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('timeout');
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      spy.mockRestore();
    }
  });

  // S-M1 回归：结果缓存防探测放大
  describe('S-M1 结果缓存', () => {
    afterEach(() => {
      delete process.env.READYZ_CACHE_MS;
      __resetReadyCacheForTest();
    });

    test('TTL 内二次调用不重发 ping（防探测放大为逐请求 DB 往返）', async () => {
      process.env.READYZ_CACHE_MS = '5000';
      const spy = jest
        .spyOn(mongoose.connection.db, 'admin')
        .mockReturnValue({ ping: () => Promise.resolve({ ok: 1 }) });

      await checkMongoReady();
      await checkMongoReady();
      await checkMongoReady();

      expect(spy).toHaveBeenCalledTimes(1);
      spy.mockRestore();
    });

    test('READYZ_CACHE_MS=0 关闭缓存：逐请求探测', async () => {
      process.env.READYZ_CACHE_MS = '0';
      const spy = jest
        .spyOn(mongoose.connection.db, 'admin')
        .mockReturnValue({ ping: () => Promise.resolve({ ok: 1 }) });

      await checkMongoReady();
      await checkMongoReady();

      expect(spy).toHaveBeenCalledTimes(2);
      spy.mockRestore();
    });

    // F-114：空串/纯空白不能等价于"故意关缓存"。Number('') === 0，而 0 在本模块是合法语义，
    // 所以判据必须把"没配"和"配了 0"分开——否则 k8s 里一个留空的 value: 就把 S-M1 防护抹掉了。
    test.each([
      ['空串（k8s `value:` 留空 / .env `READYZ_CACHE_MS=`）', ''],
      ['纯空白', '   '],
    ])('READYZ_CACHE_MS=%s 仍走默认 TTL：缓存不失效', async (_label, raw) => {
      process.env.READYZ_CACHE_MS = raw;
      const spy = jest
        .spyOn(mongoose.connection.db, 'admin')
        .mockReturnValue({ ping: () => Promise.resolve({ ok: 1 }) });

      await checkMongoReady();
      await checkMongoReady();
      await checkMongoReady();

      // 先取轮次再恢复：mockRestore() 若留在 expect 之后，本用例失败时被 mock 的 admin
      // 会泄漏给下一条用例（邻居看到的 ping 永远"成功"，红会串到不相干的用例身上）
      const pingRounds = spy.mock.calls.length;
      spy.mockRestore();
      expect(pingRounds).toBe(1);
    });

    test('失败结果同样进缓存（DB 悬挂期高频探测不放大为逐请求 ping）', async () => {
      process.env.READYZ_CACHE_MS = '5000';
      const pingSpy = jest
        .spyOn(mongoose.connection.db, 'admin')
        .mockReturnValue({ ping: () => Promise.reject(new Error('down')) });

      const first = await checkMongoReady();
      const second = await checkMongoReady();

      expect(first.reason).toBe('unreachable');
      expect(second.reason).toBe('unreachable');
      expect(pingSpy).toHaveBeenCalledTimes(1);
      spyCleanup(pingSpy);
    });

    function spyCleanup(spy) {
      spy.mockRestore();
    }
  });
});
