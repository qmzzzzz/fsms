/**
 * /readyz 的 Redis 检查：生产要求共享状态时，Redis 未就绪必须判 unready
 *
 * 背景：此前 /readyz 只 ping Mongo，而生产 config/validate 强制 REDIS_URL——
 * 限流计数、失效广播与审计链分布式锁都依赖它。Redis 挂掉但 Mongo 正常的实例
 * 会被 LB 当成健康实例继续送流量，同时静默退化为进程内语义。
 *
 * 本文件只测 checkRedisReady 的判据与失败形态（固定枚举、超时、脱敏双轨），
 * 应用层 /readyz 的合并逻辑由 appTrustProxyAndReadyzGuards 覆盖。
 */

const mockSharedCache = {
  isRedisConfigured: jest.fn(),
  isRedisEnabled: jest.fn(),
  getRedisClient: jest.fn(),
};

jest.mock('../../services/sharedCache', () => mockSharedCache);

const { checkRedisReady, __resetReadyCacheForTest } = require('../../utils/healthChecks');

describe('checkRedisReady', () => {
  const originalRedisUrl = process.env.REDIS_URL;

  beforeEach(() => {
    __resetReadyCacheForTest();
    delete process.env.READYZ_CACHE_MS;
    mockSharedCache.isRedisConfigured.mockReset();
    mockSharedCache.isRedisEnabled.mockReset();
    mockSharedCache.getRedisClient.mockReset();
  });

  afterAll(() => {
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
  });

  test('未配置 REDIS_URL：not_configured 且不算故障（本地/单机部署）', async () => {
    mockSharedCache.isRedisConfigured.mockReturnValue(false);
    const result = await checkRedisReady();
    expect(result).toMatchObject({ ok: true, reason: 'not_configured' });
    // 未配置时不得去碰客户端
    expect(mockSharedCache.getRedisClient).not.toHaveBeenCalled();
  });

  test('配置了但连接未就绪：disconnected（不能把"还没连上"报成 ready）', async () => {
    mockSharedCache.isRedisConfigured.mockReturnValue(true);
    mockSharedCache.isRedisEnabled.mockReturnValue(false);
    mockSharedCache.getRedisClient.mockReturnValue({});
    const result = await checkRedisReady();
    expect(result).toMatchObject({ ok: false, reason: 'disconnected' });
  });

  test('ping 成功：ok', async () => {
    mockSharedCache.isRedisConfigured.mockReturnValue(true);
    mockSharedCache.isRedisEnabled.mockReturnValue(true);
    mockSharedCache.getRedisClient.mockReturnValue({ ping: () => Promise.resolve('PONG') });
    const result = await checkRedisReady();
    expect(result).toMatchObject({ ok: true, reason: 'ok' });
  });

  test('ping 抛错：unreachable，原始错误只进 detail（不进枚举）', async () => {
    const leaked = 'connect ECONNREFUSED 10.9.9.9:6379 (redis-prod)';
    mockSharedCache.isRedisConfigured.mockReturnValue(true);
    mockSharedCache.isRedisEnabled.mockReturnValue(true);
    mockSharedCache.getRedisClient.mockReturnValue({
      ping: () => Promise.reject(new Error(leaked)),
    });
    const result = await checkRedisReady();
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('unreachable');
    expect(result.reason).not.toContain('10.9.9.9');
    expect(result.detail).toBe(leaked);
  });

  test('ping 悬挂：timeout（探针必须快速失败）', async () => {
    mockSharedCache.isRedisConfigured.mockReturnValue(true);
    mockSharedCache.isRedisEnabled.mockReturnValue(true);
    mockSharedCache.getRedisClient.mockReturnValue({ ping: () => new Promise(() => {}) });
    const started = Date.now();
    const result = await checkRedisReady(30);
    expect(result).toMatchObject({ ok: false, reason: 'timeout' });
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test('READYZ_CACHE_MS 内复用结果：高频探测不放大为逐请求 ping', async () => {
    process.env.READYZ_CACHE_MS = '5000';
    mockSharedCache.isRedisConfigured.mockReturnValue(true);
    mockSharedCache.isRedisEnabled.mockReturnValue(true);
    const ping = jest.fn(() => Promise.resolve('PONG'));
    mockSharedCache.getRedisClient.mockReturnValue({ ping });

    await checkRedisReady();
    await checkRedisReady();

    expect(ping).toHaveBeenCalledTimes(1);
  });
});
