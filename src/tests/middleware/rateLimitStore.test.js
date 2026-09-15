/**
 * 限流共享存储分支——行为化测试
 *
 * 覆盖 rateLimit.js 的 makeSharedStore 三条分支（2026-09-05 覆盖率复核
 * 前该分支整体未覆盖，因 REDIS_URL 在测试环境恒为空）：
 *   1. REDIS_URL 未配置 → 同步返回 undefined（express-rate-limit 默认 MemoryStore）；
 *   2. REDIS_URL 已配置但初始化失败 → 告警回退进程内 MemoryStore（fail-open）；
 *   3. Redis 就绪 → rate-limit-redis 的 RedisStore（带 rl:<prefix>: 前缀）。
 *
 * sharedCache 与 rate-limit-redis 均为文件级 mock（mock* 前缀变量供工厂引用）；
 * env 保存/恢复防泄漏。
 */
const mockRedisClient = { call: jest.fn() };

jest.mock('../../services/sharedCache', () => ({
  initSharedCache: jest.fn(),
  isRedisEnabled: jest.fn(),
  getRedisClient: jest.fn(() => mockRedisClient),
}));

jest.mock('rate-limit-redis', () => ({
  RedisStore: jest.fn().mockImplementation(() => ({
    __redisStore: true,
    init: jest.fn(),
    increment: jest.fn(),
    decrement: jest.fn(),
    resetKey: jest.fn(),
    resetAll: jest.fn(),
  })),
}));

describe('makeSharedStore 共享存储分支', () => {
  const ORIG_REDIS_URL = process.env.REDIS_URL;
  let makeSharedStore;
  let sharedCache;
  let RedisStore;
  let logger;

  beforeAll(() => {
    ({ makeSharedStore } = require('../../middleware/rateLimit'));
    sharedCache = require('../../services/sharedCache');
    RedisStore = require('rate-limit-redis').RedisStore;
    logger = require('../../utils/logger');
  });

  afterAll(() => {
    if (ORIG_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIG_REDIS_URL;
  });

  test('REDIS_URL 未配置 → 同步返回 undefined（走 express-rate-limit 默认 MemoryStore）', () => {
    delete process.env.REDIS_URL;
    expect(makeSharedStore('general')).toBeUndefined();
  });

  test('Redis 初始化失败 → 同步返回带 Store 接口的代理对象（内部回退 MemoryStore）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockRejectedValueOnce(new Error('redis down'));
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const store = makeSharedStore('login');
    expect(store).toBeDefined();
    expect(typeof store.increment).toBe('function');
    expect(typeof store.decrement).toBe('function');
    expect(typeof store.resetKey).toBe('function');
    // 等待后台异步 initSharedCache rejection → catch 生效
    await new Promise((r) => setTimeout(r, 50));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('限流共享存储初始化失败'));
    warnSpy.mockRestore();
  });

  test('Redis 未就绪（初始化成功但未启用）→ 代理对象回退 MemoryStore', () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(false);
    const store = makeSharedStore('captcha');
    expect(store).toBeDefined();
    expect(typeof store.increment).toBe('function');
    expect(RedisStore).not.toHaveBeenCalled();
  });

  test('Redis 就绪 → 代理对象就绪后委托 RedisStore，前缀 rl:<prefix>:', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(true);
    const store = makeSharedStore('ip');
    expect(store).toBeDefined();
    expect(typeof store.increment).toBe('function');
    // 等待后台异步初始化完成，使 RedisStore 被创建
    await new Promise((r) => setTimeout(r, 50));
    expect(RedisStore).toHaveBeenCalledWith(expect.objectContaining({ prefix: 'rl:ip:' }));
    // sendCommand 透传到共享 Redis client.call
    const opts = RedisStore.mock.calls[RedisStore.mock.calls.length - 1][0];
    opts.sendCommand('PING');
    expect(mockRedisClient.call).toHaveBeenCalledWith('PING');
  });

  // ===== 评价报告 #6 新增分支：init 动态分发与代理转发（2026-09-15 覆盖率债务补齐）=====

  test('切换完成前调 init → 记录 lastInitOptions，切换完成后补发给 RedisStore.init', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(true);
    const store = makeSharedStore('mfa');
    const options = { skipFailedRequests: true, windowMs: 60000 };
    // 切换尚未完成（后台 IIFE 未跑完），此时 init 只记录
    store.init(options);
    // 等待后台切换完成 → initSharedCache 的 lastInitOptions 被补发给 active.init
    await new Promise((r) => setTimeout(r, 50));
    const inst = RedisStore.mock.results[RedisStore.mock.results.length - 1].value;
    expect(inst.init).toHaveBeenCalledWith(options);
  });

  test('切换完成后调用 init → 直接转发当前 active（RedisStore.init）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(true);
    const store = makeSharedStore('password');
    await new Promise((r) => setTimeout(r, 50));
    const options = { skipFailedRequests: false };
    store.init(options);
    const inst = RedisStore.mock.results[RedisStore.mock.results.length - 1].value;
    expect(inst.init).toHaveBeenCalledWith(options);
  });

  test('代理方法转发：increment/decrement/resetKey → 当前 active', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(true);
    const store = makeSharedStore('user');
    await new Promise((r) => setTimeout(r, 50));
    const inst = RedisStore.mock.results[RedisStore.mock.results.length - 1].value;
    inst.increment.mockResolvedValueOnce({ totalHits: 1 });
    await store.increment('key-a');
    expect(inst.increment).toHaveBeenCalledWith('key-a');
    await store.decrement('key-a');
    expect(inst.decrement).toHaveBeenCalledWith('key-a');
    await store.resetKey('key-a');
    expect(inst.resetKey).toHaveBeenCalledWith('key-a');
  });

  test('resetAll：active 有该方法则转发，无则静默（不抛错）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    sharedCache.initSharedCache.mockResolvedValueOnce(undefined);
    sharedCache.isRedisEnabled.mockReturnValueOnce(true);
    const store = makeSharedStore('strict');
    // active 仍是 fallback MemoryStore（切换中）→ resetAll 不存在 → 静默
    await expect(store.resetAll()).resolves.toBeUndefined();
    await new Promise((r) => setTimeout(r, 50));
    const inst = RedisStore.mock.results[RedisStore.mock.results.length - 1].value;
    inst.resetAll.mockResolvedValueOnce(undefined);
    await expect(store.resetAll()).resolves.toBeUndefined();
    expect(inst.resetAll).toHaveBeenCalled();
  });
});
