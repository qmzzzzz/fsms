/**
 * 限流共享存储的「启动竞态」分支：Redis 晚就绪时，跨实例计数必须能自己补上
 *
 * 为什么单开一个文件：`rateLimitStore.test.js` 与 `rateLimitStoreFailover.test.js`
 * 已经把「Redis 就绪 → 用 RedisStore」和「就绪之后坏掉 → 降级不粘滞」两条钉住了，
 * 但**挂载那一瞬间还没就绪**这条臂在原实现里是一次性判定：
 *
 *   await initSharedCache();
 *   if (!isRedisEnabled()) return;      // ← 静默 return，active 永久停在 MemoryStore
 *
 * 而 sharedCache 自己会自愈：initSharedCache 有一次性闸门（initAttempted），
 * 但它的 ioredis 客户端带 retryStrategy，Redis 晚起来之后 'ready' 事件仍会把
 * redisReady 置真 ⇒ 其余 isRedisEnabled() 的调用方（验证码/权限缓存/锁/ws）
 * 全都自动回到跨实例语义，**只有限流不会**。
 *
 * 后果不是报错而是口径悄悄变了，且日志会撒谎：
 * 1. 生产多副本下登录/验证码类限流等效放大 N 倍（本文件所在模块的头注释
 *    正是为这件事写的）；
 * 2. sharedCache 随后打出「共享缓存 Redis 已就绪：限流/验证码…进入跨实例一致模式」，
 *    而限流其实还绑在进程内 store 上——一条声称已修复、实际未修复的告警。
 *
 * docker-compose 起栈时应用与 Redis 并行启动、无 healthcheck 依赖，
 * 这条臂不是理论路径：第一秒的 ping 失败就够了。
 */

let mockRedisReady = false;

jest.mock('../../services/sharedCache', () => ({
  initSharedCache: jest.fn(async () => {
    await new Promise((resolve) => setImmediate(resolve));
  }),
  isRedisEnabled: jest.fn(() => mockRedisReady),
  getRedisClient: jest.fn(() => ({ call: jest.fn() })),
}));

const mockStoreInstances = [];
const mockRedisStoreCtor = jest.fn();

jest.mock('rate-limit-redis', () => ({ RedisStore: mockRedisStoreCtor }));

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const { makeSharedStore } = require('../../middleware/rateLimitStore');
const logger = require('../../utils/logger');
const sharedCache = require('../../services/sharedCache');

// 让工厂内部那条 (async () => { await initSharedCache(); ... })() 跑到末端
const settleInit = async () => {
  for (let i = 0; i < 6; i++) await new Promise((resolve) => setImmediate(resolve));
};

// 自己记实例，不靠 mock.results：Jest 对 `new` 出来的调用只在实现**显式返回对象**时
// 才把 value 记进 results，构造函数式的 mockImplementation 会留下一串 undefined。
const lastStore = () => mockStoreInstances[mockStoreInstances.length - 1];

describe('makeSharedStore：Redis 晚就绪的补切换', () => {
  const ORIG_REDIS_URL = process.env.REDIS_URL;

  beforeEach(() => {
    mockRedisReady = false;
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    mockStoreInstances.length = 0;
    mockRedisStoreCtor.mockClear();
    mockRedisStoreCtor.mockImplementation((options) => {
      const instance = {
        options,
        init: jest.fn(),
        increment: jest.fn(async () => ({ totalHits: 1, resetTime: undefined })),
        decrement: jest.fn(async () => {}),
        resetKey: jest.fn(async () => {}),
      };
      mockStoreInstances.push(instance);
      return instance;
    });
    sharedCache.isRedisEnabled.mockClear();
    logger.warn.mockClear();
    logger.info.mockClear();
  });

  afterAll(() => {
    if (ORIG_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIG_REDIS_URL;
  });

  test('主证：初始化时未就绪 ⇒ 先用进程内计数，但必须留下点名限流的告警', async () => {
    const store = makeSharedStore('login');
    await settleInit();

    expect(store).toBeDefined();
    expect(mockRedisStoreCtor).not.toHaveBeenCalled();
    // 原实现在这里是**零日志**的静默 return：限流降级无人知晓（本文件头的第 2 条后果）
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('限流共享存储暂用进程内计数'));
    expect(logger.warn.mock.calls[0][0]).toContain('login');
  });

  test('主证：Redis 晚就绪后，第一个 increment 就走共享存储（原实现此处永久停在内存）', async () => {
    const store = makeSharedStore('login');
    await settleInit();

    // 晚就绪：sharedCache 的 retryStrategy 之后会把 redisReady 置真
    mockRedisReady = true;
    const result = await store.increment('key');

    expect(mockRedisStoreCtor).toHaveBeenCalledTimes(1);
    const redis = lastStore();
    expect(redis.increment).toHaveBeenCalledWith('key');
    expect(result).toEqual({ totalHits: 1, resetTime: undefined });
  });

  test('晚切换同样要补发 init（评价报告 #6 的不变量不能只在启动即就绪时成立）', async () => {
    const store = makeSharedStore('captcha');
    await settleInit();

    const mountOptions = { windowMs: 60000, limit: 10 };
    store.init(mountOptions); // 挂载时 active 还是 MemoryStore
    expect(mockRedisStoreCtor).not.toHaveBeenCalled();

    mockRedisReady = true;
    await store.increment('k');

    const redis = lastStore();
    expect(redis.init).toHaveBeenCalledWith(mountOptions);
  });

  test('只建一份：就绪后连发多个请求，RedisStore 构造次数为 1', async () => {
    const store = makeSharedStore('strict');
    await settleInit();
    mockRedisReady = true;

    await Promise.all([store.increment('a'), store.increment('b'), store.increment('c')]);

    expect(mockRedisStoreCtor).toHaveBeenCalledTimes(1);
    const redis = lastStore();
    expect(redis.increment).toHaveBeenCalledTimes(3);
  });

  test('decrement 路径也要能补切换（skipSuccessfulRequests 的登录类限流器）', async () => {
    const store = makeSharedStore('login');
    await settleInit();
    mockRedisReady = true;

    await store.decrement('a');

    expect(mockRedisStoreCtor).toHaveBeenCalledTimes(1);
    expect(lastStore().decrement).toHaveBeenCalledWith('a');
  });

  test('反向：Redis 一直不起来 ⇒ 不得反复重建 store、不得把请求打死', async () => {
    const store = makeSharedStore('login');
    await settleInit();

    for (let i = 0; i < 10; i++) {
      const r = await store.increment('k');
      expect(r.totalHits).toBeGreaterThanOrEqual(1);
    }
    expect(mockRedisStoreCtor).not.toHaveBeenCalled();
    // 进程内 MemoryStore 必须真的在计数（不是"catch 后放行"式假修复）
    const last = await store.increment('k');
    expect(last.totalHits).toBe(11);
  });

  test('降级不粘滞的反面：构造 RedisStore 抛错时退回进程内计数并告警一次', async () => {
    mockRedisStoreCtor.mockImplementation(() => {
      throw new Error('rate-limit-redis unavailable');
    });
    const store = makeSharedStore('login');
    await settleInit();
    mockRedisReady = true;

    const first = await store.increment('k');
    expect(first.totalHits).toBe(1);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('限流共享存储运行期异常（login/upgrade')
    );
    // 第二格：仍可用，且只告警一次（逐次刷屏会把这条信号本身冲掉）
    await store.increment('k');
    const warns = logger.warn.mock.calls.filter((c) => String(c[0]).includes('运行期异常'));
    expect(warns).toHaveLength(1);
  });

  test('前提钉住：未配置 REDIS_URL 时工厂返回 undefined，本文件所有断言都与之无关', () => {
    delete process.env.REDIS_URL;
    expect(makeSharedStore('login')).toBeUndefined();
    expect(mockRedisStoreCtor).not.toHaveBeenCalled();
  });

  test('前缀申报在晚切换后仍是 rl:<prefix>:（singleCount 校验依赖它）', async () => {
    const store = makeSharedStore('strict');
    await settleInit();
    mockRedisReady = true;
    await store.increment('k');

    expect(store.prefix).toBe('rl:strict:');
    expect(lastStore().options.prefix).toBe('rl:strict:');
  });
});
