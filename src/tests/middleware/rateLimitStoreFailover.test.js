/**
 * 限流共享存储「运行期」故障的降级行为
 *
 * 钉的是一格此前无人覆盖的状态：rateLimit.js 的 makeSharedStore 只在**初始化阶段**
 * 做过 Redis 失败回退（rateLimitStore.test.js 覆盖的就是那条），而 `active` 一旦切到
 * RedisStore 之后再坏掉（Redis 重启、主从切换、网络抖动）就没有任何兜底——
 * 包装层的 increment 直接 `return active.increment(...)`。
 *
 * 后果不是"限流失效"而是"整站 500"：express-rate-limit v7 的 `passOnStoreError`
 * 默认为 false（node_modules/express-rate-limit/dist/index.cjs:671），
 * store.increment 抛出的错误在 :715-726 被原样 rethrow，经 asyncHandler 兜成 500。
 * 而 ipLimiter + generalLimiter 挂在 `/api/`（app.js）上 ⇒ 任何一次 Redis 抖动
 * 都把全部业务接口打成 500，比"退回单实例计数"糟得多。
 *
 * 因此本套件断言两件事：① 共享存储抛错时请求**绝不**变成 5xx；
 * ② 降级后限流仍然生效（按配额回 429），而不是变成"不计数放行"。
 * 二者缺一都可能被"catch 后直接 next()"式的假修复骗过。
 */
const request = require('supertest');
const express = require('express');

const mockRedisStoreInstance = {
  init: jest.fn(),
  increment: jest.fn(),
  decrement: jest.fn(),
  resetKey: jest.fn(),
};

jest.mock('../../services/sharedCache', () => ({
  initSharedCache: jest.fn().mockResolvedValue(undefined),
  isRedisEnabled: jest.fn().mockReturnValue(true),
  getRedisClient: jest.fn(() => ({ call: jest.fn() })),
}));

jest.mock('rate-limit-redis', () => ({
  RedisStore: jest.fn().mockImplementation(() => mockRedisStoreInstance),
}));

// 等 makeSharedStore 内部那条异步切换跑完（initSharedCache → RedisStore → active 赋值）
const settleStoreSwitch = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
};

const buildApp = (limiter) => {
  const app = express();
  app.get('/probe', limiter, (req, res) => res.status(200).json({ ok: true }));
  return app;
};

describe('共享限流存储运行期抛错', () => {
  const ORIG_REDIS_URL = process.env.REDIS_URL;
  let makeSharedStore;
  let rateLimit;

  beforeAll(() => {
    ({ makeSharedStore } = require('../../middleware/rateLimitStore'));
    rateLimit = require('express-rate-limit');
  });

  afterAll(() => {
    if (ORIG_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIG_REDIS_URL;
  });

  beforeEach(() => {
    mockRedisStoreInstance.increment.mockReset();
    mockRedisStoreInstance.decrement.mockReset();
  });

  test('Redis 就绪后命令抛错 → 请求不变成 5xx，且配额用满仍回 429', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis unreachable'));
    const store = makeSharedStore('failover');
    await settleStoreSwitch();

    const limiter = rateLimit({
      windowMs: 60 * 1000,
      max: 2,
      store,
      standardHeaders: true,
      legacyHeaders: false,
      message: { success: false, message: 'too many' },
    });
    const app = buildApp(limiter);

    expect((await request(app).get('/probe')).status).toBe(200);
    expect((await request(app).get('/probe')).status).toBe(200);
    // 关键一格：降级不等于放行——回落到进程内计数后第 3 次必须被限住
    const third = await request(app).get('/probe');
    expect(third.status).toBe(429);
    expect(third.body.message).toBe('too many');
  });

  test('skipSuccessfulRequests 的 decrement 抛错同样不得冒泡成 5xx', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis unreachable'));
    mockRedisStoreInstance.decrement.mockRejectedValue(new Error('redis unreachable'));
    const store = makeSharedStore('failover-decrement');
    await settleStoreSwitch();

    const limiter = rateLimit({
      windowMs: 60 * 1000,
      max: 5,
      store,
      skipSuccessfulRequests: true,
      standardHeaders: true,
      legacyHeaders: false,
    });

    const res = await request(buildApp(limiter)).get('/probe');
    expect(res.status).toBe(200);
    // decrement 由响应收尾时触发，抛错会以未处理拒绝的形式炸掉进程 ⇒ 等一轮再断言存活
    await new Promise((resolve) => setImmediate(resolve));
    // 前提自证：这一路真的走到了 store.decrement（skipSuccessfulRequests 生效），
    // 否则本用例只是在重复测 increment。
    expect(mockRedisStoreInstance.decrement).toHaveBeenCalled();
    expect((await request(buildApp(limiter)).get('/probe')).status).toBe(200);
  });

  test('Redis 恢复后重新走共享存储（降级不粘滞）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis unreachable'));
    const store = makeSharedStore('recovery');
    await settleStoreSwitch();

    const limiter = rateLimit({
      windowMs: 60 * 1000,
      max: 3,
      store,
      standardHeaders: true,
      legacyHeaders: false,
    });
    const app = buildApp(limiter);
    expect((await request(app).get('/probe')).status).toBe(200);

    mockRedisStoreInstance.increment.mockResolvedValue({ totalHits: 1, resetTime: undefined });
    expect((await request(app).get('/probe')).status).toBe(200);
    expect(mockRedisStoreInstance.increment).toHaveBeenCalled();
  });
});

/**
 * 2026-09-26 审计 Top-4：降级态必须**可观测**（原实现只有一条一次性日志）
 *
 * 审计原文：「三处 DB/Redis 依赖 fail-open（限流配额放大 N 倍、黑名单失效）」，
 * 修复面「降级态可观测化或改 deny」。
 *
 * 本仓对「降级」的既定立场是**保留可用性但把降级显形**（不改成 deny：Redis 抖动
 * 就让全站 500 是拿可用性换一致性，与 rateLimitStore.js 文件头注释的取舍相反）。
 * 于是"可观测"就是这条路的全部防线，而原实现有两处漏：
 *   ① 只有 logger.warn，没有 Prometheus 指标 ⇒ 没有任何规则能告警它，
 *      "多副本下配额放大 N 倍"只存在于事后 grep 日志的人眼里；
 *   ② 日志标志只置位不复位 ⇒ 进程生命周期内**只可能报一次**，Redis 恢复后
 *      再次抖动时日志永久沉默，现场看起来"从没降级过"。
 *
 * 姊妹项 `checkIPBlacklist` 的 fail-open 分支已按同一机制计入
 * security_alerts_total{type=ip_blacklist_failopen}（评价报告 #7），本组把
 * 限流侧补齐到同一口径，并**同时锁住"每次发指标 / 一次发日志"的分工**——
 * 两者互换（每次发日志 / 一次发指标）都会让这套信号失效。
 */
describe('Top-4 降级态可观测化：指标每次发、日志可复位', () => {
  const ORIG_REDIS_URL = process.env.REDIS_URL;
  let makeSharedStore;
  let rateLimit;
  let metrics;
  let logger;

  beforeAll(() => {
    ({ makeSharedStore } = require('../../middleware/rateLimitStore'));
    rateLimit = require('express-rate-limit');
    metrics = require('../../utils/metrics');
    logger = require('../../utils/logger');
  });

  afterAll(() => {
    if (ORIG_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIG_REDIS_URL;
  });

  beforeEach(() => {
    mockRedisStoreInstance.increment.mockReset();
    mockRedisStoreInstance.decrement.mockReset();
    process.env.REDIS_URL = 'redis://127.0.0.1:6399';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const buildLimiter = (store, max = 50) =>
    rateLimit({
      windowMs: 60 * 1000,
      max,
      store,
      standardHeaders: true,
      legacyHeaders: false,
    });

  test('每次降级都计入 security_alerts_total{type=ratelimit_store_degraded}（速率才是信号）', async () => {
    const incSpy = jest.spyOn(metrics, 'incSecurityAlert');
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis unreachable'));
    const store = makeSharedStore('degrade-metric');
    await settleStoreSwitch();
    const app = buildApp(buildLimiter(store));

    await request(app).get('/probe');
    await request(app).get('/probe');

    // 关键：**两次**而不是一次。只报"发生过"的计数器算不出速率，
    // 也就无法区分"刚抖了一下"与"已经坏了两小时"。
    expect(incSpy.mock.calls.filter((c) => c[0] === 'ratelimit_store_degraded').length).toBe(2);
    expect(incSpy).toHaveBeenCalledWith('ratelimit_store_degraded', 'high');
  });

  test('日志只打一次（降级后每个请求都会走到兜底分支，逐次打会把日志刷满）', async () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis unreachable'));
    const store = makeSharedStore('degrade-log-once');
    await settleStoreSwitch();
    const app = buildApp(buildLimiter(store));

    await request(app).get('/probe');
    await request(app).get('/probe');
    await request(app).get('/probe');

    const degradeLogs = warnSpy.mock.calls.filter((c) =>
      String(c[0]).includes('已降级为进程内计数')
    );
    expect(degradeLogs.length).toBe(1);
  });

  test('Redis 恢复后再降级 → 日志**重新**出现（一次性标志必须可复位）', async () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    mockRedisStoreInstance.increment.mockRejectedValueOnce(new Error('redis down #1'));
    const store = makeSharedStore('degrade-reset');
    await settleStoreSwitch();
    const app = buildApp(buildLimiter(store));

    // 第一次降级
    await request(app).get('/probe');
    // 恢复：共享存储答得上
    mockRedisStoreInstance.increment.mockResolvedValue({ totalHits: 1, resetTime: undefined });
    await request(app).get('/probe');
    // 第二次降级（第二次抖动）
    mockRedisStoreInstance.increment.mockRejectedValue(new Error('redis down #2'));
    await request(app).get('/probe');

    const degradeLogs = warnSpy.mock.calls.filter((c) =>
      String(c[0]).includes('已降级为进程内计数')
    );
    // 原实现（标志只置位不复位）这里恒为 1：第二次抖动在日志里不存在
    expect(degradeLogs.length).toBe(2);
    expect(degradeLogs[1][0]).toContain('redis down #2');
    expect(infoSpy.mock.calls.some((c) => String(c[0]).includes('已恢复'))).toBe(true);
  });

  test('前提自证：正对照（共享存储始终健康）不产生任何降级信号', async () => {
    // 防空转：若上面几条的降级信号来自"每次请求都会发"，它们就与真实故障无关。
    const incSpy = jest.spyOn(metrics, 'incSecurityAlert');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    mockRedisStoreInstance.increment.mockResolvedValue({ totalHits: 1, resetTime: undefined });
    const store = makeSharedStore('healthy-control');
    await settleStoreSwitch();
    const app = buildApp(buildLimiter(store));

    await request(app).get('/probe');
    await request(app).get('/probe');

    expect(incSpy).not.toHaveBeenCalled();
    expect(warnSpy.mock.calls.filter((c) => String(c[0]).includes('已降级为进程内计数'))).toEqual(
      []
    );
  });
});
