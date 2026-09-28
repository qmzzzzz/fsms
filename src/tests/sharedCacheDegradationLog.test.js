'use strict';

/**
 * （2026-09-19）：Redis 从"就绪"跌回"不可用"的那一刻必须自带失效清单
 *
 * `constants/runtime.js` 的拓扑校验只在启动期说话一次：多实例 + Redis 的部署
 * 启动时拿到的是"相关机制已外置、跨实例一致"的结论。之后 Redis 抖一下，
 * 审计链锁与链尾 / 限流配额 / 权限缓存失效广播 / 验证码一次性消费
 * 就静默退回**进程内**语义——正是那条启动校验要防的事，
 * 却发生在"已经说过没问题"之后。原先这里只有一句 warn「暂回退内存态」，
 * 既看不出规模，也没人会把一句 warn 和"审计链可能分叉"联系起来。
 */

class FakeRedis {
  static instances = [];
  static reset() {
    FakeRedis.instances = [];
  }
  constructor() {
    FakeRedis.instances.push(this);
    this.handlers = {};
    this.subscribed = null;
  }
  on(event, cb) {
    if (!this.handlers[event]) this.handlers[event] = [];
    this.handlers[event].push(cb);
  }
  emit(event, ...args) {
    (this.handlers[event] || []).forEach((cb) => cb(...args));
  }
  async ping() {
    return 'PONG';
  }
  async subscribe(channel) {
    this.subscribed = channel;
    return 1;
  }
  async set() {
    return 'OK';
  }
  async get() {
    return null;
  }
  async del() {
    return 0;
  }
  async quit() {
    return 'OK';
  }
  disconnect() {}
}

describe('Redis 降级时刻的失效清单', () => {
  const savedUrl = process.env.REDIS_URL;
  let cache = null;

  async function boot() {
    FakeRedis.reset();
    // resetModules 之后 logger 与 sharedCache 落在**同一代**注册表里，
    // 这样对 logger.error 的 spy 才听得见 sharedCache 的调用
    // （先前用 isolateModules 只圈住 sharedCache，spy 装在了另一代实例上）
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake-for-f77:6379';
    const freshLogger = require('../utils/logger');
    cache = require('../services/sharedCache');
    const spy = jest.spyOn(freshLogger, 'error').mockImplementation(() => {});
    await cache.initSharedCache();
    return spy;
  }

  afterEach(() => {
    jest.dontMock('ioredis');
    jest.resetModules();
    if (savedUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = savedUrl;
  });

  test('就绪 → 不可用的那一刻，error 日志点名所有依赖 Redis 保持一致的机制', async () => {
    const spy = await boot();
    expect(cache.isRedisEnabled()).toBe(true);
    spy.mockClear(); // 丢掉启动期的其他 error（本用例只关心降级那一刻）

    FakeRedis.instances[0].emit('error', new Error('connection reset by peer'));

    expect(cache.isRedisEnabled()).toBe(false);
    const logged = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('降级为单进程语义');
    expect(logged).toContain('connection reset by peer');
    // 清单必须具体到模块名，且只列"此前靠 Redis 保持一致"的那些
    // 注：验证码存储的模块路径原写作 `utils/captchaStore`（该文件并不存在），
    // 已更正为真实文件 `services/captchaService.js`。
    for (const mod of [
      'utils/auditChain.js',
      'middleware/rateLimit.js',
      'services/captchaService.js',
      'middleware/auth.js',
    ]) {
      expect(logged).toContain(mod);
    }
    // 仍然单进程的机制（如审计缓冲 WAL）不该出现在这条降级消息里——它本来就没外置
    expect(logged).not.toContain('services/auditBuffer.js');
    spy.mockRestore();
  });

  test('降级只报一次：ioredis 重试风暴不再刷同一条 error（日志可靠性）', async () => {
    const spy = await boot();
    spy.mockClear();
    const client = FakeRedis.instances[0];
    client.emit('error', new Error('first'));
    client.emit('error', new Error('retry 1'));
    client.emit('error', new Error('retry 2'));
    const degradations = spy.mock.calls.filter((c) => String(c[0]).includes('降级为单进程语义'));
    expect(degradations).toHaveLength(1);
    spy.mockRestore();
  });

  test('恢复就绪后再次掉线，会再报一次（每次转换都有账）', async () => {
    const spy = await boot();
    spy.mockClear();
    const client = FakeRedis.instances[0];
    client.emit('error', new Error('down #1'));
    client.emit('ready');
    expect(cache.isRedisEnabled()).toBe(true);
    spy.mockClear();
    client.emit('error', new Error('down #2'));
    expect(spy.mock.calls.filter((c) => String(c[0]).includes('降级为单进程语义'))).toHaveLength(1);
    spy.mockRestore();
  });
});
