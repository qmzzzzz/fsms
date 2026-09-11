/**
 * sharedCache 双后端补齐（覆盖率棘轮：29% → 目标 ≥85%）
 *
 * 内存回退路径：直接用真实模块（测试环境无 REDIS_URL）驱动
 * set/get/del/incrWithTtl/setIfAbsent/锁降级/初始化守卫。
 *
 * Redis 路径：用假 ioredis（jest.doMock + isolateModules）驱动——
 * 不起真 Redis，但覆盖 set/get/del/incr/eval 脚本/阻塞锁/订阅广播/
 * publishInvalidate/shutdown 的全部分支。假客户端把「命令语义」演出来：
 * NX/PX 参数、compare-and-delete / compare-and-set 脚本、message 事件。
 */

describe('sharedCache 内存回退路径', () => {
  const cache = require('../../services/sharedCache');

  beforeEach(() => {
    cache._resetForTests();
  });

  test('未启用 Redis：isRedisEnabled=false，getRedisClient=null', () => {
    expect(cache.isRedisEnabled()).toBe(false);
    expect(cache.getRedisClient()).toBeNull();
  });

  test('jitterTtl：±10% 抖动；非正/非有限值原样返回', () => {
    for (let i = 0; i < 50; i++) {
      const j = cache.jitterTtl(1000);
      expect(j).toBeGreaterThanOrEqual(900);
      expect(j).toBeLessThanOrEqual(1100);
    }
    expect(cache.jitterTtl(0)).toBe(0);
    expect(cache.jitterTtl(-5)).toBe(-5);
    expect(cache.jitterTtl(Number.NaN)).toBeNaN();
    expect(cache.jitterTtl(1)).toBeGreaterThanOrEqual(1); // Math.max(1, ...) 下限
  });

  test('set/get/del 往返；过期条目惰性删除；del 返回是否存在过', async () => {
    await cache.set('k1', { a: 1 }, 60000);
    await expect(cache.get('k1')).resolves.toEqual({ a: 1 });
    await expect(cache.del('k1')).resolves.toBe(true);
    await expect(cache.get('k1')).resolves.toBeNull();
    await expect(cache.del('k1')).resolves.toBe(false);

    await cache.set('k-expired', 'x', 5);
    await new Promise((r) => setTimeout(r, 20));
    await expect(cache.get('k-expired')).resolves.toBeNull();
  });

  test('set 不带 TTL：永久有效（Infinity 过期点）', async () => {
    await cache.set('k-forever', 'v');
    await expect(cache.get('k-forever')).resolves.toBe('v');
  });

  test('incrWithTtl：首设 1 + 过期后重新计数；无 TTL 参数也允许', async () => {
    await expect(cache.incrWithTtl('cnt', 60000)).resolves.toBe(1);
    await expect(cache.incrWithTtl('cnt', 60000)).resolves.toBe(2);

    await cache.set('cnt-exp', 0, 5); // 占位一个即刻过期的键
    await cache.incrWithTtl('cnt-exp', 5);
    await new Promise((r) => setTimeout(r, 20));
    await expect(cache.incrWithTtl('cnt-exp', 5)).resolves.toBe(1); // 过期重计

    await expect(cache.incrWithTtl('cnt-nottl')).resolves.toBe(1);
  });

  test('setIfAbsent：首次占位成功，TTL 内重复拒绝，过期后可再占位', async () => {
    await expect(cache.setIfAbsent('nonce', 'v1', 60000)).resolves.toBe(true);
    await expect(cache.setIfAbsent('nonce', 'v2', 60000)).resolves.toBe(false);

    await cache.setIfAbsent('nonce-exp', 'v', 5);
    await new Promise((r) => setTimeout(r, 20));
    await expect(cache.setIfAbsent('nonce-exp', 'v2', 5)).resolves.toBe(true);
  });

  test('无 Redis 的锁语义：acquireLock 返回哑句柄；阻塞锁与 casSet 直接拒绝', async () => {
    const lock = await cache.acquireLock('lock-a', 1000);
    expect(lock).toBeTruthy();
    await expect(lock.release()).resolves.toBeUndefined();

    await expect(cache.acquireLockBlocking('lock-b', 1000, 50)).resolves.toBeNull();
    await expect(cache.casSet('cas-a', 'x', 'y')).resolves.toBe(false);
  });

  test('initSharedCache：无 REDIS_URL 时直接返回，重复调用幂等', async () => {
    const saved = process.env.REDIS_URL;
    delete process.env.REDIS_URL;
    try {
      await cache.initSharedCache();
      await cache.initSharedCache(); // initAttempted 守卫
      expect(cache.isRedisEnabled()).toBe(false);
    } finally {
      if (saved !== undefined) process.env.REDIS_URL = saved;
    }
  });

  test('onInvalidate 注册/注销；无 Redis 时 publishInvalidate 为无操作', async () => {
    const handler = jest.fn();
    const unregister = cache.onInvalidate(handler);
    expect(typeof unregister).toBe('function');
    await cache.publishInvalidate('auth:user:x'); // 不抛错即可
    expect(handler).not.toHaveBeenCalled(); // 无 Redis 无广播
    unregister();
  });

  test('_resetForTests 清空内存存储', async () => {
    await cache.set('k-reset', 'v', 60000);
    cache._resetForTests();
    await expect(cache.get('k-reset')).resolves.toBeNull();
  });
});

describe('sharedCache Redis 路径（假 ioredis 驱动）', () => {
  const INVAL_CHANNEL = 'xf:cache:invalidate';

  class FakeRedis {
    static reset() {
      FakeRedis.store = new Map();
      FakeRedis.instances = [];
      FakeRedis.failPing = false;
      FakeRedis.failCommands = false;
      FakeRedis.failSubscribe = false;
    }
    constructor() {
      this.listeners = {};
      FakeRedis.instances.push(this);
    }
    on(ev, cb) {
      (this.listeners[ev] = this.listeners[ev] || []).push(cb);
      return this;
    }
    emit(ev, ...args) {
      (this.listeners[ev] || []).forEach((cb) => cb(...args));
    }
    guard() {
      if (FakeRedis.failCommands) throw new Error('fake redis down');
    }
    async ping() {
      if (FakeRedis.failPing) throw new Error('ECONNREFUSED (fake)');
      return 'PONG';
    }
    async set(key, val, ...rest) {
      this.guard();
      let nx = false;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === 'NX') nx = true;
      }
      if (nx && FakeRedis.store.has(key)) return null;
      FakeRedis.store.set(key, val);
      return 'OK';
    }
    async get(key) {
      this.guard();
      return FakeRedis.store.has(key) ? FakeRedis.store.get(key) : null;
    }
    async del(key) {
      this.guard();
      return FakeRedis.store.delete(key) ? 1 : 0;
    }
    async incr(key) {
      this.guard();
      const v = (Number(FakeRedis.store.get(key)) || 0) + 1;
      FakeRedis.store.set(key, String(v));
      return v;
    }
    async pexpire() {
      this.guard();
      return 1;
    }
    async publish(channel, message) {
      this.guard();
      // 模拟广播回路：发布后订阅端收到消息（含自身实例）
      FakeRedis.instances.forEach((inst) => {
        if (inst.subscribed === channel) inst.emit('message', channel, message);
      });
      return 1;
    }
    async subscribe(channel) {
      if (FakeRedis.failSubscribe) throw new Error('subscribe refused (fake)');
      this.subscribed = channel;
      return 1;
    }
    async eval(script, _numKeys, key, ...args) {
      this.guard();
      if (FakeRedis.store.get(key) === args[0]) {
        if (script.includes('del')) {
          FakeRedis.store.delete(key);
        } else {
          FakeRedis.store.set(key, args[1]);
        }
        return 1;
      }
      return 0;
    }
    async quit() {
      return 'OK';
    }
    disconnect() {}
  }

  let cache;
  const savedUrl = process.env.REDIS_URL;

  const bootRedisMode = async () => {
    FakeRedis.reset();
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake:6379';
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
    });
    await cache.initSharedCache();
  };

  afterEach(() => {
    jest.dontMock('ioredis');
    jest.resetModules();
    if (savedUrl !== undefined) {
      process.env.REDIS_URL = savedUrl;
    } else {
      delete process.env.REDIS_URL;
    }
  });

  test('初始化成功 → Redis 模式；set/get/del/incr/setIfAbsent 走命令', async () => {
    await bootRedisMode();
    expect(cache.isRedisEnabled()).toBe(true);

    await cache.set('rk', { n: 1 }, 60000);
    await expect(cache.get('rk')).resolves.toEqual({ n: 1 });
    await expect(cache.del('rk')).resolves.toBe(true);
    await expect(cache.get('rk')).resolves.toBeNull();

    await expect(cache.incrWithTtl('rcnt', 60000)).resolves.toBe(1);
    await expect(cache.incrWithTtl('rcnt', 60000)).resolves.toBe(2);

    await expect(cache.setIfAbsent('rnonce', 'v', 60000)).resolves.toBe(true);
    await expect(cache.setIfAbsent('rnonce', 'v', 60000)).resolves.toBe(false);
  });

  test('set 不带 TTL 走无 PX 分支', async () => {
    await bootRedisMode();
    await cache.set('rk-nottl', 'v');
    await expect(cache.get('rk-nottl')).resolves.toBe('v');
  });

  test('acquireLock：获取成功 → CAS 释放；锁被占用立即返回 null', async () => {
    await bootRedisMode();
    const lock = await cache.acquireLock('rl', 60000);
    expect(lock).toBeTruthy();
    // 锁被占用时第二次获取失败（非阻塞）
    await expect(cache.acquireLock('rl', 60000)).resolves.toBeNull();
    await lock.release(); // CAS：token 匹配才删
    // 释放后可重新获取
    const again = await cache.acquireLock('rl', 60000);
    expect(again).toBeTruthy();
  });

  test('acquireLockBlocking：排队等待 → 超时 null；释放后可获取；命令失败放弃', async () => {
    await bootRedisMode();
    const first = await cache.acquireLockBlocking('bl', 60000, 500);
    expect(first).toBeTruthy();

    // 占用中：短超时拿不到 → null（走排队-超时分支）
    await expect(cache.acquireLockBlocking('bl', 60000, 120)).resolves.toBeNull();

    await first.release();
    const second = await cache.acquireLockBlocking('bl', 60000, 500);
    expect(second).toBeTruthy();
    await second.release();

    // 命令失败 → 立即放弃返回 null
    FakeRedis.failCommands = true;
    await expect(cache.acquireLockBlocking('bl2', 60000, 500)).resolves.toBeNull();
    FakeRedis.failCommands = false;
  });

  test('casSet：期望值匹配才写入；不匹配与命令失败均返回 false', async () => {
    await bootRedisMode();
    await cache.set('ck', 'v1');
    await expect(cache.casSet('ck', 'wrong', 'v2')).resolves.toBe(false);
    await expect(cache.casSet('ck', 'v1', 'v2')).resolves.toBe(true);
    await expect(cache.get('ck')).resolves.toBe('v2');

    FakeRedis.failCommands = true;
    await expect(cache.casSet('ck', 'v2', 'v3')).resolves.toBe(false);
    FakeRedis.failCommands = false;
  });

  test('命令失败回退语义：set/get/del/incr 落内存；setIfAbsent fail-closed 拒绝', async () => {
    await bootRedisMode();
    FakeRedis.failCommands = true;
    // set/get/del/incr：回退内存不抛错
    await cache.set('fk', 'fv', 60000);
    await expect(cache.get('fk')).resolves.toBe('fv');
    await expect(cache.del('fk')).resolves.toBe(true);
    await expect(cache.incrWithTtl('fcnt', 60000)).resolves.toBe(1);
    // setIfAbsent：Redis 已配置但失败 → 按重复处理（拒绝），不落内存放行
    await expect(cache.setIfAbsent('fnonce', 'v', 60000)).resolves.toBe(false);
    FakeRedis.failCommands = false;
  });

  test('失效广播：publish → 订阅端 handler 收到；异频道忽略；handler 抛错不中断', async () => {
    await bootRedisMode();
    const received = [];
    const badHandler = jest.fn(() => {
      throw new Error('handler boom');
    });
    const goodHandler = (key) => received.push(key);
    cache.onInvalidate(badHandler);
    cache.onInvalidate(goodHandler);

    await cache.publishInvalidate('auth:user:123');
    expect(badHandler).toHaveBeenCalledWith('auth:user:123');
    expect(received).toEqual(['auth:user:123']);

    // 非本频道消息被忽略
    const sub = FakeRedis.instances.find((i) => i.subscribed === INVAL_CHANNEL);
    expect(sub).toBeTruthy();
    sub.emit('message', 'other:channel', 'auth:user:999');
    expect(received).toEqual(['auth:user:123']);
  });

  test('连接异常事件：降级内存态；ready 事件恢复 Redis 模式', async () => {
    await bootRedisMode();
    expect(cache.isRedisEnabled()).toBe(true);
    FakeRedis.instances[0].emit('error', new Error('connection lost'));
    expect(cache.isRedisEnabled()).toBe(false);
    FakeRedis.instances[0].emit('ready');
    expect(cache.isRedisEnabled()).toBe(true);
  });

  test('订阅失败降级：广播不可用不阻断主链路', async () => {
    FakeRedis.reset();
    FakeRedis.failSubscribe = true;
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake:6379';
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
    });
    await cache.initSharedCache();
    // 订阅失败但读写仍可用
    expect(cache.isRedisEnabled()).toBe(true);
    await cache.set('sub-fail-key', 'v', 60000);
    await expect(cache.get('sub-fail-key')).resolves.toBe('v');
  });

  test('publishInvalidate 发布失败仅告警，不抛错', async () => {
    await bootRedisMode();
    FakeRedis.failCommands = true;
    await expect(cache.publishInvalidate('auth:user:x')).resolves.toBeUndefined();
    FakeRedis.failCommands = false;
  });

  test('初始化失败：REDIS_URL 配置但连接拒绝 → 回退内存并告警', async () => {
    FakeRedis.reset();
    FakeRedis.failPing = true;
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake:6379';
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
    });
    await cache.initSharedCache();
    expect(cache.isRedisEnabled()).toBe(false);
  });

  test('shutdownSharedCache：停止定时器、清空状态、关闭订阅连接', async () => {
    await bootRedisMode();
    await cache.set('sk', 'v', 60000);
    await cache.shutdownSharedCache();
    expect(cache.isRedisEnabled()).toBe(false);
    // 内存存储已清空
    await expect(cache.get('sk')).resolves.toBeNull();
  });
});
