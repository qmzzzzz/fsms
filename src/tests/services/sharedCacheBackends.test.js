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

  describe('内存上限与原子取删（S-L2 防护 + captcha 双花修复的底层）', () => {
    const savedMax = process.env.SHARED_CACHE_MEM_MAX;
    afterEach(() => {
      if (savedMax === undefined) delete process.env.SHARED_CACHE_MEM_MAX;
      else process.env.SHARED_CACHE_MEM_MAX = savedMax;
      cache._resetForTests();
    });

    test('超过上限时淘汰最旧条目，且不淘汰新写入（Map 插入序）', async () => {
      // getMemStoreMax 的下限是 1000（防误配把容量压到 0），故用 1000 + 3
      process.env.SHARED_CACHE_MEM_MAX = '1000';
      cache._resetForTests();
      for (let i = 0; i < 1003; i++) await cache.set(`cap-${i}`, i, 600000);

      // 淘汰发生在 set 内部的 enforceMemCap：写满后最多保留上限条
      const oldest = await cache.get('cap-0');
      expect(oldest).toBeNull(); // 最旧的被淘汰
      await expect(cache.get('cap-1002')).resolves.toBe(1002); // 最新的保留
    });

    test('低于下限的配置被忽略：SHARED_CACHE_MEM_MAX=1 仍按 1000 生效', async () => {
      // Math.max(1000, ...) 是防误配下限——钉住它，防止有人把下限删掉后
      // 一次误设 SHARED_CACHE_MEM_MAX=1 就让缓存几乎全部失能
      process.env.SHARED_CACHE_MEM_MAX = '1';
      cache._resetForTests();
      for (let i = 0; i < 200; i++) await cache.set(`low-${i}`, i, 600000);
      await expect(cache.get('low-0')).resolves.toBe(0); // 未被淘汰
      await expect(cache.get('low-199')).resolves.toBe(199);
    });

    test('非数字配置退回默认 20000（Number(...)||20000）', async () => {
      process.env.SHARED_CACHE_MEM_MAX = 'abc';
      cache._resetForTests();
      // 只需证明不会因 NaN 比较而清空/拒绝写入
      await cache.set('nan-max', 'v', 60000);
      await expect(cache.get('nan-max')).resolves.toBe('v');
    });

    test('容量淘汰前先 sweep：过期项不算作淘汰压力（最旧的健在项不被误杀）', async () => {
      // 构造要点（enforceMemCap 在 set 之前、按 size > max 触发）：
      //   · 600 条健在项（最旧） + 400 条已过期项（较新） = 1000 条，恰好不触发
      //   · 第 1001、1002 条写入才越过上限，此时 enforcement 才真正运行
      // 差异只在这里可见：
      //   先 sweep → 400 条过期项被清掉，容量回落到 601，最旧的 live-0 活着；
      //   不 sweep → 按插入序淘汰，最旧的 live-0 被砍掉。
      process.env.SHARED_CACHE_MEM_MAX = '1000';
      cache._resetForTests();
      for (let i = 0; i < 600; i++) await cache.set(`live-${i}`, i, 600000);
      for (let i = 0; i < 400; i++) await cache.set(`exp-${i}`, i, 1);
      await new Promise((r) => setTimeout(r, 20)); // 400 条全部过期
      await cache.set('filler', 'f', 600000); // size 1001（尚未触发 enforcement）
      await cache.set('trigger', 't', 600000); // 此刻 enforcement 运行

      await expect(cache.get('live-0')).resolves.toBe(0); // 最旧的健在项必须活着
      await expect(cache.get('live-599')).resolves.toBe(599);
      await expect(cache.get('trigger')).resolves.toBe('t');
    });

    test('getDel：内存路径同步取删——取出的值存在，第二次取为 null', async () => {
      cache._resetForTests();
      await cache.set('gd', { text: 'AbCd' }, 60000);
      await expect(cache.getDel('gd')).resolves.toEqual({ text: 'AbCd' });
      await expect(cache.getDel('gd')).resolves.toBeNull();
    });

    test('getDel：过期条目返回 null，且条目已被删除（不留垃圾）', async () => {
      cache._resetForTests();
      await cache.set('gd-exp', 'v', 1);
      await new Promise((r) => setTimeout(r, 20));
      await expect(cache.getDel('gd-exp')).resolves.toBeNull();
      // 已被删除：del 返回 false（若实现改成「先判过期再决定删」会留下垃圾）
      await expect(cache.del('gd-exp')).resolves.toBe(false);
    });

    test('getDel：不存在的键返回 null 且不抛错', async () => {
      cache._resetForTests();
      await expect(cache.getDel('gd-missing')).resolves.toBeNull();
    });
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
      FakeRedis.ttls = new Map(); // key -> 过期毫秒（仅由 INCR 脚本与 PEXPIRE 维护，供 L-07 断言）
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
      let px = null;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === 'NX') nx = true;
        if (String(rest[i]).toUpperCase() === 'PX') px = Number(rest[i + 1]);
      }
      if (nx && FakeRedis.store.has(key)) return null;
      FakeRedis.store.set(key, val);
      if (px) FakeRedis.ttls.set(key, px);
      return 'OK';
    }
    async get(key) {
      this.guard();
      return FakeRedis.store.has(key) ? FakeRedis.store.get(key) : null;
    }
    async del(key) {
      this.guard();
      FakeRedis.ttls.delete(key);
      return FakeRedis.store.delete(key) ? 1 : 0;
    }
    async incr(key) {
      this.guard();
      const v = (Number(FakeRedis.store.get(key)) || 0) + 1;
      FakeRedis.store.set(key, String(v));
      return v;
    }
    async pexpire(key, ms) {
      this.guard();
      FakeRedis.ttls.set(key, ms);
      return 1;
    }
    async pttl(key) {
      this.guard();
      return FakeRedis.ttls.has(key) ? FakeRedis.ttls.get(key) : -1;
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
      // L-07：incrWithTtl 的 Lua 脚本——在假客户端里按脚本语义复演
      if (script.includes('INCR')) {
        const v = (Number(FakeRedis.store.get(key)) || 0) + 1;
        FakeRedis.store.set(key, String(v));
        const ttl = Number(args[0]);
        if (ttl > 0 && (v === 1 || !FakeRedis.ttls.has(key))) {
          FakeRedis.ttls.set(key, ttl);
        }
        return v;
      }
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

  test('L-07：incrWithTtl 走单条 Lua 脚本，首自增即带 TTL（不再是 incr+pexpire 两条命令）', async () => {
    await bootRedisMode();
    const calls = [];
    const origEval = FakeRedis.prototype.eval;
    FakeRedis.prototype.eval = function (script, ...rest) {
      calls.push(script);
      return origEval.call(this, script, ...rest);
    };
    try {
      await expect(cache.incrWithTtl('lua-cnt', 60000)).resolves.toBe(1);
      await expect(cache.incrWithTtl('lua-cnt', 60000)).resolves.toBe(2);
    } finally {
      FakeRedis.prototype.eval = origEval;
    }
    expect(calls).toHaveLength(2); // 两次自增 = 两次 eval，无独立 pexpire 往返
    expect(calls[0]).toContain('INCR');
    expect(FakeRedis.ttls.get('lua-cnt')).toBe(60000); // 计数器不会永久滞留
  });

  test('L-07：历史遗留的无 TTL 键在下一次自增时补上过期时间', async () => {
    await bootRedisMode();
    // 模拟旧实现留下的永久键：有值、无 TTL
    FakeRedis.store.set('legacy-cnt', '7');
    await expect(cache.incrWithTtl('legacy-cnt', 30000)).resolves.toBe(8);
    expect(FakeRedis.ttls.get('legacy-cnt')).toBe(30000);
  });

  test('L-07：已有 TTL 的键在自增时不重置窗口（避免滑动窗口导致计数永不归零）', async () => {
    await bootRedisMode();
    await cache.incrWithTtl('win-cnt', 60000);
    FakeRedis.ttls.set('win-cnt', 1234); // 模拟窗口已推进
    await cache.incrWithTtl('win-cnt', 60000);
    expect(FakeRedis.ttls.get('win-cnt')).toBe(1234);
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
