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
      FakeRedis.setGate = null;
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
      // 测试钩子：注入一个可控 pending，制造「SET 命令正在飞、而 process.env.REDIS_URL
      // 在这一个 tick 里被改掉」的时序（F-207 的靶子：落地判据不得回读 env）。
      if (FakeRedis.setGate) await FakeRedis.setGate;
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
    // GETDEL（sharedCache.getDel 的 Redis 成功路径）。此前假客户端**没有**这个方法，
    // 于是门面里的 `redisClient.getdel(...)` 抛 TypeError 被 catch 吞掉，
    // 整条成功路径（含 F-204 后新增的「抹本地陈旧副本」）一直没被走到过。
    async getdel(key) {
      this.guard();
      if (!FakeRedis.store.has(key)) return null;
      const raw = FakeRedis.store.get(key);
      FakeRedis.store.delete(key);
      FakeRedis.ttls.delete(key);
      return raw;
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
      // F-195：守卫与否必须由**脚本文本**决定。旧实现在这里硬写了
      // `store.get(key) === args[0]`，于是把 LOCK_RELEASE_SCRIPT 改成无条件 `del`、
      // 或把 `==` 反成 `~=`，全套用例照绿——CAS 释放的牙齿其实一次也没被测过
      // （唯一调到 release 的用例用的是匹配令牌，删锁是它应有的行为，测不出差别）。
      const guarded = /redis\.call\(\s*["']get["']\s*,\s*KEYS\[1\]\s*\)\s*==\s*ARGV\[1\]/.test(
        script
      );
      if (!guarded || FakeRedis.store.get(key) === args[0]) {
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
  // 与 cache **同一个** isolateModules 注册表里取出的 logger：门面内部 require 到的
  // 就是这一份，spyOn 才可能看见它的日志调用（resetModules 之后再 require 是另一个实例）
  let isolatedLogger;
  const savedUrl = process.env.REDIS_URL;

  const bootRedisMode = async () => {
    FakeRedis.reset();
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake:6379';
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
      isolatedLogger = require('../../utils/logger');
    });
    await cache.initSharedCache();
  };

  // 「部署上根本没有共享层」这一态：假 ioredis 仍就位（防止真的去 require ioredis 连网），
  // 但不设 REDIS_URL ⇒ initSharedCache 直接 return，redisClient 为 null
  const bootNoRedisMode = async () => {
    FakeRedis.reset();
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    delete process.env.REDIS_URL;
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
      isolatedLogger = require('../../utils/logger');
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
    // 成功路径的返回值为 true：调用方据此判断「共享层确实收到了」
    await expect(cache.set('rk2', { n: 2 }, 60000)).resolves.toBe(true);
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

  // F-195：把 CAS 释放的"牙齿"变成可证伪的断言。场景即 sharedCacheLocks.js:46-49 自述的
  // 改因——A 的租约到期后 B 抢到同名锁，A 的延迟释放不得删掉 B 的锁，否则 B 仍在临界区时
  // 第三个实例又能进入（审计链的跨实例互斥当场不成立，产出同父两子）。
  // 旧 FakeRedis 在 JS 侧硬写比较、不看脚本文本，所以"无条件 del"的变异曾经全绿。
  test('release 只认自己的令牌：不得删掉后来者（B）的锁', async () => {
    await bootRedisMode();
    const lockA = await cache.acquireLock('rl-cas', 60000);
    expect(lockA).toBeTruthy();
    // 令牌形态也一并钉住：Math.random()+Date.now() 的旧拼法在同毫秒启动的两实例间可碰撞
    const tokenA = FakeRedis.store.get('rl-cas');
    expect(tokenA).toMatch(/^[0-9a-f]{32}$/);

    // ① 租约到点后 B 持有同名锁：A 的迟到释放必须无功（不删）
    FakeRedis.store.set('rl-cas', 'token-of-B');
    await lockA.release();
    expect(FakeRedis.store.get('rl-cas')).toBe('token-of-B');

    // ② 反向对照：令牌仍匹配时释放必须真的删——否则 ① 可以靠"什么都不做"蒙过去
    FakeRedis.store.set('rl-cas', tokenA);
    await lockA.release();
    expect(FakeRedis.store.get('rl-cas')).toBeUndefined();
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
    // set/get/del/incr：回退内存不抛错。
    // set 的返回值是调用方**唯一**能区分「落到共享层」与「只落到本进程内存」的信号：
    // 下一行 get 回读到 'fv' 读的是本地回退的那份，不是 Redis 确认过的——
    // "写后读回"在这种实现里必然给出假确认，所以契约只能落在返回值上
    // （auditChain 的 F-184b 降级判据依赖它）。
    await expect(cache.set('fk', 'fv', 60000)).resolves.toBe(false);
    await expect(cache.get('fk')).resolves.toBe('fv');
    await expect(cache.del('fk')).resolves.toBe(true);
    // F-205：incr 与 set/get/del **不同向**——它不回退内存，而是如实返回 null。
    // 调用方拿这个返回值去和**全局**上限比较（captchaService 的 MAX_ACTIVE_ENTRIES 洪水闸），
    // 而本进程的数字两个方向都是假的：偏小 ⇒ 洪水期护栏被骗过；偏大 ⇒ Redis 恢复后
    // 合法请求仍被这个本地值拒掉（登录前置被自己的降级史卡死）。
    await expect(cache.incrWithTtl('fcnt', 60000)).resolves.toBeNull();
    // 连续失败不得在本地累出 1→2：那正是「本地计数被当成集群计数」的形态
    await expect(cache.incrWithTtl('fcnt', 60000)).resolves.toBeNull();
    // 反向对照：命令恢复后自增从共享层真值起步（=1），证明降级期没有偷偷写过本地计数
    FakeRedis.failCommands = false;
    await expect(cache.incrWithTtl('fcnt', 60000)).resolves.toBe(1);
    FakeRedis.failCommands = true;
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

  test('F-207：SET 在飞期间 REDIS_URL 被撤 ⇒ 落地判据不得因 env 事后变化升格为 true', async () => {
    await bootRedisMode();
    let release;
    FakeRedis.setGate = new Promise((r) => {
      release = r;
    });
    FakeRedis.failCommands = true;
    const savedUrl = process.env.REDIS_URL;
    try {
      const pending = cache.set('envflip-key', 'v', 60000);
      delete process.env.REDIS_URL; // 命令仍在飞的这一拍里改掉环境
      release();
      // 修复前：`return !isRedisConfigured()` 读的是**回话时刻**的 env ⇒ 这里得到 true
      // = "已落到共享层"，而 Redis 根本没收到；调用方 utils/auditChain.js 的 writeSharedTail
      // 据此解除不可信并抹掉本地唯一副本（⇒ 权威状态只剩一个谁都不认识的本地值）。
      expect(await pending).toBe(false);
      // 可用性回退必须照旧（这是 set 文档承诺的"缓存类调用方可忽略返回值"那一半）：
      // 值仍留在本进程内存里，读抖动时取得到——**判据说真话不等于把回退删掉**。
      await expect(cache.get('envflip-key')).resolves.toBe('v');
    } finally {
      process.env.REDIS_URL = savedUrl;
      FakeRedis.setGate = null;
      FakeRedis.failCommands = false;
    }
  });

  test('F-207 对照臂：命令成功且 env 未变时判据仍为 true（证明上一条不是"set 恒返回 false"）', async () => {
    await bootRedisMode();
    let release;
    FakeRedis.setGate = new Promise((r) => {
      release = r;
    });
    try {
      const pending = cache.set('envflip-ok-key', 'v', 60000);
      release();
      await expect(pending).resolves.toBe(true);
      expect(FakeRedis.store.get('envflip-ok-key')).toBe(JSON.stringify('v'));
    } finally {
      FakeRedis.setGate = null;
    }
  });

  test('F-205：Redis 已配置但当前不可用 ⇒ 失效广播丢失要留痕（配了共享层却静默不发是谎报同步）', async () => {
    await bootRedisMode();
    const warn = jest.spyOn(isolatedLogger, 'warn').mockImplementation(() => {});
    try {
      // 用 'error' 事件把 redisReady 翻下来：REDIS_URL 仍在 ⇒ isRedisConfigured()=true，
      // 这正是「多实例部署 + 抖动」的形态，与「单实例没配 Redis」必须区分开
      FakeRedis.instances[0].emit('error', new Error('connection lost'));
      expect(cache.isRedisEnabled()).toBe(false);

      await cache.publishInvalidate('permcache:u1');
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('失效广播未发出'));

      // 反向对照：连接恢复后同一调用不得再报（否则这条告警就是恒真的噪音）
      warn.mockClear();
      FakeRedis.instances[0].emit('ready');
      expect(cache.isRedisEnabled()).toBe(true);
      await cache.publishInvalidate('permcache:u2');
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  test('F-205 反向对照：没配 Redis 的部署不得为广播刷告警（活体探针放在同一用例里防假绿）', async () => {
    await bootNoRedisMode();
    expect(cache.isRedisEnabled()).toBe(false);
    const warn = jest.spyOn(isolatedLogger, 'warn').mockImplementation(() => {});
    try {
      // 活体探针：若 spyOn 挂到了另一个 logger 实例，下面这条就会红——
      // 没有它，'not.toHaveBeenCalled()' 可以是恒真的（本仓反复踩过的"绿但不设防"）
      process.env.REDIS_URL = 'redis://fake:6379';
      await cache.publishInvalidate('permcache:probe');
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('失效广播未发出'));

      // 判据本身：撤掉 REDIS_URL（＝单实例部署）后同样的调用必须安静
      warn.mockClear();
      delete process.env.REDIS_URL;
      await cache.publishInvalidate('permcache:u1');
      await cache.publishInvalidate('sesscache:u2');
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  test('F-204 补全：getDel 成功路径必须抹掉本地陈旧副本（权威层已无此键）', async () => {
    await bootRedisMode();
    // 先造出「只落在本进程内存」的那份：命令失败期间的 set 会留本地副本并返回 false
    FakeRedis.failCommands = true;
    await expect(cache.set('gd-stale', { text: 'ABCD' }, 60000)).resolves.toBe(false);
    FakeRedis.failCommands = false;
    // 共享层从来没有这个键 ⇒ 原子取删如实给出「没有」
    await expect(cache.getDel('gd-stale')).resolves.toBeNull();
    // 判据：随后的读抖动不得把那份本地副本当成共享层真值顶回来（走 get 的内存回退）
    FakeRedis.failCommands = true;
    await expect(cache.get('gd-stale')).resolves.toBeNull();
    FakeRedis.failCommands = false;
  });

  test('getDel Redis 成功路径：取到值并从共享层删除，第二次取为 null', async () => {
    await bootRedisMode();
    await expect(cache.set('gd-ok', { text: 'XY' }, 60000)).resolves.toBe(true);
    await expect(cache.getDel('gd-ok')).resolves.toEqual({ text: 'XY' });
    expect(FakeRedis.store.has('gd-ok')).toBe(false);
    await expect(cache.getDel('gd-ok')).resolves.toBeNull();
  });

  test('F-211：配了 REDIS_URL 但连接已掉 ⇒ incr 不得伪造进程内"全局"计数（与 setIfAbsent 同口径）', async () => {
    await bootRedisMode();
    const warn = jest.spyOn(isolatedLogger, 'warn').mockImplementation(() => {});
    try {
      // 抖动形态：REDIS_URL 仍在（＝部署**要求**跨实例共享），但就绪标记已翻下。
      // F-205 当年只堵了「命令抛错」这一个入口（catch 返回 null），这条「未就绪」入口
      // 直落内存计数器——修复前实测连拿 1、2、3，而唯一的生产调用方 captchaService
      // 把这个本进程数字当"集群活跃验证码数"去比 MAX_ACTIVE_ENTRIES（偏小＝洪水期护栏被骗过）。
      FakeRedis.instances[0].emit('error', new Error('connection lost'));
      expect(cache.isRedisConfigured()).toBe(true);
      expect(cache.isRedisEnabled()).toBe(false);

      expect(await cache.incrWithTtl('f211:cnt', 60000)).toBeNull();
      // 连续降级不得在本地累出 1→2：那正是"本地计数被当成集群计数"的形态
      expect(await cache.incrWithTtl('f211:cnt', 60000)).toBeNull();
      // 降级不留痕＝上限护栏静默失效，运维看不见
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('如实返回 null'));

      // 反向对照：连接恢复后从**共享层真值**起步 ⇒ 证明降级期没有偷偷写过本地/共享计数
      warn.mockClear();
      FakeRedis.instances[0].emit('ready');
      expect(cache.isRedisEnabled()).toBe(true);
      expect(await cache.incrWithTtl('f211:cnt', 60000)).toBe(1);
      expect(await cache.incrWithTtl('f211:cnt', 60000)).toBe(2);
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  test('F-211 对照：未配 REDIS_URL（内存就是全部真相）仍须照常计数，判据不得一刀切成 null', async () => {
    await bootNoRedisMode();
    expect(cache.isRedisConfigured()).toBe(false);
    expect(await cache.incrWithTtl('f211:mem', 60000)).toBe(1);
    expect(await cache.incrWithTtl('f211:mem', 60000)).toBe(2);
    // 留痕探针：本用例的 logger 是隔离实例，门面内部 require 到的就是这一份——
    // 若 spyOn 挂错对象，上一条用例的 toHaveBeenCalledWith 就会红（防恒真断言）
    const warn = jest.spyOn(isolatedLogger, 'warn').mockImplementation(() => {});
    await cache.incrWithTtl('f211:mem2', 60000);
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
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
    // F-211：这一态（初始化即被拒）才是生产里**最常见**的"配了共享层却用不了"入口，
    // 判据与 setIfAbsent 同向：宁可不给数，也不给一个会被当集群值的本地数。
    expect(await cache.incrWithTtl('f211:initfail', 60000)).toBeNull();
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
