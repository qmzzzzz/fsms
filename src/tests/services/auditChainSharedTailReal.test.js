/**
 * 审计链共享链尾 × 真实 sharedCache 内存回退层（F-204 的端到端形态）
 *
 * auditChainDistributed.test.js 用 jest.mock 把整个 sharedCache 换成桩，能钉住
 * 「链尾写没吃到落地判据」这一层，但**钉不住内存回退层的复活机制**：那里的 memStore
 * 根本不存在。本文件让真实的 sharedCache + 真实的 auditChain 一起跑在假 ioredis 上
 * （只演"命令抛错"，不引真 Redis），复现 F-204 的实际发作形态：
 *
 *   ① 某次链尾写入没落到 Redis ⇒ 值留在本进程内存，并置「共享尾不可信」；
 *   ② 降级期间的修复写入确认成功 ⇒ 只清标记的话，①那份本地副本还活着
 *      （set 的 Redis 成功路径从不碰 memStore）；
 *   ③ 之后任意一次 GET 命令失败 ⇒ get() 的内存回退把①那份**早已死掉的父哈希**
 *      当成共享层真值顶回来：既不回 DB 重同步、也不告警；
 *   ④ 本实例就在死父哈希上续链，而共享层的尾已被其他实例推进 ⇒ 同父两子 ⇒
 *      chain_fork（审计链被误判成篡改）。
 *
 * 反向对照臂在测试内部用 jest.spyOn(dropLocalCopy) 现场拆掉修复（见 ② 那一步），
 * 于是"用例有没有牙齿"不依赖手工改生产源码就能自证。
 */

class FakeRedis {
  static reset() {
    FakeRedis.store = new Map(); // 共享层
    FakeRedis.failSet = false;
    FakeRedis.failGet = false;
  }
  constructor() {
    this.listeners = {};
  }
  on(ev, cb) {
    (this.listeners[ev] = this.listeners[ev] || []).push(cb);
    return this;
  }
  async ping() {
    return 'PONG';
  }
  async set(key, payload) {
    if (FakeRedis.failSet) throw new Error('SET refused (fake)');
    FakeRedis.store.set(key, payload);
    return 'OK';
  }
  async get(key) {
    if (FakeRedis.failGet) throw new Error('GET refused (fake)');
    return FakeRedis.store.has(key) ? FakeRedis.store.get(key) : null;
  }
  async del(key) {
    return FakeRedis.store.delete(key) ? 1 : 0;
  }
  async subscribe() {
    return 1;
  }
  async quit() {
    return 'OK';
  }
  disconnect() {}
}

const CHAIN_TAIL_KEY = 'audit:chain-tail';
const STALE_LOCAL = 'st'.repeat(32); // ① 留在本进程内存里的那份
const DB_TAIL = 'db'.repeat(32); // ② 降级期间从 DB 读到的权威尾
const SHARED_LANDED = 'aa'.repeat(32); // ③ 其他实例已推进到共享层的尾

// getLatestHash 用的最小 model 桩：findOne().sort().lean()
function makeModel(latestHash) {
  return {
    findOne: jest.fn().mockReturnValue({
      sort: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue(latestHash ? { hash: latestHash } : null),
      }),
    }),
  };
}

describe('审计链共享链尾的陈旧内存副本（F-204，真实 sharedCache）', () => {
  const savedUrl = process.env.REDIS_URL;
  let cache;
  let chain;
  let logger;

  // 每个用例都要一份干净的模块实例：memStore 与 redisReady 都是模块级状态
  async function boot() {
    FakeRedis.reset();
    jest.resetModules();
    jest.doMock('ioredis', () => FakeRedis);
    process.env.REDIS_URL = 'redis://fake:6379';
    jest.isolateModules(() => {
      cache = require('../../services/sharedCache');
      chain = require('../../utils/auditChain');
      logger = require('../../utils/logger');
    });
    jest.spyOn(logger, 'error').mockImplementation(() => {});
    await cache.initSharedCache();
    chain.__resetForTest();
    expect(cache.isRedisEnabled()).toBe(true);
  }

  // 只在测试里探"本进程内存回退层还有什么"：GET 命令抛错时 get() 才会读它
  async function peekLocalCopy(key) {
    FakeRedis.failGet = true;
    try {
      return await cache.get(key);
    } finally {
      FakeRedis.failGet = false;
    }
  }

  afterEach(() => {
    jest.dontMock('ioredis');
    jest.resetModules();
    jest.restoreAllMocks();
    if (savedUrl !== undefined) process.env.REDIS_URL = savedUrl;
    else delete process.env.REDIS_URL;
  });

  test('写入失败留下的本地副本，不得在之后的 GET 抖动里被当成共享尾顶回', async () => {
    await boot();

    // ① 链尾推进没落到 Redis：值只在本进程内存，共享层没有
    FakeRedis.failSet = true;
    await chain.advanceChainTail(STALE_LOCAL);
    expect(await peekLocalCopy(CHAIN_TAIL_KEY)).toBe(STALE_LOCAL);
    expect(FakeRedis.store.has(CHAIN_TAIL_KEY)).toBe(false);

    // ② Redis 恢复：降级期间的修复写入成功 ⇒ 解除不可信**并**让本地副本失声
    FakeRedis.failSet = false;
    await expect(chain.getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);
    expect(FakeRedis.store.get(CHAIN_TAIL_KEY)).toBe(JSON.stringify(DB_TAIL));

    // ③ GET 命令抖动一次：共享层读不到，此时内存里不该再有副本可顶
    FakeRedis.failGet = true;
    const later = makeModel(SHARED_LANDED);
    await expect(chain.getChainTail(later)).resolves.toBe(SHARED_LANDED);
    expect(later.findOne).toHaveBeenCalledTimes(1); // 关键：回 DB 重同步，而非顶回陈旧值
  });

  test('反向对照：拆掉 dropLocalCopy 后，同一场景就会顶回陈旧父哈希', async () => {
    await boot();
    // 现场拆掉修复（等价于"只清标记、不清本地副本"那一版）——用例必须变红
    jest.spyOn(cache, 'dropLocalCopy').mockImplementation(() => false);

    FakeRedis.failSet = true;
    await chain.advanceChainTail(STALE_LOCAL);
    FakeRedis.failSet = false;
    await chain.getChainTail(makeModel(DB_TAIL));

    FakeRedis.failGet = true;
    const later = makeModel(SHARED_LANDED);
    // 陈旧副本被当成共享层真值顶回来：不读 DB、不告警，直接在一个死父哈希上续链
    await expect(chain.getChainTail(later)).resolves.toBe(STALE_LOCAL);
    expect(later.findOne).not.toHaveBeenCalled();
  });

  test('共享层删除成功后，本进程内存副本一并失声（del 的同源缺口）', async () => {
    await boot();

    FakeRedis.failSet = true;
    await expect(cache.set(CHAIN_TAIL_KEY, STALE_LOCAL)).resolves.toBe(false);
    expect(await peekLocalCopy(CHAIN_TAIL_KEY)).toBe(STALE_LOCAL);

    FakeRedis.failSet = false;
    await expect(cache.del(CHAIN_TAIL_KEY)).resolves.toBe(false); // 共享层本就没有该键

    FakeRedis.failGet = true;
    await expect(cache.get(CHAIN_TAIL_KEY)).resolves.toBeNull();
  });

  test('未配置 Redis 时 dropLocalCopy 仍只清内存、不抛错（纯本地语义）', async () => {
    delete process.env.REDIS_URL;
    FakeRedis.reset();
    jest.resetModules();
    let local;
    jest.isolateModules(() => {
      local = require('../../services/sharedCache');
    });
    await local.initSharedCache();
    expect(local.isRedisEnabled()).toBe(false);

    await local.set(CHAIN_TAIL_KEY, STALE_LOCAL);
    expect(local.dropLocalCopy(CHAIN_TAIL_KEY)).toBe(true);
    expect(await local.get(CHAIN_TAIL_KEY)).toBeNull();
    expect(local.dropLocalCopy(CHAIN_TAIL_KEY)).toBe(false); // 再删一次：没有副本可删
  });
});
