/**
 * 审计链分布式锁接线（A-1）的 Redis 就绪路径测试
 *
 * 生产与测试环境默认无 REDIS_URL，`sharedCache.isRedisEnabled()` 恒为 false，
 * auditChain.js 里的分布式锁/共享链尾分支在真实 sharedCache 下永远走不到，
 * 导致这些分支成为未覆盖代码（branches/functions 撞覆盖率棘轮阈值）。
 * 这里用 jest.mock 把 sharedCache 替换为可控 stub，逐个覆盖：
 *  - withChainLock 叠加 acquireLockBlocking 分布式锁（拿锁成功 / 超时降级 / 释放失败吞错）
 *  - getChainTail / advanceChainTail / rollbackChainTail / resyncChainTail 的共享缓存路径
 *  - EMPTY_SENTINEL 哨兵与「键不存在（未初始化）」的区分
 */

// jest.mock 会被提升到文件顶部，factory 在 require 时执行；这里内联返回 stub，
// 后续通过 require('../../services/sharedCache') 拿到同一份 mock 引用。
jest.mock('../../services/sharedCache', () => ({
  EMPTY_SENTINEL: '__shared_cache_empty__',
  isRedisEnabled: jest.fn(() => false),
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  casSet: jest.fn(),
  acquireLockBlocking: jest.fn(),
}));

const sharedCache = require('../../services/sharedCache');
const {
  getChainTail,
  advanceChainTail,
  rollbackChainTail,
  resyncChainTail,
  withChainLock,
} = require('../../utils/auditChain');

const CHAIN_TAIL_KEY = 'audit:chain-tail';
const CHAIN_LOCK_KEY = 'audit:chain-lock';
const SENTINEL = '__shared_cache_empty__';

// 构造 getLatestHash 所需的最小 model stub：findOne().sort().lean()
function makeModel(latestHash) {
  return {
    findOne: jest.fn().mockReturnValue({
      sort: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue(latestHash ? { hash: latestHash } : null),
      }),
    }),
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  sharedCache.isRedisEnabled.mockReturnValue(false);
});

describe('审计链共享链尾（Redis 就绪路径）', () => {
  describe('getChainTail', () => {
    test('共享缓存存哨兵时返回空链尾 null（不读 DB）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValue(SENTINEL);
      const model = makeModel('ab'.repeat(32));
      await expect(getChainTail(model)).resolves.toBeNull();
      expect(model.findOne).not.toHaveBeenCalled();
      expect(sharedCache.set).not.toHaveBeenCalled();
    });

    test('共享缓存存 hash 时原样返回（不读 DB、不回写）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      const hash = 'cd'.repeat(32);
      sharedCache.get.mockResolvedValue(hash);
      const model = makeModel(null);
      await expect(getChainTail(model)).resolves.toBe(hash);
      expect(model.findOne).not.toHaveBeenCalled();
    });

    test('共享缓存未初始化（键不存在）时从 DB 读并回写', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValue(null);
      const hash = 'ef'.repeat(32);
      const model = makeModel(hash);
      await expect(getChainTail(model)).resolves.toBe(hash);
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, hash);
    });

    test('共享缓存未初始化且 DB 为空时回写哨兵', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValue(null);
      const model = makeModel(null);
      await expect(getChainTail(model)).resolves.toBeNull();
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, SENTINEL);
    });
  });

  describe('advanceChainTail', () => {
    test('Redis 就绪时写共享缓存（不带 TTL）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      const hash = '12'.repeat(32);
      await advanceChainTail(hash);
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, hash);
    });

    test('Redis 就绪且 hash 为 null 时落哨兵', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      await advanceChainTail(null);
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, SENTINEL);
    });
  });

  describe('rollbackChainTail', () => {
    test('Redis 就绪时用 casSet 原子回滚并透传结果', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.casSet.mockResolvedValue(true);
      const hash = '34'.repeat(32);
      const restore = '56'.repeat(32);
      await expect(rollbackChainTail(hash, restore)).resolves.toBe(true);
      expect(sharedCache.casSet).toHaveBeenCalledWith(CHAIN_TAIL_KEY, hash, restore);
    });

    test('Redis 就绪且回滚到空时 expected/restore 用哨兵', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.casSet.mockResolvedValue(false);
      await expect(rollbackChainTail(null, null)).resolves.toBe(false);
      expect(sharedCache.casSet).toHaveBeenCalledWith(CHAIN_TAIL_KEY, SENTINEL, SENTINEL);
    });
  });

  describe('resyncChainTail', () => {
    test('Redis 就绪时删除共享链尾键', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.del.mockResolvedValue(1);
      await resyncChainTail();
      expect(sharedCache.del).toHaveBeenCalledWith(CHAIN_TAIL_KEY);
    });

    test('Redis 就绪且 del 失败时吞错（自愈入口不抛 unhandled rejection）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.del.mockRejectedValue(new Error('redis down'));
      await expect(resyncChainTail()).resolves.toBeUndefined();
    });
  });
});

describe('审计链分布式锁（withChainLock Redis 就绪路径）', () => {
  test('拿锁成功时执行 fn 并释放锁', async () => {
    sharedCache.isRedisEnabled.mockReturnValue(true);
    const release = jest.fn().mockResolvedValue(undefined);
    sharedCache.acquireLockBlocking.mockResolvedValue({ release });
    const fn = jest.fn().mockResolvedValue('done');

    await expect(withChainLock(fn)).resolves.toBe('done');
    expect(sharedCache.acquireLockBlocking).toHaveBeenCalledWith(
      CHAIN_LOCK_KEY,
      expect.any(Number),
      expect.any(Number)
    );
    expect(fn).toHaveBeenCalled();
    expect(release).toHaveBeenCalled();
  });

  test('拿不到锁时抛错并标记链尾失效（不执行 fn）', async () => {
    sharedCache.isRedisEnabled.mockReturnValue(true);
    sharedCache.acquireLockBlocking.mockResolvedValue(null);
    sharedCache.del.mockResolvedValue(1);
    const fn = jest.fn();

    await expect(withChainLock(fn)).rejects.toThrow(/分布式锁获取超时/);
    expect(fn).not.toHaveBeenCalled();
    // 降级路径会 resyncChainTail -> del CHAIN_TAIL_KEY
    expect(sharedCache.del).toHaveBeenCalledWith(CHAIN_TAIL_KEY);
  });

  test('释放锁失败不覆盖 fn 结果（finally 吞错）', async () => {
    sharedCache.isRedisEnabled.mockReturnValue(true);
    const release = jest.fn().mockRejectedValue(new Error('release fail'));
    sharedCache.acquireLockBlocking.mockResolvedValue({ release });
    const fn = jest.fn().mockResolvedValue('value');

    await expect(withChainLock(fn)).resolves.toBe('value');
    expect(release).toHaveBeenCalled();
  });

  test('Redis 未就绪时不叠加分布式锁（进程内语义不变）', async () => {
    sharedCache.isRedisEnabled.mockReturnValue(false);
    const fn = jest.fn().mockResolvedValue('ok');

    await expect(withChainLock(fn)).resolves.toBe('ok');
    expect(sharedCache.acquireLockBlocking).not.toHaveBeenCalled();
  });
});
