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
 *  - F-184b：共享链尾写入未落到 Redis（set 返回 false）后的降级、修复与自愈解除
 *  - F-204：同一判据在 getChainTail「键不存在 ⇒ 回写」那条路径上的同级缺口（陈旧内存尾顶回）
 */

// jest.mock 会被提升到文件顶部，factory 在 require 时执行；这里内联返回 stub，
// 后续通过 require('../../services/sharedCache') 拿到同一份 mock 引用。
jest.mock('../../services/sharedCache', () => ({
  EMPTY_SENTINEL: '__shared_cache_empty__',
  isRedisEnabled: jest.fn(() => false),
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  // F-204：链尾写入确认落到 Redis 后必须抹掉本进程内存副本（桩默认"抹掉了"）。
  // 用 () => true 而不是 jest.fn()：mockResolvedValue 之外的同步返回值不参与
  // 判定，但保留布尔返回，方便日后按"是否真删了副本"收紧。
  dropLocalCopy: jest.fn(() => true),
  casSet: jest.fn(),
  acquireLockBlocking: jest.fn(),
}));

const sharedCache = require('../../services/sharedCache');
const logger = require('../../utils/logger');
const {
  getChainTail,
  advanceChainTail,
  rollbackChainTail,
  resyncChainTail,
  withChainLock,
  __resetForTest,
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
  __resetForTest();
  sharedCache.isRedisEnabled.mockReturnValue(false);
  // set 的返回值就是 F-184b 的降级开关，默认「已落到 Redis」，用例内按需覆写。
  // 必须在每个用例重设：clearAllMocks 只清调用记录、不清 mockResolvedValue 装上的
  // 实现，上一个用例的 false 会泄漏成下一个用例的默认（顺序耦合）。
  sharedCache.set.mockResolvedValue(true);
});

afterEach(() => {
  jest.restoreAllMocks();
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

  // F-184b：sharedCache.set 在 Redis 抛错时**静默回退本地内存**并返回 false。
  // 若不把这次失败变成状态，共享层的键仍是旧尾，而 getChainTail 无条件优先读共享层
  // ⇒ 本实例与其他实例在同一个父哈希上各挂一条子记录（链分叉成 DAG）。
  // 改前这些用例全绿（分叉看不见 + 降级不存在），是"绿但不设防"的典型。
  describe('共享链尾未能写入 Redis 的降级与自愈（F-184b）', () => {
    const STALE = 'st'.repeat(32);
    const DB_TAIL = 'db'.repeat(32);
    const BATCH = 'ba'.repeat(32);

    test('写入未落 Redis 后：不再读共享层、每批从 DB 读权威尾，且只告警一次', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(false);
      sharedCache.get.mockResolvedValue(STALE); // 毒饵：只要还信任共享层就会返回它
      const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      expect(errorSpy).toHaveBeenCalledTimes(1);

      const first = makeModel(DB_TAIL);
      await expect(getChainTail(first)).resolves.toBe(DB_TAIL);
      expect(sharedCache.get).not.toHaveBeenCalled();
      expect(first.findOne).toHaveBeenCalledTimes(1);

      // 降级是持续状态，不是一次性：第二批同样绕开共享层
      const second = makeModel('ee'.repeat(32));
      await expect(getChainTail(second)).resolves.toBe('ee'.repeat(32));
      expect(sharedCache.get).not.toHaveBeenCalled();
      // 降级期间每次都会顺手尝试修复共享键（写入的是 DB 权威值）
      expect(sharedCache.set).toHaveBeenLastCalledWith(CHAIN_TAIL_KEY, 'ee'.repeat(32));
    });

    test('写入确认落到 Redis 时不降级：此后仍优先读共享层（反向对照）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(true);
      sharedCache.get.mockResolvedValue(STALE);
      const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      const model = makeModel(DB_TAIL);
      await expect(getChainTail(model)).resolves.toBe(STALE);
      expect(errorSpy).not.toHaveBeenCalled();
      expect(model.findOne).not.toHaveBeenCalled();
    });

    test('降级期间修复写入仍失败时保持降级（不得乐观解除）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(false);
      sharedCache.get.mockResolvedValue(STALE);
      jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      await expect(getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);
      await expect(getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);
      expect(sharedCache.get).not.toHaveBeenCalled();
    });

    test('某次修复写入确认成功后自愈：恢复优先读共享层', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(false);
      sharedCache.get.mockResolvedValue(STALE);
      jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      // 本次仍返回 DB 尾（可信状态要到写入确认之后才解除）
      await expect(getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);

      sharedCache.set.mockResolvedValue(true);
      const repairing = makeModel('cc'.repeat(32));
      await expect(getChainTail(repairing)).resolves.toBe('cc'.repeat(32));
      expect(repairing.findOne).toHaveBeenCalledTimes(1);

      const recovered = makeModel(DB_TAIL);
      await expect(getChainTail(recovered)).resolves.toBe(STALE);
      expect(recovered.findOne).not.toHaveBeenCalled();
    });

    test('只认显式 false：set 未返回值（旧桩）不得触发降级', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(undefined);
      sharedCache.get.mockResolvedValue(STALE);
      const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      const model = makeModel(DB_TAIL);
      await expect(getChainTail(model)).resolves.toBe(STALE);
      expect(errorSpy).not.toHaveBeenCalled();
    });

    test('降级时同步推进内存尾：Redis 整体不可用后进程内语义接手不走偏', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValue(false);
      jest.spyOn(logger, 'error').mockImplementation(() => {});

      await advanceChainTail(BATCH);
      sharedCache.isRedisEnabled.mockReturnValue(false);
      const model = makeModel(DB_TAIL);
      await expect(getChainTail(model)).resolves.toBe(BATCH);
      expect(model.findOne).not.toHaveBeenCalled();
    });
  });

  // F-204：getChainTail 的「键不存在 ⇒ 读 DB 并回写」路径（共享尾的**第二处**写入，与
  // advanceChainTail 同源）原先丢掉了 set() 的落地判据。写没进 Redis 时 set 会把值留在
  // 本进程内存，于是"下一次共享读命令失败"就会把这份陈旧副本顶回来：主从切换后 Redis 里
  // 的尾早已被别的实例推进，而本实例既不告警也不回 DB，直接在一个已死的父哈希上续链 ⇒ 分叉。
  // 假 ioredis 三臂实测：SET 抛错 + GET 抛错 ⇒ byType.chain_fork=1 / intact=false；
  // GET 抛错但那次 SET 成功（本地无副本）⇒ 回 DB ⇒ intact=true。
  // ⇒ 根因是这里没吃落地判据，而不是 sharedCache.get 的内存回退（后者一改会波及
  //   限流/验证码/权限缓存全部降级读，那一版提议的修法已被这第三臂否掉）。
  describe('未初始化回写未能落到 Redis 的降级（F-204）', () => {
    const STALE = 'st'.repeat(32);
    const DB_TAIL = 'db'.repeat(32);

    test('回写未落 Redis ⇒ 此后共享读不可信，改读 DB 权威尾', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValue(null); // 键不存在
      sharedCache.set.mockResolvedValueOnce(false); // 这一次回写没落到 Redis
      const first = makeModel(DB_TAIL);
      await expect(getChainTail(first)).resolves.toBe(DB_TAIL);
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, DB_TAIL);

      // 此后共享层"读得到值"——正是本地那份陈旧副本被顶回来的形态
      sharedCache.get.mockClear();
      sharedCache.get.mockResolvedValue(STALE);
      const later = makeModel('f1'.repeat(32));
      await expect(getChainTail(later)).resolves.toBe('f1'.repeat(32));
      expect(sharedCache.get).not.toHaveBeenCalled();
      expect(later.findOne).toHaveBeenCalledTimes(1);
    });

    test('回写确认落到 Redis 时不降级：此后仍优先读共享层（反向对照）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValueOnce(null);
      sharedCache.set.mockResolvedValue(true);
      const first = makeModel(DB_TAIL);
      await expect(getChainTail(first)).resolves.toBe(DB_TAIL);

      sharedCache.get.mockResolvedValue(STALE);
      const later = makeModel('f2'.repeat(32));
      await expect(getChainTail(later)).resolves.toBe(STALE);
      expect(later.findOne).not.toHaveBeenCalled();
    });

    test('只认显式 false：回写未返回值（旧桩）不得触发降级', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValueOnce(null);
      sharedCache.set.mockResolvedValue(undefined);
      const first = makeModel(DB_TAIL);
      await expect(getChainTail(first)).resolves.toBe(DB_TAIL);

      sharedCache.get.mockResolvedValue(STALE);
      const later = makeModel('f3'.repeat(32));
      await expect(getChainTail(later)).resolves.toBe(STALE);
      expect(later.findOne).not.toHaveBeenCalled();
    });
  });

  // F-204 补全：光标记/清除「共享尾不可信」并不足以闭合——set 的 Redis 成功路径从不碰本进程
  // 内存，所以一次失败写入留下的本地副本会**活过**之后所有成功写入；等到任意一次 GET 命令失败，
  // get() 的内存回退就把这份早已死掉的父哈希当成共享层真值顶回来（既不回 DB 重同步也不告警）
  // ⇒ 同父两子 ⇒ chain_fork 误判篡改。不变量：确认落到 Redis 的每一次链尾写入都必须让本地
  // 副本失声。三处写入已收口到 writeSharedTail，所以这条断言只需盯 dropLocalCopy 的调用。
  describe('链尾本地内存副本不变量（F-204 补全）', () => {
    const DB_TAIL = 'db'.repeat(32);
    const BATCH = 'ba'.repeat(32);

    test('advanceChainTail 确认落 Redis 后抹掉本地副本', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      await advanceChainTail(BATCH);
      expect(sharedCache.dropLocalCopy).toHaveBeenCalledTimes(1);
      expect(sharedCache.dropLocalCopy).toHaveBeenCalledWith(CHAIN_TAIL_KEY);
    });

    test('未初始化回写确认落 Redis 后抹掉本地副本', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.get.mockResolvedValue(null); // 键不存在 ⇒ 走回写路径
      await expect(getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);
      expect(sharedCache.dropLocalCopy).toHaveBeenCalledWith(CHAIN_TAIL_KEY);
    });

    test('降级期修复写入确认成功后：既解除不可信、也抹掉那份陈旧本地副本', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      sharedCache.set.mockResolvedValueOnce(false); // 首次推进未落地 ⇒ 本地留下副本
      await advanceChainTail(BATCH);
      expect(sharedCache.dropLocalCopy).not.toHaveBeenCalled();

      sharedCache.set.mockResolvedValue(true);
      await expect(getChainTail(makeModel(DB_TAIL))).resolves.toBe(DB_TAIL);
      expect(sharedCache.dropLocalCopy).toHaveBeenCalledWith(CHAIN_TAIL_KEY);

      // 两条一起做才闭合：只清标记不清副本时，这次共享读会顶回 BATCH 那份陈旧值
      sharedCache.get.mockResolvedValue(DB_TAIL);
      const recovered = makeModel('ff'.repeat(32));
      await expect(getChainTail(recovered)).resolves.toBe(DB_TAIL);
      expect(recovered.findOne).not.toHaveBeenCalled();
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

    // F-194：resyncChainTail 的 Redis 分支此前只删共享键、直接 return，把进程内链尾
    // 留在"已加载"状态。Redis 在线时 getChainTail 不读进程内链尾，所以这只是潜伏缺陷；
    // 但 advanceChainTail 明确承诺"Redis 若整体不可用，进程内语义接手"（见其 landed===false
    // 分支），该承诺一旦兑现，接手的就是一枚幻影链尾——正是本函数声称要清除的东西。
    // auditBuffer 的"部分落库成功"自愈入口只调用 resyncChainTail()（不像 withChainLock
    // 内部那两处还手工重置 chainTailLoaded），所以这条路径实际什么也没自愈。
    test('Redis 就绪时自愈也要清进程内链尾（降级为无 Redis 后不接手幻影尾）', async () => {
      sharedCache.isRedisEnabled.mockReturnValue(true);
      const phantom = 'ee'.repeat(32);
      const dbTail = 'ab'.repeat(32);
      // 造出"共享写未落地 → 进程内接手"的状态：进程内链尾=phantom、chainTailLoaded=true
      sharedCache.set.mockResolvedValue(false);
      await advanceChainTail(phantom);
      sharedCache.del.mockResolvedValue(1);

      await resyncChainTail();
      expect(sharedCache.del).toHaveBeenCalledWith(CHAIN_TAIL_KEY);

      // Redis 整体不可用：getChainTail 退到进程内语义——此处必须回 DB，而不是接手幻影尾
      sharedCache.isRedisEnabled.mockReturnValue(false);
      const model = makeModel(dbTail);
      await expect(getChainTail(model)).resolves.toBe(dbTail);
      expect(model.findOne).toHaveBeenCalled();
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
