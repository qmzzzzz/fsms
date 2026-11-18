/**
 * 链锁超时僵尸窗口的跨实例防护
 *
 * 超时只能停止**等待** fn，不会取消它：僵尸 insertMany 仍可能稍后提交。
 * 若此时释放分布式锁，其他实例会从「僵尸写之前」的链尾续链，而僵尸提交的
 * 记录也引用同一父哈希 ⇒ 一父两子（分叉）。修复判据：
 *   1. 超时后不释放分布式锁直到僵尸落定；
 *   2. 僵尸在飞期间持续续租（PX 到期前延长），否则锁会先于僵尸落定过期；
 *   3. 本进程的后继调用立即失败（冻结），不得进入临界区；
 *   4. 僵尸落定后强制重同步（删共享链尾键）再解冻、再释放锁。
 */
// 写入前快照原值（env 泄漏收口）：链锁预算是 withChainLock 每次现读的，
// 不还原的话同 worker 后续套件的锁预算被钉死在 30ms——满载下 flush 全部超时回缓冲
const PREV_LOCK_TIMEOUT = process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '30';

jest.mock('../../services/sharedCache', () => ({
  EMPTY_SENTINEL: '__shared_cache_empty__',
  isRedisEnabled: jest.fn(() => false),
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  dropLocalCopy: jest.fn(() => true),
  casSet: jest.fn(),
  acquireLockBlocking: jest.fn(),
}));

const sharedCache = require('../../services/sharedCache');
const {
  withChainLock,
  getChainTail,
  advanceChainTail,
  __resetForTest,
} = require('../../utils/auditChain');
const fence = require('../../utils/auditChainFence');
const logger = require('../../utils/logger');
const { waitFor } = require('../helpers/waitFor');

const CHAIN_TAIL_KEY = 'audit:chain-tail';

describe('僵尸窗口：分布式锁保持与续租', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    __resetForTest();
    sharedCache.isRedisEnabled.mockReturnValue(true);
    sharedCache.set.mockResolvedValue(true);
    sharedCache.del.mockResolvedValue(1);
  });

  test('超时后锁不释放并持续续租；僵尸落定后重同步、解冻、释放', async () => {
    let finishZombie;
    const hang = new Promise((resolve) => {
      finishZombie = resolve;
    });
    const release = jest.fn().mockResolvedValue(undefined);
    const renew = jest.fn().mockResolvedValue(true);
    sharedCache.acquireLockBlocking.mockResolvedValue({ release, renew });

    await expect(withChainLock(() => hang)).rejects.toThrow(/锁持有超时/);
    expect(release).not.toHaveBeenCalled();

    // 僵尸在飞：后续批次必须立即失败，且不得去抢锁（抢了就会从旧尾续链）
    const nextFn = jest.fn().mockResolvedValue('next');
    await expect(withChainLock(nextFn)).rejects.toThrow(/冻结窗口/);
    expect(nextFn).not.toHaveBeenCalled();
    expect(sharedCache.acquireLockBlocking).toHaveBeenCalledTimes(1);

    // 30ms 的 PX 早该过期：没有续租的话锁此刻已可被其他实例抢走
    expect(await waitFor(() => renew.mock.calls.length > 0, 500)).toBe(true);

    finishZombie('zombie-done');
    expect(await waitFor(() => release.mock.calls.length === 1, 500)).toBe(true);
    // 重同步必须早于解冻：删共享链尾键，下一批从 DB 读僵尸写之后的权威尾
    expect(sharedCache.del.mock.calls.some((c) => c[0] === CHAIN_TAIL_KEY)).toBe(true);

    await expect(withChainLock(async () => 'after')).resolves.toBe('after');
  });

  test('P1 回归：前驱慢批次在飞、后继「前驱等待超时」冻结 → 前驱正常落定后必须解冻恢复', async () => {
    // 场景（2026-11-17 审计 P1-1，多实例 + Redis 锁）：前驱的批次只是慢（排队 +
    // 慢批次），不是僵尸；后继的 waitPrev 定时器先于前驱落定到点。修复前：
    // fence.freeze() 在这里无解冻归属——前驱正常完成（timedOut=false）不经过任何
    // 解冻路径，本实例链写入从此在 fence.check() 永久失败（flush 跳过、create 降级
    // legacy），且定时器里的代际递增把前驱的合法推进误判为僵尸跳过。修复后：
    // 冻结交给 waitForZombie（观察在飞的前驱 fn），前驱落定 → 重同步 → 解冻。
    //
    // 时序铺法：链锁预算是 withChainLock 每次现读的，可在用例内改 env——前驱 #2
    // 持有 300ms 预算（其 fn 由测试闸门控制，远快于预算 ⇒ 正常完成），后继只等
    // 60ms ⇒ 后继的等待超时定时器确定性先触发，不依赖真实竞速。
    const fileBudget = process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
    process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '300';
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    sharedCache.acquireLockBlocking.mockResolvedValue({
      release: jest.fn().mockResolvedValue(undefined),
      renew: jest.fn().mockResolvedValue(true),
    });

    try {
      // 前驱 #1：快批次，正常占锁并释放，让前驱 #2 排在它之后进入临界区
      await withChainLock(async () => 'c1');

      // 前驱 #2：慢批次（闸门控制）。fn 内先推进链尾再返回，模拟真实写路径
      let releaseC2;
      const c2Gate = new Promise((resolve) => {
        releaseC2 = resolve;
      });
      let c2Started = false;
      const c2 = withChainLock(async (gen) => {
        c2Started = true;
        await c2Gate;
        await advanceChainTail('c2'.repeat(64), gen);
        return 'c2';
      });
      await waitFor(() => c2Started, { label: '前驱 #2 进入临界区' });

      // 后继：预算压到 60ms——它的「前驱等待超时」先于前驱 #2 落定触发
      process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '60';
      const succErr = await withChainLock(async () => 'succ').catch((e) => e);
      expect(succErr.message).toMatch(/冻结窗口/);
      expect(fence.isFrozen()).toBe(true);
      // 冻结事件必须有可观测信号（修复前此处零日志）
      expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('前驱等待超时'));
      // 冻结窗内的后继不得去抢分布式锁（抢了就会从旧尾续链）
      expect(sharedCache.acquireLockBlocking).toHaveBeenCalledTimes(2);

      // 前驱 #2 正常落定（timedOut=false）：修复前冻结永不解除；修复后必须解冻
      releaseC2();
      await expect(c2).resolves.toBe('c2');
      expect(await waitFor(() => !fence.isFrozen(), { label: '前驱正常落定后解冻' })).toBe(true);
      // 前驱的合法推进不得被代际守卫误跳过（修复前的附带症状：链尾停止推进）
      expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('已过期'));
      // 解冻前先重同步：共享链尾键被删，下一批从 DB 读权威尾
      expect(sharedCache.del.mock.calls.some((c) => c[0] === CHAIN_TAIL_KEY)).toBe(true);

      // 链写入恢复 + 链尾推进正常：重同步后从 DB 读权威尾，新推进能落共享层
      sharedCache.get.mockResolvedValue(null); // 共享键已删 ⇒ 走「未初始化 → 回 DB 读」
      const model = {
        findOne: jest.fn().mockReturnValue({
          sort: jest.fn().mockReturnValue({
            lean: jest.fn().mockResolvedValue({ hash: 'db'.repeat(64) }),
          }),
        }),
      };
      let tail = null;
      await expect(
        withChainLock(async (gen) => {
          tail = await getChainTail(model);
          await advanceChainTail('aa'.repeat(64), gen);
          return 'recovered';
        })
      ).resolves.toBe('recovered');
      expect(tail).toBe('db'.repeat(64));
      expect(sharedCache.set).toHaveBeenCalledWith(CHAIN_TAIL_KEY, 'aa'.repeat(64));
      expect(sharedCache.acquireLockBlocking).toHaveBeenCalledTimes(3);
    } finally {
      process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = fileBudget;
      warnSpy.mockRestore();
      errSpy.mockRestore();
    }
  });
});

// 链锁预算随套件归还（快照见文件头）：auditChainZombieDuplicate.test.js 的 afterAll 同款口径
// ——不还则同 worker 后续套件（如 attackDetectionIntegration 的真实链路）在满载下全线超时回缓冲。
afterAll(() => {
  if (PREV_LOCK_TIMEOUT === undefined) delete process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
  else process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = PREV_LOCK_TIMEOUT;
});
