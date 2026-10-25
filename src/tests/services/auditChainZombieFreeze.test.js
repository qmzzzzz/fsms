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
const { withChainLock, __resetForTest } = require('../../utils/auditChain');
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
});
