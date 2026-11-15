/**
 * P3：审计链围栏的僵尸续租上界。
 *
 * 守的是什么：僵尸 fn（链锁持有超时后仍在飞的批次）若**永不落定**，围栏原本会
 * 无限续租分布式锁——其余实例从此永远拿不到链锁，审计链整体停摆且无任何告警。
 * 修复后：续租有总时长上界（AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS，默认 10×租约且
 * ≥60s），超界即停止续租 + error 日志 + 安全告警计数，锁按 PX 自然过期（可接管）。
 *
 * 用假时钟驱动：env 把上界压到 100ms，advanceTimersByTime 直接过界，不靠真实等待。
 */
const fence = require('../../utils/auditChainFence');
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

describe('P3 审计链围栏：僵尸续租上界', () => {
  let errSpy;
  let alertSpy;

  beforeEach(() => {
    fence.reset();
    errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    process.env.AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS = '100';
  });

  afterEach(() => {
    delete process.env.AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS;
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  test('僵尸永不落定：续租在上界处停止 + error + 安全告警计数；锁未释放（等 PX 过期）', () => {
    jest.useFakeTimers();
    fence.freeze(); // withChainLock 超时路径已冻结；此处模拟该状态
    const renew = jest.fn(async () => {});
    const release = jest.fn(async () => {});
    const work = new Promise(() => {}); // 永不 resolve = 僵尸
    fence.waitForZombie(work, { renew, release }, { ttlMs: 30, resync: async () => {} });

    jest.advanceTimersByTime(90);
    const renewalsBeforeBound = renew.mock.calls.length;
    expect(renewalsBeforeBound).toBeGreaterThan(0); // 上界内照常续租（锁不被抢走）

    jest.advanceTimersByTime(300); // 远超 100ms 上界
    expect(renew.mock.calls.length).toBe(renewalsBeforeBound); // 不再续租 ⇒ 锁可按 PX 过期
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('续租上界'));
    expect(alertSpy).toHaveBeenCalledWith('audit_chain_zombie_renewal_exceeded', 'high');
    expect(release).not.toHaveBeenCalled(); // 僵尸未落定：不主动释放（交给 PX 过期）
    expect(fence.isFrozen()).toBe(true); // 冻结窗保持：后继批次仍被挡住
  });

  test('僵尸正常落定：重同步 → 解冻 → 释放，续租停止（既有契约不回归）', async () => {
    jest.useFakeTimers();
    fence.freeze();
    const renew = jest.fn(async () => {});
    const release = jest.fn(async () => {});
    const resync = jest.fn(async () => {});
    let finish;
    const work = new Promise((r) => {
      finish = r;
    });
    fence.waitForZombie(work, { renew, release }, { ttlMs: 30, resync });

    jest.advanceTimersByTime(10);
    expect(renew.mock.calls.length).toBeGreaterThan(0); // 落定前有续租
    finish(); // 僵尸落定
    for (let i = 0; i < 4; i += 1) await Promise.resolve(); // 让 settle 链跑完

    expect(resync).toHaveBeenCalledTimes(1); // 先重同步（顺序不能反）
    expect(fence.isFrozen()).toBe(false); // 再解冻
    expect(release).toHaveBeenCalledTimes(1); // 最后释放
    const n = renew.mock.calls.length;
    jest.advanceTimersByTime(200);
    expect(renew.mock.calls.length).toBe(n); // 落定后不再续租
  });

  test('无分布式锁（单进程语义）：僵尸落定照常重同步解冻，不产生告警', async () => {
    const resync = jest.fn(async () => {});
    fence.freeze();
    fence.waitForZombie(Promise.resolve(), null, { ttlMs: 30, resync });
    for (let i = 0; i < 4; i += 1) await Promise.resolve();
    expect(resync).toHaveBeenCalledTimes(1);
    expect(fence.isFrozen()).toBe(false);
    expect(alertSpy).not.toHaveBeenCalled();
  });

  test('非法预算 env ⇒ 回落默认并 error 告警（负值/0 不得让上界失效）', () => {
    jest.useFakeTimers();
    process.env.AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS = '-1';
    // 预算只在「有分布式锁可续租」的分支里读取：必须给 distLock 桩才能到达该判据
    fence.waitForZombie(
      new Promise(() => {}),
      { renew: jest.fn(async () => {}), release: jest.fn(async () => {}) },
      { ttlMs: 30, resync: async () => {} }
    );
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining('AUDIT_CHAIN_ZOMBIE_RENEWAL_BUDGET_MS')
    );
  });
});
