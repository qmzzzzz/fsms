/**
 * B-L4/B-L5 链尾代际守卫——确定性覆盖（与运行时序无关）
 *
 * 锁超时/僵尸推进分支依赖真实时序：本地快机能触发，慢 CI 上时序漂移会让
 * 这些分支时而未覆盖（2026-09-05 CI 实测 auditChain branches 86.66% < 87%
 * 棘轮，同一套用例本地 100%）。本套件用直接函数调用 + 极小锁超时环境变量
 * 把相关分支变成确定性覆盖，不再依赖竞态是否碰巧发生。
 */
describe('auditChain 链尾代际守卫（B-L4/B-L5）', () => {
  const ORIG_LOCK_TIMEOUT = process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
  const ORIG_REDIS_URL = process.env.REDIS_URL;
  let auditChain;
  let logger;

  beforeAll(() => {
    // 模块级常量在 require 时读取：极小超时让定时器路径确定性触发；
    // 去掉 REDIS_URL 保证走进程内链尾语义（与 CI 测试环境一致）
    jest.resetModules();
    process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '1';
    delete process.env.REDIS_URL;
    logger = require('../../utils/logger');
    auditChain = require('../../utils/auditChain');
  });

  afterAll(() => {
    if (ORIG_LOCK_TIMEOUT === undefined) {
      delete process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
    } else {
      process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = ORIG_LOCK_TIMEOUT;
    }
    if (ORIG_REDIS_URL === undefined) {
      delete process.env.REDIS_URL;
    } else {
      process.env.REDIS_URL = ORIG_REDIS_URL;
    }
  });

  test('僵尸推进：代际过期 → 跳过并告警，不用过期 hash 覆写链尾（B-L4）', async () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    await auditChain.advanceChainTail('a'.repeat(64), 999999999);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('代际 999999999 已过期'));
    warnSpy.mockRestore();
  });

  test('fn 悬挂持锁超时 → 强制释放并拒绝，代际递增使初始代际过期（B-L5）', async () => {
    await expect(auditChain.withChainLock(() => new Promise(() => {}))).rejects.toThrow(
      /锁持有超时/
    );
    // 超时路径已递增代际：初始代际 0 已过期 → 对应的僵尸推进被跳过
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    await auditChain.advanceChainTail('b'.repeat(64), 0);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('代际 0 已过期'));
    warnSpy.mockRestore();
  });
});
