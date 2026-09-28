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

/**
 * F-192：前驱等待的超时定时器**输掉 Promise.race 之后仍然会触发副作用**。
 *
 * `waitPrev = Promise.race([prev, 超时定时器])`，而那个 setTimeout 从未被 clear
 * （`finally` 里只 clear 了"持有超时"的 timer）。前驱正常放行是最常见的路径，
 * 于是每一次 withChainLock 都留下一枚 CHAIN_LOCK_TIMEOUT_MS（默认 15s）后必爆的定时器，
 * 到点无条件执行 `chainTailLoaded=false; chainTail=null; chainGeneration+=1`——
 * 注释里写的是"前驱超时放行时"才做的失效标记，代码却把它变成了无条件。
 *
 * 实测（本地探针，超时设 200ms）：两次无争用调用 g1=g2=0，推进链尾后**只静置**，
 * 再读链尾就从"命中缓存"变成"回库重读"（内存尾被抹），新调用的代际从 0 跳到 2。
 * 代价是三条：① 链尾缓存每 15s 自我作废一次，"避免额外写放大"的前提失效；
 * ② 正常批次的 advanceChainTail 被代际守卫判成僵尸而跳过（B-L4 的守卫失去区分能力）；
 * ③ 那条"链尾推进被跳过"的告警开始为合法批次说话——运维据此判断链状态，谎报即缺陷。
 */
describe('前驱等待定时器只在真正超时时生效（F-192）', () => {
  let chain;
  let log;

  beforeAll(() => {
    // 独立实例：外层套件把超时设成 1ms，这里需要一个"静置得越久越能证明没被触发"的量级。
    // resetModules 后重新 require 得到另一个模块实例，外层已捕获的引用不受影响。
    jest.resetModules();
    process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '300';
    delete process.env.REDIS_URL;
    log = require('../../utils/logger');
    chain = require('../../utils/auditChain');
    chain.__resetForTest();
  });

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const cachedTail = {
    findOne: () => ({ sort: () => ({ lean: async () => ({ hash: 'DB-1' }) }) }),
  };
  const mustNotReadDb = {
    findOne: () => {
      throw new Error('不该读库：内存链尾被判定失效');
    },
  };

  test('无超时的调用：静置超过锁超时后，链尾仍有效、代际仍未被递增', async () => {
    await chain.getChainTail(cachedTail); // 建立内存尾
    const gen = await chain.withChainLock(async (g) => g); // 快路径，prev 已 settle
    await chain.advanceChainTail('a'.repeat(64), gen);

    await sleep(500); // >300ms：只静置，期间没有任何并发、没有超时

    const warnSpy = jest.spyOn(log, 'warn').mockImplementation(() => {});
    // 同一代际的后续推进必须仍然被认作"当前代"：若输掉竞赛的定时器递增过代际，
    // 这里会被 B-L4 守卫跳过并告警
    await chain.advanceChainTail('b'.repeat(64), gen);
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('已过期'));
    warnSpy.mockRestore();

    // 链尾必须还在内存里：读库即说明它被那枚定时器抹掉了
    await expect(chain.getChainTail(mustNotReadDb)).resolves.toBe('b'.repeat(64));

    const gen2 = await chain.withChainLock(async (g) => g);
    expect(gen2).toBe(gen);
  });
});
