'use strict';

/**
 * （2026-09-19）：sharedCacheLocks 的锁令牌与"无锁降级"可见性
 *
 * 逐行读 sharedCache.js 时连带读了它装配的锁模块。两条改动都有牙齿：
 *  ① 锁令牌原先是 `Math.random().toString(36) + Date.now().toString(36)`。
 *     令牌是"谁持有这把锁"的唯一凭据（释放脚本按字符串相等比较），
 *     同一毫秒启动的两个实例存在可测的碰撞概率，碰撞后果是 B 的 release 删掉 A 的锁。
 *     现改为 crypto.randomBytes(16)。
 *  ② `acquireLock` 在 Redis 不可用时返回**空实现句柄**（=无锁继续执行），
 *     而原先这一条路径**一行日志都没有**（只有命令抛错时才 debug 一句）。
 *     三个锁原语在"不可用"时的极性其实互不相同（acquireLock 降级、
 *     acquireLockBlocking/casSet 返回 null/false），所以 acquireLock 的降级
 *     必须可观测：配了 REDIS_URL ⇒ warn，未配置 ⇒ debug（单实例是常态，不能刷日志）。
 */

const logger = require('../../src/utils/logger');
const { createLockOperations } = require('../../src/services/sharedCacheLocks');

/** 只记录 SET 值的假客户端 */
function fakeClient() {
  const calls = [];
  return {
    calls,
    async set(key, value, ...rest) {
      calls.push({ op: 'set', key, value, rest });
      return 'OK';
    },
    async eval(script, numKeys, key, ...args) {
      calls.push({ op: 'eval', script, key, args });
      return 1;
    },
  };
}

function makeLocks({ enabled, configured, client }) {
  return createLockOperations({
    getRedisClient: () => client,
    isRedisEnabled: () => enabled,
    isRedisConfigured: () => configured,
  });
}

describe('锁令牌与降级可见性', () => {
  test('令牌是 32 位十六进制（CSPRNG），不再由 Math.random + 时间戳拼出', async () => {
    const client = fakeClient();
    const { acquireLock, acquireLockBlocking } = makeLocks({
      enabled: true,
      configured: true,
      client,
    });

    await acquireLock('lock:a', 5000);
    await acquireLockBlocking('lock:b', 5000, 1);

    const tokens = client.calls.filter((c) => c.op === 'set').map((c) => c.value);
    expect(tokens).toHaveLength(2);
    tokens.forEach((t) => expect(t).toMatch(/^[0-9a-f]{32}$/));
    expect(tokens[0]).not.toBe(tokens[1]);
    // SET 仍然带 PX + NX（一次性改动不许顺手改掉互斥语义）
    client.calls
      .filter((c) => c.op === 'set')
      .forEach((c) => expect(c.rest).toEqual(expect.arrayContaining(['NX'])));
    expect(client.calls.filter((c) => c.op === 'set')[0].rest).toContain(5000);
  });

  test('配了 Redis 但链路不可用 ⇒ acquireLock 降级为无锁时必须 warn', async () => {
    const spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      const { acquireLock } = makeLocks({
        enabled: false,
        configured: true,
        client: fakeClient(),
      });
      const handle = await acquireLock('lock:down', 1000);
      expect(handle).not.toBeNull(); // 降级语义本来就是"照旧放行"，这条钉住不动
      await expect(handle.release()).resolves.toBeUndefined();
      const logged = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logged).toContain('退化为无锁语义');
      expect(logged).toContain('已配置 REDIS_URL');
    } finally {
      const calls = spy.mock.calls.length;
      spy.mockRestore();
      // 前提自证：spy 确实抓到了调用（本仓有过 spy 静默失效的前科）
      expect(calls).toBeGreaterThan(0);
    }
  });

  test('未配置 Redis（单实例常态）⇒ 同一降级只记 debug，不产生 warn 噪音', async () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const debugSpy = jest.spyOn(logger, 'debug').mockImplementation(() => {});
    try {
      const { acquireLock } = makeLocks({
        enabled: false,
        configured: false,
        client: fakeClient(),
      });
      await acquireLock('lock:solo', 1000);
      expect(warnSpy).not.toHaveBeenCalled();
      expect(debugSpy.mock.calls.map((c) => c.join(' ')).join('\n')).toContain('退化为无锁语义');
    } finally {
      warnSpy.mockRestore();
      debugSpy.mockRestore();
    }
  });

  test('三原语在链路不可用时的极性差异被固定下来（防被"统一"成错误方向）', async () => {
    const client = fakeClient();
    const opts = { enabled: false, configured: true, client };
    const locks = makeLocks(opts);
    expect(await locks.acquireLock('k', 1000)).not.toBeNull(); // 无锁放行
    expect(await locks.acquireLockBlocking('k', 1000, 1)).toBeNull(); // 拿不到锁
    expect(await locks.casSet('k', 'a', 'b')).toBe(false); // 未提交
    expect(client.calls).toHaveLength(0); // 三条都没碰过客户端
  });
});
