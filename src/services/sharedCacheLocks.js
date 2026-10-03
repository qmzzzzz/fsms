/**
 * SharedCache 分布式锁与 CAS 原子操作：集中封装 Redis 原子脚本和退避语义。
 *
 * 极性提示（给调用方，别踩）：三个原语在"Redis 当前不可用"时的返回值方向**不同**，
 * 这是刻意的，但含义相反——
 *  - `acquireLock` → 返回一个空实现的句柄（=无锁继续执行）；
 *  - `acquireLockBlocking` → 返回 null（=拿不到锁，调用方须自行拒绝/排队失败）；
 *  - `casSet` → 返回 false（=改不动，调用方须按未提交处理）。
 * 也就是说只有 `acquireLock` 会"降级为无锁"。用它保护跨实例互斥的临界区时，
 * 必须清楚 Redis 故障期该临界区是**不设防**的（现已会 warn 出来，见下）。
 */

const crypto = require('crypto');
const logger = require('../utils/logger');
// 锁的三条失败分支都是"退化后继续跑"，catch 体自己不能抛（全总化唯一实现，见 utils/auditWriteFailure）
const { errText } = require('../utils/auditWriteFailure');

const LOCK_RELEASE_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

const CAS_SET_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  redis.call("set", KEYS[1], ARGV[2])
  return 1
else
  return 0
end
`;

const createLockOperations = ({ getRedisClient, isRedisEnabled, isRedisConfigured }) => {
  const releaseLockSafely = async (lockKey, token) => {
    try {
      await getRedisClient().eval(LOCK_RELEASE_SCRIPT, 1, lockKey, token);
    } catch {
      /* 锁会随 PX 到期，释放失败不致命 */
    }
  };

  const createLockHandle = (lockKey, token) => ({
    release: () => releaseLockSafely(lockKey, token),
  });

  // 锁令牌是"谁持有这把锁"的唯一凭据：释放脚本按字符串相等比较。
  // 原先用 Math.random()+Date.now() 拼——同一毫秒内启动的两个实例有可测的碰撞概率，
  // 碰撞后果是 B 的 release 删掉 A 的锁（A 还在临界区里）。改用 CSPRNG，成本为零。
  const newLockToken = () => crypto.randomBytes(16).toString('hex');

  // 分级规则（三处 catch 与 noOpLock 共用同一判据）：
  //  - 未配置 Redis = 单实例设计语义 ⇒ debug，且这是热路径，不能刷日志；
  //  - **已配置却拿不到结果**（连接不可用 / 命令报错）= 部署预期被打破 ⇒ warn。
  // 后一格原先记的是 debug：`acquireLock` 在 Redis 命令抛错时返回的是**无锁句柄**
  // （调用方以为自己持锁，跨实例互斥当场不成立），这是全局可见的行为差异，
  // 用 debug 等于在默认 LOG_LEVEL 下完全隐身——事故当天没人知道互斥已经没了。
  // 同文件 noOpLock 已经为"配了 REDIS_URL 但链路不可用"给出 warn，三条 catch 必须同口径。
  const noOpLock = (lockKey, configured) => {
    const line = `共享缓存锁退化为无锁语义（${lockKey} 的跨实例互斥当前不成立）`;
    if (configured) logger.warn(`${line}：已配置 REDIS_URL 但链路不可用`);
    else logger.debug(line);
    return { async release() {} };
  };

  const acquireLock = async (lockKey, ttlMs) => {
    if (!isRedisEnabled()) return noOpLock(lockKey, isRedisConfigured());
    const token = newLockToken();
    try {
      const ok = await getRedisClient().set(lockKey, token, 'PX', ttlMs, 'NX');
      return ok === 'OK' ? createLockHandle(lockKey, token) : null;
    } catch (error) {
      logger.warn(
        `共享缓存锁获取失败，本次退化为无锁语义（${lockKey} 的跨实例互斥当前不成立）：${errText(
          error
        )}`
      );
      return { async release() {} };
    }
  };

  const acquireLockBlocking = async (lockKey, ttlMs, waitTimeoutMs) => {
    if (!isRedisEnabled()) return null;
    const token = newLockToken();
    const deadline = Date.now() + waitTimeoutMs;
    const retryDelayMs = 50;
    const client = getRedisClient();

    for (;;) {
      let ok;
      try {
        ok = await client.set(lockKey, token, 'PX', ttlMs, 'NX');
      } catch (error) {
        logger.warn(
          `共享缓存阻塞锁获取失败，调用方将拿不到锁（本应串行的段落可能不串行）：${errText(error)}`
        );
        return null;
      }
      if (ok === 'OK') return createLockHandle(lockKey, token);
      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;
      await new Promise((resolve) => setTimeout(resolve, Math.min(retryDelayMs, remaining)));
    }
  };

  const casSet = async (key, expected, value) => {
    if (!isRedisEnabled()) return false;
    try {
      const result = await getRedisClient().eval(
        CAS_SET_SCRIPT,
        1,
        key,
        JSON.stringify(expected),
        JSON.stringify(value)
      );
      return result === 1;
    } catch (error) {
      logger.warn(`共享缓存 casSet 失败（Redis 侧异常，不是版本冲突）：${errText(error)}`);
      return false;
    }
  };

  return { acquireLock, acquireLockBlocking, casSet };
};

module.exports = { createLockOperations };
