/**
 * SharedCache 分布式锁与 CAS 原子操作：集中封装 Redis 原子脚本和退避语义。
 */

const logger = require('../utils/logger');

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

const createLockOperations = ({ getRedisClient, isRedisEnabled }) => {
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

  const acquireLock = async (lockKey, ttlMs) => {
    if (!isRedisEnabled()) return { async release() {} };
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    try {
      const ok = await getRedisClient().set(lockKey, token, 'PX', ttlMs, 'NX');
      return ok === 'OK' ? createLockHandle(lockKey, token) : null;
    } catch (error) {
      logger.debug(`共享缓存锁获取失败（退化为无锁语义）：${error.message}`);
      return { async release() {} };
    }
  };

  const acquireLockBlocking = async (lockKey, ttlMs, waitTimeoutMs) => {
    if (!isRedisEnabled()) return null;
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const deadline = Date.now() + waitTimeoutMs;
    const retryDelayMs = 50;
    const client = getRedisClient();

    for (;;) {
      let ok;
      try {
        ok = await client.set(lockKey, token, 'PX', ttlMs, 'NX');
      } catch (error) {
        logger.debug(`共享缓存阻塞锁获取失败：${error.message}`);
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
      logger.debug(`共享缓存 casSet 失败：${error.message}`);
      return false;
    }
  };

  return { acquireLock, acquireLockBlocking, casSet };
};

module.exports = { createLockOperations };
