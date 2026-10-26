/**
 * 认证用户本地缓存与失效广播（自 middleware/auth.js 抽出）
 *
 * 抽出的原因：tokenBlacklist 在吊销令牌后要失效 auth 的用户缓存，于是它反向
 * 引用 auth，而 auth 顶层又 require tokenBlacklist——两者互为惰性环。
 * 缓存与失效逻辑只依赖 logger / sharedCache / 权限服务，独立成叶子后
 * auth 与 tokenBlacklist 都单向引用本模块，环消失。
 *
 * 本文行为与抽取前逐字一致：本地热缓存 TTL 60 秒；失效事件经共享缓存广播跨实例
 * 传播（L-4）；配置 REDIS_URL 时任一实例禁用/锁定/改密后，所有实例立即标记本地
 * 条目失效；未配置时退化为单实例语义（最长 60 秒自然过期）。
 */

const logger = require('../utils/logger');
const sharedCache = require('../services/sharedCache');

const userCache = new Map(); // userId -> { user, expireAt, loadedAt, invalidatedAt }
const USER_CACHE_TTL = 60 * 1000;
const MAX_CACHE_SIZE = 1000; // 防止无限增长
// 失效广播键前缀：跨实例共用同一命名，收到即对该用户执行本地失效
const USER_CACHE_INVALIDATE_PREFIX = 'auth:user:';

/** 读一条缓存（调用方自行判断 expireAt / invalidatedAt） */
const getCacheEntry = (userId) => userCache.get(userId);

/**
 * 写一条缓存。
 *
 * 容量保护说明（与抽取前一致）：Map 的迭代顺序是**插入顺序**，而每次命中缓存
 * 并不重新 set，因此这里淘汰的是「最早写入的一半」而非 LRU 意义上的「最久未使用」。
 * 刻意不改成真 LRU：条目带 60s TTL，长期不用的条目本就会过期，
 * 而按插入序批量淘汰的实现更简单、无额外记账开销。
 */
const setCacheEntry = (userId, entry) => {
  if (userCache.size > MAX_CACHE_SIZE) {
    let deleted = 0;
    for (const key of userCache.keys()) {
      userCache.delete(key);
      if (++deleted >= MAX_CACHE_SIZE / 2) break;
    }
  }
  userCache.set(userId, entry);
};

const deleteCacheEntry = (userId) => userCache.delete(userId);

/**
 * 本地失效某个用户的缓存（改密、禁用、锁定时调用；
 * 也是收到其他实例失效广播时的执行路径）
 * 使用 invalidatedAt 时间戳来确保失效操作不会被后续的缓存更新覆盖
 */
const invalidateUserCacheLocal = (userId) => {
  const id = String(userId);
  const now = Date.now();
  const cached = userCache.get(id);

  if (cached) {
    // 只标记失效，不清除缓存条目，这样即使有竞态请求也不会重新填充有效数据
    cached.invalidatedAt = now;
  } else {
    // 如果没有缓存，创建一个失效标记，防止后续请求直接填充缓存
    userCache.set(id, {
      user: null,
      expireAt: now + USER_CACHE_TTL,
      loadedAt: 0,
      invalidatedAt: now,
    });
  }

  // 联动失效「权限结果缓存」（userPermissionService 的进程内 TTL 缓存，P-01 性能优化）。
  // 角色权限变更（assignPermissions）/ 用户角色变更（assignRoles）后必须立即失效，
  // 否则该用户仍会命中旧权限缓存最长 30 秒，导致权限调整延迟生效、存在安全窗口。
  // 惰性引入权限服务：本模块被 auth 与 tokenBlacklist 共同引用，不应把整个权限
  // 聚合查询链拉进加载期依赖。
  try {
    require('../services/userPermissionService').invalidatePermissionCache(id);
  } catch (err) {
    // 失效失败不应阻断主流程；权限缓存最多 30 秒后自然过期，仅记录告警
    logger.warn('权限缓存联动失效失败', { userId: id, error: err.message });
  }
};

// 订阅跨实例失效广播（L-4）：其他实例发布 'auth:user:<id>' 时，
// 本实例执行同一套本地失效。广播含自身发布（幂等，重复失效无副作用）。
// 未配置 REDIS_URL 时 onInvalidate 为空操作，行为与单实例历史一致。
sharedCache.onInvalidate((key) => {
  if (typeof key === 'string' && key.startsWith(USER_CACHE_INVALIDATE_PREFIX)) {
    invalidateUserCacheLocal(key.slice(USER_CACHE_INVALIDATE_PREFIX.length));
  }
});

/**
 * 主动失效某个用户的缓存（改密、禁用、锁定时调用）：
 * 先本地失效，再经共享缓存广播给其余实例。
 * 广播为尽力而为（内部吞错），失败时其余实例最长延迟至自然过期。
 *
 * publishInvalidate 是 async 而本函数是同步的：调用点（roleController / rolePermissionController /
 * initData）都不 await 本函数，所以那条 promise 必须由这里持有——本仓的 unhandledRejection
 * 兜底在所有环境都 process.exit(1)，一次无人持有的拒绝 = 全进程下线。
 * 判据：src/tests/services/observabilityWritesNeverReject.test.js
 */
const invalidateUserCache = (userId) => {
  invalidateUserCacheLocal(userId);
  sharedCache
    .publishInvalidate(USER_CACHE_INVALIDATE_PREFIX + String(userId))
    .catch((err) => logger.warn(`缓存失效广播异常（不阻断本次操作）：${err?.message ?? err}`));
};

/**
 * 定期清理过期缓存条目（每 30 秒）
 */
const cacheCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, value] of userCache.entries()) {
    if (value.expireAt <= now) {
      userCache.delete(key);
    }
  }
}, 30000);
cacheCleanupTimer.unref?.();

module.exports = {
  USER_CACHE_TTL,
  USER_CACHE_INVALIDATE_PREFIX,
  getCacheEntry,
  setCacheEntry,
  deleteCacheEntry,
  invalidateUserCacheLocal,
  invalidateUserCache,
};
