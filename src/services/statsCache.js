/**
 * 统计缓存模块
 * 基于内存 Map、带 TTL 的进程内缓存，为 /api/users/stats 提供缓存底座。
 * 提供 get / set / del / invalidateByUserId 四个操作，任何内部异常均降级为
 * { hit: false }，让调用方走直接查库路径，保证可用性优先。
 */

const config = require('../config');
const logger = require('../utils/logger');

// 底层存储：key -> { data, expireAt }
const store = new Map();
// 最近访问时间（用于超过上限时清除最旧条目）
const lastAccess = new Map();

let cleanupTimer = null;

/**
 * 读取缓存
 * @param {string} cacheKey 缓存键
 * @returns {{ hit: boolean, data?: object }}
 */
function get(cacheKey) {
  try {
    const entry = store.get(cacheKey);
    if (!entry) {
      logger.debug(`统计缓存未命中: ${cacheKey}`);
      return { hit: false };
    }
    if (Date.now() > entry.expireAt) {
      store.delete(cacheKey);
      lastAccess.delete(cacheKey);
      logger.debug(`统计缓存已过期: ${cacheKey}`);
      return { hit: false };
    }
    lastAccess.set(cacheKey, Date.now());
    logger.debug(`统计缓存命中: ${cacheKey}, 剩余TTL=${entry.expireAt - Date.now()}ms`);
    return { hit: true, data: entry.data };
  } catch (err) {
    logger.warn(`统计缓存读取异常，降级为直查数据库: ${err.message}`);
    return { hit: false };
  }
}

/**
 * 写入缓存
 * @param {string} cacheKey 缓存键
 * @param {object} data 缓存数据
 * @param {number} [ttl] 过期时间（秒），缺省使用 config.cache.statsCacheTtl
 */
function set(cacheKey, data, ttl) {
  try {
    const ttlMs = Number.isFinite(ttl) && ttl > 0 ? ttl * 1000 : config.cache.statsCacheTtl * 1000;
    // P3-23：写入路径上做容量兜底。定时清理改为显式启动（不再模块加载即启动），
    // 若调用方忘记 startCleanup()，仅靠 get() 的惰性过期无法回收「写入后再没被
    // 读取过」的键——那类键会永久滞留。此处在越界时同步触发一次清理。
    if (store.size >= config.cache.statsCacheMaxSize) sweepExpired();
    store.set(cacheKey, { data, expireAt: Date.now() + ttlMs });
    lastAccess.set(cacheKey, Date.now());
    logger.debug(`统计缓存写入: ${cacheKey}, TTL=${ttlMs}ms`);
  } catch (err) {
    logger.warn(`统计缓存写入异常，忽略: ${err.message}`);
  }
}

/**
 * 删除单条缓存
 * @param {string} cacheKey 缓存键
 */
function del(cacheKey) {
  try {
    store.delete(cacheKey);
    lastAccess.delete(cacheKey);
  } catch (err) {
    logger.warn(`统计缓存删除异常: ${err.message}`);
  }
}

/**
 * 使指定用户的所有统计缓存失效（前缀匹配 stats:{userId}:）
 * @param {string} userId 用户 ID
 */
function invalidateByUserId(userId) {
  try {
    const escapedPrefix = `stats:${userId}:`;
    let removed = 0;
    for (const key of store.keys()) {
      if (key.startsWith(escapedPrefix)) {
        store.delete(key);
        lastAccess.delete(key);
        removed += 1;
      }
    }
    logger.info('统计缓存失效', { userId, removed });
  } catch (err) {
    logger.warn(`统计缓存失效异常: ${err.message}`);
  }
}

/**
 * 清理过期条目；条目数超过上限时清除最旧 50%
 */
function sweepExpired() {
  try {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (entry.expireAt <= now) {
        store.delete(key);
        lastAccess.delete(key);
      }
    }
    if (store.size > config.cache.statsCacheMaxSize) {
      const removeCount = Math.max(
        store.size - config.cache.statsCacheMaxSize,
        Math.floor(config.cache.statsCacheMaxSize * 0.5)
      );
      const sortedKeys = [...lastAccess.entries()]
        .sort((a, b) => a[1] - b[1])
        .slice(0, removeCount)
        .map(([key]) => key);
      for (const key of sortedKeys) {
        store.delete(key);
        lastAccess.delete(key);
      }
      logger.warn(
        `统计缓存超过上限(${config.cache.statsCacheMaxSize})，清除最旧${sortedKeys.length}条`
      );
    }
  } catch (err) {
    logger.warn(`统计缓存清理异常: ${err.message}`);
  }
}

/**
 * 启动定时清理
 */
function startCleanup() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(sweepExpired, config.cache.statsCacheCleanupInterval);
  // 不阻塞 Node 进程退出（测试环境尤其需要）
  if (cleanupTimer && cleanupTimer.unref) cleanupTimer.unref();
}

/**
 * 停止定时清理（用于测试收尾）
 */
function stopCleanup() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

// P3-23：不在模块加载期启动定时器。
// 本仓库对其余后台任务（auditBuffer / auditMonitor / reminderScheduler /
// alertCleanup / captchaCleanup）一律采用「index.js 显式 start()」模式，
// 唯独此处 require 即副作用——测试、脚本、CLI 工具只要 require 到任何
// 间接依赖本模块的文件就会凭空多出一个定时器，且与 gracefulShutdown 的
// 停止序列脱节。改为由 index.js 与其余任务一同显式启动。
//
// 兼容性：sweepExpired 也在 get() 的惰性路径上被调用（见文件上方），
// 未启动定时器时缓存仍会在读取时清理过期项，只是没有周期性主动回收。

module.exports = {
  get,
  set,
  del,
  invalidateByUserId,
  sweepExpired,
  startCleanup,
  stopCleanup,
  // 仅供测试/调试访问
  _store: store,
};
