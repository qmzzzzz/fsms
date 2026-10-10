/**
 * 统计缓存模块
 * 基于内存 Map、带 TTL 的进程内缓存，为 /api/users/stats 提供缓存底座。
 * 提供 get / set / del / invalidateByUserId 四个操作，任何内部异常均降级为
 * { hit: false }，让调用方走直接查库路径，保证可用性优先。
 */

const config = require('../config');
const logger = require('../utils/logger');
// 跨实例失效广播通道（sharedCache 仅依赖 logger，顶层引入无环路）
const sharedCache = require('./sharedCache');

// 底层存储：key -> { data, expireAt }
const store = new Map();
// 最近访问时间（用于超过上限时清除最旧条目）
const lastAccess = new Map();

let cleanupTimer = null;

/**
 * 陈旧窗口的上界（秒）。
 *
 * 存在的理由不是"防呆"，而是这条链路里唯一真实存在的防线：`STATS_CACHE_TTL` 只校验
 * "有限正数"（src/config/index.js 的 statsCacheTtl），配成一年也不会被拒；而那句
 * 用来给长 TTL 背书的注释——"写路径已有 invalidateByUserId 主动失效"——按现网键形
 * 并不成立。缓存键是 `stats:{查看者id}:{范围摘要}`（controllers/userController.js:993），
 * 失效只删 `stats:{被改用户id}:` 前缀（本文件 invalidateByUserIdLocal）⇒ 除了被改者
 * 本人以外，其他管理员的桶一条都删不掉；公开注册与角色改名更是根本不触达失效。
 * 也就是说：多数情况下"多久变新"完全由 TTL 决定，所以 TTL 必须有界。
 * 上界取 3600 秒：派生统计在 1 小时内不可见变化已经是可感知的口径漂移，再长就是
 * 把缓存当成快照，而它没有任何版本号能保证一致性。
 */
const MAX_TTL_SECONDS = 3600;

const clampTtlSeconds = (seconds, source) => {
  if (seconds <= MAX_TTL_SECONDS) return seconds;
  // 只写一次性的、可定位的留痕：运维必须能在日志里看到"你配的值没生效"，
  // 否则他以为配的是 1 年，实际是 1 小时——这类静默夹取正是本仓反复要防的形态
  logger.warn(
    `统计缓存 TTL 被夹到上界 ${MAX_TTL_SECONDS} 秒（请求值 ${seconds} 秒，来源 ${source}）；` +
      '失效广播按查看者键前缀匹配，覆盖不到其他查看者，因此不能让 TTL 充当无限期的快照'
  );
  return MAX_TTL_SECONDS;
};

// 配置默认值在模块加载时就定死：每次 set 都 warn 会变成刷屏
// （config.cache.statsCacheTtl 侧已保证"有限正数否则回落 300"，这里只负责上界）
const configTtlSeconds = clampTtlSeconds(config.cache.statsCacheTtl, 'STATS_CACHE_TTL');

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
 * @param {number} [ttl] 过期时间（秒），缺省使用 config.cache.statsCacheTtl；
 *   两条来源都要过 MAX_TTL_SECONDS 上界（见文件头说明），调用方也不能自行放大陈旧窗口
 */
function set(cacheKey, data, ttl) {
  try {
    const ttlSeconds =
      Number.isFinite(ttl) && ttl > 0 ? clampTtlSeconds(ttl, '调用方传入的 ttl') : configTtlSeconds;
    const ttlMs = ttlSeconds * 1000;
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
 * 使指定用户的所有统计缓存失效（本地，前缀匹配 stats:{userId}:）
 * @param {string} userId 用户 ID
 */
function invalidateByUserIdLocal(userId) {
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
 * 跨实例失效广播（同型问题）：store 是进程内 Map，
 * 其它副本上的 `stats:{userId}:…` 不会因本副本的失效而消失，
 * 只能等 TTL 自然过期——期间删除/改权限后的聚合数字在另一个副本上仍是旧的。
 * 影响面是"陈旧计数"而非跨租户读取（键里含操作者本人 id），
 * 但权限缓存与用户缓存都接了广播，这里补齐同一口径。
 * 未配置 REDIS_URL 时发布为无操作，退化为单进程语义。
 */
const STATS_INVAL_PREFIX = 'statscache:';

function invalidateByUserId(userId) {
  invalidateByUserIdLocal(userId);
  sharedCache.publishInvalidate(`${STATS_INVAL_PREFIX}${userId}`).catch(() => {
    /* 发布失败退化为自然过期，不阻断主流程 */
  });
}

function handleRemoteStatsInvalidation(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(STATS_INVAL_PREFIX)) return;
  invalidateByUserIdLocal(raw.slice(STATS_INVAL_PREFIX.length));
}

sharedCache.onInvalidate(handleRemoteStatsInvalidation);

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
// 兼容性：get() 只清理**它自己访问到的那个键**（命中过期即删除），并不会调用
// sweepExpired。因此未启动定时器时，除被读取到的键以外，其余过期条目会一直滞留
// 到容量上限触发整体淘汰为止（有界，非泄漏）。
//
// L-17 修正：原注释称"sweepExpired 也在 get() 的惰性路径上被调用"，与实现不符
// （get() 内无该调用）。此处改为如实描述，避免维护者据此认为"不启动定时器也无妨"。

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
