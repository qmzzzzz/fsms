/**
 * 共享缓存门面（R-3/M-1 基础设施）
 *
 * 问题：限流计数、验证码、权限缓存、审计链锁等关键状态全是进程内内存态，
 * 多副本部署时各实例状态互不可见——限流配额翻倍、验证码跨实例校验失败、
 * 权限失效不跨实例传播。
 *
 * 解法：统一经本门面读写。配置 `REDIS_URL` 时走 Redis（跨实例一致）；
 * 未配置时自动回退到进程内内存实现（单机/开发/测试零配置照旧可用）。
 * 两种后端对外同一套异步 API，调用方无需感知部署形态。
 *
 * 为什么回退而不是报错：本仓库测试与本地开发不依赖 Redis，
 * 强制依赖会让 1000+ 用例与单机部署全部无法启动；多实例是**部署选择**，
 * 该由部署侧显式提供 REDIS_URL，而不是由代码强制。
 *
 * O-15（TTL 抖动与穿透防护）也在本层统一提供：
 * - jitterTtl：所有建议走此函数的 TTL 附加 ±10% 随机抖动，
 *   避免大批键同一时刻过期引发的缓存雪崩；
 * - EMPTY_SENTINEL：空结果哨兵值，调用方可缓存「查无结果」防穿透。
 */

const logger = require('../utils/logger');
const { createLockOperations } = require('./sharedCacheLocks');

/** 空结果哨兵：缓存「查无此物」防止同键反复打穿到数据库（穿透防护） */
const EMPTY_SENTINEL = '__shared_cache_empty__';

let redisClient = null; // ioredis 实例（未启用为 null）
let redisReady = false; // 连接就绪标记（未就绪期间自动走内存回退）
let initAttempted = false;

// 失效广播（L-4）：ioredis 订阅模式连接不能再执行普通命令，
// 故订阅端必须单独建连；未配置 Redis 时整套广播为无操作
let subClient = null;
const INVAL_CHANNEL = 'xf:cache:invalidate';
const invalidationHandlers = new Set();

// 内存回退存储：key -> { value, expireAt }
const memStore = new Map();
let memCleanupTimer = null;

function isRedisEnabled() {
  return redisClient !== null && redisReady;
}

function getRedisClient() {
  return redisClient;
}

const lockOperations = createLockOperations({ getRedisClient, isRedisEnabled });

// S-L2（改后审计）：内存回退存储硬上限——Redis 未配置时 nonce 防重放表等
// 可能被分布式来源推高（对照 alertRateLimit 的 P3-24 同类防护）。
// 超限先清过期，仍超则按插入序淘汰最旧：淘汰命中限流计数器仅重置该键窗口，
// 由 express-rate-limit 内存限流器兜底，可接受。env 可调，默认 2 万条。
const getMemStoreMax = () => Math.max(1000, Number(process.env.SHARED_CACHE_MEM_MAX) || 20000);

function enforceMemCap() {
  if (memStore.size <= getMemStoreMax()) return;
  memSweep();
  while (memStore.size > getMemStoreMax()) {
    memStore.delete(memStore.keys().next().value); // Map 插入序 = 最旧优先
  }
}

/**
 * TTL 抖动：±10% 随机（O-15）。
 * 固定 TTL 的大批缓存键会在同一时刻集体过期，下一波请求同时打穿到
 * 数据库（缓存雪崩的理论面）。抖动把过期点摊开，成本为零。
 * @param {number} ttlMs 基准毫秒
 * @returns {number} 抖动后的毫秒
 */
function jitterTtl(ttlMs) {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) return ttlMs;
  const jitter = Math.floor(ttlMs * 0.1 * (Math.random() * 2 - 1));
  return Math.max(1, ttlMs + jitter);
}

function memSweep() {
  const now = Date.now();
  for (const [key, entry] of memStore) {
    if (entry.expireAt <= now) memStore.delete(key);
  }
}

function ensureMemCleanup() {
  if (memCleanupTimer) return;
  memCleanupTimer = setInterval(memSweep, 60 * 1000);
  memCleanupTimer.unref?.();
}

/**
 * 初始化：读取 REDIS_URL（支持 *_FILE 注入）并尝试建立连接。
 * 惰性连接 + 失败回退：Redis 不可达不阻断服务启动，降级为单实例语义并告警。
 */
async function initSharedCache() {
  if (initAttempted) return;
  initAttempted = true;

  const url = (process.env.REDIS_URL || '').trim();
  if (!url) return;

  try {
    const Redis = require('ioredis');
    redisClient = new Redis(url, {
      lazyConnect: false,
      maxRetriesPerRequest: 1, // 缓存场景快速失败，回退内存，不拖住请求
      enableOfflineQueue: false,
      retryStrategy: (times) => Math.min(times * 500, 10000),
    });
    redisClient.on('error', (err) => {
      if (redisReady) logger.warn(`共享缓存 Redis 连接异常，暂回退内存态：${err.message}`);
      redisReady = false;
    });
    redisClient.on('ready', () => {
      if (!redisReady) logger.info('共享缓存 Redis 已就绪：限流/验证码/权限缓存进入跨实例一致模式');
      redisReady = true;
      ensureSubscriber();
    });
    await redisClient.ping();
    redisReady = true;
    ensureSubscriber();
  } catch (err) {
    redisReady = false;
    logger.warn(
      `REDIS_URL 已配置但连接失败，回退进程内内存态（多实例部署将状态不一致）：${err.message}`
    );
  }
}

/** 序列化写入（值需可 JSON 化）；ttlMs 缺省视为不过期（慎用） */
async function set(key, value, ttlMs) {
  const payload = JSON.stringify(value);
  if (isRedisEnabled()) {
    try {
      if (Number.isFinite(ttlMs) && ttlMs > 0) {
        await redisClient.set(key, payload, 'PX', ttlMs);
      } else {
        await redisClient.set(key, payload);
      }
      return;
    } catch (err) {
      logger.debug(`共享缓存 set 失败（回退内存）：${err.message}`);
    }
  }
  ensureMemCleanup();
  enforceMemCap();
  memStore.set(key, {
    value,
    expireAt: Number.isFinite(ttlMs) && ttlMs > 0 ? Date.now() + ttlMs : Infinity,
  });
}

/** 读取；不存在或已过期返回 null */
async function get(key) {
  if (isRedisEnabled()) {
    try {
      const raw = await redisClient.get(key);
      return raw === null ? null : JSON.parse(raw);
    } catch (err) {
      logger.debug(`共享缓存 get 失败（回退内存）：${err.message}`);
    }
  }
  const entry = memStore.get(key);
  if (!entry) return null;
  if (entry.expireAt <= Date.now()) {
    memStore.delete(key);
    return null;
  }
  return entry.value;
}

/** 删除；返回是否删除了存在的键 */
async function del(key) {
  if (isRedisEnabled()) {
    try {
      return (await redisClient.del(key)) > 0;
    } catch (err) {
      logger.debug(`共享缓存 del 失败（回退内存）：${err.message}`);
    }
  }
  return memStore.delete(key);
}

/**
 * 原子取删（评价报告低危项：验证码 get→del 两步在并发下可双花）。
 * Redis ≥6.2 走 GETDEL（compose 钉 redis:7）；命令不可用时降级为
 * get→del 的旧两步语义（可用性优先，调用方可接受极小双花窗口）。
 * 内存回退路径本身是同步取删，天然原子。
 * @returns {Promise<{value:*|null}>|Promise<*|null>} 取出的值，不存在/已过期返回 null
 */
async function getDel(key) {
  if (isRedisEnabled()) {
    try {
      const raw = await redisClient.getdel(key);
      return raw === null ? null : JSON.parse(raw);
    } catch (err) {
      logger.debug(`共享缓存 getdel 失败（降级 get+del）：${err.message}`);
      try {
        const value = await get(key);
        await del(key);
        return value;
      } catch (_) {
        return null;
      }
    }
  }
  const entry = memStore.get(key);
  if (!entry) return null;
  memStore.delete(key);
  if (entry.expireAt <= Date.now()) return null;
  return entry.value;
}

/**
 * 原子自增 + 首设过期（限流计数类用途）。
 * @returns {number} 自增后的值
 */
async function incrWithTtl(key, ttlMs) {
  if (isRedisEnabled()) {
    try {
      const value = await redisClient.incr(key);
      if (value === 1 && Number.isFinite(ttlMs) && ttlMs > 0) {
        await redisClient.pexpire(key, ttlMs);
      }
      return value;
    } catch (err) {
      logger.debug(`共享缓存 incr 失败（回退内存）：${err.message}`);
    }
  }
  ensureMemCleanup();
  enforceMemCap();
  const entry = memStore.get(key);
  const now = Date.now();
  if (!entry || entry.expireAt <= now) {
    memStore.set(key, {
      value: 1,
      expireAt: Number.isFinite(ttlMs) && ttlMs > 0 ? now + ttlMs : Infinity,
    });
    return 1;
  }
  entry.value += 1;
  return entry.value;
}

const { acquireLock, acquireLockBlocking, casSet } = lockOperations;

/**
 * 原子占位（仅当键不存在时写入，带 TTL）。
 * 登录防重放 nonce 的一次性消费：返回 true=首次见到，false=重复。
 *
 * 回退语义刻意 fail-closed：Redis 已配置但命令失败时返回 false（按重复处理，
 * 拒绝本次请求）而非落内存放行——「可能放行一条重放」比「抖动期拒绝一次合法
 * 登录」危害大，且合法请求重试时会携带新的随机 nonce 自然恢复。
 * @returns {Promise<boolean>}
 */
async function setIfAbsent(key, value, ttlMs) {
  if (isRedisEnabled()) {
    try {
      const ok = await redisClient.set(key, JSON.stringify(value), 'PX', ttlMs, 'NX');
      return ok === 'OK';
    } catch (err) {
      logger.debug(`共享缓存 setIfAbsent 失败（按重复处理）：${err.message}`);
      return false;
    }
  }
  ensureMemCleanup();
  enforceMemCap();
  const entry = memStore.get(key);
  if (entry && entry.expireAt > Date.now()) return false;
  memStore.set(key, {
    value,
    expireAt: Number.isFinite(ttlMs) && ttlMs > 0 ? Date.now() + ttlMs : Infinity,
  });
  return true;
}

/**
 * 建立失效广播的订阅连接（独立于读写连接：ioredis 订阅模式禁用普通命令）。
 * 订阅失败不影响主链路——广播缺失时各实例缓存退化为「最长自然过期」语义。
 */
async function ensureSubscriber() {
  if (subClient || !isRedisEnabled()) return;
  try {
    const Redis = require('ioredis');
    const url = (process.env.REDIS_URL || '').trim();
    subClient = new Redis(url, {
      lazyConnect: false,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: true,
      retryStrategy: (times) => Math.min(times * 500, 10000),
    });
    subClient.on('error', (err) => {
      logger.debug(`共享缓存失效广播订阅连接异常：${err.message}`);
    });
    subClient.on('message', (channel, raw) => {
      if (channel !== INVAL_CHANNEL) return;
      for (const handler of invalidationHandlers) {
        try {
          handler(raw);
        } catch (err) {
          logger.warn(`缓存失效广播处理异常（key=${raw}）：${err.message}`);
        }
      }
    });
    await subClient.subscribe(INVAL_CHANNEL);
    logger.info('共享缓存失效广播订阅就绪：用户/权限缓存失效进入跨实例传播模式');
  } catch (err) {
    try {
      subClient.disconnect();
    } catch (_) {
      /* 连接可能已断 */
    }
    subClient = null;
    logger.warn(`共享缓存失效广播订阅失败（缓存失效退化为单实例语义）：${err.message}`);
  }
}

/**
 * 注册远端失效回调（收到其他实例广播的失效键时执行本地失效）。
 * @param {(key: string) => void} handler
 * @returns {() => void} 注销函数
 */
function onInvalidate(handler) {
  invalidationHandlers.add(handler);
  ensureSubscriber();
  return () => invalidationHandlers.delete(handler);
}

/**
 * 广播一个失效键给所有实例（含自身，本地幂等失效无副作用）。
 * 未启用 Redis 或订阅不可用时静默跳过——单实例部署本就无需跨进程失效。
 * 发布走读写连接，不依赖 subReady（发布者不必同时是订阅者）。
 */
async function publishInvalidate(key) {
  if (!isRedisEnabled()) return;
  try {
    await redisClient.publish(INVAL_CHANNEL, key);
  } catch (err) {
    logger.warn(`缓存失效广播发布失败（其余实例最长延迟至自然过期）：${err.message}`);
  }
}

/** 优雅关闭（供进程退出钩子） */
async function shutdownSharedCache() {
  if (memCleanupTimer) {
    clearInterval(memCleanupTimer);
    memCleanupTimer = null;
  }
  memStore.clear();
  invalidationHandlers.clear();
  if (subClient) {
    try {
      await subClient.quit();
    } catch (_) {
      subClient.disconnect?.();
    }
    subClient = null;
  }
  if (redisClient) {
    try {
      await redisClient.quit();
    } catch (_) {
      redisClient.disconnect?.();
    }
    redisClient = null;
    redisReady = false;
  }
  initAttempted = false;
}

/** 测试钩子：重置到未初始化状态 */
function _resetForTests() {
  if (subClient) {
    subClient.disconnect?.();
  }
  subClient = null;
  invalidationHandlers.clear();
  if (redisClient) {
    redisClient.disconnect?.();
  }
  redisClient = null;
  redisReady = false;
  initAttempted = false;
  memStore.clear();
  if (memCleanupTimer) {
    clearInterval(memCleanupTimer);
    memCleanupTimer = null;
  }
}

module.exports = {
  EMPTY_SENTINEL,
  isRedisEnabled,
  getRedisClient,
  jitterTtl,
  initSharedCache,
  shutdownSharedCache,
  set,
  get,
  del,
  getDel,
  incrWithTtl,
  setIfAbsent,
  acquireLock,
  acquireLockBlocking,
  casSet,
  onInvalidate,
  publishInvalidate,
  _resetForTests,
};
