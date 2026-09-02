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

/** 是否启用 Redis 后端（供调用方做行为分支与启动日志） */
function isRedisEnabled() {
  return redisClient !== null && redisReady;
}

/** 取底层 ioredis 客户端（供 rate-limit-redis 等需要直发命令的适配器） */
function getRedisClient() {
  return redisClient;
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

/**
 * 分布式锁原子释放（compare-and-delete）：
 * 仅当锁仍由本 token 持有时才删除。避免「GET → DEL」两步之间锁恰好过期
 * 并被他人重新获取，导致误删他人之锁。对正确性关键路径（审计链互斥）必须原子。
 */
const LOCK_RELEASE_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

/**
 * 安全释放锁：token 匹配才删。释放失败不致命（锁会随 PX 到期）。
 * @param {string} lockKey
 * @param {string} token 获取时生成的持有者标识
 */
async function releaseLockSafely(lockKey, token) {
  try {
    await redisClient.eval(LOCK_RELEASE_SCRIPT, 1, lockKey, token);
  } catch (_) {
    /* 锁会随 PX 到期，释放失败不致命 */
  }
}

/**
 * 分布式互斥（A-1）：SET key token NX PX ttl。
 * 成功返回释放句柄；失败返回 null。释放用原子 CAS，防止误删他人之锁。
 * Redis 不可用时退化为「永远拿得到」——即调用方原有的进程内语义，
 * 不因缓存层故障把业务锁死。
 *
 * 注意：本函数**不阻塞等待**，锁被占用时立即返回 null。需要排队等待的
 * 调用方（如审计链串行化）请用 acquireLockBlocking。
 */
async function acquireLock(lockKey, ttlMs) {
  const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
  if (isRedisEnabled()) {
    try {
      const ok = await redisClient.set(lockKey, token, 'PX', ttlMs, 'NX');
      if (ok !== 'OK') return null;
      return {
        release: () => releaseLockSafely(lockKey, token),
      };
    } catch (err) {
      logger.debug(`共享缓存锁获取失败（退化为无锁语义）：${err.message}`);
    }
  }
  // 回退：调用方自身保留进程内锁语义，这里返回可释放的哑句柄
  return { async release() {} };
}

/**
 * 阻塞式分布式互斥（A-1 审计链专用）：在 waitTimeoutMs 内反复尝试
 * `SET key token NX PX ttl`，直到获取成功或超时。
 *
 * 与 acquireLock 的区别：锁被占用时**排队等待**而非立即放弃——
 * 审计链追加必须严格串行，拿不到锁时放行会造成链分叉，宁可等待。
 *
 * 返回值：
 *  - 获取成功：{ release }，release 用原子 CAS 防误删；
 *  - 超时未获取到：null（调用方应视为「临界区不可进入」，按超时路径处理）；
 *  - Redis 未启用：null（调用方应退回自身进程内锁语义）。
 *
 * @param {string} lockKey 锁键
 * @param {number} ttlMs 锁的自动过期（持有者崩溃后借此恢复，须大于临界区最坏耗时）
 * @param {number} waitTimeoutMs 获取等待上限，超时返回 null
 */
async function acquireLockBlocking(lockKey, ttlMs, waitTimeoutMs) {
  if (!isRedisEnabled()) return null;
  const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const deadline = Date.now() + waitTimeoutMs;
  const RETRY_DELAY_MS = 50;
  // 循环内命令失败即放弃（返回 null）：Redis 抖动期不阻塞审计链排队，
  // 交由调用方按超时/降级路径处理，避免无限重试拖住写入
  for (;;) {
    let ok;
    try {
      ok = await redisClient.set(lockKey, token, 'PX', ttlMs, 'NX');
    } catch (err) {
      logger.debug(`共享缓存阻塞锁获取失败：${err.message}`);
      return null;
    }
    if (ok === 'OK') {
      return { release: () => releaseLockSafely(lockKey, token) };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) return null;
    await new Promise((r) => setTimeout(r, Math.min(RETRY_DELAY_MS, remaining)));
  }
}

/**
 * 原子 compare-and-set 的 Lua 脚本（A-1）：仅当键当前值（JSON 序列化字节）
 * 等于 expected 时才写入 value。与 LOCK_RELEASE_SCRIPT 同类——用服务端脚本
 * 避免「GET → SET」两步之间被其他实例推进链尾的竞态。
 * 链尾是长期状态，写入不带 TTL（普通 set，非 PX）。
 */
const CAS_SET_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  redis.call("set", KEYS[1], ARGV[2])
  return 1
else
  return 0
end
`;

/**
 * 原子 compare-and-set：仅当键当前值（JSON 序列化口径）等于 expected 时，
 * 才写入 value，返回是否写入成功。
 *
 * 用于审计链分布式模式下的链尾回滚（A-1）：回滚发生在锁外（save 失败钩子），
 * 若直接 SET 可能覆盖其他实例刚推进的链尾；CAS 保证「仍是期望尾才回滚」。
 * 与 set/get 同一 JSON 序列化口径，比较的是序列化后的字节。
 *
 * @param {string} key
 * @param {*} expected 期望的当前值（按 JSON 序列化后比较）
 * @param {*} value 新值
 * @returns {Promise<boolean>} 是否成功写入
 */
async function casSet(key, expected, value) {
  if (!isRedisEnabled()) return false;
  try {
    const r = await redisClient.eval(
      CAS_SET_SCRIPT,
      1,
      key,
      JSON.stringify(expected),
      JSON.stringify(value)
    );
    return r === 1;
  } catch (err) {
    logger.debug(`共享缓存 casSet 失败：${err.message}`);
    return false;
  }
}

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
  incrWithTtl,
  setIfAbsent,
  acquireLock,
  acquireLockBlocking,
  casSet,
  onInvalidate,
  publishInvalidate,
  _resetForTests,
};
