/**
 * 共享缓存 · 失效广播（L-4，2026-10-19 批 3c 自 services/sharedCache.js 拆出）
 *
 * ioredis 订阅模式连接不能再执行普通命令，故订阅端单独建连（subClient）；
 * 未配置 Redis 时整套广播为无操作。发布走读写连接（state.redisClient），
 * 发布者不必同时是订阅者。本模块不是公开 API；对外导出面仍由 index.js 承担。
 */

const logger = require('../../utils/logger');
const { state, isRedisEnabled, isRedisConfigured, redisConnectionPassword } = require('./state');

// 失效广播（L-4）：ioredis 订阅模式连接不能再执行普通命令，
// 故订阅端必须单独建连；未配置 Redis 时整套广播为无操作
let subClient = null;
const INVAL_CHANNEL = 'xf:cache:invalidate';
const invalidationHandlers = new Set();

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
      password: redisConnectionPassword(),
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
 *
 * F-205：但「没配 Redis」与「配了 Redis 而它此刻不可用」不是同一件事。后者这一次
 * 广播确实丢了（其余实例上的权限/会话/统计缓存要等到自然过期才失效，30s~60s 量级），
 * 原实现在这条路径上连一行日志都不留——事故当天只能从"权限收回后还能放行"反推。
 * 读写命令失败那一路径本来就 warn（下面的 catch），缺的正是"根本没发出去"这一路。
 */
async function publishInvalidate(key) {
  if (!isRedisEnabled()) {
    if (isRedisConfigured()) {
      logger.warn(
        `缓存失效广播未发出（Redis 已配置但当前不可用），其余实例的该键将延迟至自然过期：${key}`
      );
    }
    return;
  }
  try {
    await state.redisClient.publish(INVAL_CHANNEL, key);
  } catch (err) {
    // 本函数被 middleware/auth.js 的 invalidateUserCache **裸调用**（不 await），
    // 所以"内部吞错"是硬契约：catch 体自己不能抛。
    // `${err.message}` 在被 reject(undefined/字符串) 时会抛 TypeError ⇒ 契约破 ⇒ 全进程下线。
    logger.warn(`缓存失效广播发布失败（其余实例最长延迟至自然过期）：${err?.message ?? err}`);
  }
}

/** 优雅关闭订阅连接（供 index 的 shutdownSharedCache 调用） */
async function shutdownInvalidation() {
  invalidationHandlers.clear();
  if (subClient) {
    try {
      await subClient.quit();
    } catch (_) {
      subClient.disconnect?.();
    }
    subClient = null;
  }
}

/** 测试钩子：断开订阅连接并清空回调（供 index 的 _resetForTests 调用） */
function resetInvalidation() {
  if (subClient) {
    subClient.disconnect?.();
  }
  subClient = null;
  invalidationHandlers.clear();
}

module.exports = {
  ensureSubscriber,
  onInvalidate,
  publishInvalidate,
  shutdownInvalidation,
  resetInvalidation,
};
