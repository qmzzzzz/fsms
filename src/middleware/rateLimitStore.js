/**
 * 限流共享存储适配层
 *
 * 从 rateLimit.js 搬出：那个文件在体积棘轮（max-lines 300）的红线上，
 * 而存储适配与限流器定义是两件事——前者只认 store 接口，后者只认键与阈值。
 * 行为逐字节未动（搬运时做过 sha 对账）。
 */

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

/**
 * 限流存储工厂（R-3/M-1）
 *
 * 默认 MemoryStore 的计数是**每实例一份**：多副本 + 负载均衡时，
 * 同一客户端的配额在每个实例各算一遍，等效于把上限放大 N 倍，
 * 暴力破解防护与资源保护同时失真。
 *
 * 配置 REDIS_URL 时改用 rate-limit-redis（共享计数，跨实例一致）。
 * 本工厂**同步**返回一个符合 Store 接口的包装对象（express-rate-limit v7 在
 * parseOptions 里同步校验 store.increment/decrement/resetKey，不接受 Promise<Store>），
 * Redis 的准备与切换都发生在包装对象背后：启动时就绪 ⇒ 后台切换直接落到 RedisStore；
 * 启动时还没就绪 ⇒ 先按进程内 MemoryStore 计数，并在请求路径上持续探测，
 * Redis 一旦可用即自动切回共享计数（见 upgradeIfNeeded；不会等满一个窗口再不看）。
 *
 * 探测不是可选的：sharedCache 的 initSharedCache 是一次性的（initAttempted 闸门），
 * 但其 ioredis 客户端带 retryStrategy，晚起来的 Redis 之后仍会 ready
 * （其余 isRedisEnabled() 的调用方每次现读，所以会自愈）。本包装对象若只在
 * 挂载那一瞬间判一次，就会把"启动竞态"变成**永久**的每实例一份，
 * 而日志里随后出现的「Redis 已就绪：限流…进入跨实例一致模式」是假的。
 *
 * 未配置 REDIS_URL 时返回 undefined —— express-rate-limit 用默认
 * MemoryStore，本地开发/测试行为与历史完全一致。
 */
function makeSharedStore(prefix) {
  if (!(process.env.REDIS_URL || '').trim()) return undefined;
  // 同步返回一个符合 Store 接口的包装对象；后台异步初始化 Redis，
  // 就绪后自动切到 RedisStore，未就绪或失败时走 MemoryStore。
  // express-rate-limit v7.5.1 在 parseOptions 中同步校验
  // store.increment/decrement/resetKey，不接受 Promise<Store>。
  const fallback = new rateLimit.MemoryStore();
  let active = fallback;
  // 评价报告 #6：express-rate-limit 只在中间件挂载时同步调用一次 store.init，
  // 此刻异步切换尚未完成——原实现 init 固定绑在 fallback 上，切换到
  // RedisStore 后其 init 永远不会被调用，跨实例共享计数可能不生效。
  // 修复：init 动态分发到当前 active，并记录 options；RedisStore 就绪切换后
  // 显式补一次 init，保证共享存储完成与挂载期等价的初始化。
  let lastInitOptions = null;
  // 存储运行期异常只告警一次：降级后每个请求都会走到兜底分支，逐次告警会把日志刷满，
  // 而这条告警要传达的只是「共享计数已退化为进程内计数」这一个事实。
  let failureLogged = false;
  const noteStoreDegraded = (op, err) => {
    // 指标必须**每次**都发（计数器的价值在于速率，不是"发生过"）：
    // 降级态只写日志等于没有可告警信号——`grep 日志` 不是运维动作，
    // 而这条降级意味着限流配额在多副本下被放大 N 倍（暴力破解防护同时失真）。
    // 走 incSecurityAlert 与 checkIPBlacklist 的 ip_blacklist_failopen 同一机制，
    // 从而被 alert-rules 的「安全告警突增」（sum(increase(security_alerts_total[10m])) >= 10）
    // 一并覆盖，不需要新增规则。采集失败不影响降级主流程。
    try {
      require('../utils/metrics').incSecurityAlert('ratelimit_store_degraded', 'high');
    } catch (_) {
      /* 指标端不可用不影响限流降级 */
    }
    if (failureLogged) return;
    failureLogged = true;
    logger.warn(
      `限流共享存储运行期异常（${prefix}/${op}），已降级为进程内计数（多副本下等效放大）：${err.message}`
    );
  };
  /**
   * 恢复信号：降级标志必须**可复位**。
   *
   * 原实现只置位不复位 ⇒ 「打一次日志」在进程生命周期内只可能发生一次：
   * Redis 恢复后再次降级（第二次抖动）时日志与告警**都不再出现**，
   * 现场看起来"从没降级过"。指标侧因为每次都发所以仍可观测，但日志这条
   * 最直接的人工排障线索会永久沉默——这正是本仓反复出现的
   * 「一次性信号被当成持续信号」形态。
   */
  const noteStoreRecovered = () => {
    if (!failureLogged) return;
    failureLogged = false;
    logger.info(`限流共享存储已恢复（${prefix}）：共享计数重新生效`);
  };

  /**
   * 把 active 从进程内兜底换成 RedisStore（调用方已确认 Redis 可用）。
   * 全程同步（RedisStore 构造与 init 都不 await）⇒ 无需并发闸门：
   * 单线程内要么没换、要么换完，不会有两个请求各建一份 store。
   */
  const switchToRedis = () => {
    try {
      const { RedisStore } = require('rate-limit-redis');
      const client = require('../services/sharedCache').getRedisClient();
      const store = new RedisStore({
        sendCommand: (...args) => client.call(...args),
        prefix: `rl:${prefix}:`,
      });
      if (typeof store.init === 'function' && lastInitOptions) store.init(lastInitOptions);
      active = store;
      logger.info(`限流共享存储已切到 Redis（${prefix}），跨实例计数开始生效`);
    } catch (err) {
      // 建 store 失败：留在进程内计数，下一个请求再探（与"不做粘滞降级"同口径）
      noteStoreDegraded('upgrade', err);
    }
  };

  /** 请求路径上的补切换：仍是进程内 store 且 Redis 已可用才动手 */
  const upgradeIfNeeded = () => {
    if (active !== fallback) return;
    if (!require('../services/sharedCache').isRedisEnabled()) return;
    switchToRedis();
  };

  (async () => {
    const { initSharedCache, isRedisEnabled } = require('../services/sharedCache');
    await initSharedCache();
    if (isRedisEnabled()) {
      switchToRedis();
      return;
    }
    // 原实现在这里 `return`：一声不响地把限流永久绑成每实例一份
    logger.warn(
      `限流共享存储暂用进程内计数（${prefix}：REDIS_URL 已配置但 Redis 尚未就绪），` +
        `请求路径会持续探测，Redis 就绪后自动切回跨实例计数`
    );
  })().catch((err) => {
    logger.warn(`限流共享存储初始化失败（${prefix}），回退进程内计数：${err.message}`);
  });
  return {
    // 让这个包装对象如实申报自己的键前缀。
    // express-rate-limit 的 singleCount 校验用 `store.localKeys ? store : store.constructor.name`
    // 作为去重桶的键（index.cjs:232）——本包装对象没有 localKeys，于是 11 个 limiter 全部
    // 塌缩到同一个桶 "Object"；又不申报 prefix，则 :238 的比较值退化成裸 IP。
    // 结果：app.js 把 ipLimiter + generalLimiter 同时挂在 /api/ 上（两者键都是 IP）时，
    // 第二个 limiter 必然抛 ERR_ERL_DOUBLE_COUNT，每个 /api/ 请求打一段 error 级堆栈
    // （生产必须配 REDIS_URL，所以线上一直在刷）。计数本身并未互吃——各自闭包持有
    // fallback MemoryStore / 带独立前缀的 RedisStore；纯校验层误报。
    // 取值必须与内部 RedisStore 的前缀一致；该字段库内仅被 singleCount 读取，不参与计数。
    // 不要改 localKeys：它还参与 creationStack 判定（index.cjs:361）。
    prefix: `rl:${prefix}:`,
    // 运行期故障必须降级而不是把请求打死：express-rate-limit 的 passOnStoreError
    // 默认 false（index.cjs:671），store.increment 的 rejection 会在其内部被原样
    // 重新抛出（:715-726），而 ipLimiter / generalLimiter 挂在 `/api/` 上——
    // Redis 一次重启/抖动即全站 500。回落到进程内 MemoryStore 计数：
    // 宁可退回「每实例一份」的弱口径（多副本等效放大 N 倍），也不拿可用性换一致性。
    // 不做粘滞降级：active 仍是 RedisStore，Redis 恢复后下一个请求自动回到共享计数。
    async increment(...a) {
      try {
        upgradeIfNeeded();
        const r = await active.increment(...a);
        // 共享存储真的答上了 ⇒ 复位降级标志（见 noteStoreRecovered）
        if (active !== fallback) noteStoreRecovered();
        return r;
      } catch (err) {
        noteStoreDegraded('increment', err);
        return fallback.increment(...a);
      }
    },
    async decrement(...a) {
      try {
        upgradeIfNeeded();
        const r = await active.decrement(...a);
        if (active !== fallback) noteStoreRecovered();
        return r;
      } catch (err) {
        // skipSuccessfulRequests 的登录类限流器会在响应收尾时调到这里，
        // 那一路没有 express-rate-limit 的错误兜底，抛出去就是未处理拒绝
        noteStoreDegraded('decrement', err);
        return fallback.decrement(...a);
      }
    },
    async resetKey(...a) {
      return active.resetKey(...a);
    },
    async resetAll() {
      if (active.resetAll) return active.resetAll();
    },
    init(options) {
      lastInitOptions = options;
      if (active && typeof active.init === 'function') active.init(options);
    },
  };
}

/** 只导出工厂本身：各限流器在**模块加载期**调用它（一进程一份 store）。 */
module.exports = { makeSharedStore };
