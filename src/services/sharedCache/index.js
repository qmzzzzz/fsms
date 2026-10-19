/**
 * 共享缓存门面（R-3/M-1 基础设施；2026-10-19 批 3c 自 services/sharedCache.js 拆分）
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
 *
 * 拆分说明（2026-10-19，max-lines）：原文件 409 代码行。按职责切三块——
 * state.js（Redis 连接态与判据）、memoryStore.js（内存回退存储/容量收口/
 * 降级留痕）、invalidation.js（L-4 失效广播）；本文件保留门面与核心读写
 * （set/get/del/getDel/incrWithTtl/setIfAbsent）及锁装配。对外导出面逐字同序，
 * `require('./sharedCache')` 的调用方无需改动。
 */

const logger = require('../../utils/logger');
const { createLockOperations } = require('../sharedCacheLocks');
const { state, isRedisEnabled, isRedisConfigured, redisConnectionPassword } = require('./state');
const {
  memStore,
  enforceMemCap,
  ensureMemCleanup,
  warnIncrDegraded,
  resetMemoryFallback,
} = require('./memoryStore');
const {
  ensureSubscriber,
  onInvalidate,
  publishInvalidate,
  shutdownInvalidation,
  resetInvalidation,
} = require('./invalidation');

/** 空结果哨兵：缓存「查无此物」防止同键反复打穿到数据库（穿透防护） */
const EMPTY_SENTINEL = '__shared_cache_empty__';

function getRedisClient() {
  return state.redisClient;
}

const lockOperations = createLockOperations({
  getRedisClient,
  isRedisEnabled,
  isRedisConfigured,
});

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

/**
 * 初始化：读取 REDIS_URL（支持 *_FILE 注入）并尝试建立连接。
 * 惰性连接 + 失败回退：Redis 不可达不阻断服务启动，降级为单实例语义并告警。
 */
/**
 * Redis 从"就绪"跌回"不可用"时，把**具体哪些机制**失去跨实例一致性说清楚。
 *
 * 为什么需要：`constants/runtime.js` 的启动期拓扑校验只在启动时说话一次。
 * 多实例 + Redis 的部署在启动时拿到的是"一切正常"的结论；之后 Redis 抖一下，
 * 审计链锁/链尾、限流配额、权限缓存失效广播、验证码一次性消费就**静默**退回
 * 进程内语义——正是启动校验要防的那件事，却发生在"已经说过没问题"之后。
 * 降级这一刻必须自带失效清单，而不是等运维从审计链分叉或 429 消失里反推。
 *
 * 懒加载以避免与 constants/runtime 形成加载期循环（该模块在函数内反向 require 本模块）。
 */
function degradedMechanismHint() {
  try {
    const { SINGLE_PROCESS_DEPENDENCIES } = require('../../constants/runtime');
    const list = SINGLE_PROCESS_DEPENDENCIES.filter((d) => d.redisExternalized).map(
      (d) => `${d.module}（${d.impact}）`
    );
    return list.length ? `以下机制退回进程内语义：${list.join('；')}` : '';
  } catch {
    return '';
  }
}

async function initSharedCache() {
  if (state.initAttempted) return;
  state.initAttempted = true;

  const url = (process.env.REDIS_URL || '').trim();
  if (!url) return;

  try {
    const Redis = require('ioredis');
    state.redisClient = new Redis(url, {
      lazyConnect: false,
      maxRetriesPerRequest: 1, // 缓存场景快速失败，回退内存，不拖住请求
      enableOfflineQueue: false,
      retryStrategy: (times) => Math.min(times * 500, 10000),
      password: redisConnectionPassword(),
    });
    state.redisClient.on('error', (err) => {
      // 只在"就绪 → 不可用"这一次转换上报（随后 state.redisReady=false，
      // ioredis 的重试风暴不会再刷日志）
      if (state.redisReady) {
        logger.error(
          `共享缓存 Redis 连接异常，跨实例状态已降级为单进程语义：${err.message}。${degradedMechanismHint()}`
        );
      }
      state.redisReady = false;
    });
    state.redisClient.on('ready', () => {
      if (!state.redisReady)
        logger.info('共享缓存 Redis 已就绪：限流/验证码/权限缓存进入跨实例一致模式');
      state.redisReady = true;
      ensureSubscriber();
    });
    await state.redisClient.ping();
    state.redisReady = true;
    ensureSubscriber();
  } catch (err) {
    state.redisReady = false;
    logger.warn(
      `REDIS_URL 已配置但连接失败，回退进程内内存态（多实例部署将状态不一致）：${err.message}`
    );
  }
}

/**
 * 序列化写入（值需可 JSON 化）；ttlMs 缺省视为不过期（慎用）
 *
 * @returns {Promise<boolean>} **本次写入是否真的落到了共享层（Redis）**。
 *   - 未配置 REDIS_URL → `true`：只有进程内一层，不存在"本地以为写成了、别的实例看不到"的分叉；
 *     但若内存池已饱和而放弃写入，仍返回 `false`（值确实没写进去）。
 *   - 配置了 Redis 且写入成功 → `true`。
 *   - **配置了 Redis 但本次没写进去（未就绪 / 命令抛错）→ `false`**：此刻实现仍回退写本地内存
 *     （可用性优先，缓存类调用方可忽略返回值），但对其他实例是**假象**——它们读到的是旧值。
 *   只用作缓存的键可以忽略返回值；把键当**权威状态**的调用方（审计链链尾）必须据此降级，
 *   否则"写入失败"会被静默当成"状态已同步"（F-184b 的成因）。
 *   「部署上有没有共享层」按**发起这一拍**捕获，不随 await 期间的 process.env 变化而变（F-207）。
 *   注意：不能用"写后再读"自检来替代本返回值——读也带同样的内存回退，
 *   失败写入刚塞进去的本地值会被读回来，得到**假的成功确认**。
 */
async function set(key, value, ttlMs) {
  const payload = JSON.stringify(value);
  const redisOn = isRedisEnabled();
  // F-207：`部署上有没有共享层`必须在**发起写入的那一拍**定死，不能在 await 之后再读一次 env。
  // 原实现 `return !isRedisConfigured()` 位于两次 await 之后，于是判据读的是"回话时刻"的环境：
  //  - 连接仍在、SET 抛错、而此刻 REDIS_URL 被撤 ⇒ 返回 true = "已落到共享层"，
  //    而 Redis 根本没收到；调用方（utils/auditChain.js 的 writeSharedTail）据此**解除不可信
  //    并抹掉本地唯一副本** ⇒ 权威状态只剩一个谁都不认识的本地值。
  //  - 反向：内存态部署（本来内存就是全部真相）在 await 期间被补上 REDIS_URL ⇒ 返回 false，
  //    把一次完整成功的写入谎报成"没落地"。
  // 生产不改 env，但本仓有 20 个测试文件会改 REDIS_URL ⇒ 这一行同时是判据方向错误与偶发红的燃料。
  const configured = isRedisConfigured();
  if (redisOn) {
    try {
      if (Number.isFinite(ttlMs) && ttlMs > 0) {
        await state.redisClient.set(key, payload, 'PX', ttlMs);
      } else {
        await state.redisClient.set(key, payload);
      }
      return true;
    } catch (err) {
      logger.debug(`共享缓存 set 失败（回退内存）：${err.message}`);
    }
  }
  ensureMemCleanup();
  // 饱和时放弃本次缓存写入（下次重算，语义等同于未命中）
  if (!enforceMemCap()) return false;
  memStore.set(key, {
    value,
    expireAt: Number.isFinite(ttlMs) && ttlMs > 0 ? Date.now() + ttlMs : Infinity,
  });
  // 只有"部署上根本没有共享层"（未配 REDIS_URL）时，内存写入才是完整真相。
  // 配了 REDIS_URL 而本次没写进 Redis（未就绪 / 命令抛错）：其他实例看不到这个值
  // ⇒ 如实返回 false。可用性回退照做（缓存类调用方忽略返回值即可），但绝不谎报已同步
  // ——审计链链尾（F-184b）就靠这个区分"共享尾已推进"和"只有我本地知道"。
  // 判据用「发起这一拍捕获的 configured」而非 isRedisEnabled()：与 setIfAbsent 同口径，
  // "连接暂不可用"同样是"共享层没收到"，不能升格成 true（F-207：也不能因为 env 事后被改而升格）。
  return !configured;
}

/** 读取；不存在或已过期返回 null */
async function get(key) {
  if (isRedisEnabled()) {
    try {
      const raw = await state.redisClient.get(key);
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
      const removed = (await state.redisClient.del(key)) > 0;
      // F-204：共享层这一删之后，本进程内存里无论留着什么值都是陈旧副本（权威层已无此键）。
      // 不顺手抹掉的话，`get` 的内存回退会在下一次读抖动时把它当成共享层真值顶回来——
      // 对缓存类调用方只是命中率损失，对把键当权威状态的调用方（审计链链尾）是脏读。
      memStore.delete(key);
      return removed;
    } catch (err) {
      logger.debug(`共享缓存 del 失败（回退内存）：${err.message}`);
    }
  }
  return memStore.delete(key);
}

/**
 * **只**抹掉本进程内存里的这份副本，绝不碰共享层。同步，不 reject。
 *
 * 为什么需要它（F-204，给把键当**权威状态**用的调用方）：`set` 在 Redis 命令失败时
 * 会把值留在内存里并返回 false，而 `get` 在命令失败时又会从同一份内存回退取值——
 * 于是"某次写入没落到 Redis"留下的本地副本，可以在之后任意一次读抖动时被当成
 * 共享层真值顶回来，而共享层里这个键早已被其他写入方推进。缓存类调用方读到自己的
 * 旧值只是命中率损失；审计链链尾读错一个哈希就是同父两子的分叉（实测见
 * utils/auditChain.js 的 writeSharedTail）。
 * 不变量由调用方维持：「确认落到 Redis 的那一次写入」之后本地必须失声，
 * 「未落到 Redis 的那一次写入」之后本地副本一律不可信、不再被读。
 */
function dropLocalCopy(key) {
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
      const raw = await state.redisClient.getdel(key);
      // F-204 同源缺口的另一半（`del` 那一半已经补过）：这一步之后权威层已经没有这个键
      // （或本来就没有），本进程内存里留着的那份就一定是陈旧副本——不抹掉的话，
      // 下一次读抖动会让 `get` 把它当成共享层真值顶回来。今天不被利用只是因为
      // 唯一调用方（验证码）的键是 UUID、不会复用；任何新调用方用 getDel 取删一个
      // 曾被失败 SET 污染过的键就立刻中招。
      memStore.delete(key);
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
 *
 * L-07 修复：原实现是 `INCR` + `PEXPIRE` 两条独立命令，与「原子」注释不符。
 * 两个后果：① `INCR` 成功而 `PEXPIRE` 失败（或进程在两条命令之间退出）→
 * Redis 键永不带 TTL，限流/验证码计数器永久滞留，且计数再也不重置；
 * ② 两条命令之间若抛错落入内存分支，同一逻辑操作会被重复计一次。
 *
 * 现改为单条 Lua 脚本，两条命令在 Redis 端原子执行：
 *  - 脚本整体成功或整体失败，消除 ① 的中间态；
 *  - 额外处理历史遗留的「无 TTL 键」（PTTL < 0）——即使某键此前因旧实现
 *    落成了永久键，下一次自增时也会补上过期时间，无需人工清理。
 *
 * 残留风险（如实记录）：`eval` 若在服务端已执行、回包时连接中断，调用方
 * 无法区分「没执行」与「执行了但没收到回执」，此时**不计这一笔**（见下），
 * 最坏后果是这一次自增在共享层生效而本地未统计——即阈值判定偏松一次，
 * 而不是原实现的「再计一次」。
 *
 * F-205：Redis 已启用而命令抛错时返回 **null**，绝不回退进程内计数后照常给数字。
 * 调用方拿这个返回值是去和**全局**上限比较的（`captchaService` 的 MAX_ACTIVE_ENTRIES
 * 洪水闸），而本进程的数字在两个方向上都是假的：偏小 ⇒ 洪水期护栏被骗过；
 * 偏大（本地累计过阈值而共享层早已归零）⇒ Redis 恢复后合法请求继续被这个本地值拒掉。
 * null 的语义是「本次没有可用的上限判定」，由调用方按各自口径处置——
 * 验证码侧的 `active === null` 分支已经是「放行、只靠 captchaLimiter 与条目 TTL」，
 * 且降级期的存储本身就是受 enforceMemCap 约束的内存，不会因为少一次阈值而失控。
 *
 * @returns {Promise<number|null>} 自增后的值；Redis 启用但命令失败时为 null（计数不可信）
 */
const INCR_WITH_TTL_SCRIPT = `
local v = redis.call('INCR', KEYS[1])
local ttl = tonumber(ARGV[1])
if ttl and ttl > 0 then
  if v == 1 or redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], ttl)
  end
end
return v
`;

async function incrWithTtl(key, ttlMs) {
  if (isRedisEnabled()) {
    try {
      const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.floor(ttlMs) : 0;
      return await state.redisClient.eval(INCR_WITH_TTL_SCRIPT, 1, key, String(ttl));
    } catch (err) {
      logger.debug(`共享缓存 incr 失败（本次计数不可用，返回 null 而非本地假值）：${err.message}`);
      return null;
    }
  }
  // F-211：F-205 只堵了「已就绪但命令抛错」这一个入口（上面的 catch），**未就绪**这一入口
  // 当时直落内存计数器。实测（配 REDIS_URL、端口不可达）连拿 1、2、3，而调用方
  // captchaService 把这个本进程数字当"集群活跃验证码数"去和 MAX_ACTIVE_ENTRIES 比 ⇒
  // 洪水期护栏被骗过（偏小）、恢复期合法请求被降级史卡住（偏大）——两个方向都是假的。
  // 同文件的 setIfAbsent 早就两个入口一起堵（:451 那段 `if (isRedisConfigured())`），
  // 本行只是把 incr 补齐到同一口径：配了共享层就绝不拿本地凑一个全局值。
  if (isRedisConfigured()) {
    warnIncrDegraded(key);
    return null;
  }
  ensureMemCleanup();
  const entry = memStore.get(key);
  const now = Date.now();
  if (!entry || entry.expireAt <= now) {
    // 新键才需要挤空间；挤无可挤时本次计数不落库（下次从 1 重来，
    // 与"淘汰命中限流计数器仅重置该键窗口"同口径），但绝不为此挤掉防重放键
    if (!entry && !enforceMemCap()) return 1;
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
 *
 * 但这条 fail-closed 原先只在**命令抛错**时兑现。真正更常见的故障形态是
 * "连接整体不可用"（未就绪 / 断线 / init 失败），此时 isRedisEnabled() 为 false，
 * 原实现直接落到内存分支——而内存里"从没见过这个 nonce"恰恰**不等于**"全局第一次见"：
 * 多实例部署（配 REDIS_URL 的唯一理由）下，被另一实例消费过的 nonce 在这里会被
 * 判为首次 ⇒ 登录防重放在 Redis 故障期间整体失效（captured 登录信封可反复重放）。
 * 现在：配了 REDIS_URL 就绝不退回内存占位，一律按重复处理。
 * 未配 REDIS_URL 的单实例部署语义不变（内存就是它的全部真相）。
 * 内存分支还有第三种拒绝：容量饱和且表里只剩关键键时，新 nonce 同样按重复处理
 * （拒收）——宁可拒绝也不把已有的防重放记录挤出去。
 *
 * @returns {Promise<boolean>}
 */
async function setIfAbsent(key, value, ttlMs) {
  if (isRedisEnabled()) {
    try {
      const ok = await state.redisClient.set(key, JSON.stringify(value), 'PX', ttlMs, 'NX');
      return ok === 'OK';
    } catch (err) {
      logger.debug(`共享缓存 setIfAbsent 失败（按重复处理）：${err.message}`);
      return false;
    }
  }
  if (isRedisConfigured()) {
    logger.warn(
      `共享缓存 setIfAbsent：已配置 REDIS_URL 但当前不可用，按重复处理（拒绝而非落内存占位）。` +
        ` 键=${key}；持续出现说明 Redis 链路故障，登录防重放此刻只在单进程内有效`
    );
    return false;
  }
  ensureMemCleanup();
  // 先判重再挤空间：原实现反了次序，连"重放尝试"本身都会挤掉一条表项
  const existing = memStore.get(key);
  if (existing && existing.expireAt > Date.now()) return false;
  if (!existing && !enforceMemCap()) return false;
  memStore.set(key, {
    value,
    // 关键键：容量收口时不参与淘汰（见 enforceMemCap 注释里的实测链路）
    critical: true,
    expireAt: Number.isFinite(ttlMs) && ttlMs > 0 ? Date.now() + ttlMs : Infinity,
  });
  return true;
}

/** 优雅关闭（供进程退出钩子） */
async function shutdownSharedCache() {
  resetMemoryFallback();
  await shutdownInvalidation();
  if (state.redisClient) {
    try {
      await state.redisClient.quit();
    } catch (_) {
      state.redisClient.disconnect?.();
    }
    state.redisClient = null;
    state.redisReady = false;
  }
  state.initAttempted = false;
}

/** 测试钩子：重置到未初始化状态 */
function _resetForTests() {
  resetInvalidation();
  if (state.redisClient) {
    state.redisClient.disconnect?.();
  }
  state.redisClient = null;
  state.redisReady = false;
  state.initAttempted = false;
  resetMemoryFallback();
}

module.exports = {
  EMPTY_SENTINEL,
  isRedisEnabled,
  isRedisConfigured,
  getRedisClient,
  redisConnectionPassword,
  jitterTtl,
  initSharedCache,
  shutdownSharedCache,
  set,
  get,
  del,
  dropLocalCopy,
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
