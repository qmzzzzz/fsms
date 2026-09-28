/**
 * 用户权限服务（I-08 自 User 模型拆出）
 *
 * 职责：用户权限查询 + 进程内 TTL 结果缓存。
 * User 模型回归纯数据 schema（字段定义 + 密码哈希钩子 + 密码比对），
 * 权限聚合与缓存管理集中在此，便于独立演进（如替换 Redis）。
 *
 * ================= 权限结果缓存（性能优化 P-01） =================
 * 背景：每个受保护请求原本都要执行「查用户 → populate roles → populate
 * permissions」三层关联查询，100 QPS 下即产生 300+ 次/秒的数据库聚合负载。
 * 策略：进程内 TTL 缓存（30 秒）+ 显式失效：
 *  - 用户级失效：assignRoles 等变更某用户角色时，仅删除该用户条目
 *  - 全局失效：角色权限被修改（assignPermissions）时清空整个缓存（permCache.clear()）
 *
 * L-16 与后续修正：这里的 `permCacheGeneration` 有一段反复。
 *  L-16 时它"只被读取、从未递增"，因此是死变量，被删掉并把注释改成描述真实
 *  机制（全局失效走 `clear()`）——那一步判断本身没错，错在删完没留等价机制：
 *  getPermissions 是"先 await 查库、后 set 写回"，失效若落在这一趟往返中间，
 *  delete/clear 都作用在一个还不存在的条目上，随后 in-flight 的旧结果把条目
 *  种回去，主动失效被静默撤销到 TTL 到期（方向是"收回的权限仍能放行"）。
 *  现在代际被重新引入，且**两侧都接上了**：invalidatePermissionCacheLocal 递增、
 *  getPermissions 写回前比对（见该处注释）。与 middleware/auth.js 用户缓存的
 *  queryStartedAt/invalidatedDuringQuery 是同一条不变量的第二次实现。
 *
 * ================= 跨实例主动失效（L-4） =================
 * 单进程内上述缓存自洽，但多副本部署时各进程各持一份缓存：实例 A 改了某用户
 * 角色/权限后，实例 B 的缓存最长仍会放行旧权限 30 秒。解法是借共享缓存门面的
 * 失效广播（sharedCache.publishInvalidate / onInvalidate，Redis pub/sub）：
 *  - 本地失效（invalidatePermissionCache）发生时同步广播失效键给所有实例；
 *  - 收到广播的实例做**本地**失效（不再二次广播，避免实例间互相触发成环）。
 * 未配置 REDIS_URL 时广播为无操作，退化为原「最长 30 秒自然过期」语义，行为不变。
 */

// E-04：**必须**保持惰性 require，不得提到文件顶部。
//
// 原因：本模块（service）↔ models/User 之间存在潜在循环依赖，
// 顶层引入会在加载顺序不利时拿到未完成的 module.exports（undefined）。
// 惰性化让 require 推迟到首次调用，那时两侧都已加载完毕。
// 仓内另有 architecture/requireCycles.test.js 对全仓依赖图做无环断言，
// 若把此处改成顶层 require 触发环，该测试会红灯并指认这条边。
function getUserModel() {
  return require('../models/User');
}

// 共享缓存门面（失效广播）。sharedCache 仅依赖 logger，无循环依赖，可顶层引入。
// 未配置 REDIS_URL 时 publishInvalidate/onInvalidate 均为无操作。
const sharedCache = require('./sharedCache');

/**
 * 缓存代际：每次本地失效 +1，读路径据此拒绝写回（见 getPermissions 的写回闸门）。
 *
 * 要防的窗口：getPermissions 是"先查库、后 set"，而查库是一次 await。
 * 若 invalidatePermissionCache 落在这一趟往返中间，它 delete 的是一个**还不存在**的
 * 条目（no-op），随后 in-flight 的读取拿着"改权限之前"的权限集把条目种回去，
 * 于是这次主动失效被静默撤销、最长到 TTL（30 秒）才收敛。
 * 方向上是授权而不是显示问题：被收回的权限在这 30 秒里照常放行，与本文件
 * getPermissions 的 populate match 处口径（「停用角色或权限项后必须立即失效，
 * 不得等缓存自然过期」）直接矛盾。
 * 与 middleware/auth.js 的 queryStartedAt/invalidatedDuringQuery 是同一条不变量——
 * 那里早已修过，这里是漏网的一处（旧的代际变量被 L-16 当死代码删掉时没留等价机制）。
 *
 * 判定粗（任何一次失效会连带让并发的写回一起作废）是刻意的方向选择：
 * 代价只是下一次多查一次库，收益是绝不会把旧的权限集当成最新结果缓存下来。
 */
let permCacheGeneration = 0;

const permCache = new Map(); // userId -> { perms, expireAt }
const PERM_CACHE_TTL_MS = 30 * 1000;
const PERM_CACHE_MAX_SIZE = 2000;

// 失效广播键命名空间（L-4）：sharedCache 的失效通道是多业务共享的，
// 用统一前缀隔离权限缓存的键，接收端只处理本前缀，互不干扰。
// `*` 表示全局失效（角色权限定义变更），其余为用户级失效。
const INVAL_KEY_PREFIX = 'permcache:';
const INVAL_KEY_GLOBAL = `${INVAL_KEY_PREFIX}*`;

// 显式生命周期（与 statsCache/securityAlert/deviceReminder 口径一致，报告 O-4）：
// 原为模块加载即 setInterval，与其余后台任务的 start*/stop* 模式脱节，
// 测试隔离与优雅关闭无法控制。get() 本身带过期判断，定时器仅做周期性内存回收。
let permCacheCleanupTimer = null;

/**
 * 启动缓存过期清理定时器（由 index.js 在启动期调用）
 */
function startCleanup() {
  if (permCacheCleanupTimer) return;
  permCacheCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of permCache.entries()) {
      if (entry.expireAt <= now) permCache.delete(key);
    }
  }, PERM_CACHE_TTL_MS);
  if (permCacheCleanupTimer && permCacheCleanupTimer.unref) permCacheCleanupTimer.unref();
}

/**
 * 停止清理定时器（优雅关闭/测试隔离时调用）
 */
function stopCleanup() {
  if (permCacheCleanupTimer) {
    clearInterval(permCacheCleanupTimer);
    permCacheCleanupTimer = null;
  }
}

/**
 * 获取用户完整权限编码列表（带 TTL 缓存）
 * @param {string} userId
 * @returns {Promise<string[]>}
 */
async function getPermissions(userId) {
  const User = getUserModel();
  const key = String(userId);
  const now = Date.now();

  const cached = permCache.get(key);
  if (cached && cached.expireAt > now) {
    return cached.perms;
  }

  // 查库前取号，写回时比对（见文件头 permCacheGeneration）
  const genAtRead = permCacheGeneration;
  const user = await User.findById(key).populate({
    path: 'roles',
    // 仅生效角色/权限参与授权（与 permissionHelper.getUserPermissions 同口径）：
    // 管理员停用角色或权限项后必须立即失效，不得等缓存自然过期
    match: { status: 'active' },
    populate: {
      path: 'permissions',
      match: { status: 'active' },
    },
  });

  if (!user) {
    // 缓存空结果短 TTL：防止不存在的 userId 反复穿透打库
    if (permCache.size >= PERM_CACHE_MAX_SIZE) permCache.clear();
    permCache.set(key, { perms: [], expireAt: now + 5 * 1000 });
    return [];
  }

  const permissions = new Set();
  // 防御性 filter(Boolean)：实测 mongoose 8.24.1 不留 null 洞（见 zzqoder_populateMatchShape.test.js），保留以防版本改行为
  user.roles.filter(Boolean).forEach((role) => {
    (role.permissions || []).filter(Boolean).forEach((perm) => permissions.add(perm.code));
  });
  const perms = Array.from(permissions);

  // 容量保护：超过上限直接清空（重建成本远低于逐条淘汰的复杂度）
  if (permCache.size >= PERM_CACHE_MAX_SIZE) permCache.clear();
  // 写回闸门：查库期间发生过本地失效 ⇒ 本次结果可能是失效前的旧权限集，
  // 缓存它等于把刚 delete 掉的条目重新种回去（收回的权限继续放行到 TTL 到期）。
  // 宁可这次不缓存、让下一个请求再查一趟库。
  if (permCacheGeneration === genAtRead) {
    permCache.set(key, { perms, expireAt: now + PERM_CACHE_TTL_MS });
  }

  return perms;
}

/**
 * 本地失效权限缓存（仅当前进程，不广播）
 * @param {string} [userId] - 指定用户则仅失效该用户；不传则全局失效（角色权限定义变更时使用）
 */
function invalidatePermissionCacheLocal(userId) {
  permCacheGeneration += 1;
  if (userId !== undefined && userId !== null) {
    permCache.delete(String(userId));
  } else {
    // 全局失效：直接清空。历史实现依赖一个"代际变量 + 读取路径校验"的组合，
    // 但那个变量从未被递增、读取路径也没有校验（L-16 删除时未留等价机制），
    // 于是并发写回无人拦截。现在代际由本函数递增、由 getPermissions 消费。
    permCache.clear();
  }
}

/**
 * 失效权限缓存并广播给所有实例（L-4）
 *
 * 先做本地失效，再把失效键广播出去；其余实例收到后只做本地失效
 * （走 invalidatePermissionCacheLocal），不会再二次广播，因此不会成环。
 * 未配置 REDIS_URL 时 publishInvalidate 为无操作，退化为单进程语义。
 * 广播为尽力而为：发布失败时各实例最长延迟至缓存自然过期（30 秒），
 * 不阻断主流程，故不 await、不向调用方抛错。
 *
 * @param {string} [userId] - 指定用户则仅失效该用户；不传则全局失效
 */
function invalidatePermissionCache(userId) {
  invalidatePermissionCacheLocal(userId);
  const key =
    userId !== undefined && userId !== null ? `${INVAL_KEY_PREFIX}${userId}` : INVAL_KEY_GLOBAL;
  sharedCache.publishInvalidate(key).catch(() => {
    /* 发布失败退化为自然过期，见注释 */
  });
}

/**
 * 处理来自其他实例的失效广播：仅做本地失效。
 * 只认本模块的键前缀，忽略共享通道上其它业务的失效消息。
 * @param {string} raw 广播的失效键
 */
function handleRemoteInvalidation(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(INVAL_KEY_PREFIX)) return;
  if (raw === INVAL_KEY_GLOBAL) {
    invalidatePermissionCacheLocal();
    return;
  }
  invalidatePermissionCacheLocal(raw.slice(INVAL_KEY_PREFIX.length));
}

// 注册远端失效回调。模块加载期注册即可：sharedCache 的订阅连接在 Redis 就绪后
// 才建立，消息到达时才遍历处理器，注册时机早于/晚于 Redis 就绪均可。
// 未配置 Redis 时该注册为无副作用（不会有订阅连接产生）。
sharedCache.onInvalidate(handleRemoteInvalidation);

/**
 * 检查用户是否拥有指定权限编码（无缓存直查，低频路径）
 * @param {string} userId
 * @param {string} permissionCode
 * @returns {Promise<boolean>}
 */
async function hasPermission(userId, permissionCode) {
  const perms = await getPermissions(userId);
  if (perms.includes(permissionCode)) return true;
  if (perms.includes('*:*')) return true;
  const [mod] = permissionCode.split(':');
  return perms.includes(`${mod}:*`);
}

module.exports = {
  getPermissions,
  invalidatePermissionCache,
  invalidatePermissionCacheLocal,
  handleRemoteInvalidation,
  hasPermission,
  startCleanup,
  stopCleanup,
};
