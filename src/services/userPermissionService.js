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
 * 策略：进程内 TTL 缓存（30 秒）+ 代际失效（generation）：
 *  - 用户级失效：assignRoles 等变更某用户角色时，仅删除该用户条目
 *  - 全局失效：角色权限被修改（assignPermissions）时递增 generation，所有旧条目即刻过期
 *
 * ================= 跨实例主动失效（L-4） =================
 * 单进程内上述缓存自洽，但多副本部署时各进程各持一份缓存：实例 A 改了某用户
 * 角色/权限后，实例 B 的缓存最长仍会放行旧权限 30 秒。解法是借共享缓存门面的
 * 失效广播（sharedCache.publishInvalidate / onInvalidate，Redis pub/sub）：
 *  - 本地失效（invalidatePermissionCache）发生时同步广播失效键给所有实例；
 *  - 收到广播的实例做**本地**失效（不再二次广播，避免实例间互相触发成环）。
 * 未配置 REDIS_URL 时广播为无操作，退化为原「最长 30 秒自然过期」语义，行为不变。
 */

// 延迟 require 打破 service ↔ model 潜在的循环依赖
function getUserModel() {
  return require('../models/User');
}

// 共享缓存门面（失效广播）。sharedCache 仅依赖 logger，无循环依赖，可顶层引入。
// 未配置 REDIS_URL 时 publishInvalidate/onInvalidate 均为无操作。
const sharedCache = require('./sharedCache');

const permCache = new Map(); // userId -> { perms, gen, expireAt }
let permCacheGeneration = 0;
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
  if (cached && cached.gen === permCacheGeneration && cached.expireAt > now) {
    return cached.perms;
  }

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
    permCache.set(key, { perms: [], gen: permCacheGeneration, expireAt: now + 5 * 1000 });
    return [];
  }

  const permissions = new Set();
  // match 过滤后数组可能残留 null 占位，需跳过
  user.roles.filter(Boolean).forEach((role) => {
    (role.permissions || []).filter(Boolean).forEach((perm) => permissions.add(perm.code));
  });
  const perms = Array.from(permissions);

  // 容量保护：超过上限直接清空（重建成本远低于逐条淘汰的复杂度）
  if (permCache.size >= PERM_CACHE_MAX_SIZE) permCache.clear();
  permCache.set(key, { perms, gen: permCacheGeneration, expireAt: now + PERM_CACHE_TTL_MS });

  return perms;
}

/**
 * 本地失效权限缓存（仅当前进程，不广播）
 * @param {string} [userId] - 指定用户则仅失效该用户；不传则全局失效（角色权限定义变更时使用）
 */
function invalidatePermissionCacheLocal(userId) {
  if (userId !== undefined && userId !== null) {
    permCache.delete(String(userId));
  } else {
    // 全局失效：清空即可（读取路径的 gen 校验与 clear 二选一，保留 clear）
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
