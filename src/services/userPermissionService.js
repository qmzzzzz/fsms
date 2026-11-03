// 用户权限服务（查询 + TTL 缓存 + 跨实例失效广播 + 降级期 TTL 策略）：全文论证见 docs/user-permission-service.md

// **必须**保持惰性 require，不得提到文件顶部。
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
const privilegeGrantService = require('./privilegeGrantService');

privilegeGrantService.setPermissionCacheInvalidator(invalidatePermissionCache);
privilegeGrantService.setPermissionChecker((userId, code, options) =>
  hasPermission(userId, code, options)
);
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

const permCache = new Map(); // userId -> { perms, cachedAt, ttlMs, expireAt }
const PERM_CACHE_TTL_MS = 30 * 1000;
// P-3：共享失效通道断绝期间的最长收敛窗口（见文件头「降级期 TTL 策略」）
const PERM_CACHE_DEGRADED_TTL_MS = 2 * 1000;
const PERM_CACHE_MISS_TTL_MS = 5 * 1000;
const PERM_CACHE_MAX_SIZE = 2000;

/**
 * 跨实例失效是否处于「部署上要求、但此刻用不了」的降级态
 *
 * 只认「配了 REDIS_URL 且连接未就绪」：完全没配是静态单实例，
 * 本地失效即全部真相，不需要为跨实例窗口牺牲命中率。
 */
function sharedInvalidationUnavailable() {
  return sharedCache.isRedisConfigured() && !sharedCache.isRedisEnabled();
}

/** 按当前降级态收敛 TTL（正常态原样返回） */
function effectiveCacheTtlMs(ttlMs) {
  return sharedInvalidationUnavailable() ? Math.min(ttlMs, PERM_CACHE_DEGRADED_TTL_MS) : ttlMs;
}

/**
 * 条目是否仍新鲜
 *
 * 不能只看 expireAt：降级前写下的条目 expireAt 还指向 30 秒后，
 * 若只按写入时的 TTL 判断，Redis 刚断开的瞬间仍会放行整段旧权限。
 * 这里用 `cachedAt + 当前口径 TTL` 复核，使降级立即生效。
 */
function isEntryFresh(entry, now) {
  if (!entry || entry.expireAt <= now) return false;
  return now - entry.cachedAt < effectiveCacheTtlMs(entry.ttlMs);
}

function grantBoundTtlMs(grantExpiresAt, now) {
  if (!grantExpiresAt) return PERM_CACHE_TTL_MS;
  return Math.max(0, Math.min(PERM_CACHE_TTL_MS, grantExpiresAt.getTime() - now)); // A3：TTL 收敛到「最近一条临时授予的到期时刻 − now」，到期后 0ms 就该不可见，不得被 30 秒 TTL 吃掉
}

/** 统一写入口：TTL 在写入当拍按降级态定死 */
function setCacheEntry(key, perms, now, baseTtlMs) {
  const ttlMs = effectiveCacheTtlMs(baseTtlMs);
  permCache.set(key, { perms, cachedAt: now, ttlMs, expireAt: now + ttlMs });
}

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
      // 用新鲜度口径而非 expireAt：降级后长 TTL 条目也要被回收
      if (!isEntryFresh(entry, now)) permCache.delete(key);
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
 * 从用户文档收集生效权限码（getPermissions 与批量路径共用）
 * 防御性 filter(Boolean)：实测 mongoose 8.24.1 不留 null 洞
 * （见 populateMatchShape.test.js），保留以防版本改行为。
 * @param {object} user 已 populate roles.permissions 的用户文档
 * @returns {string[]}
 */
function collectPermissionCodes(user) {
  const permissions = new Set();
  (user.roles || []).filter(Boolean).forEach((role) => {
    (role.permissions || []).filter(Boolean).forEach((perm) => permissions.add(perm.code));
  });
  return Array.from(permissions);
}

/**
 * 取用户文档的 populate 形态（单查与批量必须完全一致，否则匹配口径会漂移）
 */
const PERMISSION_POPULATE = {
  path: 'roles',
  // 仅生效角色/权限参与授权（与 permissionHelper.getUserPermissions 同口径）：
  // 管理员停用角色或权限项后必须立即失效，不得等缓存自然过期
  match: { status: 'active' },
  populate: {
    path: 'permissions',
    match: { status: 'active' },
  },
};

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
  if (isEntryFresh(cached, now)) {
    return cached.perms;
  }

  // 查库前取号，写回时比对（见文件头 permCacheGeneration）
  const genAtRead = permCacheGeneration;
  const user = await User.findById(key).populate(PERMISSION_POPULATE);

  if (!user) {
    // 缓存空结果短 TTL：防止不存在的 userId 反复穿透打库
    if (permCache.size >= PERM_CACHE_MAX_SIZE) permCache.clear();
    setCacheEntry(key, [], now, PERM_CACHE_MISS_TTL_MS);
    return [];
  }

  const perms = collectPermissionCodes(user);
  const granted = (await privilegeGrantService.activeGrantsForUsers([key], new Date(now))).get(key);
  const grantedCodes = granted ? granted.codes : [];
  const merged = grantedCodes.length > 0 ? [...new Set([...perms, ...grantedCodes])] : perms;

  // 容量保护：超过上限直接清空（重建成本远低于逐条淘汰的复杂度）
  if (permCache.size >= PERM_CACHE_MAX_SIZE) permCache.clear();
  // 写回闸门：查库期间发生过本地失效 ⇒ 本次结果可能是失效前的旧权限集，
  // 缓存它等于把刚 delete 掉的条目重新种回去（收回的权限继续放行到 TTL 到期）。
  // 宁可这次不缓存、让下一个请求再查一趟库。
  if (permCacheGeneration === genAtRead) {
    setCacheEntry(key, merged, now, grantBoundTtlMs(granted && granted.expiresAt, now));
  }

  return merged;
}

/** 命中缓存的直接写入 result；未命中的去重后返回。 */
function splitCachedAndMissing(userIds, now, result) {
  const missing = [];
  const seen = new Set();
  for (const raw of userIds || []) {
    if (raw === undefined || raw === null || raw === '') continue;
    const key = String(raw);
    if (seen.has(key)) continue;
    seen.add(key);

    const cached = permCache.get(key);
    if (isEntryFresh(cached, now)) {
      result.set(key, cached.perms);
    } else {
      missing.push(key);
    }
  }
  return missing;
}

/** 批量写回缓存与结果；查库期间发生过失效则整批不写回。 */
function writeBackBatch(missing, byId, now, genAtRead, result, grantedByUser) {
  // 容量保护只需判一次：整批写回是原子的，不会出现批内反复清空
  if (permCache.size + missing.length >= PERM_CACHE_MAX_SIZE) permCache.clear();

  for (const key of missing) {
    const user = byId.get(key);
    const base = user ? collectPermissionCodes(user) : [];
    const granted = (grantedByUser && grantedByUser.get(key)) || null;
    const grantedCodes = granted ? granted.codes : [];
    const perms = grantedCodes.length > 0 ? [...new Set([...base, ...grantedCodes])] : base;
    const ttl = user ? grantBoundTtlMs(granted && granted.expiresAt, now) : PERM_CACHE_MISS_TTL_MS;
    if (permCacheGeneration === genAtRead) {
      setCacheEntry(key, perms, now, ttl);
    }
    result.set(key, perms);
  }
}

/**
 * 批量获取多个用户的权限码（权限热生效推送路径，A-5）
 *
 * 为什么需要它：角色变更后要向「持有该角色的全部用户」下发新权限集。逐用户调用
 * getPermissions 会在一次广播里产生 N 次串行查库（N = 在线用户数），角色下挂几百人
 * 时推送延迟随之线性增长。这里把未命中的用户合并成**一次** `$in` 查询。
 *
 * 缓存语义与单查完全一致：命中直接返回；不存在用户写 5 秒空结果；有用户文档写
 * 30 秒 TTL；查库期间发生过本地失效则整批不写回（宁可多查一趟，不种回旧权限）。
 * 失效是全局代际推进，不存在"只失效某个用户、其余仍可写回"的细分——单查与批量
 * 共用同一代际，判定天然一致。
 *
 * @param {Array<string|object>} userIds
 * @returns {Promise<Map<string, string[]>>} key 为字符串 userId；查不到的用户映射为空数组
 */
async function getPermissionsForUsers(userIds) {
  const now = Date.now();
  const result = new Map();
  const missing = splitCachedAndMissing(userIds, now, result);
  if (missing.length === 0) return result;

  const User = getUserModel();
  // 查库前取号，写回时比对（与 getPermissions 同一条不变量）
  const genAtRead = permCacheGeneration;
  const users = await User.find({ _id: { $in: missing } }).populate(PERMISSION_POPULATE);
  const byId = new Map((users || []).map((user) => [String(user._id), user]));
  const grantedByUser = await privilegeGrantService.activeGrantsForUsers(missing, new Date(now));
  writeBackBatch(missing, byId, now, genAtRead, result, grantedByUser);

  return result;
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
 * 只取角色链上的持权码（不合并临时授权、不读缓存）
 *
 * 供临时授权的审批资格判定使用（见 hasPermission 的 includeGrants）。这里刻意不用缓存：
 * 缓存的合并结果分不清某个码来自角色还是来自另一张临时授权；审批是低频路径，多查一趟库
 * 换来「资格判定看的是目录现值」。
 * @param {string} userId
 * @returns {Promise<string[]>}
 */
async function getBasePermissions(userId) {
  const User = getUserModel();
  const user = await User.findById(String(userId)).populate(PERMISSION_POPULATE);
  return user ? collectPermissionCodes(user) : [];
}

/**
 * 检查用户是否拥有指定权限编码（无缓存直查，低频路径）
 * @param {string} userId
 * @param {string} permissionCode
 * @returns {Promise<boolean>}
 */
async function hasPermission(userId, permissionCode, { includeGrants = true } = {}) {
  // includeGrants=false：只认角色链持权，不合并临时授权。审批资格必须用这一档——
  // 否则「自己持有一张临时授权」就能替同码的第二个人签批，高敏权限沿「授予→再授予」
  // 链自我扩散，两个各持 168h 临时权限的人即可凑齐全域双审批。
  const perms = includeGrants ? await getPermissions(userId) : await getBasePermissions(userId);
  if (perms.includes(permissionCode)) return true;
  if (perms.includes('*:*')) return true;
  const [mod] = permissionCode.split(':');
  return perms.includes(`${mod}:*`);
}

module.exports = {
  getPermissions,
  getPermissionsForUsers,
  invalidatePermissionCache,
  invalidatePermissionCacheLocal,
  handleRemoteInvalidation,
  hasPermission,
  startCleanup,
  stopCleanup,
  // P-3 策略参数：测试据此断言降级/正常两档 TTL，避免复制魔数
  PERM_CACHE_TTL_MS,
  PERM_CACHE_DEGRADED_TTL_MS,
};
