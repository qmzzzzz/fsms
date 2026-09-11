/**
 * 认证中间件
 * 验证 JWT Token 并提取用户信息
 */

const jwt = require('jsonwebtoken');
const config = require('../config');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const AuditLog = require('../models/AuditLog');
const sharedCache = require('../services/sharedCache');
const { isTokenBlacklisted } = require('./tokenBlacklist');
const sessionService = require('../services/sessionService');
const { isIPAllowed } = require('../utils/ipRange');
const { userLimiter } = require('./rateLimit');
const { getCookies, ACCESS_COOKIE_NAME } = require('../utils/cookie');
const { extendLogContext } = require('../utils/logContext');

/**
 * 提取访问令牌（I-01 双路径）：
 * 优先 Authorization: Bearer <token>（兼容既有 API 消费者），
 * 缺失时回退读取 httpOnly 的 access_token cookie；
 * 两条路径返回同一令牌，后续走同一套校验（黑名单/改密时间）
 * @returns {string|null}
 */
const extractAccessToken = (req) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (token) return token;
  }
  const cookies = getCookies(req);
  return cookies[ACCESS_COOKIE_NAME] || null;
};

// 用户缓存：避免每次请求都查库。键为 userId，值为 { user, expireAt, invalidatedAt }
// 本地热缓存，TTL 60 秒；失效事件经共享缓存广播跨实例传播（L-4）：
// 配置 REDIS_URL 时任一实例禁用/锁定/改密后，所有实例立即标记本地条目失效；
// 未配置时退化为单实例语义（最长 60 秒自然过期，与历史行为一致）。
const userCache = new Map();
const USER_CACHE_TTL = 60 * 1000;
const MAX_CACHE_SIZE = 1000; // 防止无限增长
// 失效广播键前缀：跨实例共用同一命名，收到即对该用户执行本地失效
const USER_CACHE_INVALIDATE_PREFIX = 'auth:user:';

/**
 * 查询并校验用户有效性（带短缓存）
 * @returns {Object|null} 用户基础信息对象，校验失败返回 null
 */
const loadValidUser = async (userId) => {
  const now = Date.now();
  const cached = userCache.get(userId);

  // 检查缓存是否有效且未被主动失效
  if (cached && cached.expireAt > now) {
    // 如果设置了 invalidatedAt，说明缓存被标记为失效，需要重新从数据库加载
    if (cached.invalidatedAt && cached.invalidatedAt > cached.loadedAt) {
      // 缓存被主动失效，忽略已缓存的数据
    } else {
      return cached.user;
    }
  }

  const User = require('../models/User');
  // 记录查询发起时刻：若查询期间发生主动失效（禁用/改密），
  // 不能用本次结果清除失效标记，否则旧数据会复活最长 60 秒
  const queryStartedAt = Date.now();
  // 必须 populate roles 以提取 roleCode，供 userLimiter 等中间件使用
  // 必须 select tokenVersion 用于会话吊销校验
  // 必须 select allowedIPs 用于每请求的 IP 访问范围校验
  const user = await User.findById(userId)
    .select(
      'username email status roles passwordChangedAt lastLoginAt tokenVersion allowedIPs failedLoginCount lockUntil'
    )
    .populate('roles', 'code');
  if (!user) {
    userCache.delete(userId);
    return null;
  }

  // 缓存容量保护
  // P3-36：此处原注释称「删除最旧的一半」——不准确。Map 的迭代顺序是**插入顺序**，
  // 而每次命中缓存并不重新 set（见下方 getFreshUser 的读路径），因此这里淘汰的是
  // 「最早写入的一半」而非 LRU 意义上的「最久未使用」。
  // 刻意不改成真 LRU：条目带 60s TTL，长期不用的条目本就会过期，
  // 而按插入序批量淘汰的实现更简单、无额外记账开销。注释与实现对齐即可，
  // 否则日后有人依据「LRU」假设去调容量或做性能推算会得出错误结论。
  if (userCache.size > MAX_CACHE_SIZE) {
    let deleted = 0;
    for (const key of userCache.keys()) {
      userCache.delete(key);
      if (++deleted >= MAX_CACHE_SIZE / 2) break;
    }
  }

  // 查询期间是否发生了主动失效
  const existing = userCache.get(userId);
  const invalidatedDuringQuery = !!(
    existing &&
    existing.invalidatedAt &&
    existing.invalidatedAt >= queryStartedAt
  );

  userCache.set(userId, {
    user,
    expireAt: Date.now() + USER_CACHE_TTL,
    // 若失效发生在查询期间，本次读取的数据可能已过期：保留失效标记且 loadedAt 归零，
    // 使下一次请求重新查库，直到读到失效之后的数据为止
    loadedAt: invalidatedDuringQuery ? 0 : Date.now(),
    invalidatedAt: invalidatedDuringQuery ? existing.invalidatedAt : null,
  });
  return user;
};

/**
 * 本地失效某个用户的缓存（改密、禁用、锁定时调用；
 * 也是收到其他实例失效广播时的执行路径）
 * 使用 invalidatedAt 时间戳来确保失效操作不会被后续的缓存更新覆盖
 */
const invalidateUserCacheLocal = (userId) => {
  const id = String(userId);
  const now = Date.now();
  const cached = userCache.get(id);

  if (cached) {
    // 只标记失效，不清除缓存条目，这样即使有竞态请求也不会重新填充有效数据
    cached.invalidatedAt = now;
  } else {
    // 如果没有缓存，创建一个失效标记，防止后续请求直接填充缓存
    userCache.set(id, {
      user: null,
      expireAt: now + USER_CACHE_TTL,
      loadedAt: 0,
      invalidatedAt: now,
    });
  }

  // 联动失效「权限结果缓存」（User.getPermissions 的进程内 TTL 缓存，P-01 性能优化）。
  // 角色权限变更（assignPermissions）/ 用户角色变更（assignRoles）后必须立即失效，
  // 否则该用户仍会命中旧权限缓存最长 30 秒，导致权限调整延迟生效、存在安全窗口。
  // 惰性引入 User，避免与模型层形成模块加载期循环依赖。
  try {
    const User = require('../models/User');
    User.invalidatePermissionCache(id);
  } catch (err) {
    // 失效失败不应阻断主流程；权限缓存最多 30 秒后自然过期，仅记录告警
    logger.warn('权限缓存联动失效失败', { userId: id, error: err.message });
  }
};

// 订阅跨实例失效广播（L-4）：其他实例发布 'auth:user:<id>' 时，
// 本实例执行同一套本地失效。广播含自身发布（幂等，重复失效无副作用）。
// 未配置 REDIS_URL 时 onInvalidate 为空操作，行为与单实例历史一致。
sharedCache.onInvalidate((key) => {
  if (typeof key === 'string' && key.startsWith(USER_CACHE_INVALIDATE_PREFIX)) {
    invalidateUserCacheLocal(key.slice(USER_CACHE_INVALIDATE_PREFIX.length));
  }
});

/**
 * 主动失效某个用户的缓存（改密、禁用、锁定时调用）：
 * 先本地失效，再经共享缓存广播给其余实例。
 * 广播为尽力而为（内部吞错），失败时其余实例最长延迟至自然过期。
 */
const invalidateUserCache = (userId) => {
  invalidateUserCacheLocal(userId);
  sharedCache.publishInvalidate(USER_CACHE_INVALIDATE_PREFIX + String(userId));
};

/**
 * 定期清理过期缓存条目（每 30 秒）
 */
const cacheCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, value] of userCache.entries()) {
    if (value.expireAt <= now) {
      userCache.delete(key);
    }
  }
}, 30000);
cacheCleanupTimer.unref?.();

/**
 * 验证 JWT Token
 * 将解析后的用户信息附加到 req.user，并校验用户当前是否仍有效
 */
const authenticate = async (req, res, next) => {
  try {
    // 1. 提取令牌：Authorization Bearer 优先，缺失时回退 access_token cookie（I-01）
    const token = extractAccessToken(req);
    if (!token) {
      return ApiResponse.unauthorized(res, '未提供认证令牌');
    }

    // 2. 验证 Token 签名与有效期（限制算法防止 alg:none 攻击）
    const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });

    // 2.5. 检查 Token 是否在黑名单中（登出后失效）
    if (await isTokenBlacklisted(token)) {
      return ApiResponse.unauthorized(res, '认证令牌已失效，请重新登录');
    }

    // 3. 查询用户当前是否仍有效（防止已禁用/锁定用户的旧 Token 继续使用）
    const freshUser = await loadValidUser(decoded.userId);
    if (!freshUser) {
      return ApiResponse.unauthorized(res, '用户不存在或已被删除');
    }
    if (freshUser.status === 'inactive') {
      return ApiResponse.unauthorized(res, '账户已被禁用，请联系管理员');
    }
    if (freshUser.status === 'locked') {
      return ApiResponse.unauthorized(res, '账户已被锁定，请联系管理员');
    }
    if (freshUser.lockUntil && freshUser.lockUntil > new Date()) {
      return ApiResponse.unauthorized(res, '账户因多次登录失败被临时锁定，请稍后再试');
    }

    // 4. 检查密码是否已修改（token 签发时间早于密码修改时间则拒绝）
    // 用秒级比较：iat 为整秒，passwordChangedAt 为毫秒，直接比会因同秒内
    // ms > iat*1000 误拒"改密后同秒新签发"的合法令牌（如 refresh 重放触发
    // invalidateUserTokens 置 passwordChangedAt 后的即时新登录）。
    if (freshUser.passwordChangedAt && decoded.iat) {
      const changedAtSec = Math.floor(freshUser.passwordChangedAt.getTime() / 1000);
      if (changedAtSec > decoded.iat) {
        return ApiResponse.unauthorized(res, '密码已修改，请重新登录');
      }
    }

    // 4.5 校验 tokenVersion：令牌必须携带且匹配当前版本
    // 强制要求字段存在——省略 tokenVersion 的令牌一律拒绝，
    // 防止伪造令牌通过省略字段绕过会话吊销（改密/禁用/refresh 重放检测后的全量吊销）
    // 历史文档可能缺少该字段，按 schema 默认值 0 参与比对
    const expectedTokenVersion = freshUser.tokenVersion ?? 0;
    if (decoded.tokenVersion === undefined || decoded.tokenVersion !== expectedTokenVersion) {
      return ApiResponse.unauthorized(res, '会话已失效，请重新登录');
    }

    // 4.6 校验用户 IP 访问范围：token 有效期内换到未授权 IP 同样被拒绝，
    // 避免「登录时校验通过后换网络仍可长期使用」的绕过路径。
    // 规则为空时不限制，不影响未配置该功能的用户
    if (freshUser.allowedIPs) {
      const clientIP = req.ip || req.connection?.remoteAddress;
      const { allowed, reason } = isIPAllowed(clientIP, freshUser.allowedIPs);
      if (!allowed) {
        logger.warn('IP 访问范围校验拒绝', {
          username: freshUser.username,
          ip: clientIP,
          reason,
        });
        AuditLog.record({
          action: 'ip_range_denied',
          category: 'auth',
          userId: freshUser._id,
          username: freshUser.username,
          method: req.method,
          path: req.path,
          ip: clientIP,
          success: false,
          riskLevel: 'high',
          riskFactors: ['ip_range_violation'],
          reason: `请求 IP 不在允许范围内（${reason}）`,
        });
        return ApiResponse.forbidden(res, '当前 IP 不在您的允许访问范围内');
      }
    }

    // 4.7 校验设备级会话（tokenVersion 只能全局吊销，无法踢单台设备）
    //
    // 令牌里的 sid 指向 UserSession 一条记录，用户在「登录会话」界面踢除某台
    // 设备后，该记录置为 revoked，此处即拒绝——其余设备不受影响。
    //
    // 兼容不含 sid 的令牌：本功能上线前签发的令牌、以及登录时会话注册失败
    // 降级签发的令牌都没有 sid。对它们跳过会话校验而非拒绝，否则功能上线
    // 瞬间会把所有在线用户全部踢下线。这些令牌最长在 refresh 有效期后自然消亡。
    if (decoded.sid) {
      // 不在此处 try/catch：validateSession 的 fail-closed 异常
      // （code=SESSION_SERVICE_UNAVAILABLE）交由下方统一 catch 转成 503，
      // 与黑名单服务故障同一口径。在这里捕获再原样抛出没有任何作用，
      // 反而会让人误以为此处做了额外处理。
      const sessionState = await sessionService.validateSession(decoded.sid);
      if (!sessionState.usable) {
        return ApiResponse.unauthorized(res, '该设备的登录已被终止，请重新登录');
      }
      // 活跃信息更新（节流写入）：不 await，避免把只读认证路径变成阻塞写路径
      // ——lastSeenAt 是观测性数据，迟一点无妨。
      // 不挂 .catch：touchSession 的契约是**永不 reject**（整个函数体在 try 内，
      // 见 sessionService.touchSession）。挂一个空 catch 只会增加一处永远
      // 执行不到的分支，反而让人误以为这里可能抛错。
      sessionService.touchSession(decoded.sid, req);
    }

    // 5. 附加用户信息到请求对象
    // 角色信息一律以实时加载的 freshUser 为准，不信任 token payload 中的 roles——
    // 用户角色被全部撤销后，旧 token 在有效期内不得继续携带签发时的角色快照
    let freshRoles = [];
    let freshRoleCodes = [];
    if (freshUser.roles && freshUser.roles.length > 0) {
      // freshUser.roles 可能是 ObjectId 数组或已 populate 的 Role 文档
      freshRoles = freshUser.roles.map((r) => {
        if (typeof r === 'object' && r.code) {
          freshRoleCodes.push(r.code);
          return r.code;
        }
        return r;
      });
    }

    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      roles: freshRoles,
      roleCodes: freshRoleCodes, // 供 userLimiter 等中间件使用，实时角色
      realName: decoded.realName, // 用于报警上报时记录真实姓名
      sessionId: decoded.jti || null,
      // 设备会话标识：会话管理接口据此标记「本设备」并禁止误踢自己
      sid: decoded.sid || null,
      iat: decoded.iat,
      exp: decoded.exp,
    };

    // userId 自动注入日志上下文（报告 5.6）：认证成功即写入 ALS store，
    // 本请求后续所有日志（morgan finish、审计、限流/业务告警）经 logger format
    // 自动携带 userId——此前靠各控制器显式传 meta，遗漏即断链
    extendLogContext({ userId: decoded.userId });

    logger.debug('用户认证成功', { username: req.user.username });
    // 用户维度限流：必须在 req.user 就绪后执行，才能按 userId 建键、按角色定配额
    // （修复：此前 userLimiter 挂在全局路由之前，req.user 恒为空，用户级限流实际未按用户生效）
    return userLimiter(req, res, next);
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return ApiResponse.unauthorized(res, '无效的认证令牌');
    }
    if (error.name === 'TokenExpiredError') {
      return ApiResponse.unauthorized(res, '认证令牌已过期');
    }
    // 黑名单服务故障（fail-closed 上抛）：明确返回 503 而非笼统 500，
    // 与 tokenBlacklist.isTokenBlacklisted 的注释契约一致
    if (error.code === 'BLACKLIST_SERVICE_UNAVAILABLE') {
      logger.error(`认证中止 - 黑名单服务不可用：${error.message}`);
      return ApiResponse.error(res, '安全服务暂不可用，请稍后重试', 503);
    }
    // 会话服务故障同样 fail-closed 转 503：会话校验是授权决策的一部分，
    // 查不到结论时放行等于取消设备级吊销这条防线
    if (error.code === 'SESSION_SERVICE_UNAVAILABLE') {
      logger.error(`认证中止 - 会话服务不可用：${error.message}`);
      return ApiResponse.error(res, '安全服务暂不可用，请稍后重试', 503);
    }
    logger.error(`认证失败：${error.message}`);
    return ApiResponse.serverError(res, '认证过程出错');
  }
};

/**
 * 可选认证（已移除）
 *
 * 原实现存在两个问题且全项目无任何路由挂载：
 * 1. fail-open：黑名单/用户加载故障时外层 catch 一律 next() 静默降级为匿名，
 *    使 isTokenBlacklisted 的 fail-closed 语义失效；
 * 2. 死代码：无消费者，维护成本大于价值。
 *
 * 如未来需要"公开但可个性化"的接口，请基于 authenticate 提取
 * 共享校验函数实现，并对服务故障返回 503 而非静默降级。
 */

module.exports = {
  authenticate,
  invalidateUserCache,
  extractAccessToken,
};
