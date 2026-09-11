/**
 * 限流中间件
 * 防止 API 滥用和暴力攻击
 */

const rateLimit = require('express-rate-limit');
const config = require('../config');
const logger = require('../utils/logger');
const { SUPER_ADMIN_ROLE_CODE } = require('../utils/superAdmin');

// 白名单豁免：checkIPBlacklist 中间件命中白名单时会挂 req.ipWhitelisted，
// 各限流器统一跳过白名单 IP，形成"黑白名单 + 限流"联动的完整访问控制
//
// P3-35：豁免范围有明确边界，不是「所有限流器都加上」——
// - 资源型限流（generalLimiter/ipLimiter/userLimiter/strictLimiter/captchaLimiter）：
//   目的是防滥用与资源保护，可信 IP 豁免；此前 strictLimiter/captchaLimiter 漏挂，
//   表现为「加白后导出/验证码仍被限流」，运维只能靠调大 max 绕过，等于全局放宽
// - 凭据型限流（loginLimiter/loginIpLimiter/loginUserLimiter/passwordChangeLimiter）：
//   刻意**不豁免**。白名单表达的是「该 IP 可信、不是攻击源」，而暴力破解防护
//   针对的是凭据本身；办公出口 IP 通常在白名单里，若一并豁免，
//   内网发起的撞库将完全不受限速 —— 这两类风险不能用同一个开关表达
const skipIfWhitelisted = (req) => req.ipWhitelisted === true;

/**
 * 限流存储工厂（R-3/M-1）
 *
 * 默认 MemoryStore 的计数是**每实例一份**：多副本 + 负载均衡时，
 * 同一客户端的配额在每个实例各算一遍，等效于把上限放大 N 倍，
 * 暴力破解防护与资源保护同时失真。
 *
 * 配置 REDIS_URL 时改用 rate-limit-redis（共享计数，跨实例一致）。
 * express-rate-limit v7 支持 store 传 Promise：这里先等共享缓存完成
 * 初始化，Redis 就绪则返回 RedisStore，连不上则回退一个全新
 * MemoryStore（单实例语义，与未配置 REDIS_URL 时等价，不阻断启动）。
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
  (async () => {
    const { initSharedCache, isRedisEnabled, getRedisClient } = require('../services/sharedCache');
    await initSharedCache();
    if (!isRedisEnabled()) return;
    const { RedisStore } = require('rate-limit-redis');
    const client = getRedisClient();
    active = new RedisStore({
      sendCommand: (...args) => client.call(...args),
      prefix: `rl:${prefix}:`,
    });
  })().catch((err) => {
    logger.warn(`限流共享存储初始化失败（${prefix}），回退进程内计数：${err.message}`);
  });
  return {
    async increment(...a) {
      return active.increment(...a);
    },
    async decrement(...a) {
      return active.decrement(...a);
    },
    async resetKey(...a) {
      return active.resetKey(...a);
    },
    async resetAll() {
      if (active.resetAll) return active.resetAll();
    },
    init: fallback.init, // 透传 init（如有）
  };
}

/**
 * 通用限流器
 * 适用于大多数 API 接口
 * 生产环境：300 次/15 分钟（约 20 次/分钟）
 */
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  store: makeSharedStore('general'),
  skip: skipIfWhitelisted, // 修复：白名单 IP 豁免通用限流
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '请求过于频繁，请稍后再试',
  },
  handler: (req, res, _next) => {
    logger.warn(`限流触发：${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      message: '请求过于频繁，请稍后再试',
    });
  },
});

/**
 * 严格限流器
 * 适用于注册、修改密码、数据导出等敏感/重资源操作
 * 生产环境：30 次/15 分钟
 */
const strictLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: 30,
  store: makeSharedStore('strict'),
  skip: skipIfWhitelisted, // P3-35：资源型限流，可信 IP 豁免（口径同 generalLimiter）
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '操作过于频繁，请稍后再试',
  },
  handler: (req, res, _next) => {
    logger.warn(`严格限流触发：${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      message: '操作过于频繁，请稍后再试',
    });
  },
});

/**
 * 登录限流器（IP 维度）
 * 防止暴力破解密码
 * 生产环境：10 次/15 分钟，跳过成功请求
 */
const loginLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: 10,
  store: makeSharedStore('login'),
  skipSuccessfulRequests: true, // 成功登录不计入限流
  keyGenerator: (req) => {
    // 仅按来源 IP 限流：username 是客户端可控字段，参与组键会让攻击者通过
    // 任意轮换用户名不断获得新配额，使暴力破解防护形同虚设
    return `login:${req.ip}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '登录尝试次数过多，请稍后再试',
  },
  handler: (req, res, _next) => {
    logger.warn('登录限流触发', { ip: req.ip, username: req.body?.username });
    res.status(429).json({
      success: false,
      message: '登录尝试次数过多，请稍后再试',
    });
  },
});

/**
 * 登录限流器（纯 IP 维度，更宽配额）
 * 与上方 loginLimiter 串联使用：前者（10 次）控制单 IP 对单一登录入口的尝试频率，
 * 本限流器（30 次）作为外层兜底，封住“单 IP 撞库”路径（轮换用户名批量尝试）
 * 生产环境：30 次/15 分钟，跳过成功请求
 */
const loginIpLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: 30,
  store: makeSharedStore('login-ip'),
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `login-ip:${req.ip}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`登录 IP 维度限流触发：${req.ip}（可能存在撞库/轮换用户名攻击）`);
    res.status(429).json({
      success: false,
      message: '该网络环境登录尝试过于频繁，请稍后再试',
    });
  },
});

/**
 * 登录限流器（账号维度）
 * 与上方两个 IP 维度限流器互补：IP 维度防「单 IP 撞库/轮换用户名」，
 * 账号维度防「分布式撞单账号」（多个 IP 各自少量尝试同一用户名，IP 维度无法察觉）。
 * 单账号 20 次/15 分钟，跳过成功请求（成功登录不应占用配额）。
 * username 缺失时回退 IP 键，避免无 username 字段时键为 undefined。
 */
const loginUserLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: 20,
  store: makeSharedStore('login-user'),
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    const username = req.body?.username;
    return username ? `login-user:${String(username).toLowerCase()}` : `login-user-ip:${req.ip}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(
      `登录账号维度限流触发：username=${req.body?.username || '-'}, ip=${req.ip}（可能存在分布式撞单账号攻击）`
    );
    res.status(429).json({
      success: false,
      message: '该账户登录尝试次数过多，请稍后再试或联系管理员',
    });
  },
});

/**
 * IP 限流器
 * 基于 IP 地址的限流（从 config 读取配置）
 */
const ipLimiter = rateLimit({
  windowMs: config?.rateLimit?.ipWindowMs || 60 * 60 * 1000, // 默认 1 小时
  max: config?.rateLimit?.ipMaxRequests || 1000, // 默认每小时 1000 请求
  store: makeSharedStore('ip'),
  skip: skipIfWhitelisted, // 修复：白名单 IP 豁免 IP 限流
  keyGenerator: (req) => req.ip,
  message: {
    success: false,
    message: 'IP 请求频率超限',
  },
});

/**
 * 用户级限流器
 * 基于已认证用户的 userId 限流，防止同 IP 下多用户滥用
 * 适用于已登录用户的 API 调用频率控制
 * 注意：未认证请求不再跳过——按来源 IP 计入配额，
 * 与 ipLimiter 形成双重覆盖，扩大限流触发条件范围
 */
const userLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  store: makeSharedStore('user'),
  skip: skipIfWhitelisted,
  max: (req) => {
    // 注意：不信任 token payload 中的 roles，仅按 userId 限流
    // 角色配额如需实时生效，应由上层 authenticate 中间件加载后挂到 req.user.roleCodes
    const roleCodes = req.user?.roleCodes || [];
    if (roleCodes.includes(SUPER_ADMIN_ROLE_CODE)) return 500;
    if (roleCodes.includes('SECURITY_ADMIN')) return 400;
    return 200; // 普通用户
  },
  keyGenerator: (req) => {
    // 已认证用户按 userId 限流，未认证按 IP
    return req.user?.userId ? `user:${req.user.userId}` : `ip:${req.ip}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('用户级限流触发', { userId: req.user?.userId || '-', ip: req.ip });
    res.status(429).json({
      success: false,
      message: '操作过于频繁，请稍后再试',
    });
  },
});

/**
 * 验证码限流器
 * 每次生成都占内存，需防止恶意刷取（配合服务的内存上限保护双保险）
 * 60 次/5 分钟/IP，正常"点击刷新 + 登录失败重取"远用不完
 */
const captchaLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 60,
  store: makeSharedStore('captcha'),
  skip: skipIfWhitelisted, // P3-35：资源型限流（防内存刷取），可信 IP 豁免
  keyGenerator: (req) => `captcha:${req.ip}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`验证码限流触发：${req.ip}`);
    res.status(429).json({
      success: false,
      message: '验证码获取过于频繁，请稍后再试',
    });
  },
});

/**
 * 改密限流器
 * 专用于修改密码等敏感凭证变更操作，按 userId+IP 组合建键：
 * - 与 loginLimiter 分开计数，避免登录尝试配额与改密配额互相污染
 *   （共用一个限流器时，攻击者刷登录会把受害者的改密配额一起耗尽，反之亦然）
 * - 组合键同时约束「单账号高频改密」与「单 IP 批量撞改密接口」两条路径
 * 生产环境：5 次/15 分钟；成功请求也计入（改密本身即敏感动作，成功同样占额度）
 */
const passwordChangeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  store: makeSharedStore('pwd-change'),
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    const userId = req.user?.userId;
    return userId ? `pwd-change:${userId}:${req.ip}` : `pwd-change-ip:${req.ip}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('改密限流触发', { userId: req.user?.userId || '-', ip: req.ip });
    res.status(429).json({
      success: false,
      message: '密码修改操作过于频繁，请稍后再试',
    });
  },
});

/**
 * 注册限流器（IP 维度）
 * 防止暴力注册/滥用：按真实客户端 IP 限流（req.ip），
 * 生产环境 trust proxy=false 不受 X-Forwarded-For 伪造影响；
 * 与 strictLimiter 独立计数，避免注册尝试耗尽严格限流配额、
 * 也避免严格限流配额不足时注册被误伤。
 * 默认：10 次/5 分钟/IP，超限返回 429 + Retry-After（express-rate-limit 自动带）
 */
const registerIpLimiter = rateLimit({
  windowMs: config.rateLimit.registerWindowMs || 5 * 60 * 1000,
  max: config.rateLimit.registerMaxRequests || 10,
  store: makeSharedStore('register-ip'),
  skip: skipIfWhitelisted, // 资源型限流，可信 IP 豁免（口径同 generalLimiter）
  keyGenerator: (req) => `register:${req.ip}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`注册 IP 限流触发：${req.ip}（可能存在批量注册滥用）`);
    res.status(429).json({
      success: false,
      message: '注册过于频繁，请稍后再试',
    });
  },
});

module.exports = {
  generalLimiter,
  strictLimiter,
  loginLimiter,
  loginIpLimiter,
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  ipLimiter,
  userLimiter,
  registerIpLimiter,
  // 仅供测试：makeSharedStore 的 Redis/MemoryStore 分支需直接驱动（rateLimitStore.test.js）
  makeSharedStore,
};
