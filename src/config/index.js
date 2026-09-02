/**
 * 系统配置中心
 * 集中管理所有配置项
 */

require('dotenv').config();

// P3-48：密钥文件注入必须在读取任何 process.env 之前完成。
// 下方所有字段在模块加载时求值，若晚于此处 hydrate，拿到的会是空串。
const { hydrateSecretsFromFiles } = require('./secrets');
const secretHydration = hydrateSecretsFromFiles();

module.exports = {
  // 密钥注入结果（供 index.js 启动期输出日志，此处不能 require logger——
  // logger → config 会构成加载期循环依赖）
  secretHydration,
  // 服务器配置
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',

  // MongoDB 配置
  mongodbUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/fire_safety_db',

  // JWT 配置
  // 注意：生产环境必须通过环境变量设置强密钥，validateProductionConfig() 会校验
  jwt: {
    secret: process.env.JWT_SECRET || '',
    // 访问令牌默认 2h（安全审计加固：原 24h 过长，token 泄露后的可滥用窗口大；
    // 前端拦截器已实现 401 自动刷新，缩短对用户无感；7d refresh token 兜底会话连续性）
    expire: process.env.JWT_EXPIRE || '2h',
    refreshSecret: process.env.JWT_REFRESH_SECRET || '',
    refreshExpire: process.env.JWT_REFRESH_EXPIRE || '7d',
  },

  // 生产环境配置校验（委托给 config/validate.js 统一实现，避免两套规则不一致）
  validateProductionConfig() {
    const { validateConfig } = require('./validate');
    validateConfig();
  },

  // 加密密钥（AES-256 / HMAC）
  aesSecret: process.env.AES_SECRET_KEY || '',
  hmacSecret: process.env.HMAC_SECRET || '',

  // CORS 允许的来源（逗号分隔）
  // P3-36：此处曾声称「未配置时反射请求来源」——与实现不符。
  // app.js 与 middleware/originCheck.js 在本值为空时都回退到**固定**的本地
  // 开发白名单（localhost/127.0.0.1 的 3001 与 5173），从不回显 Origin。
  // 回显来源在 credentials:true 下等于允许任意站点带凭据跨域，
  // 保留这句错误注释会让人误判现有行为不安全，或据此写出真的回显实现。
  corsOrigin: process.env.CORS_ORIGIN || '',

  // 是否开放公开注册（生产环境可关闭，仅由管理员创建用户）
  allowPublicRegistration: process.env.ALLOW_PUBLIC_REGISTRATION === 'true',

  // 登录图形验证码开关（数据库配置读取失败时的静态回退值，默认关闭）
  loginCaptchaEnabled: process.env.LOGIN_CAPTCHA_ENABLED === 'true',

  // 登录口令加密传输：双轨兼容期结束后置 true 拒绝明文口令字段
  // （注意：浏览器 WebCrypto 仅在 secure context 可用，纯 HTTP 内网部署勿开启）
  loginEncryptStrict: process.env.LOGIN_ENCRYPT_STRICT === 'true',

  // 安全配置
  bcryptRounds: (() => {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS, 10);
    // 默认 12 轮：现代 GPU 下的推荐下限（10 轮已不足以抵抗离线爆破），
    // 仅影响新哈希，存量哈希仍可校验；如需迁移可在用户下次改密时自然升级
    return Number.isFinite(rounds) && rounds > 0 ? rounds : 12;
  })(),
  rateLimit: {
    windowMs: (() => {
      const ms = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10);
      return Number.isFinite(ms) && ms > 0 ? ms : 15 * 60 * 1000;
    })(),
    maxRequests: (() => {
      const max = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10);
      return Number.isFinite(max) && max > 0 ? max : 300;
    })(),
    // 基于客户端 IP 的限流（默认与 middleware/rateLimit.js 兼容：1000 次/小时）
    ipWindowMs: (() => {
      const ms = parseInt(process.env.RATE_LIMIT_IP_WINDOW_MS, 10);
      return Number.isFinite(ms) && ms > 0 ? ms : 60 * 60 * 1000;
    })(),
    ipMaxRequests: (() => {
      const max = parseInt(process.env.RATE_LIMIT_IP_MAX_REQUESTS, 10);
      return Number.isFinite(max) && max > 0 ? max : 1000;
    })(),
    // 注册图形验证码开关（默认开启：注册接口强制人机校验）
    registerCaptchaEnabled: process.env.REGISTER_CAPTCHA_ENABLED !== 'false',
    // 注册 IP 限流阈值（默认 10 次/5 分钟/IP）
    registerWindowMs: (() => {
      const ms = parseInt(process.env.REGISTER_IP_WINDOW_MS, 10);
      return Number.isFinite(ms) && ms > 0 ? ms : 5 * 60 * 1000;
    })(),
    registerMaxRequests: (() => {
      const max = parseInt(process.env.REGISTER_IP_MAX_REQUESTS, 10);
      return Number.isFinite(max) && max > 0 ? max : 10;
    })(),
  },

  // 统计缓存配置
  cache: {
    // 统计缓存 TTL（秒），默认 300 秒；
    // 统计为派生数据且写路径已有 invalidateByUserId 主动失效，延长 TTL 可显著提高命中率、
    // 降低冷缓存时的聚合查询压力（原 60 秒在 30–60s 不一致窗口收益下命中率偏低）
    statsCacheTtl: (() => {
      const ttl = parseInt(process.env.STATS_CACHE_TTL, 10);
      return Number.isFinite(ttl) && ttl > 0 ? ttl : 300;
    })(),
    // 统计缓存最大条目数
    statsCacheMaxSize: 500,
    // 过期条目清理间隔（毫秒）
    statsCacheCleanupInterval: 120000,
  },

  // 生产前端静态托管（L-1）：后端直接服务 web-admin 构建产物。
  // 'auto'=仅 NODE_ENV=production 且产物存在时启用；'true'/'false' 强制开/关
  // （Nginx 托管方案下置 false，纯 API 节点同理）
  frontend: {
    serve: process.env.SERVE_FRONTEND || 'auto',
    distDir: process.env.FRONTEND_DIST || '',
  },

  // 日志配置
  logLevel: process.env.LOG_LEVEL || 'info',
};
