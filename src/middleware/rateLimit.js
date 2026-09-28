/**
 * 限流中间件
 * 防止 API 滥用和暴力攻击
 */

const rateLimit = require('express-rate-limit');
const config = require('../config');
const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { SUPER_ADMIN_ROLE_CODE } = require('../utils/superAdmin');
const { makeSharedStore } = require('./rateLimitStore');
const { isProbeRequest } = require('../constants/probePaths');

/**
 * 限流键的 IP 归一化（CC 防护同源收口，见总账 §4.4「限流键直接拼原文 req.ip」条目）
 *
 * `::ffff:1.2.3.4` 与 `1.2.3.4` 在名单侧是同一地址（IPBlacklist 入库前归一化），
 * 限流侧若按原文组键就是两个桶——同一来源拿到两份配额，标称阈值名存实亡；
 * IPv6 的等价写法（压缩/展开）同理。这里统一走 ipUtils.normalizeIP 与名单侧
 * 同一把尺。归一化失败的歧义写法（八进制/十六进制等）回退原文：该形态自成一桶，
 * 不与任何他人共享，fail-closed 语义与改前一致（只是不再翻倍）。
 * @param {unknown} ip req.ip
 * @returns {string} 归一化后的限流键 IP 部分
 */
const normalizeRateLimitIp = (ip) => normalizeIP(ip) || String(ip ?? 'unknown');

/**
 * 限流触发 → 升级服务（CC 防护闭环）的统一挂钩
 *
 * 惰性 require：rateLimit.js 在 app.js 加载链的最前端，而升级服务要拉
 * AuditLog 模型与 securityAlert 一串依赖，提前加载会放大启动链路与循环
 * 依赖风险；首次 429 才加载，代价是一次 require 缓存命中。
 *
 * 升级服务的 noteRateLimitHit 自身永不抛错，这里的 catch 只兜"模块加载
 * 本身失败"（如数据模型未注册）——信号丢了可以，429 响应不能挂。
 */
let escalationModule = null;
const noteRateLimitHit = (req, limiterName) => {
  try {
    if (!escalationModule) escalationModule = require('../services/rateLimitEscalation');
    escalationModule.noteRateLimitHit(req, limiterName);
  } catch (err) {
    logger.warn(`限流升级信号上报失败（忽略）: ${err.message}`);
  }
};

// 白名单豁免：checkIPBlacklist 中间件命中白名单时会挂 req.ipWhitelisted，
// 各限流器统一跳过白名单 IP，形成"黑白名单 + 限流"联动的完整访问控制。
// 标记只在可信边界内发放（security.js isWhitelistExemptionTrustworthy）：
// 公网直连伪造一跳 XFF 冒充白名单 IP 拿不到标记，资源型限流不会被买通
//
// P3-35：豁免范围有明确边界，不是「所有限流器都加上」——
// - 资源型限流（generalLimiter/ipLimiter/userLimiter/strictLimiter/captchaLimiter）：
//   目的是防滥用与资源保护，可信 IP 豁免；此前 strictLimiter/captchaLimiter 漏挂，
//   表现为「加白后导出/验证码仍被限流」，运维只能靠调大 max 绕过，等于全局放宽
// - 凭据型限流（loginLimiter/loginUserLimiter/passwordChangeLimiter）：
//   刻意**不豁免**。白名单表达的是「该 IP 可信、不是攻击源」，而暴力破解防护
//   针对的是凭据本身；办公出口 IP 通常在白名单里，若一并豁免，
//   内网发起的撞库将完全不受限速 —— 这两类风险不能用同一个开关表达
const skipIfWhitelisted = (req) => req.ipWhitelisted === true;

// 探针豁免（全站挂载的前提）：/health、/readyz 由编排器与部署门禁以 127.0.0.1 高频探测，
// 计入配额会让门禁对完全健康的新版本恒红并自动回滚。清单与 protocolCompliance.skipPaths
// 同源（constants/probePaths），不在这里再造第二份——两份清单迟早有一份先忘。
// 判据是 `isProbeRequest`（精确路径 + GET/HEAD）而不是路径前缀：前缀语义曾把整个
// `/health/...` 子树连同任意方法一起免配额免闸门，实测 40 发 ~200KB 的
// `POST /health/zzflood` 一条 429 都没有——body 解析放大正是这两个限流器要挡的东西。
const skipProbeRequests = (req) => isProbeRequest(req.method, req.path);
const skipProbesAndWhitelisted = (req) => skipIfWhitelisted(req) || skipProbeRequests(req);

/**
 * 通用限流器
 * 适用于大多数 API 接口
 * 生产环境：300 次/15 分钟（约 20 次/分钟）
 *
 * 挂载范围是**全站**（app.js 不带 `/api/` 前缀）：`/`、`/csp-report`、`/api-docs` 这些
 * 表面上同样会为每一次协议违规写一条走哈希链的审计记录，只挂 `/api/` 时它们一条 429 都不吃。
 */
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  store: makeSharedStore('general'),
  keyGenerator: (req) => normalizeRateLimitIp(req.ip),
  skip: skipProbesAndWhitelisted, // 白名单 IP 与探针 IP 豁免通用限流
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '请求过于频繁，请稍后再试',
  },
  handler: (req, res, _next) => {
    noteRateLimitHit(req, 'general');
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
  keyGenerator: (req) => normalizeRateLimitIp(req.ip),
  skip: skipIfWhitelisted, // P3-35：资源型限流，可信 IP 豁免（口径同 generalLimiter）
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '操作过于频繁，请稍后再试',
  },
  handler: (req, res, _next) => {
    noteRateLimitHit(req, 'strict');
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
 *
 * 这是登录入口**唯一**的 IP 维度桶，不要再在这里并联"同键空间、阈值更宽"的第二个桶：
 * 此前 `authRoutes.js` 还挂过一个 `loginIpLimiter`（30 次/15 分钟，键 `login-ip:${ip}`），
 * 与本桶键空间（只由来源 IP 决定）、窗口、`skipSuccessfulRequests` 全同，只有阈值更宽
 * ⇒ 它既不可能多挡一次，也不可能多放行一次，只把第 31 次之后的 429 文案换成另一句
 * （实测见 `src/tests/security/loginIpBucketDominator.test.js`：串联时本桶第 11 次触顶，
 * 宽桶单独挂载第 31 次触顶）。注释里"外层兜底、封住轮换用户名撞库"描述的是一个
 * 不存在的能力——那条路径由本桶（更严）与 `loginUserLimiter`（账号维度）共同覆盖。
 *
 * 分层事实（不随本条改动）：非白名单 IP 通常在第 6 次失败登录时就被
 * `securityAlert` 的暴力破解阈值（5 次/5 分钟）自动封禁，`checkIPBlacklist` 早于限流，
 * 于是第 6 次起拿到的是 403。本桶真正管住的是白名单 IP（凭据型限流刻意**不**豁免白名单）
 * 与"慢速滴灌"（5 分钟窗口内不足 5 次、15 分钟窗口内累计超 10 次）两条路径。
 */
const loginLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: 10,
  store: makeSharedStore('login'),
  skipSuccessfulRequests: true, // 成功登录不计入限流
  keyGenerator: (req) => {
    // 仅按来源 IP 限流：username 是客户端可控字段，参与组键会让攻击者通过
    // 任意轮换用户名不断获得新配额，使暴力破解防护形同虚设
    return `login:${normalizeRateLimitIp(req.ip)}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '登录尝试次数过多，请稍后再试',
  },
  handler: (req, res, _next) => {
    noteRateLimitHit(req, 'login-ip');
    logger.warn('登录限流触发', { ip: req.ip, username: req.body?.username });
    res.status(429).json({
      success: false,
      message: '登录尝试次数过多，请稍后再试',
    });
  },
});

/**
 * 登录限流器的账号维度键归一化。
 *
 * 必须与 `loginValidation` 的 `body('username').trim()` 同形：限流器挂在验证之前，
 * 控制器拿到的是 trim 后的名字，而"admin␣␣"与"admin"若算两个键，
 * 每多一个空格就多一个 20 次/15 分钟 的桶（128 字符上限给了数百个），
 * 本限流器唯一的存在理由——多 IP 各自少量尝试同一账号——就此失效。
 * @param {unknown} username
 * @returns {string}
 */
const normalizeLoginRateKey = (username) => String(username).trim().toLowerCase();

/**
 * 登录限流器（账号维度）
 * 与上方 IP 维度限流器互补：IP 维度防「单 IP 撞库/轮换用户名」，
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
    return username
      ? `login-user:${normalizeLoginRateKey(username)}`
      : `login-user-ip:${normalizeRateLimitIp(req.ip)}`;
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
 * 挂载范围同 generalLimiter：全站（含非 `/api/` 表面），豁免口径也同源
 */
const ipLimiter = rateLimit({
  windowMs: config?.rateLimit?.ipWindowMs || 60 * 60 * 1000, // 默认 1 小时
  max: config?.rateLimit?.ipMaxRequests || 1000, // 默认每小时 1000 请求
  store: makeSharedStore('ip'),
  keyGenerator: (req) => normalizeRateLimitIp(req.ip),
  skip: skipProbesAndWhitelisted, // 白名单 IP 与探针 IP 豁免 IP 限流
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'IP 请求频率超限',
  },
  // 显式 handler 而非默认：响应体与原先的 message 选项逐字一致，
  // 差异只在多出升级信号上报——ipLimiter 是全站每小时桶，是 CC 洪水里
  // 最先持续触顶的那一层，没有 handler 就没有升级信号
  handler: (req, res, _next) => {
    noteRateLimitHit(req, 'ip');
    res.status(429).json({
      success: false,
      message: 'IP 请求频率超限',
    });
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
    return req.user?.userId ? `user:${req.user.userId}` : `ip:${normalizeRateLimitIp(req.ip)}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    // 升级信号只看 IP 维度：按 userId 组键的触顶是已认证用户的配额问题，
    // 封 IP 会误伤同源的其他用户
    if (!req.user?.userId) noteRateLimitHit(req, 'user-ip');
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
  keyGenerator: (req) => `captcha:${normalizeRateLimitIp(req.ip)}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    noteRateLimitHit(req, 'captcha');
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
    return userId
      ? `pwd-change:${userId}:${normalizeRateLimitIp(req.ip)}`
      : `pwd-change-ip:${normalizeRateLimitIp(req.ip)}`;
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
 * 凭据型限流的「账号维度」姊妹桶（改密 / 二次验证各一个）
 *
 * 为什么原样组合键不够（实测：`zztmpctl/laneE/xffCredentialLimiter.test.js`，
 * 判据见 `src/tests/security/credentialLimiterPerUserBucket.test.js`）：
 * `passwordChangeLimiter`/`reauthLimiter` 的键由 userId 与来源 IP 拼装而成，
 * IP 是键的**组成部分**而不是并列的另一把尺子 ⇒ 换 IP 就换一个全新桶，
 * "单账号 5 次/15 分钟"实际变成"单账号 × 每个源 IP 各 5 次"。
 * 两条独立放大路径：
 *   · 代理池/NAT 后面的真·多源 IP（不需要任何伪造）；
 *   · `TRUST_PROXY_HOPS>0` 时（生产 compose 默认 1 跳，`app.js:112-113`）
 *     能直连应用端口的主体（同网段容器、宿主进程、SSRF 跳转）用
 *     `X-Forwarded-For` 任意编造 req.ip——实测伪造一跳即可让 req.ip 变成 1.2.3.4，
 *     审计行记录的来源 IP 与 `password_changed` 溯源同被写成假值。
 * `/auth/login` 一侧早就有账号维度的 `loginUserLimiter` 盯这件事，
 * 而"拿窃取到的令牌改密/二次验证"这条路径只有 IP 尺子 ⇒ 补齐同一条不变量。
 *
 * 口径：**并列两个桶**而不是把 IP 从组合键里删掉。
 * 只留账号桶会丢掉"单 IP 横扫多账号"的约束，只留 IP 桶就是本条缺陷本身；
 * 两者阈值/窗口保持一致，不放宽任何一侧。userId 缺失时跳过（未认证请求由
 * 组合键回退分支与 generalLimiter 负责，不能让所有匿名请求共享一个 `undefined` 桶）。
 */
function makeCredentialUserLimiter(prefix, message) {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    store: makeSharedStore(`${prefix}-user`),
    skipSuccessfulRequests: false,
    skip: (req) => !req.user?.userId,
    keyGenerator: (req) => `${prefix}-user:${req.user?.userId}`,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn(`${prefix} 账号维度限流触发`, { userId: req.user?.userId || '-', ip: req.ip });
      res.status(429).json({ success: false, message });
    },
  });
}

const passwordChangeUserLimiter = makeCredentialUserLimiter(
  'pwd-change',
  '密码修改操作过于频繁，请稍后再试'
);
const reauthUserLimiter = makeCredentialUserLimiter('reauth', '二次验证尝试过于频繁，请稍后再试');

/**
 * 注册限流器（IP 维度）
 * 防止暴力注册/滥用：按真实客户端 IP 限流（req.ip），
 * 与 strictLimiter 独立计数，避免注册尝试耗尽严格限流配额、
 * 也避免严格限流配额不足时注册被误伤。
 * 注意 req.ip 的可信度取决于部署：`TRUST_PROXY_HOPS>0`（生产 compose 默认 1）时
 * req.ip 取自 X-Forwarded-For，能直连应用端口者可伪造；注册是无凭证的公开入口，
 * 键里没有任何攻击者不可控的量，因此本限流器的那条"不受 XFF 影响"的老注释不成立，
 * 已按实际口径改写。真正的缓解在 nginx 侧（覆盖式 `X-Forwarded-For $remote_addr`）
 * 与"不信任直连"的部署边界上。
 * 默认：10 次/5 分钟/IP，超限返回 429 + Retry-After（express-rate-limit 自动带）
 */
const registerIpLimiter = rateLimit({
  windowMs: config.rateLimit.registerWindowMs || 5 * 60 * 1000,
  max: config.rateLimit.registerMaxRequests || 10,
  store: makeSharedStore('register-ip'),
  skip: skipIfWhitelisted, // 资源型限流，可信 IP 豁免（口径同 generalLimiter）
  keyGenerator: (req) => `register:${normalizeRateLimitIp(req.ip)}`,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    noteRateLimitHit(req, 'register');
    logger.warn(`注册 IP 限流触发：${req.ip}（可能存在批量注册滥用）`);
    res.status(429).json({
      success: false,
      message: '注册过于频繁，请稍后再试',
    });
  },
});

/**
 * 二次验证（step-up re-authentication）限流器
 *
 * 为什么必须与 passwordChangeLimiter 分开：两者都是"凭据校验"型端点，
 * 强度同级（把 /view-sensitive 拉齐到凭据型限流是对的），
 * 但**共用一个桶**恰好违反了本文件对改密限流器自己的要求——
 * "避免 X 尝试配额与 Y 配额互相污染"。实测后果：用户连做 5 次二次验证
 * （查看本人手机号/邮箱，正常操作就会发生）之后，
 * PUT /change-password 直接被 429 挡在门外，而且文案是"密码修改操作过于频繁"，
 * 用户完全不知道是被查看接口耗尽的。反之，攻击者刷改密也能耗尽受害者的二次验证配额。
 * 键位独立、窗口与阈值保持一致（不放宽任何一侧的防护强度）。
 */
const reauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  store: makeSharedStore('reauth'),
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    const userId = req.user?.userId;
    return userId
      ? `reauth:${userId}:${normalizeRateLimitIp(req.ip)}`
      : `reauth-ip:${normalizeRateLimitIp(req.ip)}`;
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('二次验证限流触发', { userId: req.user?.userId || '-', ip: req.ip });
    res.status(429).json({
      success: false,
      message: '二次验证尝试过于频繁，请稍后再试',
    });
  },
});

module.exports = {
  generalLimiter,
  strictLimiter,
  loginLimiter,
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  passwordChangeUserLimiter,
  reauthLimiter,
  reauthUserLimiter,
  ipLimiter,
  userLimiter,
  registerIpLimiter,
  // 仅供测试：账号维度键的归一化规则（空格填充分裂计数桶的回归由它盯着）
  normalizeLoginRateKey,
  // 仅供测试与 wellKnownRoutes 复用：限流键 IP 部分的归一化（::ffff: 双桶回归由它盯着）
  normalizeRateLimitIp,
};
