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
// 静态面判据的**唯一事实来源**在 staticFrontend（它才是"谁托管哪一面"的权威）。
// 此前本文件自带一份，两份独立清单漂移出 8 条判定相反的路径——见下方 skipResourceLimiter 注释。
const { isStaticSurfaceRequest } = require('./staticFrontend');

/**
 * 限流键的 IP 归一化（CC 防护同源收口，见总账 §4.4「限流键直接拼原文 req.ip」条目）
 *
 * `::ffff:1.2.3.4` 与 `1.2.3.4` 在名单侧是同一地址（IPBlacklist 入库前归一化），
 * 限流侧若按原文组键就是两个桶——同一来源拿到两份配额，标称阈值名存实亡；
 * IPv6 的等价写法（压缩/展开）同理。这里统一走 ipUtils.normalizeIP 与名单侧同一把尺。
 *
 * 归一化失败**不再回退原文**（2026-10-01 修正原推断）。原注释写"回退原文：该形态
 * 自成一桶，不与任何他人共享，fail-closed 语义不变"——这个推断在 trust proxy 开着时
 * 是反的：req.ip 取自 X-Forwarded-For，而那个头是请求方写的。实测
 * `X-Forwarded-For: garbage-not-an-ip` 时 proxy-addr 原样透传该文本，于是"自成一桶"
 * 等于"每请求换一个全新桶"：general/ip/captcha/register/login 五套 IP 配额全部刷不完，
 * 升级封禁侧（同一把尺）计数永不累积 ⇒ 封禁阶梯不可达。对**请求方可控**的输入，
 * 失败封闭只能是"并进一个共享占位键"：换不来新配额，也污染不到正常流量。
 * @param {unknown} ip req.ip
 * @returns {string} 归一化后的限流键 IP 部分
 */
const normalizeRateLimitIp = (ip) => normalizeIP(ip) || 'unknown';

/**
 * 限流触发 → 升级服务（CC 防护闭环）的统一挂钩
 *
 * 惰性 require：rateLimit.js 在 app.js 加载链的最前端，而升级服务要拉
 * AuditLog 模型与 securityAlert 一串依赖，提前加载会放大启动链路与循环
 * 依赖风险；首次 429 才加载，代价是一次 require 缓存命中。
 *
 * 升级服务的 noteRateLimitHit 自身永不抛错，这里的 catch 只兜"模块加载
 * 本身失败"（如数据模型未注册）——信号丢了可以，429 响应不能挂。
 *
 * limiterName 的取值不是自由的：它决定该次信号落进升级服务的**哪一个类别**，
 * 而各类别的阀值相差 10 倍（ANON_ABUSE 10 / VOLUME 100 / AUTH 30 且不封 IP）。
 * 改名 = 改判据归属。分类表见 services/rateLimitEscalation.js 的
 * SIGNAL_CLASSES / LIMITER_CLASS，门禁见
 * src/tests/services/rateLimitEscalation.test.js「未登记的限流器归入 VOLUME」。
 *
 * 哪些限流器**不**接本挂钩，以及为什么，是这套设计里最容易做错的一半：
 *   - 账号维度桶（login-user / pwd-change-user / reauth-user）：按 username 或
 *     userId 组键，没有可封的 IP（见 rateLimitEscalation.js 文件头）；
 *   - 组合键桶（passwordChange / reauth 的「userId:ip」）：IP 只是键的组成部分，
 *     失败语义属凭据操作而非 IP 洪水；
 *   - staticSurfaceLimiter：NAT 出口聚合流量，接封禁阶梯会把误封从单个 IP
 *     放大到整个办公室。
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
// - 账号维度写滥用桶（securityReportUserLimiter）同样不豁免：它约束的是
//   「单个账号能往高危审计里写多少条」，与来源 IP 是否可信正交
const skipIfWhitelisted = (req) => req.ipWhitelisted === true;

// 探针豁免（全站挂载的前提）：/health、/readyz 由编排器与部署门禁以 127.0.0.1 高频探测，
// 计入配额会让门禁对完全健康的新版本恒红并自动回滚。清单与 protocolCompliance.skipPaths
// 同源（constants/probePaths），不在这里再造第二份——两份清单迟早有一份先忘。
// 判据是 `isProbeRequest`（精确路径 + GET/HEAD）而不是路径前缀：前缀语义曾把整个
// `/health/...` 子树连同任意方法一起免配额免闸门，实测 40 发 ~200KB 的
// `POST /health/zzflood` 一条 429 都没有——body 解析放大正是这两个限流器要挡的东西。
const skipProbeRequests = (req) => isProbeRequest(req.method, req.path);
const skipProbesAndWhitelisted = (req) => skipIfWhitelisted(req) || skipProbeRequests(req);

// 静态前端面豁免资源型限流（generalLimiter / ipLimiter 这两个全站挂载的）
//
// 判据来自 middleware/staticFrontend 的 `isStaticSurfaceRequest`——**唯一事实来源**。
// 此前本文件自带一份（安全方法 + 非 `/api/` 前缀），与 staticFrontend 的
// RESERVED_PREFIXES 是两份独立清单，实测对 11 条非 /api 路径有 8 条判定相反：
// `/health` `/readyz` `/metrics` `/socket.io` `/api-docs` `/csp-report`
// `/client-errors` `/.well-known` 全被旧判据豁免，而 staticFrontend 一个都不托管。
// 其中真正裸奔的是 `/socket.io/`（Socket.IO HTTP long-polling 握手是未认证 GET，
// 而 MAX_CONNECTIONS=1000 约束的是**已建立连接数**不是握手速率）与 `/metrics`
// （metricsAuth 允许内网免令牌，而 app.js 自陈的威胁模型正是容器网络内直连）。
//
// 为什么必须豁免静态面：浏览器一次页面加载实测发出 **35 个请求，其中 34 个是静态
// 资源/文档、只有 1 个打 /api/**（CI e2e-browser 的 Playwright trace 实测）。
// 通用配额 300 次/15 分钟 ⇒ **约 9 次页面加载**就把配额打满，而 429 返回的是 JSON——
// 浏览器把它当文档渲染（e2e 快照实证：页面体就是
// `{"success":false,"message":"请求过于频繁，请稍后再试"}`），整个 SPA 白屏。
// 这不是"测试环境打得太猛"：NAT 出口共用 IP、或部署后客户端全量重取
// （index.html/sw.js 是 maxAge:0 + no-cache）都会在正常使用下触发。
//
// 为什么豁免是安全的：这两个限流器前移到 express.json 之前，目的是给「未认证请求的
// **放大面**」设闸——JSON.parse、递归 sanitize、以及协议违规写一条走哈希链的审计。
// 而安全方法打到静态面时：不解析 body、不 sanitize、无协议违规故不写审计。
//
// 注意用 `=== '/api' || startsWith('/api/')` 而不是 `startsWith('/api')`：
// 后者会把 `/api-docs` 一并算进 API 面（它有自己的 docsLimiter，口径不同）。
const skipResourceLimiter = (req) => skipProbesAndWhitelisted(req) || isStaticSurfaceRequest(req);

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
  skip: skipResourceLimiter, // 白名单 IP、探针 IP、以及静态前端面（安全方法）豁免通用限流
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
 * 静态前端面限流器（2026-09-30 新增）
 *
 * 存在的理由是**修一个度量缺陷**，不是加一道闸：
 * 此前静态面被 generalLimiter / ipLimiter 整体豁免，豁免的代价是「零预算」——
 * 单个 IP 可以无限拉 `/assets/*`。而它之所以需要豁免，恰恰是因为通用配额
 * （300 次/15 分钟）在度量**错误的东西**：一次页面加载 = 34 个静态请求 + 1 个 API
 * 请求（Playwright trace 实测），静态请求的成本（一次 express.static 取文件）
 * 与 API 请求的成本（认证 + 授权 + DB 往返）差着两三个数量级，共享一个计数器时
 * 无论把阈值调多高都会在某一侧出错——调高则 API 侧失去保护，调低则 SPA 白屏。
 *
 * 正确形态是**按成本分桶**：静态面自己一个宽松但非零的桶，API 面保留严桶。
 * 于是"豁免"变成"换桶"，不再是"无上限"。
 *
 * 阈值推导（全部来自实测，不是拍的）：
 *   34 静态请求/页面 × 30 人（NAT 出口的常见规模）× 10 次页面加载/15 分钟 = 10200
 *   取 12000，留约 18% 余量。
 * 按 IP 而非 IP+UA 键：NAT 出口后同版本同浏览器的 UA 完全一致，
 * 加 UA 进键只是把一个桶拆成几个值相同的桶，收益为零而键空间凭空变大。
 *
 * 这个桶的定位要说清：它挡的是**意外洪水**（脚本误循环、爬虫无节制重取），
 * 不是决心明确的攻击者——10000 req/min 的攻击者打穿 12000/15min 毫不费力，
 * 那种流量本来就该由前置反代挡（Nginx 示例配置里对 /metrics 也有同层限流）。
 * 把应用层桶当反代来用，只会在"正常用户被误伤"和"真攻击打不穿"之间两头不讨好。
 *
 * 429 文案与 generalLimiter **刻意不同**：静态面被限流时页面已加载一半，
 * 返回通用文案会让用户以为是接口故障。命中几乎总是"某个 IP 出口后面的人全被限了"，
 * 直接说明现象即可。
 */
const STATIC_SURFACE_MAX_REQUESTS = 12000;
/**
 * 本桶的计数范围判定。单独导出（仅供测试驱动语义）——express-rate-limit 的实例上
 * 不暴露 skip，测试拿不到它；这与 normalizeLoginRateKey / normalizeRateLimitIp
 * 「导出以供测试」是同一条既有做法，而不是为测试新增的后门。
 */
const staticSurfaceSkip = (req) => !isStaticSurfaceRequest(req) || skipProbesAndWhitelisted(req);

const staticSurfaceLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: STATIC_SURFACE_MAX_REQUESTS,
  store: makeSharedStore('static-surface'),
  keyGenerator: (req) => normalizeRateLimitIp(req.ip),
  // 只在静态面计数：本桶是给静态面**补**预算的，挂到全站会把 API 请求也计进来
  skip: staticSurfaceSkip,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: '静态资源请求过于频繁，请稍后再试',
  },
  handler: (req, res, _next) => {
    // 刻意**不**接 noteRateLimitHit：CC 升级服务的阶梯是按"IP 触顶即封"设计的，
    // 而静态面被限流绝大多数是 NAT 出口聚合的结果（一个人多刷几个标签页就可能撞上），
    // 接到封禁阶梯上就是把误封风险从"一个 IP"放大到"一整个办公室"。
    logger.warn(`静态面限流触发：${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      message: '静态资源请求过于频繁，请稍后再试',
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
  skip: skipResourceLimiter, // 白名单 IP、探针 IP、以及静态前端面（安全方法）豁免 IP 限流
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
 * 账号维度桶工厂（改密 / 二次验证 / 安全举报）
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
 *
 * `max` 是后加的形参（安全举报桶用 20 次/15 分钟，理由见下方 securityReportUserLimiter）：
 * 凭据型两桶保持原值 5，不因复用而放宽任何一侧。
 */
function makeUserBucketLimiter(prefix, message, max = 5) {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max,
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

const passwordChangeUserLimiter = makeUserBucketLimiter(
  'pwd-change',
  '密码修改操作过于频繁，请稍后再试'
);
const reauthUserLimiter = makeUserBucketLimiter('reauth', '二次验证尝试过于频繁，请稍后再试');

/**
 * 安全举报（POST /api/security/report）的账号维度桶
 *
 * 为什么这个低频写入口也必须有独立的桶：它**刻意不挂权限码**（人人可举报是产品设计，
 * 见 securityRoutes 的 PERMISSION-EXEMPT 说明），而每一次成功举报都写一条
 * `riskLevel:'high'` 的审计行——它同时是安全概览「高风险操作数」的取数来源。
 * 于是单个被盗令牌可以把高危计数刷成噪声，让真正的告警被淹没（告警疲劳型投毒），
 * 且刷的是**别人的记录**（targetId 由请求方指定，现另需通过存在性与数据范围核验）。
 * 全站通用配额帮不上忙：300 次/15 分钟按 IP 组键，NAT 出口下全办公室共用一桶，
 * 既拦不住定向刷又先误伤正常用户。
 *
 * 20 次/15 分钟的来历：一次现场巡检可能顺带报十几条（十几条就是十几个对象），
 * 而脚本刷量要的是成百上千——20 已经把洪水压在告警噪声之下，同时不把真人挡在门外。
 * 阈值/键/豁免口径的推导与凭据型姊妹桶一致（见上方工厂注释），
 * 同样**不接** noteRateLimitHit——账号桶没有可封的 IP（分类表见文件头）。
 * 该数值不导出：判据要能在配额被改动时**变红**，测试里钉死 20 并同时校验
 * 响应声明的 `RateLimit-Limit`（见 reportTargetScopeAndLimiter.test.js 的 D 组）。
 */
const securityReportUserLimiter = makeUserBucketLimiter(
  'report',
  '举报提交过于频繁，请稍后再试',
  20
);

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
  securityReportUserLimiter,
  ipLimiter,
  userLimiter,
  registerIpLimiter,
  staticSurfaceLimiter,
  // 仅供测试：账号维度键的归一化规则（空格填充分裂计数桶的回归由它盯着）
  normalizeLoginRateKey,
  // 仅供测试与 wellKnownRoutes 复用：限流键 IP 部分的归一化（::ffff: 双桶回归由它盯着）
  normalizeRateLimitIp,
  // 静态面限流器的计数范围判定（仅供测试驱动语义，见 staticSurfaceSkip 的注释）
  staticSurfaceSkip,
  STATIC_SURFACE_MAX_REQUESTS,
};
