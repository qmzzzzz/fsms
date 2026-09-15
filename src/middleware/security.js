/**
 * 安全增强中间件模块
 * 提供多层次的安全防护机制
 */

const crypto = require('crypto');
const helmet = require('helmet');
const logger = require('../utils/logger');
const ApiResponse = require('../utils/apiResponse');
const { stripControlChars, stripControlCharsDeep } = require('../utils/helpers');
const { normalizeIP } = require('../utils/ipUtils');
const { auditPath, deriveAuditMeta, ROUTE_CATEGORY_MAP } = require('../utils/auditMeta');
// T-1：顶层引入——recordEarlyRejection 经 setImmediate 异步写审计，回调可能在
// 测试环境销毁后执行，惰性 require 会抛「import after torn down」
const AuditLog = require('../models/AuditLog');
const { computeFingerprint } = require('../utils/fingerprint');
// #10：脱敏名单单一事实来源——与 models/auditLogSanitizer.js 复用同一份
// SENSITIVE_KEYS，避免两处名单漂移（原内联名单缺 secret/apikey，同一审计体
// 两条路径脱敏口径不一、可能明文入库）。此处仅取名单键，脱敏遍历逻辑各自保留。
const { SENSITIVE_KEYS: AUDIT_SENSITIVE_KEYS } = require('../models/auditLogSanitizer');

/**
 * CSP 违规上报端点（G9）
 * 由 CSP_REPORT_ENABLED 开启：开启后 CSP 头附加 report-uri，浏览器把违规详情
 * POST 到该路径。默认关闭——未部署上报消费方时下发 report-uri 只会给
 * 每个客户端凭空增加一条失败请求。
 */
const CSP_REPORT_PATH = '/csp-report';
const cspReportEnabled = process.env.CSP_REPORT_ENABLED === 'true';

/**
 * 1. HTTP 安全头配置
 * 使用 Helmet 设置各种安全相关的 HTTP 响应头
 *
 * style-src（L-5）：全站不再允许 'unsafe-inline'，改为每请求随机 nonce；
 * 仅 /api-docs（Swagger UI 会自注入内联 <style>，无法携带 nonce）单独
 * 放行 'unsafe-inline'，把放宽面收敛到文档路径。
 */
const SWAGGER_PATH_PREFIX = '/api-docs';

const isSwaggerDocsPath = (req) =>
  req.path === SWAGGER_PATH_PREFIX || req.path.startsWith(`${SWAGGER_PATH_PREFIX}/`);

const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'"],
  'style-src': [
    "'self'",
    (req, res) => (isSwaggerDocsPath(req) ? "'unsafe-inline'" : `'nonce-${res.locals.cspNonce}'`),
  ],
  'img-src': ["'self'", 'data:', 'blob:'],
  'font-src': ["'self'", 'data:'],
  'connect-src': ["'self'"],
  'object-src': ["'none'"],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
};

if (cspReportEnabled) {
  // report-uri 已被规范标记为废弃，但仍是当前浏览器覆盖面最广的上报通道，
  // 因此与新版 report-to（配合 Reporting-Endpoints 响应头）同时下发
  CSP_DIRECTIVES['report-uri'] = [CSP_REPORT_PATH];
  CSP_DIRECTIVES['report-to'] = ['csp-endpoint'];
}

/**
 * 生成每请求 CSP nonce（L-5）
 * 必须在 securityHeaders 之前挂载：helmet 的 style-src 函数指令在写响应头时
 * 读取 res.locals.cspNonce。API 以 JSON 为主，生成开销可忽略。
 */
const attachCspNonce = (req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
};

const securityHeaders = helmet({
  // 内容安全策略：API 以 JSON 为主，仍启用严格 CSP；
  // style 走每请求 nonce（仅 /api-docs 放行 'unsafe-inline'），script 仅限同源
  contentSecurityPolicy: {
    useDefaults: false,
    directives: CSP_DIRECTIVES,
  },
  // 跨域嵌入策略
  crossOriginEmbedderPolicy: false,
  // 跨域 opener 隔离
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  // 跨域资源策略
  crossOriginResourcePolicy: { policy: 'same-site' },
  // DNS 预获取控制
  dnsPrefetchControl: { allow: false },
  // 帧选项（防止点击劫持）
  frameguard: { action: 'deny' },
  // 隐藏 X-Powered-By 头
  hidePoweredBy: true,
  // HSTS (HTTP Strict Transport Security)
  // 注意：helmet 仅在 HTTPS 请求上下发该头；HTTP 兜底下发见 applySecurity 中的 ensureHsts
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  // IE 禁止
  ieNoOpen: true,
  // 禁止 MIME 嗅探
  noSniff: true,
  // 来源策略
  originAgentCluster: true,
  // Referrer 策略
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // XSS 保护（旧版浏览器）
  xssFilter: true,
});

/**
 * 1.2 Permissions-Policy 显式下发
 * helmet 7.x 已移除该功能（旧配置会被静默忽略），必须手工下发。
 * 覆盖常见敏感特性：禁用定位/麦克风/摄像头/支付/USB/传感器等。
 */
const PERMISSIONS_POLICY_VALUE = [
  'camera=()',
  'microphone=()',
  'geolocation=()',
  'payment=()',
  'usb=()',
  'magnetometer=()',
  'gyroscope=()',
  'accelerometer=()',
  'fullscreen=(self)',
].join(', ');

const permissionsPolicy = (req, res, next) => {
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY_VALUE);
  next();
};

/**
 * 1.3 Reporting-Endpoints 下发（G9）
 * report-to 指令依赖该响应头解析具名端点；仅在上报开启时下发，
 * 否则浏览器会为一个不存在的端点保留上报队列。
 */
const reportingEndpoints = (req, res, next) => {
  if (cspReportEnabled) {
    res.setHeader('Reporting-Endpoints', `csp-endpoint="${CSP_REPORT_PATH}"`);
  }
  next();
};

/**
 * 1.1 HSTS 兜底下发
 * helmet 默认仅在安全连接（HTTPS）下设置 Strict-Transport-Security。
 * 为保证反向代理/扫描器在任意入口都能看到该头，此处对未携带 HSTS 的响应统一下发；
 * 浏览器按 RFC 6797 只会采纳经 HTTPS 送达的 HSTS，明文下的头不构成安全风险。
 */
const ensureHsts = (req, res, next) => {
  if (!res.getHeader('Strict-Transport-Security')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
};

/**
 * 2. 数据清理 - MongoDB 注入防护（原地修改，兼容 Express 4.x getter-only req.query）
 * 清理请求中的 MongoDB 操作符，防止 NoSQL 注入
 */
// 递归深度上限：1mb 请求体可构造数千层嵌套，无上限的同步递归会被极端载荷
// 打爆调用栈（RangeError→500 资源骚扰）；超限分支直接整体丢弃该子树
const SANITIZE_MAX_DEPTH = 10;

const deepSanitizeKeys = (obj, depth = 0) => {
  if (!obj || typeof obj !== 'object') return;
  // 数组需逐元素递归清洗：数组本身不携带 $ 键，但其元素对象可能携带，
  // 直接跳过数组会让数组内对象的 $ 操作符成为漏网之鱼
  if (Array.isArray(obj)) {
    if (depth >= SANITIZE_MAX_DEPTH) {
      obj.length = 0;
      return;
    }
    obj.forEach((item) => deepSanitizeKeys(item, depth + 1));
    return;
  }
  // 跳过 Date、Buffer 等特殊对象
  if (obj instanceof Date || Buffer.isBuffer(obj)) return;
  if (depth >= SANITIZE_MAX_DEPTH) {
    for (const k of Object.keys(obj)) delete obj[k];
    return;
  }
  for (const key of Object.keys(obj)) {
    // 删除以 $ 开头或包含 . 的键（MongoDB 操作符/嵌套语法）；
    // 同时剔除 __proto__/constructor——JSON.parse 可产生同名自有属性，
    // 当前下游虽无对象合并消费点，显式剔除不依赖隐式前提
    if (
      key.startsWith('$') ||
      key.includes('.') ||
      key === '__proto__' ||
      key === 'constructor' ||
      key === 'prototype'
    ) {
      logger.warn(`MongoDB 注入尝试被拦截：键 "${key}"`);
      delete obj[key];
    } else {
      deepSanitizeKeys(obj[key], depth + 1);
    }
  }
};

const sanitizeMongo = (req, res, next) => {
  [req.body, req.query, req.params].forEach(deepSanitizeKeys);
  next();
};

/**
 * 4. HTTP 参数污染防护
 * 防止通过重复参数名进行攻击
 */
const hpp = require('hpp');
const preventHPP = hpp({
  // 不保留数组白名单：所有接口都消费标量 query；重复 key 由 hpp 收敛，
  // 对象/嵌套形态仍由 queryScalarGuard 拒绝，避免两道防线口径冲突。
  whitelist: [],
});

/**
 * 5. 敏感操作二次验证中间件
 * 对于敏感操作要求提供当前密码或 MFA 验证码，防止会话劫持后被冒用
 */
const requireReAuthentication = () => {
  return async (req, res, next) => {
    try {
      const { currentPassword, mfaCode } = req.body;

      if (!currentPassword && !mfaCode) {
        return ApiResponse.codeError(res, 'REAUTH_REQUIRED');
      }

      // 优先校验当前密码
      if (currentPassword) {
        const User = require('../models/User');
        const user = await User.findById(req.user.userId).select('+password');
        if (!user) {
          return ApiResponse.codeError(res, 'USER_NOT_FOUND');
        }
        const isValid = await user.comparePassword(currentPassword);
        if (!isValid) {
          logger.warn('敏感操作二次验证失败（密码错误）', { username: req.user.username });
          return ApiResponse.codeError(res, 'REAUTH_PASSWORD_INCORRECT');
        }
        req.reAuthenticated = true;
        return next();
      }

      // MFA 动态口令校验（I-06）：仅对已开启两步验证的用户生效
      const { verifyTotp } = require('../utils/totp');
      const { decryptMfaSecret } = require('../utils/mfaSecret');
      const User = require('../models/User');
      const user = await User.findById(req.user.userId).select('+mfaSecret');
      if (!user) {
        return ApiResponse.codeError(res, 'USER_NOT_FOUND');
      }
      if (!user.mfaEnabled) {
        return ApiResponse.codeError(res, 'REAUTH_MFA_NOT_ENABLED');
      }
      // 库内 mfaSecret 为 AES-GCM 密文（存量明文由 decryptMfaSecret 原样透传）
      if (!verifyTotp(decryptMfaSecret(user.mfaSecret), String(mfaCode || '').trim())) {
        logger.warn('敏感操作二次验证失败（MFA 验证码错误）', { username: req.user.username });
        return ApiResponse.codeError(res, 'REAUTH_MFA_INCORRECT');
      }
      req.reAuthenticated = true;
      return next();
    } catch (error) {
      logger.error(`二次验证失败：${error.message}`);
      return ApiResponse.codeError(res, 'REAUTH_PROCESS_FAILED');
    }
  };
};

/**
 * 6. IP 黑白名单检查（全站最高优先级访问控制闸门）
 *
 * 挂载位置：app.js 中 CORS 之前、body 解析之前（早于 securityHeaders/protocolCompliance
 * 等所有其他中间件）。黑名单命中立即 403，不读请求体、不做 CORS 协商、不生成安全头，
 * 把被封禁 IP 的资源消耗压到最低；白名单命中挂 req.ipWhitelisted，供后续所有限制类
 * 中间件（限流/来源校验/query 限制等）豁免。
 *
 * 持久化到 MongoDB，进程重启后不丢失。带进程内缓存：仅在 DB 故障时降级使用
 * （拦截已知恶意 IP），DB 正常时一律以库为准。
 */
// 进程内 IP 缓存：DB 故障时的降级手段（仅缓存已知被封禁的 IP）
// 注意：绝不能在 DB 正常时前置短路——否则管理员解除封禁或加入白名单后，
// 该 IP 仍会被陈旧缓存拦截最长 5 分钟（表现为「界面已解封但依然 403」）
const ipBlockCache = new Map(); // normalizedIp -> expiresAt
const IP_BLOCK_CACHE_TTL_MS = 5 * 60 * 1000;

const ipBlockCacheCleanupTimer = setInterval(
  () => {
    const now = Date.now();
    for (const [ip, expiresAt] of ipBlockCache.entries()) {
      if (expiresAt <= now) ipBlockCache.delete(ip);
    }
  },
  5 * 60 * 1000
);
// P3-36：此处原注释称「setInterval(...).unref?.() 返回 undefined」——实测不成立，
// Node 的 Timeout.unref() 返回 Timeout 自身（`t.unref() === t` 为 true），
// 链式写法同样能拿到句柄。保留「先存句柄再 unref」的写法理由是可读性与
// 可清理性：句柄需要在 gracefulShutdown 里 clearInterval，显式命名比
// 依赖 unref 的返回值更不易误改。
ipBlockCacheCleanupTimer.unref?.();

/**
 * 统一缓存键：归一化后存取，使 ::ffff:1.2.3.4 与 1.2.3.4 命中同一条目
 * @param {string} ip 原始 IP
 * @returns {string} 缓存键
 */
const ipCacheKey = (ip) => normalizeIP(ip) || String(ip);

/**
 * 失效降级缓存
 * 名单发生变更（解除封禁、加入白名单等）时调用，避免 DB 故障期沿用陈旧封禁判定。
 * 传入 CIDR 或不传时清空全部（无法从网段反推已缓存的具体 IP）
 * @param {string} [ip] 变更的 IP 或 CIDR；省略则全清
 */
const invalidateIPBlockCache = (ip) => {
  if (!ip || typeof ip !== 'string' || ip.includes('/')) {
    ipBlockCache.clear();
    return;
  }
  ipBlockCache.delete(ipCacheKey(ip));
};

/**
 * 记录「早于 auditLog 中间件的 403 拒绝」审计（P3-35）
 *
 * checkIPBlacklist 与 originCheck 都挂在 auditLog 之前（必须如此：黑名单要在
 * 一切业务处理前拦下，来源校验要在写操作触达控制器前拦下）。副作用是它们的
 * 403 完全不进审计——攻击探测最密集的这段流量在合规留存里是一片空白，
 * 事后既无法统计封禁命中，也无法证明拦截曾生效。
 *
 * 直写 AuditLog.record 而不走 auditBuffer：这类事件量小且属安全信号，
 * 需要即时可查（暴力探测检测也依赖实时性），与 ip_range_denied 同口径。
 * @param {import('express').Request} req
 * @param {{action: string, reason: string, riskFactors: string[], riskLevel?: string}} meta
 * @returns {void}
 */
const recordEarlyRejection = (req, meta) => {
  setImmediate(() => {
    try {
      AuditLog.record({
        action: meta.action,
        category: 'security',
        userId: req.user?.userId,
        username: req.user?.username || 'anonymous',
        sessionId: req.user?.sessionId || null,
        fingerprint: computeFingerprint(req),
        method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)
          ? req.method
          : undefined,
        path: auditPath(req),
        ip: req.ip,
        userAgent: stripControlChars(req.get('user-agent'), 512),
        statusCode: 403,
        success: false,
        riskLevel: meta.riskLevel || 'medium',
        riskFactors: meta.riskFactors,
        reason: stripControlChars(meta.reason, 512),
      });
    } catch (e) {
      logger.debug(`早期拒绝审计写入跳过：${e.message}`);
    }
  });
};

const checkIPBlacklist = async (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;

  try {
    const IPBlacklist = require('../models/IPBlacklist');

    // 黑白名单并行查询（两者共用模型层名单快照，单次加载即可完成两次匹配）
    const [isWhitelisted, isBlocked] = await Promise.all([
      IPBlacklist.isWhitelisted(clientIP),
      IPBlacklist.isBlocked(clientIP),
    ]);

    // 白名单优先：命中则豁免黑名单拦截，并挂标记供限流器豁免
    if (isWhitelisted) {
      req.ipWhitelisted = true;
      // 已被信任的 IP 不应留有封禁缓存，否则 DB 故障期会被误拦
      invalidateIPBlockCache(clientIP);
      return next();
    }

    if (isBlocked) {
      // 写入进程内缓存（5 分钟 TTL），供 DB 故障时降级使用
      ipBlockCache.set(ipCacheKey(clientIP), Date.now() + IP_BLOCK_CACHE_TTL_MS);
      logger.warn(`黑名单 IP 访问被拦截：${clientIP}`);
      recordEarlyRejection(req, {
        action: 'ip_blacklist_blocked',
        reason: '请求 IP 命中黑名单，已拒绝访问',
        riskFactors: ['ip_blacklisted'],
        riskLevel: 'high',
      });
      // 黑名单命中通知（可观测性轮）：按 IP 频控去重后投递 webhook，
      // fire-and-forget 不拖慢拦截路径
      try {
        const { shouldSendAlert, sendNotification } = require('../services/securityAlert');
        if (shouldSendAlert('blacklist_hit_' + clientIP)) {
          void sendNotification('ip_blacklist_hit', 'high', '黑名单 IP 访问被拦截：' + clientIP, {
            ip: clientIP,
            path: req.originalUrl,
          });
        }
      } catch (_) {
        /* 通知失败不影响拦截主流程 */
      }
      return ApiResponse.codeError(res, 'IP_BLOCKED');
    }

    // DB 查询成功且未命中黑名单：清除可能存在的陈旧缓存（解封后立即放行）
    invalidateIPBlockCache(clientIP);
  } catch (err) {
    // DB 故障时才启用降级缓存：仅拦截故障前已确认的恶意 IP，
    // 缓存未命中则放行（避免数据库抖动造成全站不可用），并记录告警
    logger.error(`IP 黑名单查询失败，降级到缓存模式：${err.message}`);
    const cachedExpiry = ipBlockCache.get(ipCacheKey(clientIP));
    if (cachedExpiry && cachedExpiry > Date.now()) {
      logger.warn(`黑名单 IP 访问被拦截（降级缓存）：${clientIP}`);
      recordEarlyRejection(req, {
        action: 'ip_blacklist_blocked',
        reason: '请求 IP 命中黑名单降级缓存（数据库查询失败），已拒绝访问',
        riskFactors: ['ip_blacklisted', 'blacklist_db_degraded'],
        riskLevel: 'high',
      });
      return ApiResponse.codeError(res, 'IP_BLOCKED');
    }
    // 评价报告 #7：fail-open 放行（缓存未命中）必须有显式可观测信号——
    // 否则「DB 挂了 + 全站裸奔」只有一条 error 日志可循。计入
    // security_alerts_total{type=ip_blacklist_failopen,level=high}，
    // 由 alert-rules 的「安全告警突增」规则捕获，运维可据此紧急处置。
    try {
      require('../utils/metrics').incSecurityAlert('ip_blacklist_failopen', 'high');
    } catch (_) {
      /* 指标端不可用不影响放行主流程 */
    }
    logger.warn(`IP 黑名单降级缓存未命中，fail-open 放行：${clientIP}`);
  }

  next();
};

/**
 * 动态添加 IP 到黑名单（持久化到 MongoDB）
 * 入库前归一化 IP：Node 在 IPv6 栈下 req.ip 形如 ::ffff:1.2.3.4，
 * 若原样入库会与管理员手动录入的 1.2.3.4 产生两条指向同一地址的记录
 * （复合唯一索引 { ip, type } 按文本判重，无法拦截），导致解封时漏删。
 * @param {string} ip - 要封禁的 IP
 * @param {number} durationMs - 封禁时长（毫秒），默认 1 小时
 * @param {string} reason - 封禁原因
 * @param {string} source - 封禁来源（manual/auto）
 */
const addToBlacklist = async (
  ip,
  durationMs = 3600000,
  reason = 'security_policy',
  source = 'manual'
) => {
  try {
    const IPBlacklist = require('../models/IPBlacklist');

    const normalizedIp = normalizeIP(ip);
    if (!normalizedIp) {
      logger.warn(`IP 黑名单添加跳过：无法解析的地址 ${ip}`);
      return;
    }

    // 白名单优先：信任 IP 不做自动封禁（如内网监控探针等可信来源的高频请求）
    const whitelisted = await IPBlacklist.isWhitelisted(normalizedIp).catch(() => false);
    if (whitelisted) {
      logger.info(`IP ${normalizedIp} 在白名单中，跳过自动封禁`);
      return;
    }

    await IPBlacklist.blockIP(normalizedIp, { reason, durationMs, source });
    logger.warn(
      `IP 已加入黑名单：${normalizedIp}, 封禁时长：${durationMs / 1000}秒, 原因：${reason}`
    );
  } catch (err) {
    logger.error(`IP 黑名单添加失败：${ip}, 错误：${err.message}`);
  }
};

/**
 * 8. 审计日志中间件
 * 记录所有敏感操作的详细日志，并持久化到 AuditLog 集合用于操作溯源
 *
 * 本中间件是请求型审计日志的唯一入口，自动从路由派生语义 category/action，
 * 控制器不再手动调用 AuditLog.record()，避免同一操作产生两条重复记录。
 *
 * 路径取值约束：category/action 派生与 excludePaths 判断统一使用 req.originalUrl
 * （见 utils/auditMeta）。Express 在 `app.use('/api/', mw)` + `router` 两级挂载下会
 * 逐层剥离 req.path，用 req.path 会导致全部记录退化为 category=system 且排除规则失效。
 */
const auditLog = (options = {}) => {
  const {
    operations = ['POST', 'PUT', 'DELETE', 'PATCH'],
    excludePaths = ['/api/auth/login', '/api/auth/refresh'],
    // 敏感读取路径白名单：GET 请求命中这些前缀时也走审计，但不记录请求体；
    // 报表导出/审计日志查询与导出为批量数据出口，必须纳入审计（补齐审计盲区）
    auditGetPaths = [
      '/api/security/config',
      '/api/users',
      '/api/roles',
      '/api/permissions',
      '/api/reports/export',
      '/api/security/audit-logs',
    ],
  } = options;

  return async (req, res, next) => {
    // 审计用的规范路径（含 /api 前缀，已去查询串）
    const fullPath = auditPath(req);

    // 跳过不需要审计的路径（登录/刷新由 authController 写专用事件型审计，
    // 此处必须用 fullPath 判断，否则排除失效会产生 anonymous 的重复记录）
    if (excludePaths.some((p) => fullPath === p || fullPath.startsWith(`${p}/`))) {
      return next();
    }

    // 判断是否为需审计的 GET 敏感读取（命中白名单前缀）
    const isGetAudit =
      req.method === 'GET' &&
      auditGetPaths.some((p) => fullPath === p || fullPath.startsWith(`${p}/`));

    // 只记录指定类型的操作，或命中 GET 审计白名单
    if (!operations.includes(req.method) && !isGetAudit) {
      return next();
    }

    // 控制器已手动记录（极少数特殊场景），跳过避免重复
    if (res.locals && res.locals.skipGlobalAudit) {
      return next();
    }

    // 记录开始时间
    const startTime = Date.now();

    // 保存原始 json 和 send 方法
    const originalJson = res.json.bind(res);
    const originalSend = res.send.bind(res);
    let logged = false;

    // 统一的审计日志记录逻辑
    const doLog = () => {
      if (logged) return; // 防止重复记录
      logged = true;

      const duration = Date.now() - startTime;
      // 用中间件入口已固化的 fullPath 派生：res.json 时刻 req.path 会被路由二次剥离，
      // 且 req.params 此时才有值，故路径必须取快照而非现读
      const { category, action } = deriveAuditMeta(req);
      const success = res.statusCode < 400;

      // 异步记录（不阻塞响应）
      setImmediate(() => {
        // 控制字符清洗：userAgent / params / query 为外部可控输入，
        // 含 \n \r \u0000 时会污染下游日志渲染与 SIEM 解析，入库前统一剥离
        const safeUserAgent = stripControlChars(req.get('user-agent'), 512);
        const safeParams = stripControlCharsDeep(req.params || {});
        const safeQuery = stripControlCharsDeep(req.query || {});
        const { computeFingerprint } = require('../utils/fingerprint');
        const fingerprint = computeFingerprint(req);

        // 1. winston 日志（运维查看）—— 仅写关联指针，不重复写完整审计体
        //    完整审计体已持久化到 AuditLog 集合，此处仅留 reqId 关联线索供日志检索
        logger.info(
          'AUDIT ref=audit act=' +
            action +
            ' reqId=' +
            (req.id || '-') +
            ' u=' +
            (req.user?.username || 'anon')
        );

        // 2. 持久化到 AuditLog 集合（操作溯源/合规留存）
        //    走缓冲批量写（auditBuffer），降低高频写操作下每请求一次 DB 写的入库压力；
        //    事件型审计（AuditLog.record）不经此路径，保持直写以保证暴力破解检测实时性
        const auditBuffer = require('../services/auditBuffer');
        auditBuffer.push({
          action,
          category,
          userId: req.user?.userId,
          username: req.user?.username || 'anonymous',
          sessionId: req.user?.sessionId || null,
          fingerprint,
          method: req.method,
          path: fullPath,
          params: safeParams,
          query: safeQuery,
          body: isGetAudit
            ? null
            : (() => {
                // 脱敏敏感字段（递归处理嵌套对象与数组，防止嵌套的密码/令牌明文入库）
                // #10：名单来自 models/auditLogSanitizer 单一事实来源（含 secret/apikey）
                const SENSITIVE_KEYS = AUDIT_SENSITIVE_KEYS;
                const sanitizeValue = (value, depth = 0) => {
                  // 深度保护，避免循环引用/超深嵌套导致栈溢出
                  if (depth > 6 || value === null || typeof value !== 'object') return value;
                  if (Array.isArray(value)) return value.map((v) => sanitizeValue(v, depth + 1));
                  const cleaned = {};
                  for (const [k, v] of Object.entries(value)) {
                    cleaned[k] = SENSITIVE_KEYS.some((s) => k.toLowerCase().includes(s))
                      ? '***'
                      : sanitizeValue(v, depth + 1);
                  }
                  return cleaned;
                };
                return stripControlCharsDeep(sanitizeValue(req.body || {}));
              })(),
          statusCode: res.statusCode,
          success,
          errorMessage: success ? undefined : stripControlChars(res.statusMessage, 512),
          ip: req.ip,
          userAgent: safeUserAgent,
          duration,
        });
      });
    };

    // 拦截 json 响应
    res.json = (body) => {
      doLog(body);
      return originalJson(body);
    };

    // 同时拦截 send 响应（如导出文件等场景）
    res.send = (body) => {
      doLog(body);
      return originalSend(body);
    };

    next();
  };
};

/**
 * 9. 文件上传安全检查
 * 验证上传文件的类型和大小
 *
 * 注意（预留能力）：当前项目暂无文件上传路由，本中间件尚未被任何路由挂载。
 * 未来引入文件上传功能时，必须在上传路由强制启用本中间件（配合 MIME 白名单、
 * 扩展名校验与大小限制），不可直接裸奔上传接口。
 */
const fileUploadSecurity = (options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024, // 默认 5MB
    allowedTypes = [],
  } = options;

  return async (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return next();
    }

    for (const file of req.files) {
      // 检查文件大小
      if (file.size > maxSize) {
        return ApiResponse.codeError(res, 'UPLOAD_FILE_TOO_LARGE', { message: `文件 ${file.originalname} 超过最大限制 ${maxSize / 1024 / 1024}MB`, params: { filename: file.originalname, maxSize: maxSize / 1024 / 1024 } });
      }

      // 检查文件类型
      if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
        return ApiResponse.codeError(res, 'UPLOAD_TYPE_NOT_ALLOWED', { message: `不允许的文件类型：${file.mimetype}`, params: { mimetype: file.mimetype } });
      }

      // 检查文件扩展名（防止 MIME 类型欺骗）
      const ext = file.originalname.split('.').pop().toLowerCase();
      const mimeToExt = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'application/pdf': 'pdf',
        'application/zip': 'zip',
      };
      // 过滤掉 undefined 值，只保留有效的扩展名
      const allowedExts = allowedTypes.map((t) => mimeToExt[t]).filter(Boolean);

      if (allowedExts.length > 0 && !allowedExts.includes(ext)) {
        return ApiResponse.codeError(res, 'UPLOAD_EXT_NOT_ALLOWED', { message: `不允许的文件扩展名：.${ext}`, params: { ext: ext } });
      }
    }

    next();
  };
};

/**
 * 10. 会话安全配置
 * 注意：本项目使用 JWT 认证，不使用 session。此配置仅作参考。
 * 如需启用 session，请使用 express-session 并配置下方选项。
 */

/**
 * 启动期断言：审计 category 枚举一致性防护
 *
 * ROUTE_CATEGORY_MAP（路由前缀 → category 映射）的取值必须全部落在
 * AuditLog schema 的 category enum 内；否则该分类的审计记录会因
 * ValidationError 被 insertMany({ordered:false}) 静默丢弃，形成审计盲区。
 * 不一致时直接抛出错误阻止启动（带病启动不如启动失败），不修改任何映射值。
 */
const assertAuditCategoryConsistency = () => {
  const AuditLog = require('../models/AuditLog');
  const allowed = AuditLog.schema.path('category').enumValues;
  const mapped = [...new Set(Object.values(ROUTE_CATEGORY_MAP))];
  const invalid = mapped.filter((cat) => !allowed.includes(cat));
  if (invalid.length > 0) {
    throw new Error(
      `审计 category 枚举不一致：ROUTE_CATEGORY_MAP 中的 [${invalid.join(', ')}] ` +
        `不在 AuditLog.schema category enum [${allowed.join(', ')}] 内，` +
        '该分类审计记录将被静默丢弃，请同步两侧取值后再启动'
    );
  }
};

/**
 * 挂载「不依赖已解析 body」的安全中间件（P3-35）
 *
 * 拆分原因：protocolCompliance 的设计意图之一是「Content-Length 超限早于 body
 * 解析即拒绝，避免无谓读流」，但此前整个 applySecurity 挂在 express.json()
 * **之后** —— body 已经被完整读入并解析完，该项收益完全不存在，注释与行为背离。
 * 头部卫生/方法白名单/Host 校验同理：越早拒绝，下游解析器暴露面越小。
 *
 * securityHeaders 等响应头中间件一并前置，使被拒绝的 4xx 响应同样带安全头。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyPreBodySecurity = (app) => {
  // 启动期防护：审计分类映射与模型枚举不一致时拒绝启动，避免审计静默丢失
  assertAuditCategoryConsistency();

  // nonce 必须先于 securityHeaders 挂载：helmet 写 CSP 头时读取 res.locals.cspNonce
  app.use(attachCspNonce);
  app.use(securityHeaders);
  app.use(ensureHsts);
  app.use(permissionsPolicy);
  app.use(reportingEndpoints);
  // 协议合规校验：置于 body 解析之前，畸形请求早拒绝、不进入下游解析
  const { protocolCompliance } = require('./protocolCompliance');
  // 评价报告低危项：Content-Length 上限与 express.json 的 body 上限（1mb）
  // 对齐——原默认 10MB 让 1MB~10MB 的请求在协议层放行后又被 body 解析
  // 413 拒掉，两道闸门口径不一，审计里的拒绝原因也不一致。
  // 业务载荷均为小表单（无文件上传端点），1MB 是两层的统一收口。
  app.use(protocolCompliance({ maxContentLength: 1024 * 1024 }));
};

/**
 * 挂载「需要已解析 body/query」的安全中间件（P3-35）
 *
 * 注意：checkIPBlacklist 已移至 app.js 中 CORS 之前独立挂载（见 app.js），
 * 是全站最早的访问控制闸门——黑名单在 body 解析/CORS/安全头/限流之前即拒绝，
 * 白名单标记 req.ipWhitelisted 在此处之前已就绪，供后续所有限制类中间件豁免。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyPostBodySecurity = (app) => {
  app.use(sanitizeMongo);
  // JSON API 不做全局输入转义，转义责任在输出层（前端渲染/报表导出）
  app.use(preventHPP);
};

/**
 * 一次性挂载全部安全中间件（保留给不区分 body 解析阶段的调用方，如测试）
 * @param {import('express').Application} app
 * @returns {void}
 */
const applySecurity = (app) => {
  applyPreBodySecurity(app);
  applyPostBodySecurity(app);
};

module.exports = {
  securityHeaders,
  attachCspNonce,
  ensureHsts,
  permissionsPolicy,
  reportingEndpoints,
  CSP_REPORT_PATH,
  cspReportEnabled,
  sanitizeMongo,
  preventHPP,
  requireReAuthentication,
  checkIPBlacklist,
  addToBlacklist,
  invalidateIPBlockCache,
  auditLog,
  fileUploadSecurity,
  recordEarlyRejection,
  applySecurity,
  applyPreBodySecurity,
  applyPostBodySecurity,
};
