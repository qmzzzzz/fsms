/**
 * 安全增强中间件模块
 * 提供多层次的安全防护机制
 */

const crypto = require('crypto');
const helmet = require('helmet');
const logger = require('../utils/logger');
const ApiResponse = require('../utils/apiResponse');
const {
  stripControlChars,
  stripControlCharsDeep,
  matchesAnyPathPrefix,
} = require('../utils/helpers');
// 白名单豁免标记的可信边界判定已收口到 ipUtils（认证侧 allowedIPs 与这里共用同一把尺）
const { normalizeIP, isClientIpIdentityTrustworthy } = require('../utils/ipUtils');
const { auditPath, deriveAuditMeta, ROUTE_CATEGORY_MAP } = require('../utils/auditMeta');
// T-1：顶层引入——recordEarlyRejection 经 setImmediate 异步写审计，回调可能在
// 测试环境销毁后执行，惰性 require 会抛「import after torn down」
const AuditLog = require('../models/AuditLog');
const { computeFingerprint } = require('../utils/fingerprint');
// #10：脱敏判定单一事实来源——与 models/auditLogSanitizer.js 复用同一个
// 键名判定函数（原内联名单缺 secret/apikey，同一审计体两条路径脱敏口径不一、
// 可能明文入库）。这里接的是**函数**而不是名单数组：名单一致而判定口径不一致
// （子串匹配 vs 整键相等）会漂移回同一个洞。
// body 的递归遍历逻辑本模块各自保留（要与自身的深度/占位策略对齐）；
// params/query 直接复用 sanitizeAuditQuery，不再各抄一份名单判定
// （它是 body 名单 ∪ 查询专用名单的并集口径，比 sanitizeAuditBody 宽一档）。
const { isBodySensitiveKey, sanitizeAuditQuery } = require('../models/auditLogSanitizer');

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

// 路径前缀判定用全仓同一把尺（按段边界 + 大小写不敏感）：Express 5 默认大小写不敏感路由，
// 手写的 `=== / startsWith` 会让 `/API-docs` 命中 Swagger 路由却判为"非文档路径"，
// 于是那条响应拿不到它必需的 'unsafe-inline'（方向是变严、不是漏洞，但两处口径不一致）。
const isSwaggerDocsPath = (req) => matchesAnyPathPrefix([SWAGGER_PATH_PREFIX], req.path);

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
 * 2. 数据清理 - MongoDB 注入防护
 * 清理请求中的 MongoDB 操作符，防止 NoSQL 注入
 *
 * ⚠ Express 5 前提（P1-33 修正，2026-09-17；2026-09-30 收口）：req.query 是 getter
 * （node_modules/express/lib/request.js 的 defineGetter(req, 'query', ...)），
 * 每次访问都重新解析 URL 查询串。因此本中间件对 req.query 的**原地赋值无效**，
 * 且实测比"下次访问才丢"更彻底——同一 handler 同一 tick 内回读就已经是全新对象。
 *
 * 2026-09-30 起 query 侧改由 materializeQuery 收口：读一次 → 清洗 → 物化成自有
 * 数据属性 → **回读自证身份**。本中间件不再遍历 req.query（写了也是空操作，
 * 留着只会让人误以为 query 有两道防线）。
 *
 * req.body 与 req.params 是普通自有属性，原地清洗对它们确实生效。
 *
 * 注意：本中间件的单测用**手搓的 req 桩对象**，而桩上的 query 是普通属性——
 * 所以那组单测**结构上不可能**发现上面这条 Express 5 前提。
 * 「物化真的生效」由 src/tests/app/queryDefenseSingleSource.test.js 在**真实
 * express 实例**上钉住（真实 getter + 真实 supertest），不接受桩。
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
  // **刻意不含 req.query**：Express 5 下 req.query 是原型上的 getter
  // （express/lib/request.js: defineGetter(req, 'query', ...)），每次访问都重新解析
  // URL 查询串，因此对它的原地清洗是**彻底无效的**——实测（Express 5.2.1 + supertest）
  // `delete req.query.search` 之后**同一 handler 同一 tick** 内 `Object.keys(req.query)`
  // 仍然读得到 `search`。
  //
  // 此处此前把 req.query 一起遍历（写作"对 body/params/query 都生效"），读代码的人
  // 会以为 query 有两道防线，实际其中一道从未存在过。已移交给 materializeQuery：
  // 它把解析结果物化成**自有数据属性**，清洗与"物化真的生效"由运行时自证。
  //
  // 必须显式包一层箭头函数：forEach 的实参是 (元素, 下标, 数组)，
  // 直接传函数引用会把**下标**当成 deepSanitizeKeys 的 depth 入参——
  // body 从 0 起算（正确），params 从 1 起算，于是 params 的可用嵌套预算凭空少 1 层：
  // 第 9 层子树就被整体清空，而注释承诺的是「SANITIZE_MAX_DEPTH 层内不误伤」。
  // 方向上仍偏保守（超限是删除而非放行），所以不是注入缺口，是数据损失 + 契约不符。
  [req.body, req.params].forEach((part) => deepSanitizeKeys(part));
  next();
};

/**
 * 2.5 req.query 物化 —— Express 5 下 query 侧唯一的收口点
 *
 * 解决的问题：`req.query` 是原型上的 getter，每次访问都从 `req.url` 重新解析。
 * 于是任何"清洗后再消费"的写法都不成立——清洗写在某次访问返回的临时对象上，
 * 下一个消费者拿到的是全新解析结果。Express 4 上（getter 内部有缓存）这是成立的，
 * v5 把缓存去掉后，全仓既有的 sanitizeMongo + hpp 的 query 分支**同时变成空操作**，
 * 而它们仍留在挂载链上，看起来像两道防线。
 *
 * 做法：读一次（触发唯一一次解析）→ 原地清洗（复用 deepSanitizeKeys，与 body/params
 * 同一份实现，不另造第二套规则）→ 用 defineProperty 把这个对象**物化**成 req 的自有
 * 数据属性，遮蔽原型 getter。此后所有消费者读到的是同一份、已清洗的快照。
 *
 * 为什么必须自证（这是本中间件与「注释里说它有效」的根本区别）：
 * 物化成不生效只有两种可能——defineProperty 抛错（req 被冻结），或将来 Express 改了
 * 实现让自有属性不再遮蔽原型 getter。两者都不会有任何报错，只会让防线**静默归零**，
 * 而这正是本仓吃过一次亏的形态（P1-33：防线失效是被 e2e 白屏偶然发现的，不是被发现的）。
 * 所以每次物化后立即回读比对身份，不等即**拒绝本次请求**并 error 级留痕——
 * 「服务不可用」远好过「带着未清洗的 query 把请求处理下去」。
 *
 * 附带收益：解析次数从「每个消费者一次」（sanitizeMongo / hpp / queryScalarGuard /
 * queryLengthLimit / 各控制器各一次）降到全请求一次，query 键多时省掉的是实打实的
 * URL 重复解析与 GC 压力。
 *
 * 挂载位置（src/app.js）：必须在 queryScalarGuard 与 queryLengthLimit **之前**
 * （它们要读清洗后的形态），且在 auditLog 之前（审计落盘的 query 快照应当是清洗后的）。
 */
const materializeQuery = () => {
  return (req, res, next) => {
    let parsed;
    try {
      // 触发原型 getter，产出本次请求唯一一次解析结果
      parsed = req.query;
    } catch (parseErr) {
      // getter 内部抛错（query parser 配置错误等）：此时没有任何可清洗的形态，
      // 继续下去等于把未处理异常留给控制器伪装成业务 500。
      logger.error(`req.query 解析失败，拒绝本次请求：${parseErr.message}`, {
        reqId: req.id,
      });
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    if (!parsed || typeof parsed !== 'object') {
      // query parser 被配成 false（Express 语义：解析禁用）时 getter 返回
      // Object.create(null)，仍需物化——否则下面所有消费者各自触发一次解析。
      parsed = {};
    }

    // 原地清洗：与 req.body / req.params 复用同一份 deepSanitizeKeys，
    // 保证三处的键判定规则（$ 前缀、含 .、__proto__/constructor/prototype）不会分叉
    deepSanitizeKeys(parsed);

    try {
      Object.defineProperty(req, 'query', {
        value: parsed,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch (defineErr) {
      logger.error(
        `req.query 物化失败（defineProperty 抛错），拒绝本次请求：${defineErr.message}`,
        {
          reqId: req.id,
        }
      );
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    // 自证：回读必须拿到**同一个对象**。不相等意味着物化没生效——
    // 继续服务等于宣称"已清洗"而实际未清洗，是本仓最忌讳的那类谎报。
    if (req.query !== parsed) {
      logger.error(
        'req.query 物化未生效（回读身份不一致）：req.query 仍为原型 getter 或被框架重新定义。' +
          'query 注入防线此刻为零，拒绝本次请求而非放行',
        { reqId: req.id }
      );
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    return next();
  };
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
      // `|| {}` 不是防御性冗余：Express 5 在 JSON 解析器跳过时把 req.body 留成
      // undefined（v4 恒为 {}），对 undefined 解构抛 TypeError 并被下面的 catch 吞成 500——
      // "客户端根本没带凭证"这一正常拒绝因此伪装成服务端故障（还按 UnhandledError 记 error 日志）。
      const { currentPassword, mfaCode } = req.body || {};

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
      //
      // 原实现走裸 `verifyTotp`（只回布尔），既不烧时间窗计数器也不记失败，
      // 于是同一个合法码在 ±1 窗口（约 90s）内可**无限次重放**通过步进验证，
      // 且错误尝试不计数、不锁定——而 6 位码空间只有 10^6。
      // 现对齐仓内既有两处实现：authService.verifyTotpChallenge 的 P2-12 原子消费
      // （以 `mfaLastCounter < counter` 为条件的更新，只有第一个请求能命中，
      //  并发双花由 DB 兜底），以及 mfaService 的失败计数 + 阈值锁定。
      // 与登录共用同一个 mfaLastCounter 字段是有意的：同一个码不得在两个上下文各用一次。
      const { verifyTotpDetailed } = require('../utils/totp');
      const { decryptMfaSecret } = require('../utils/mfaSecret');
      const mfaService = require('../services/mfaService');
      const User = require('../models/User');

      if (await mfaService.isMfaLocked(req.user.userId)) {
        logger.warn('敏感操作二次验证被拒（MFA 通道临时锁定中）', {
          username: req.user.username,
        });
        return ApiResponse.codeError(res, 'MFA_ATTEMPTS_EXCEEDED');
      }

      const user = await User.findById(req.user.userId).select('+mfaSecret');
      if (!user) {
        return ApiResponse.codeError(res, 'USER_NOT_FOUND');
      }
      if (!user.mfaEnabled) {
        return ApiResponse.codeError(res, 'REAUTH_MFA_NOT_ENABLED');
      }
      // 库内 mfaSecret 为 AES-GCM 密文（存量明文由 decryptMfaSecret 原样透传）
      // mfaCode 此处必为真值：上面的守卫要求"密码与验证码至少有一个"，而密码分支已 return。
      const totpResult = verifyTotpDetailed(
        decryptMfaSecret(user.mfaSecret),
        String(mfaCode).trim()
      );
      let claimedCounter = false;
      if (totpResult.valid) {
        const advanced = await User.findOneAndUpdate(
          {
            _id: user._id,
            $or: [
              { mfaLastCounter: { $lt: totpResult.counter } },
              { mfaLastCounter: { $exists: false } },
              { mfaLastCounter: null },
            ],
          },
          { $set: { mfaLastCounter: totpResult.counter } },
          { new: true }
        ).catch(() => null);
        claimedCounter = !!advanced;
      }
      if (!totpResult.valid || !claimedCounter) {
        // 重放与口令错误同样计入失败并按同一码拒绝：不向调用方区分
        // "码正确但已消费"，否则本端点又变成一个验证码探测面。
        await mfaService.recordMfaFailure(user);
        logger.warn('敏感操作二次验证失败（MFA 验证码错误或重放）', {
          username: req.user.username,
          replayed: totpResult.valid && !claimedCounter,
        });
        return ApiResponse.codeError(res, 'REAUTH_MFA_INCORRECT');
      }
      await mfaService.resetMfaFailures(user._id);
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
 * 统一缓存键：归一化后存取，使 ::ffff:1.2.3.4 与 1.2.3.4 命中同一条目。
 * 归一化失败并到一个共享占位键而不是回退原文——原文可能是请求方写的 XFF，
 * 逐请求换文本会把本缓存撑成无上限的键集（口径同 rateLimit.js）。
 * @param {string} ip 原始 IP
 * @returns {string} 缓存键
 */
const ipCacheKey = (ip) => normalizeIP(ip) || 'unknown';

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
 * @param {{action: string, reason: string, riskFactors: string[], riskLevel?: string, statusCode?: number}} meta
 *        statusCode 缺省 403（黑名单/来源这两类都是拒绝式 403）；
 *        查询形态守卫那类是 400，必须传真实值——审计里记错状态码，
 *        等于让事后统计把"畸形请求被拒"算成"越权被拒"。
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
        // method 原样交下去：取值全集与"越枚举怎么办"由 AuditLog schema
        // （constants/audit.js 的 AUDIT_HTTP_METHODS + setter）单点决定。
        // 原先这里私抄一份 5 动词白名单，把 HEAD/OPTIONS 探测**静默降级成无 method 的记录**，
        // 而这类探测恰恰是安全信号——事后看不出它是 HEAD。
        method: req.method,
        path: auditPath(req),
        ip: req.ip,
        userAgent: stripControlChars(req.get('user-agent'), 512),
        statusCode: meta.statusCode || 403,
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

/**
 * 白名单豁免标记（req.ipWhitelisted）的**可信边界**判定（2026-09-26 审计 Top3）
 *
 * 为什么需要：req.ip 在 TRUST_PROXY_HOPS>0 时取自 X-Forwarded-For（生产 compose
 * 默认 1 跳），能直连应用端口的主体（容器网络、误配入口、SSRF 跳板）伪造一跳
 * XFF 即可把 req.ip 变成任意白名单 IP——该标记会被资源型限流（rateLimit.js 的
 * skipIfWhitelisted）、CSRF 来源校验（originCheck.js）、query 长度限制
 * （queryLimit.js queryLengthLimit）同时豁免，一次伪造拿到三重豁免（伪造实测
 * 口径见 tests 的 laneE/xffCredentialLimiter）。修复范式与 metricsAuth 的 M-07
 * 同源：安全豁免只信**不可伪造的 socket 对端**。
 *
 * 三种可发放形态（其余一律不发，宁可不豁免也不能被伪造头买通）：
 *  1) 未启用 trust proxy：req.ip 恒等于 socket 对端，请求头不参与判定；
 *  2) 请求未携带 X-Forwarded-For：即使 trust proxy 开着，req.ip 也只能是 socket 对端；
 *  3) trust proxy 开启且携带 XFF：req.ip 来自请求头，只有 socket 对端属于
 *     内网/回环（即 nginx/容器网络等基础设施，与 metricsAuth 的放行口径一致）时，
 *     该 XFF 才是可信代理写入的（生产 nginx 覆写 `X-Forwarded-For $remote_addr`）。
 * 经 nginx 的正常流量命中 3) ⇒ 办公网 IP 白名单功能不受影响；
 * 公网直连 + 伪造 XFF 落在 3) 的拒绝侧 ⇒ 三重豁免不再可用。
 *
 * 判据本体自 2026-10-01 移到 utils/ipUtils.js 的 `isClientIpIdentityTrustworthy`
 * （理由见那里的头注释：认证侧的 allowedIPs 与豁免发放是同一条伪造链的两侧，必须
 * 共用一个事实来源）。本文件保留同名再导出，消费方与既有断言口径不变。
 *
 * 顺带更正本注释的一处旧推断：原先写「黑名单/封禁判定由网络层兜底（仅 nginx 可达
 * 应用端口）」——这个前提在随仓交付的 compose 拓扑里不成立：`docker-compose.yml`
 * 把应用端口发布为 `127.0.0.1:3000:3000`，同一容器网络内的任意服务都能直连 `app:3000`，
 * 其对端地址恰是 RFC1918 ⇒ 命中上面的可信形态 3) ⇒ 单个 XFF 即可把处置目标换成任意
 * 地址。惩罚侧（自动封禁的归属判定）因此不能再靠"网络层兜底"这句话免责。
 *
 * @param {import('express').Request} req
 * @returns {boolean} true=可发放豁免标记
 */
const isWhitelistExemptionTrustworthy = (req) => isClientIpIdentityTrustworthy(req);

const checkIPBlacklist = async (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;

  try {
    const IPBlacklist = require('../models/IPBlacklist');

    // 黑白名单并行查询（两者共用模型层名单快照，单次加载即可完成两次匹配）
    const [isWhitelisted, isBlocked] = await Promise.all([
      IPBlacklist.isWhitelisted(clientIP),
      IPBlacklist.isBlocked(clientIP),
    ]);

    // 白名单优先：命中则豁免黑名单拦截，并挂标记供限流器豁免。
    // 豁免标记只在可信边界内发放（见 isWhitelistExemptionTrustworthy）：
    // 命中但边界不可信时**不发放标记、也不拦截请求**——限流与来源校验照常生效，
    // 只损失"不该有的豁免"，不产生可用性回退
    if (isWhitelisted) {
      if (isWhitelistExemptionTrustworthy(req)) {
        req.ipWhitelisted = true;
      } else {
        logger.warn(
          `白名单命中但来源边界不可信（公网直连且携带 X-Forwarded-For），豁免标记不下发：${clientIP}`
        );
      }
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
      // fire-and-forget 不拖慢拦截路径。
      // F-214：这里必须走统一入口 dispatchNotification，不能写成
      // `void sendNotification(...)`。裸调的 promise 没有 catch，而**下面这个
      // try 抓不到异步 reject**（async 函数不抛异常，它返回 rejected promise），
      // 于是「通知失败不影响主流程」这句注释在裸 void 下是不成立的：它会命中
      // index.js 的 unhandledRejection 分支，而那条分支在所有环境都 process.exit(1)。
      // 换成统一入口之后这个 try/catch 才真的闭合：它覆盖的是 require 与
      // shouldSendAlert 两处同步抛点，没有逃逸的异步路径。
      try {
        const { shouldSendAlert, dispatchNotification } = require('../services/securityAlert');
        if (shouldSendAlert('blacklist_hit_' + clientIP)) {
          dispatchNotification('ip_blacklist_hit', 'high', '黑名单 IP 访问被拦截：' + clientIP, {
            ip: clientIP,
            path: req.originalUrl,
          });
        }
      } catch (_) {
        /* 通知失败不影响拦截主流程（同步部分；异步部分由统一入口的 catch 负责） */
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
 * @returns {Promise<{banned: boolean, reason?: string, normalizedIp?: string}>}
 *   本函数**从不抛错**（内部自己 catch 掉持久化失败），所以"await 正常返回"绝不等于"封禁生效"。
 *   成功与否只能靠这个返回值判断，调用方不得按"没抛异常"记成功：
 *   - `{banned:true, normalizedIp}`：黑名单已落库；
 *   - `{banned:false, reason}`：一条记录都没写，reason ∈ unparsable_ip / whitelisted / persist_failed。
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
      return { banned: false, reason: 'unparsable_ip' };
    }

    // 白名单优先：信任 IP 不做自动封禁（如内网监控探针等可信来源的高频请求）
    const whitelisted = await IPBlacklist.isWhitelisted(normalizedIp).catch(() => false);
    if (whitelisted) {
      logger.info(`IP ${normalizedIp} 在白名单中，跳过自动封禁`);
      return { banned: false, reason: 'whitelisted' };
    }

    await IPBlacklist.blockIP(normalizedIp, { reason, durationMs, source });
    logger.warn(
      `IP 已加入黑名单：${normalizedIp}, 封禁时长：${durationMs / 1000}秒, 原因：${reason}`
    );
    return { banned: true, normalizedIp };
  } catch (err) {
    logger.error(`IP 黑名单添加失败：${ip}, 错误：${err.message}`);
    return { banned: false, reason: 'persist_failed' };
  }
};

/**
 * 8. 审计日志中间件
 * 记录所有敏感操作的详细日志，并持久化到 AuditLog 集合用于操作溯源
 *
 * 本中间件是请求型审计日志的默认入口，自动从路由派生语义 category/action。
 * 例外：需要专用语义/字段的动作（密码修改、敏感数据查看、IP 名单变更、审计链
 * 校验等）由控制器手写 AuditLog.create 并置 res.locals.skipGlobalAudit，跳过
 * 本中间件，避免同一操作产生两条重复记录。该标志共 11 处赋值点
 * （securityController 8 / ipListController 2 / auditController 1，2026-09-17 实测）。
 * P0-5 修复（2026-09-17）：标志必须在**响应时刻**读取（见 doLog）——控制器赋值
 * 发生在本中间件入口之后，入口处读取必然早于赋值。原实现正是在入口只读一次，
 * 标志 100% 失效：每个这类操作都被双写（控制器手写 1 条 + 本中间件按路由再写
 * 1 条，且两条 action/category 不同）。
 *
 * 路径取值约束：category/action 派生与 excludePaths 判断统一使用 req.originalUrl
 * （见 utils/auditMeta）。Express 在 `app.use('/api/', mw)` + `router` 两级挂载下会
 * 逐层剥离 req.path，用 req.path 会导致全部记录退化为 category=system 且排除规则失效。
 *
 * 敏感读取判据（2026-09-30 反转，收口审计报告 §3.4）：GET/HEAD **默认全量审计**，
 * 仅 auditGetExcludePaths 清单显式豁免。原实现是 6 条前缀的**允许清单**（auditGetPaths），
 * 失效形态是 fail-open：新增一条敏感 GET 路由而忘记登记，它就零留痕——设备/报警/
 * 巡检的列表与详情正是一批这样的盲区（HEAD 归一修复只救了已登记的 6 条前缀；列表
 * 与详情共用派生 action `*_view`，无需新增 action 登记；tests/constants/
 * auditActionReachability 的 A 类 25 条即反转前实测的盲区清单，反转后剩 9 条）。
 * 反转后默认 fail-closed：新路由不做任何登记即被审计；想豁免必须在清单里写明理由，
 * 归入口径只有两类：
 *   a) 预认证/登录流程面——无业务数据，调用频率由认证流程决定（每次登录页、
 *      每次登录尝试都打），审计只灌大集合，证据价值由 login_failed/封禁事件承担；
 *   b) 纯自读面——返回的只是**请求者本人**的会话/绑定/日志状态，且被前端在每次
 *      导航时轮询；数据主体即请求者，他人读不到，操作留痕由写路径承担（改密/
 *      MFA 变更/踢会话均为写方法，照常审计）。
 * 已知取舍（如实记录）：看板若轮询设备/报警列表，每次轮询都是一条审计记录——真
 * 发生时按上面口径逐条评估后加入豁免清单，而不是回退到允许清单；匿名/未匹配路径
 * 的 GET 探测也会留痕（与既有 /api/users 行为一致），这正是探测证据。
 */
const auditLog = (options = {}) => {
  // 延迟 require：originCheck 顶层就 require 了本模块（recordEarlyRejection），
  // 反向在顶层 require 会成环拿到半初始化导出
  const { WRITE_METHODS } = require('./originCheck');
  const {
    // 写操作口径的单一事实来源（原此处再写一遍四个方法名，与 originCheck 的 CSRF 闸
    // 各自漂移过：一处加了方法，另一处就出现"拦了但没审计"/"审计了但没拦"）
    operations = WRITE_METHODS,
    excludePaths = ['/api/auth/login', '/api/auth/refresh'],
    // GET/HEAD 敏感读取的**豁免清单**：默认全量审计，命中才跳过（口径与反转依据
    // 见本中间件头部注释）；GET 审计不记录请求体。
    // P0-6 修复（2026-09-17）历史备注：导出类响应只经过 write/end 而非 json/send，
    // 响应包装现覆盖 write/end——本反转不影响该修复，报表/审计导出照常被审计。
    auditGetExcludePaths = [
      // a) 预认证/登录流程面
      '/api/auth/captcha',
      '/api/auth/captcha-status',
      '/api/auth/login-public-key',
      '/api/auth/mfa/status', // 登录第二步轮询
      // b) 纯自读面（数据主体即请求者本人 + 前端高频轮询）
      '/api/auth/session', // 前端路由守卫每次导航轮询
      '/api/auth/me',
      '/api/auth/sessions', // 踢会话是 DELETE（写方法），仍审计
      '/api/security/my-info',
      '/api/security/bindings',
      '/api/security/my-logs',
    ],
  } = options;

  return async (req, res, next) => {
    // 审计用的规范路径（含 /api 前缀，已去查询串）
    const fullPath = auditPath(req);

    // 跳过不需要审计的路径（登录/刷新由 authController 写专用事件型审计，
    // 此处必须用 fullPath 判断，否则排除失效会产生 anonymous 的重复记录）
    if (matchesAnyPathPrefix(excludePaths, fullPath)) {
      return next();
    }

    // 判断是否为需审计的 GET/HEAD 敏感读取：**默认审计，命中豁免清单才跳过**。
    // 必须与路由同尺（大小写不敏感）：GET /API/reports/export 真实执行导出，
    // 若这里做大小写敏感比较，改一个字母大小写即可静默批量取数而零留痕
    // （反转后同尺的意义不变：改大小写换来的只是一条审计记录，不是静默）。
    //
    // HEAD 与 GET 同判：Express 的 Route.dispatch 把 HEAD 归一成 GET
    // （`if (method === 'HEAD') method = 'GET'`），所以 `app.get('/api/reports/export')`
    // 的处理函数对 HEAD **全量执行**——报表导出把 workbook 完整生成一遍、Node 只是
    // 不把响应体写出去。原先只认 `req.method === 'GET'` 时，HEAD 是一条既跑了业务、
    // 又零留痕的口子。实测（真实 createApp，带 user:read 的合法令牌）：
    // GET /api/users 审计增量 1、HEAD /api/users 审计增量 0。反转后 HEAD 与 GET
    // 走同一份豁免清单，整类口子随反转一起闭合。
    // HEAD 已在 constants/audit.js 的 AUDIT_HTTP_METHODS 里，不需要动 schema。
    const isGetAudit =
      (req.method === 'GET' || req.method === 'HEAD') &&
      !matchesAnyPathPrefix(auditGetExcludePaths, fullPath);

    // 只记录指定类型的操作，或未豁免的 GET/HEAD 敏感读取
    if (!operations.includes(req.method) && !isGetAudit) {
      return next();
    }

    // 记录开始时间
    const startTime = Date.now();

    // 保存原始响应方法。统一先 bind 到 res：包装器可能被以任意 this 调用，
    // 且 res.send 内部会再调 res.end，绑定后行为与原生一致。
    const originalJson = res.json.bind(res);
    const originalSend = res.send.bind(res);
    // P0-6：导出类响应只经过 write/end，不经 json/send。部分响应替身
    // （如既有测试的 makeRes()）没有这两个方法，缺失时不包装。
    const originalWrite = typeof res.write === 'function' ? res.write.bind(res) : null;
    const originalEnd = typeof res.end === 'function' ? res.end.bind(res) : null;
    let logged = false;

    // 统一的审计日志记录逻辑
    const doLog = () => {
      // logged 先置位再判定：res.send 内部会调 res.end，第二次进入必须在
      // skip 判定之前就被守卫吃掉，避免重复判定与重复记录
      if (logged) return; // 防止重复记录
      logged = true;

      // P0-5 修复（2026-09-17）：skipGlobalAudit 在**响应时刻**读取。
      // 原实现在中间件入口只检查一次，而 11 处赋值点都在控制器内部、响应之前
      // 才写 res.locals —— 入口检查永远早于赋值，标志 100% 失效，每个这类操作
      // 都被双写（控制器手写 1 条 + 本中间件按路由再写 1 条，action/category 不同）。
      if (res.locals && res.locals.skipGlobalAudit) {
        return; // 控制器已手动记录，本条操作跳过全局审计
      }

      const duration = Date.now() - startTime;
      // 用中间件入口已固化的 fullPath 派生：res.json 时刻 req.path 会被路由二次剥离，
      // 且 req.params 此时才有值，故路径必须取快照而非现读
      const { category, action } = deriveAuditMeta(req);
      // 状态码在流式响应里早在第一个 chunk 之前就已发出（200），此后出错无法回改。
      // 于是"半截 CSV/半截 Excel"会被记成一次**成功导出**——而审计库正是事后追责的
      // 依据，不能替失败的导出背书。由 errorHandler 与导出控制器在"错误终止响应"时
      // 显式打这个标记（人读的原因走 logger.error，这里只翻转机器可读的结论）。
      const abortedAfterHeaders = Boolean(res.locals && res.locals.responseAbortedByError);
      const success = res.statusCode < 400 && !abortedAfterHeaders;
      // 告诉错误处理器"这条审计已经落出去了"：流式响应在**第一个 chunk** 时就记一条
      // （P0-6 的刻意设计，崩溃也不丢记录），且 auditBuffer.push 会同步写 WAL，
      // 之后再改内存对象只会让 WAL 与库不一致。所以事后失败只能追加一条更正事件，
      // 不能就地翻转——这正是 append-only 审计的正确形态。
      if (res.locals) res.locals.auditRecordWritten = true;

      // 异步记录（不阻塞响应）；回调体见模块级 persistAuditRecord（体积棘轮拆分）
      setImmediate(() =>
        persistAuditRecord({ req, res, action, category, success, duration, fullPath, isGetAudit })
      );
    };

    // 拦截 json 响应
    res.json = (body) => {
      doLog();
      return originalJson(body);
    };

    // 同时拦截 send 响应（如导出文件等场景）
    res.send = (body) => {
      doLog();
      return originalSend(body);
    };

    // P0-6 修复（2026-09-17）：导出接口绕过 json/send——
    //   - services/auditExportService.js 直接 res.write(...) / res.end()
    //   - services/reportWorkbookService.js 走 workbook.xlsx.write(res)
    //     （ExcelJS 内部同样是 res.write/res.end）
    // 实测 GET /api/reports/export 与 GET /api/security/audit-logs/export
    // 真实下载成功但 auditBuffer 计数为 0。此处一并包装 write/end：
    //   - 用 rest 参数原样透传（含 write(chunk, encoding, callback) 的三参形态），
    //     返回值原样返回，不改变背压/流控语义；
    //   - logged 守卫保证整条响应只记录一次，多次 write 不会重复留痕；
    //   - 响应替身缺这两个方法时（typeof 守卫）跳过包装，不改变其行为。
    if (originalWrite) {
      res.write = (...args) => {
        doLog();
        return originalWrite(...args);
      };
    }
    if (originalEnd) {
      res.end = (...args) => {
        doLog();
        return originalEnd(...args);
      };
    }

    next();
  };
};

/**
 * 构造并投递一条请求型审计记录（doLog 的 setImmediate 回调体抽出）
 *
 * 抽出原因：该回调体内联在 auditLog 工厂函数里，使函数体达 117 行、doLog 达 64 行，
 * 双双顶爆体积棘轮（max-lines-per-function 100 行）。eslint.ratchet.json 只许降不许升，
 * 故按仓库既有约定拆为模块级函数；本函数即原回调体，逐行搬运、未改行为。
 *
 * 读取时机（抽出前后完全一致，勿提前快照）：
 *   - action/category/success/duration/fullPath/isGetAudit 由调用方在**响应时刻**固化后传入；
 *   - req.get("user-agent") / req.params / req.query / req.body / res.statusCode /
 *     res.statusMessage 仍在本函数执行时（setImmediate 回调时刻）读取。
 *
 * 脱敏口径：SENSITIVE_KEYS 取自 models/auditLogSanitizer（单一事实来源），深度上限与
 * 该模块 MAX_SANITIZE_DEPTH 对齐（P1-10：超限返回占位文案，不得原样返回子树）。
 *
 * @param {object} ctx 由 doLog 传入的响应时刻上下文
 * @returns {void}
 */
const persistAuditRecord = (ctx) => {
  const { req, res, action, category, success, duration, fullPath, isGetAudit } = ctx;
  // 控制字符清洗：userAgent / params / query 为外部可控输入，
  // 含 \n \r \u0000 时会污染下游日志渲染与 SIEM 解析，入库前统一剥离
  const safeUserAgent = stripControlChars(req.get('user-agent'), 512);
  // 键脱敏（此前缺）：body 走 SENSITIVE_KEYS 名单，而 params/query **完全不脱敏**，
  // 于是 `POST /api/auth/refresh?refreshToken=<真 JWT>` 这类经 query 传令牌的请求，
  // 会把可用凭证原样写进不可篡改、且会被定期导出成 CSV 的审计集合——
  // 审计库因此成了凭据库。名单与 body 同源（auditLogSanitizer 单一事实来源，
  // 其匹配是 matchesSensitiveBodyKey：先把键名里的空白/控制字符删掉再比子串，
  // 故 refreshToken/accessToken 能命中，插在词中间的 `pass\u0000word` 也能命中）。
  // query/params 额外并上「查询专用名单」（与 morgan URL 打码同一份口径）：
  // `?code=` / `?otp=` / `?authorization=` 这类裸键不含 token/password 子串，
  // 子串名单抓不到；而只用查询名单又会漏 camelCase（盲区方向相反），所以取并集。
  const safeParams = sanitizeAuditQuery(stripControlCharsDeep(req.params || {}));
  const safeQuery = sanitizeAuditQuery(stripControlCharsDeep(req.query || {}));
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
          // #10：判定函数来自 models/auditLogSanitizer 单一事实来源（含 secret/apikey，
          // 且与它同样先删键名噪声再比子串）
          // P1-10 修复（2026-09-17）：深度超限**不得原样返回子树**。
          // 原实现 `depth > 6` 时 return value，而 sanitizeMongo 的
          // SANITIZE_MAX_DEPTH = 10（本文件上方）——7/8/9 层嵌套的明文
          // 口令因此绕过脱敏进入 auditBuffer（漏网窗口宽 3 层）。
          // 现与 models/auditLogSanitizer 的 MAX_SANITIZE_DEPTH = 6 对齐：
          // 超限返回同一占位文案 '[深度超限]'。
          // 为何未收敛为直接调用该模块的 sanitizeAuditBody：本文件的脱敏
          // 与 sanitizeMongo 的深度窗口同处一条防线，需要独立控制深度常量
          // （常量同值但不同源，直接调用会把本文件的窗口交给被调用方决定）。
          // 两处实现必须在 0–10 层输出逐字节一致，由
          // src/tests/middleware/auditStreamingCoverage.test.js
          // 「0–10 层：中间件脱敏结果与 sanitizeAuditBody 逐字节一致」锁定：
          // 实测把任一侧的深度上限改为 7，该用例立即转红。
          const AUDIT_BODY_MAX_SANITIZE_DEPTH = 6;
          const SANITIZE_DEPTH_EXCEEDED = '[深度超限]';
          const sanitizeValue = (value, depth = 0) => {
            // 深度保护，避免循环引用/超深嵌套导致栈溢出；判定顺序与
            // models/auditLogSanitizer.sanitizeAuditBody 保持一致（先判深度，再判原始类型）
            if (depth > AUDIT_BODY_MAX_SANITIZE_DEPTH) return SANITIZE_DEPTH_EXCEEDED;
            if (value === null || typeof value !== 'object') return value;
            if (Array.isArray(value)) return value.map((v) => sanitizeValue(v, depth + 1));
            const cleaned = {};
            for (const [k, v] of Object.entries(value)) {
              // 必须用 defineProperty 落键：express.json 走 JSON.parse，`{"__proto__":{...}}`
              // 的 __proto__ 是**自身可枚举键**，`cleaned[k] = ...` 会触发 Object.prototype
              // setter 使该键整个消失 ⇒ 攻击探针在审计副本里蒸发。models/auditLogSanitizer.js
              // 早已为此改成 defineProperty，本函数是同一规则的第二份实现，此前漏改。
              Object.defineProperty(cleaned, k, {
                value: isBodySensitiveKey(k.toLowerCase()) ? '***' : sanitizeValue(v, depth + 1),
                enumerable: true,
                writable: true,
                configurable: true,
              });
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
};

/**
 * 9. 文件上传安全检查
 * 验证上传文件的类型和大小
 *
 * 注意（预留能力）：当前项目暂无文件上传路由，本中间件尚未被任何路由挂载。
 * 未来引入文件上传功能时，必须在上传路由强制启用本中间件（配合 MIME 白名单、
 * 扩展名校验与大小限制），不可直接裸奔上传接口。
 *
 * 【2026-10-01：扩展名闸由 fail-open 改为构造期 fail-closed】
 * 原实现是 `allowedExts = allowedTypes.map(t => mimeToExt[t]).filter(Boolean)`，
 * 再用 `if (allowedExts.length > 0 && ...)` 短路。于是当 `allowedTypes` 里**一个
 * 都不在** mimeToExt 表里时（表里只有 5 项：jpeg/png/gif/pdf/zip），`filter(Boolean)`
 * 把整组映射结果清空 ⇒ `allowedExts.length === 0` ⇒ **扩展名校验整条消失**，
 * 只剩客户端自报的 `file.mimetype`（`allowedTypes.includes(file.mimetype)` 也一并失效，
 * 因为那条判据同样依赖调用方传的 MIME 与真实类型一致）。即"配置了白名单却等于没配"，
 * 且没有任何信号——这正是本仓纪律里"配了却不生效=最危险"的形态。
 * 今天无 multer 挂载故不可利用，但这类缺口一旦随首个上传路由上线就会同时生效。
 *
 * 收口方式：把映射与校验提到**构造期**（= 路由装配期，即启动期）——
 * 只要 `allowedTypes` 里存在**任何一个**没有扩展名映射的 MIME，直接抛错。
 * 于是运行期不可能再出现"白名单非空但扩展名闸为空"的组合，
 * 短路判据也随之简化为 `allowedTypes.length > 0`（语义变得与直觉一致）。
 * 之所以对"部分未映射"也抛：未映射的那一项在运行期就是一条静默放行，
 * 只抛"全部未映射"会把部分漏洞留在原地。
 */
const MIME_TO_EXT = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
  'application/zip': 'zip',
};

const fileUploadSecurity = (options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024, // 默认 5MB
    allowedTypes = [],
  } = options;

  // 构造期 fail-closed：白名单里每一项都必须有扩展名映射，否则这条防线是纸面的。
  // 抛错而不是降级告警：修复它不需要服务先跑起来（与 ALLOWED_HOSTS 那类致命项同口径）。
  const unmapped = allowedTypes.filter((t) => !MIME_TO_EXT[t]);
  if (unmapped.length > 0) {
    throw new Error(
      `fileUploadSecurity 配置无效：allowedTypes 中的 ${unmapped.join(', ')} 没有对应的` +
        `扩展名映射（当前仅支持 ${Object.keys(MIME_TO_EXT).join(', ')}）。` +
        '继续装配会让扩展名校验整条失效（只凭客户端自报的 MIME 判断）——' +
        '请改用受支持的 MIME，或先在 MIME_TO_EXT 里补齐映射。'
    );
  }
  // 映射后必与 allowedTypes 等长（上面已保证无未映射项），故此处不再 filter(Boolean)：
  // 那个 filter 正是原先 fail-open 的来源。
  const allowedExts = allowedTypes.map((t) => MIME_TO_EXT[t]);

  return async (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return next();
    }

    for (const file of req.files) {
      // 检查文件大小
      if (file.size > maxSize) {
        return ApiResponse.codeError(res, 'UPLOAD_FILE_TOO_LARGE', {
          message: `文件 ${file.originalname} 超过最大限制 ${maxSize / 1024 / 1024}MB`,
          params: { filename: file.originalname, maxSize: maxSize / 1024 / 1024 },
        });
      }

      // 检查文件类型
      if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
        return ApiResponse.codeError(res, 'UPLOAD_TYPE_NOT_ALLOWED', {
          message: `不允许的文件类型：${file.mimetype}`,
          params: { mimetype: file.mimetype },
        });
      }

      // 检查文件扩展名（防止 MIME 类型欺骗）
      const ext = file.originalname.split('.').pop().toLowerCase();

      if (allowedTypes.length > 0 && !allowedExts.includes(ext)) {
        return ApiResponse.codeError(res, 'UPLOAD_EXT_NOT_ALLOWED', {
          message: `不允许的文件扩展名：.${ext}`,
          params: { ext: ext },
        });
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
 * 响应头卫生不在这里挂载，见下面的 applyResponseHardening（它必须比本函数更早）。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyPreBodySecurity = (app) => {
  // 启动期防护：审计分类映射与模型枚举不一致时拒绝启动，避免审计静默丢失
  assertAuditCategoryConsistency();

  // 协议合规校验：置于 body 解析之前，畸形请求早拒绝、不进入下游解析
  const { protocolCompliance } = require('./protocolCompliance');
  // 评价报告低危项：Content-Length 上限与 express.json 的 body 上限（1mb）
  // 对齐——原默认 10MB 让 1MB~10MB 的请求在协议层放行后又被 body 解析
  // 413 拒掉，两道闸门口径不一，审计里的拒绝原因也不一致。
  // 业务载荷均为小表单（无文件上传端点），1MB 是两层的统一收口。
  app.use(protocolCompliance({ maxContentLength: 1024 * 1024 }));
};

/**
 * 挂载「纯写响应头」的那一段 —— 必须是 createApp 里最早的中间件
 *
 * 为什么单独成一段、且要排在 IP 黑名单与两个全局限流**之前**：响应头前置此前只做到
 * protocolCompliance 之前，而 ipLimiter/generalLimiter 与 checkIPBlacklist 为了封住
 * "小请求放大成链上审计写入"特意挂得比它更早 ⇒ 全站最早的两类拒绝（429 与黑名单 403）
 * 反而一个安全头都没有，helmet 的 hidePoweredBy 也在这两条路径上失效——被限流/封禁的
 * 响应替攻击者把 `X-Powered-By` 送出来，全站唯此处泄露服务器指纹。
 *
 * 前置不违背限流前移的两条理由：这一段不读 body、不碰数据库，只 setHeader
 * （每请求 16 字节 randomBytes 生成 CSP nonce，开销相对 express 路由可忽略）。
 * 顺序不变量：attachCspNonce 必须先于 securityHeaders（helmet 写 CSP 头时读取 res.locals.cspNonce）。
 * @param {import('express').Application} app
 * @returns {void}
 */
const applyResponseHardening = (app) => {
  app.use(attachCspNonce);
  app.use(securityHeaders);
  app.use(ensureHsts);
  app.use(permissionsPolicy);
  app.use(reportingEndpoints);
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
  applyResponseHardening(app);
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
  materializeQuery,
  preventHPP,
  requireReAuthentication,
  checkIPBlacklist,
  isWhitelistExemptionTrustworthy,
  addToBlacklist,
  invalidateIPBlockCache,
  auditLog,
  fileUploadSecurity,
  recordEarlyRejection,
  applySecurity,
  applyResponseHardening,
  applyPreBodySecurity,
  applyPostBodySecurity,
};
