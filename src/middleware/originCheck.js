/**
 * CSRF 纵深防护：写操作 Origin/Referer 白名单校验（回应外部报告 CSRF 项）
 *
 * 背景：认证令牌经 httpOnly cookie 下发（utils/cookie.js，SameSite=Lax），
 * 现代浏览器下跨站写请求不携带 cookie，经典 CSRF 已被阻断。本中间件在其上
 * 再加一层服务端校验：携带来源（Origin/Referer）的写请求，来源必须命中白名单，
 * 覆盖 SameSite 支持不全的旧浏览器与未来 cookie 策略变动。
 *
 * 放行口径（重要，避免误伤非浏览器客户端）：
 * - 仅对写方法 POST/PUT/PATCH/DELETE 生效；OPTIONS 预检与其余方法（GET 等）直接放行
 * - 来源缺失（Origin 头不存在且 Referer 缺失/不可解析）→ 放行：
 *   curl/Postman/服务器间调用通常不带来源；而浏览器发起的跨站写请求必带 Origin，
 *   该放行不构成绕过路径
 * - Origin 头存在但为空串：正常浏览器不会发出此类请求，属于异常来源，
 *   视为校验失败直接拒绝——空串是 falsy 值，若与「头不存在」混同处理会形成绕过口子
 *
 * 白名单来源：优先使用调用方传入的数组（app.js 已计算的 CORS 白名单，单一配置源）；
 * 无参调用时按与 app.js 完全相同的逻辑从 config.corsOrigin 计算，保证行为一致。
 */

const config = require('../config');
const logger = require('../utils/logger');
// P3-35：早期 403 留痕。延迟到调用时 require 以避免 middleware 目录内的
// 模块加载顺序耦合（security.js 体量大且会按需引入模型）
const recordEarlyRejection = (req, meta) => {
  require('./security').recordEarlyRejection(req, meta);
};

// 需要校验来源的写方法（与 auditLog 的写操作口径一致）
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * 与 app.js 中 CORS 白名单回退逻辑保持一致（无参调用时的兜底白名单）
 */
const DEFAULT_DEV_ORIGINS = [
  'http://localhost:3001',
  'http://127.0.0.1:3001',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

/**
 * 解析请求来源：优先 Origin 头；缺失时回退从 Referer 提取 origin
 * @param {import('express').Request} req
 * @returns {string|null} origin 字符串；Origin 头存在但为空串时返回 ''（异常来源）；
 *          头不存在且 Referer 无法解析时返回 null（无来源）
 */
const resolveRequestOrigin = (req) => {
  const origin = req.headers.origin;
  // 区分「头不存在」（undefined，非浏览器客户端）与「头存在但为空串」：
  // 空串是 falsy 值，若用真值判断会静默落入 Referer 回退或放行分支
  if (origin !== undefined) {
    return typeof origin === 'string' && origin ? origin : '';
  }
  const referer = req.headers.referer;
  if (referer && typeof referer === 'string') {
    try {
      return new URL(referer).origin;
    } catch (_) {
      // Referer 非法（非 URL 语法）按无来源处理
      return null;
    }
  }
  return null;
};

/**
 * 创建写操作来源校验中间件
 * @param {string[]} [allowedOrigins] 白名单（完整 origin，含协议与端口）；
 *        缺省时按 app.js 相同逻辑从 config.corsOrigin 计算
 * @returns {import('express').RequestHandler}
 */
const createOriginCheck = (allowedOrigins) => {
  let whitelist;
  if (Array.isArray(allowedOrigins) && allowedOrigins.length > 0) {
    whitelist = allowedOrigins.map((s) => String(s).trim()).filter(Boolean);
  } else if (config.corsOrigin) {
    whitelist = config.corsOrigin
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  } else {
    whitelist = [...DEFAULT_DEV_ORIGINS];
    if (config.nodeEnv !== 'development') {
      logger.warn(
        `originCheck 未配置 CORS_ORIGIN（NODE_ENV=${config.nodeEnv}），已回退到本地开发白名单，请显式配置以避免来源校验异常`
      );
    }
  }

  return (req, res, next) => {
    // IP 白名单豁免：checkIPBlacklist 已在更早阶段（CORS 之前）判定可信来源，
    // 白名单 IP 不受来源校验约束（内网工具/探针等非浏览器客户端可能携带非常规 Origin）
    if (req.ipWhitelisted === true) {
      return next();
    }

    // 非写方法与预检请求不校验
    if (req.method === 'OPTIONS' || !WRITE_METHODS.includes(req.method)) {
      return next();
    }

    const origin = resolveRequestOrigin(req);

    // 无来源（Origin 头不存在且 Referer 不可解析，非浏览器客户端）→ 放行；
    // 浏览器跨站写请求必带 Origin，不构成绕过
    if (origin === null) {
      return next();
    }

    // Origin 头存在但为空串：异常来源，视为校验失败拒绝，
    // 防止利用空串的 falsy 特性绕过白名单
    if (origin === '') {
      logger.warn(
        `来源校验失败（空 Origin）：method=${req.method} path=${req.originalUrl} ip=${req.ip}`
      );
      // P3-35：本中间件挂在 auditLog 之前（写操作必须在触达控制器前拦下），
      // 其 403 此前只进 logger 不进审计——CSRF 探测在合规留存里毫无痕迹
      recordEarlyRejection(req, {
        action: 'csrf_origin_denied',
        reason: '写操作 Origin 头为空串（异常来源）',
        riskFactors: ['csrf_origin_violation', 'empty_origin'],
      });
      return res.status(403).json({ success: false, message: '来源校验失败' });
    }

    if (whitelist.includes(origin)) {
      return next();
    }

    logger.warn(
      `来源校验失败：origin=${origin} method=${req.method} path=${req.originalUrl} ip=${req.ip}`
    );
    recordEarlyRejection(req, {
      action: 'csrf_origin_denied',
      reason: `写操作来源 ${origin} 不在白名单内`,
      riskFactors: ['csrf_origin_violation'],
    });
    return res.status(403).json({ success: false, message: '来源校验失败' });
  };
};

module.exports = { createOriginCheck, WRITE_METHODS, resolveRequestOrigin };
