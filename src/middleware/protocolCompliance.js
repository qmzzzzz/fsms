/**
 * 请求协议合规校验中间件
 *
 * 目的：在业务逻辑之前拦截畸形/非预期的 HTTP 请求，减少下游解析器与控制器
 * 需要处理的异常输入面。属于应用层的轻量「协议净化」，不替代 WAF。
 *
 * 校验项（全部可通过 options 关闭或调整）：
 * 1. Content-Type：写操作（POST/PUT/PATCH）必须声明受支持的媒体类型
 * 2. Content-Length：声明值不得超过上限（早于 body 解析即拒绝，避免无谓读流）
 * 3. 请求头卫生：拒绝头部数量异常、单个头部超长、头名非法的请求
 * 4. HTTP 方法白名单：拒绝 TRACE/TRACK/CONNECT 等无业务用途且易被滥用的方法
 * 5. Host 头校验：配置了允许列表时，拒绝 Host 不匹配的请求（防 Host 头注入）
 *
 * 所有拒绝均记录 warn 级日志并写审计（category=security），便于统计畸形请求趋势。
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
const { auditPath } = require('../utils/auditMeta');
// T-1：顶层引入——下方 setImmediate 回调属 fire-and-forget，可能在测试环境
// 销毁后才执行，届时惰性 require 会抛「import after torn down」
const AuditLog = require('../models/AuditLog');
const { computeFingerprint } = require('../utils/fingerprint');

// 允许的媒体类型（写操作）
const DEFAULT_ALLOWED_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  // G9：浏览器上报 CSP 违规时固定使用这两种媒体类型，不受调用方控制；
  // 不放行会让上报请求全部被 415 拦掉，report-uri 形同虚设
  'application/csp-report',
  'application/reports+json',
];

// 明确禁止的 HTTP 方法：无业务用途，历史上多次成为跨站追踪/代理滥用的载体
const FORBIDDEN_METHODS = ['TRACE', 'TRACK', 'CONNECT'];

// 需要 Content-Type 声明的方法
const BODY_METHODS = ['POST', 'PUT', 'PATCH'];

// 合法 HTTP 头名字符集（RFC 7230 token）
const VALID_HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * 记录协议违规审计（异步，不阻塞拒绝响应）
 */
const recordViolation = (req, violation, detail) => {
  logger.warn('协议合规校验拒绝', {
    violation,
    detail,
    method: req.method,
    url: req.originalUrl,
  });

  setImmediate(() => {
    try {
      AuditLog.record({
        action: 'malformed_request_blocked',
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
        userAgent: req.get('user-agent'),
        success: false,
        riskLevel: 'medium',
        riskFactors: ['protocol_violation', violation],
        reason: detail,
      });
    } catch (e) {
      logger.debug(`协议违规审计写入跳过：${e.message}`);
    }
  });
};

/**
 * 协议合规校验中间件工厂
 *
 * @param {object} options
 * @param {string[]} [options.allowedContentTypes] 允许的写操作媒体类型
 * @param {number} [options.maxContentLength] Content-Length 上限（字节），默认 10MB
 * @param {number} [options.maxHeaderCount] 头部数量上限，默认 60
 * @param {number} [options.maxHeaderValueLength] 单个头部值长度上限，默认 8192
 * @param {string[]} [options.allowedHosts] 允许的 Host（含端口），为空则不校验
 * @param {string[]} [options.skipPaths] 跳过校验的路径前缀（如健康检查、文件上传）
 */
const protocolCompliance = (options = {}) => {
  const {
    allowedContentTypes = DEFAULT_ALLOWED_CONTENT_TYPES,
    maxContentLength = 10 * 1024 * 1024,
    maxHeaderCount = 60,
    maxHeaderValueLength = 8192,
    allowedHosts = (process.env.ALLOWED_HOSTS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    // P3-35：原默认值含 '/api/health'——本服务的健康检查挂在根路径 '/health'
    // （见 app.js 的 app.get('/health')），'/api/health' 从不存在，是死配置。
    // 死配置的危害不只是冗余：它让人误以为「健康检查已全部豁免」，
    // 若日后新增 /api/health 而忘记回看这里，会得到一个意外豁免的端点
    skipPaths = ['/health'],
  } = options;

  return (req, res, next) => {
    const fullPath = auditPath(req);

    if (skipPaths.some((p) => fullPath === p || fullPath.startsWith(`${p}/`))) {
      return next();
    }

    // 1. HTTP 方法白名单
    if (FORBIDDEN_METHODS.includes(req.method)) {
      recordViolation(req, 'forbidden_method', `方法 ${req.method} 不被允许`);
      return ApiResponse.codeError(res, 'HTTP_METHOD_UNSUPPORTED', { message: `不支持的请求方法：${req.method}`, params: { method: req.method } });
    }

    // 2. 请求头卫生检查
    const headerNames = Object.keys(req.headers || {});
    if (headerNames.length > maxHeaderCount) {
      recordViolation(
        req,
        'excessive_headers',
        `头部数量 ${headerNames.length} 超过上限 ${maxHeaderCount}`
      );
      return ApiResponse.codeError(res, 'HEADER_COUNT_EXCESSIVE');
    }

    for (const name of headerNames) {
      // Node 已将头名小写化，此处校验字符集，拦截含控制字符/空格的畸形头名
      if (!VALID_HEADER_NAME.test(name)) {
        recordViolation(req, 'invalid_header_name', `非法头名：${name.slice(0, 64)}`);
        return ApiResponse.codeError(res, 'HEADER_NAME_INVALID');
      }
      const value = req.headers[name];
      const len = Array.isArray(value)
        ? value.reduce((sum, v) => sum + String(v).length, 0)
        : String(value ?? '').length;
      if (len > maxHeaderValueLength) {
        recordViolation(req, 'oversized_header', `头部 ${name} 长度 ${len} 超过上限`);
        return ApiResponse.codeError(res, 'HEADER_VALUE_TOO_LONG');
      }
    }

    // 3. Host 头校验（防 Host 头注入导致的密码重置链接投毒等）
    if (allowedHosts.length > 0) {
      const host = req.get('host');
      if (!host || !allowedHosts.includes(host)) {
        recordViolation(req, 'host_mismatch', `Host 头 ${host || '(空)'} 不在允许列表内`);
        return ApiResponse.codeError(res, 'HOST_HEADER_INVALID');
      }
    }

    // 4. Content-Length 上限（早于 body 解析拒绝）
    const contentLengthRaw = req.get('content-length');
    if (contentLengthRaw !== undefined) {
      const contentLength = Number(contentLengthRaw);
      if (!Number.isFinite(contentLength) || contentLength < 0) {
        recordViolation(
          req,
          'invalid_content_length',
          `Content-Length 值非法：${contentLengthRaw}`
        );
        return ApiResponse.codeError(res, 'CONTENT_LENGTH_INVALID');
      }
      if (contentLength > maxContentLength) {
        recordViolation(
          req,
          'payload_too_large',
          `Content-Length ${contentLength} 超过上限 ${maxContentLength}`
        );
        return ApiResponse.codeError(res, 'PAYLOAD_TOO_LARGE');
      }
    }

    // 5. Content-Type 校验（仅对携带 body 的写操作）
    if (BODY_METHODS.includes(req.method)) {
      const contentLength = Number(req.get('content-length') || 0);
      const hasBody = contentLength > 0 || req.get('transfer-encoding') === 'chunked';

      if (hasBody) {
        const contentType = req.get('content-type');
        if (!contentType) {
          recordViolation(req, 'missing_content_type', `${req.method} 请求未声明 Content-Type`);
          return ApiResponse.codeError(res, 'CONTENT_TYPE_MISSING');
        }
        // 只取媒体类型部分，忽略 charset / boundary 等参数
        const mediaType = contentType.split(';')[0].trim().toLowerCase();
        if (!allowedContentTypes.includes(mediaType)) {
          recordViolation(req, 'unsupported_media_type', `不支持的 Content-Type：${mediaType}`);
          return ApiResponse.codeError(res, 'CONTENT_TYPE_UNSUPPORTED', { message: `不支持的 Content-Type：${mediaType}`, params: { mediaType: mediaType } });
        }
      }
    }

    next();
  };
};

module.exports = {
  protocolCompliance,
  DEFAULT_ALLOWED_CONTENT_TYPES,
  FORBIDDEN_METHODS,
};
