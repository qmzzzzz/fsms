/**
 * 中间件统一导出
 */

const { authenticate, invalidateUserCache } = require('./auth');
const {
  checkPermission,
  checkViewSensitivePermission,
  checkRole,
  getDataScope,
  buildDataScopeFilter,
} = require('./rbac');
const {
  generalLimiter,
  strictLimiter,
  loginLimiter,
  loginIpLimiter,
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  ipLimiter,
  userLimiter,
} = require('./rateLimit');
const errorHandler = require('./errorHandler');
const requestId = require('./requestId');
const queryLengthLimit = require('./queryLimit');
const { queryScalarGuard } = require('./queryLimit');
const { createOriginCheck } = require('./originCheck');
const {
  applySecurity,
  applyPreBodySecurity,
  applyPostBodySecurity,
  auditLog,
  securityHeaders,
  sanitizeMongo,
  preventHPP,
  checkIPBlacklist,
  addToBlacklist,
  invalidateIPBlockCache,
  requireReAuthentication,
  fileUploadSecurity,
} = require('./security');

module.exports = {
  // 认证中间件
  authenticate,
  invalidateUserCache,

  // 授权中间件
  checkPermission,
  checkViewSensitivePermission,
  checkRole,
  getDataScope,
  buildDataScopeFilter,

  // 限流中间件
  generalLimiter,
  strictLimiter,
  loginLimiter,
  loginIpLimiter,
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  ipLimiter,
  userLimiter,

  // 错误处理
  errorHandler,

  // 请求追踪
  requestId,

  // 查询参数长度限制
  queryLengthLimit,

  // 查询参数标量收敛（阻断 ?x[$ne]=y 操作符注入与 .trim() 型 500）
  queryScalarGuard,

  // CSRF 纵深：写操作 Origin/Referer 白名单校验
  createOriginCheck,

  // 综合安全中间件
  applySecurity,
  applyPreBodySecurity,
  applyPostBodySecurity,
  auditLog,
  securityHeaders,
  sanitizeMongo,
  preventHPP,
  checkIPBlacklist,
  addToBlacklist,
  invalidateIPBlockCache,
  requireReAuthentication,
  fileUploadSecurity,
};
