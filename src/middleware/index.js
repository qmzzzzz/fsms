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
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  ipLimiter,
  userLimiter,
  staticSurfaceLimiter,
} = require('./rateLimit');
const errorHandler = require('./errorHandler');
const requestId = require('./requestId');
const queryLengthLimit = require('./queryLimit');
// 同一模块不重复 require：queryLimit.js 是「默认导出即函数 + 挂具名属性」的形状，
// 两条 require 语句指向同一模块，属 L-21 同类的「同一模块多入口」残留。
const { queryScalarGuard } = queryLengthLimit;
const { createOriginCheck } = require('./originCheck');

// L-21：补齐统一导出面。以下模块原先未被 index.js 覆盖，而 app.js 以独立
// require 引入——形成"两套入口"，新增/重命名时容易只改一处。此处收口后，
// app.js 与其余调用方统一从 ./middleware 取用。
const { applyObjectIdParams } = require('./validateObjectId');
const { consumeValidation } = require('./validateQuery');
const { mountStaticFrontend } = require('./staticFrontend');
const { metricsAuth } = require('./metricsAuth');
const {
  applySecurity,
  applyResponseHardening,
  applyPreBodySecurity,
  applyPostBodySecurity,
  auditLog,
  securityHeaders,
  sanitizeMongo,
  materializeQuery,
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
  loginUserLimiter,
  captchaLimiter,
  passwordChangeLimiter,
  ipLimiter,
  userLimiter,
  staticSurfaceLimiter,

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
  applyResponseHardening,
  applyPreBodySecurity,
  applyPostBodySecurity,
  auditLog,
  securityHeaders,
  sanitizeMongo,
  materializeQuery,
  preventHPP,
  checkIPBlacklist,
  addToBlacklist,
  invalidateIPBlockCache,
  requireReAuthentication,
  fileUploadSecurity,

  // L-21：原先游离于统一导出面之外的四个中间件（app.js 曾各自独立 require）
  applyObjectIdParams,
  consumeValidation,
  mountStaticFrontend,
  metricsAuth,
};
