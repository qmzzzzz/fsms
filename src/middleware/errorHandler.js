/**
 * 全局错误处理中间件
 * 统一处理所有未捕获的错误
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * 全局错误处理
 */
const errorHandler = (err, req, res, _next) => {
  // 开发模式下输出详细错误
  const isDev = process.env.NODE_ENV === 'development';

  // Mongoose 坏 ObjectId 错误
  if (err.name === 'CastError') {
    const message = '资源 ID 格式无效';
    logger.warn(`CastError: ${err.path} - ${err.message}`);
    return ApiResponse.error(res, message, 400);
  }

  // Mongoose 重复键错误
  if (err.code === 11000) {
    const message = '资源已存在';
    // P3-34：keyPattern 并非始终存在——驱动在部分场景（批量写错误、
    // 旧版驱动、经序列化传递的错误对象）只给 errmsg 而无 keyPattern/keyValue。
    // 原实现直接 Object.keys(err.keyPattern) 会在错误处理器内部抛 TypeError，
    // 由 Express 交给默认处理器，把一个本该 400 的重复键变成 500 + 堆栈泄露。
    const dupKeys = Object.keys(err.keyPattern || err.keyValue || {});
    const detail =
      dupKeys.length > 0
        ? dupKeys.join(',')
        : `未提供字段信息（${err.errmsg || err.message || 'unknown'})`;
    logger.warn(`DuplicateKeyError: ${detail}`);
    return ApiResponse.error(res, message, 400);
  }

  // Mongoose 验证错误
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    logger.warn(`ValidationError: ${JSON.stringify(errors)}`);
    // 生产环境不返回具体字段名，避免泄露 schema 信息
    const safeErrors = isDev ? errors : undefined;
    return ApiResponse.error(res, '数据验证失败', 400, safeErrors);
  }

  // JWT 错误
  if (err.name === 'JsonWebTokenError') {
    const message = '无效的认证令牌';
    logger.warn('JsonWebTokenError');
    return ApiResponse.unauthorized(res, message);
  }

  if (err.name === 'TokenExpiredError') {
    const message = '认证令牌已过期';
    logger.warn('TokenExpiredError');
    return ApiResponse.unauthorized(res, message);
  }

  // 自定义 API 错误
  if (err.isApiError) {
    logger.warn(`ApiError: ${err.message}`);
    return res.status(err.statusCode || 400).json({
      success: false,
      message: err.message,
      errors: err.errors,
    });
  }

  // 请求体 JSON 解析失败（body-parser entity.parse.failed）
  // 对外仅返回通用文案，不回显解析器内部错误细节（生产环境口径一致，不泄堆栈）
  if (err.type === 'entity.parse.failed') {
    logger.warn(`JSON 解析失败：${req.method} ${req.originalUrl}`);
    return ApiResponse.error(res, '请求体 JSON 解析失败', 400);
  }

  // 请求体超过大小限制（body-parser entity.too.large，上限见 app.js 的 express.json limit）
  // 同样只返回通用文案，不暴露具体限额配置与堆栈信息
  if (err.type === 'entity.too.large') {
    logger.warn(`请求体超限：${req.method} ${req.originalUrl}`);
    return ApiResponse.error(res, '请求体超过大小限制', 413);
  }

  // 未知错误 - 服务器内部错误
  // 日志按环境决定详细程度；对外响应一律通用文案，不回显内部错误信息
  if (isDev) {
    logger.error(`UnhandledError: ${err.message}\nStack: ${err.stack}`);
  } else {
    logger.error(`UnhandledError: ${err.message} (${err.name})`);
  }

  return ApiResponse.serverError(res, '服务器内部错误，请稍后重试');
};

/**
 * 异步处理器包装器
 * 避免在 async 函数中使用 try-catch
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    return Promise.resolve(fn(req, res, next)).catch(next);
  };
};

module.exports = errorHandler;
module.exports.asyncHandler = asyncHandler;
