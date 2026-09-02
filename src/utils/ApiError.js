/**
 * 统一 API 错误类
 * 用于在 Service 层和中间件中抛出带状态码的业务错误，
 * 由全局 errorHandler 统一捕获并格式化响应
 */

class ApiError extends Error {
  /**
   * @param {string} message - 错误消息
   * @param {number} statusCode - HTTP 状态码
   * @param {Object} [errors] - 详细错误信息（如字段校验错误）
   * @param {string} [code] - 业务错误码
   */
  constructor(message, statusCode = 400, errors = undefined, code = undefined) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.errors = errors;
    this.code = code;
    this.isApiError = true;
    // 保持正确的堆栈跟踪
    Error.captureStackTrace(this, this.constructor);
  }

  // 常用静态工厂方法
  static badRequest(message, errors) {
    return new ApiError(message, 400, errors);
  }
  static unauthorized(message = '未授权访问') {
    return new ApiError(message, 401);
  }
  static forbidden(message = '无权访问') {
    return new ApiError(message, 403);
  }
  static notFound(message = '资源不存在') {
    return new ApiError(message, 404);
  }
  static conflict(message = '资源冲突') {
    return new ApiError(message, 409);
  }
  static tooMany(message = '请求过于频繁') {
    return new ApiError(message, 429);
  }
  static serverError(message = '服务器内部错误') {
    return new ApiError(message, 500);
  }
}

module.exports = ApiError;
