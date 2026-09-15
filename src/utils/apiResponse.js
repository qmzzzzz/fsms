/**
 * 统一 API 响应工具
 * 规范所有接口的返回格式
 */

const logger = require('./logger');
const { ERROR_CODES } = require('./errorCodes');

class ApiResponse {
  /**
   * 成功响应
   * @param {Object} res - Express response 对象
   * @param {*} data - 返回数据
   * @param {string} message - 成功消息
   * @param {number} statusCode - HTTP 状态码
   */
  static success(res, data = null, message = '操作成功', statusCode = 200) {
    return res.status(statusCode).json({
      success: true,
      message,
      data,
    });
  }

  /**
   * 分页成功响应
   * @param {Object} res - Express response 对象
   * @param {Array} data - 数据数组
   * @param {Object} pagination - 分页信息（游标模式可携带 hasMore/nextCursor，
   *   此时 total/totalPages 为 null——游标分页不做 countDocuments 全量统计）
   * @param {string} message - 成功消息
   */
  static paginated(res, data, pagination, message = '获取成功') {
    return res.status(200).json({
      success: true,
      message,
      data,
      pagination: {
        page: pagination.page,
        limit: pagination.limit,
        total: pagination.total,
        totalPages: pagination.totalPages,
        ...(pagination.hasMore !== undefined ? { hasMore: pagination.hasMore } : {}),
        ...(pagination.nextCursor !== undefined ? { nextCursor: pagination.nextCursor } : {}),
      },
    });
  }

  /**
   * 错误响应
   * @param {Object} res - Express response 对象
   * @param {string} message - 错误消息
   * @param {number} statusCode - HTTP 状态码
   * @param {Object|null} errors - 附加错误信息（表单字段错误 / { errorCode, ...params }）
   */
  static error(res, message = '操作失败', statusCode = 400, errors = null) {
    if (!res) {
      // res 为 null 时降级处理，避免在中间件或单元测试中抛出 ReferenceError
      logger.error(`ApiResponse.error called with null res: ${message}`);
      return;
    }
    return res.status(statusCode).json({
      success: false,
      message,
      errors,
    });
  }

  /**
   * 按错误码响应（码化错误的统一入口）
   *
   * message/statusCode 取自 errorCodes 注册表，调用方无需重复维护文案；
   * 响应 errors 携带 { errorCode, ...params }，前端 resolveErrorMessage
   * 据此做 i18n，取代中文字符串匹配。
   *
   * @param {Object} res - Express response 对象
   * @param {string} code - 错误码（ERROR_CODES 的键）
   * @param {Object} [options]
   * @param {Object} [options.params] - 附带参数（如动态文案变量），合并进 errors
   * @param {string} [options.message] - 覆盖注册表文案（仅动态文案场景）
   * @param {number} [options.statusCode] - 覆盖注册表状态码
   */
  static codeError(res, code, options = {}) {
    const def = ERROR_CODES[code];
    if (!def) {
      // 未注册的码是编程错误：日志暴露 + 兜底 400，避免静默产出无意义的码
      logger.error(`ApiResponse.codeError 收到未注册的错误码：${code}`);
    }
    const message = options.message || (def && def.message) || '操作失败';
    const statusCode = options.statusCode || (def && def.status) || 400;
    return this.error(res, message, statusCode, {
      errorCode: code,
      ...(options.params || {}),
      // fieldErrors：批量/校验类错误的明细透传（P2-23：调用方须能知晓被拒原因）
      ...(options.fieldErrors !== undefined ? { fieldErrors: options.fieldErrors } : {}),
    });
  }

  /**
   * 认证失败响应
   * @param {Object|null} errors - 附加错误信息（透传给 error，如 { errorCode }）
   */
  static unauthorized(res, message = '未授权访问', errors = null) {
    return this.error(res, message, 401, errors);
  }

  /**
   * 权限不足响应
   * @param {Object|null} errors - 附加错误信息（透传给 error，如 { errorCode }）
   */
  static forbidden(res, message = '权限不足', errors = null) {
    return this.error(res, message, 403, errors);
  }

  /**
   * 资源不存在响应
   * @param {Object|null} errors - 附加错误信息（透传给 error，如 { errorCode }）
   */
  static notFound(res, message = '资源不存在', errors = null) {
    return this.error(res, message, 404, errors);
  }

  /**
   * 服务器错误响应
   * @param {Object|null} errors - 附加错误信息（透传给 error，如 { errorCode }）
   */
  static serverError(res, message = '服务器内部错误', errors = null) {
    return this.error(res, message, 500, errors);
  }
}

module.exports = ApiResponse;
