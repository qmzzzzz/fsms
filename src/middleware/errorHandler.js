/**
 * 全局错误处理中间件
 * 统一处理所有未捕获的错误
 */

const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');
// 这一路是"更正审计写入失败"的兜底日志：写成裸读 err.message 时，非 Error 的被拒值会把
// 兜底本身变成新的抛出源。本处 catch 包的是同步调用（require + push），今天只会拿到
// Error，但同一仓的口径不按"今天可达"打折——措辞不会自己变好。
const { errText } = require('../utils/auditWriteFailure');
// 日志里的 URL 必须过 redactUrlQuery：app.js 替换 morgan 的 :url 时就是这么做的
// （query 里可能带令牌/口令，明文长期留存于 combined-*.log）。
// 错误路径同样是攻击者可稳定触发的写日志入口，没理由例外。
// stripControlChars 用于更正事件的 reason：定长截断必须在清洗之内完成（同批次 34 的不变量）。
const { redactUrlQuery, stripControlChars } = require('../utils/helpers');

/**
 * 全局错误处理
 */
const errorHandler = (err, req, res, _next) => {
  // 响应头已发出时不能再改写响应体。Express 5 下这里若继续走
  // ApiResponse.* → res.json()，会在**错误处理器内部**抛 ERR_HTTP_HEADERS_SENT，
  // 结果真实原因（下面那条 err）被一次二次异常覆盖掉，日志里只剩"处理器自己坏了"。
  // 可达路径不是假设：流式导出把 workbook 直接写进 res
  // （reportWorkbookService.writeExportWorkbook），客户端中途断开即命中；
  // auditController 早已为同一情形手写 !res.headersSent，反证这条路径真实存在。
  if (res.headersSent) {
    const reason = err && err.message ? err.message : '未知错误';
    logger.error(`响应已开始写出，错误只记日志不改写响应：${reason}`, {
      path: req.originalUrl ? redactUrlQuery(req.originalUrl) : undefined,
    });
    // 状态码早在第一个 chunk 之前就已发出（200），此后无法改写响应。
    // 人读的原因走这里的 error 日志；审计侧的结论修正（标记 + 更正事件）由
    // utils/auditWriteFailure 统一负责，与 auditController 的导出 catch 同一实现。
    markResponseAbortedByError(req, res, reason);
    if (!res.writableEnded) res.end();
    return;
  }

  // 开发模式下输出详细错误
  const isDev = process.env.NODE_ENV === 'development';

  // Mongoose 坏 ObjectId 错误
  if (err.name === 'CastError') {
    const message = '资源 ID 格式无效';
    logger.warn(`CastError: ${err.path} - ${err.message}`);
    return ApiResponse.error(res, message, 400);
  }

  // Mongoose 乐观并发冲突（schema 开了 optimisticConcurrency 才会出现）：两个请求各自
  // 加载同一文档后先后写库，后写者的 update filter（含它加载时读到的 __v）不再命中。
  // 不映射就落到兜底分支变成 500——把"你手里那份已过期、刷新即可重试"这种**客户端可自愈**
  // 的情况报成服务端故障，还会在日志里制造假事故。
  // 状态码取 400 而不是 409：设备系列接口对"当前状态不允许该操作"一直回 400
  // （既有契约用例钉着），同一业务结果不应分叉出两个码。原文只进日志不回客户端。
  if (err.name === 'VersionError') {
    logger.warn(`乐观并发冲突（文档已被其他请求变更）：${err.message}`);
    return ApiResponse.error(res, '该记录已被其他操作变更，请刷新后重试', 400);
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
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: safeErrors });
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
    logger.warn(`JSON 解析失败：${req.method} ${redactUrlQuery(req.originalUrl)}`);
    return ApiResponse.codeError(res, 'JSON_PARSE_FAILED');
  }

  // 请求体超过大小限制（body-parser entity.too.large，上限见 app.js 的 express.json limit）
  // 同样只返回通用文案，不暴露具体限额配置与堆栈信息
  if (err.type === 'entity.too.large') {
    logger.warn(`请求体超限：${req.method} ${redactUrlQuery(req.originalUrl)}`);
    return ApiResponse.codeError(res, 'PAYLOAD_EXCEEDS_LIMIT');
  }

  // 未知错误 - 服务器内部错误
  // 日志按环境决定详细程度；对外响应一律通用文案，不回显内部错误信息
  if (isDev) {
    logger.error(`UnhandledError: ${err.message}\nStack: ${err.stack}`);
  } else {
    logger.error(`UnhandledError: ${err.message} (${err.name})`);
  }

  return ApiResponse.codeError(res, 'INTERNAL_ERROR');
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

/**
 * 登记「这条响应是被错误截断的」，并保证审计结论不说谎。
 *
 * 流式响应（审计 CSV / Excel 导出）在第一个 chunk 之前就必须把状态码发出去，
 * 之后无论出什么事都改不了那个 200；而全局审计的结论是
 * `success = res.statusCode < 400` —— 半截文件于是被记成一次成功交付。
 * 两种情形分别处理，因为它们能做到的事不同：
 *   ① 审计记录尚未写出：只打标记。auditLog 读到 `responseAbortedByError`
 *      就把那条记录的 success 记成 false（一条记录，结论正确）。
 *   ② 审计记录已经写出（auditLog 刻意在第一个 chunk 就记，崩溃也不丢；
 *      且 auditBuffer.push 同步写 WAL）：回改内存对象只会让 WAL 与库不一致，
 *      append-only 审计的正解是**追加一条更正事件**。
 * 调用方必须在自己的 `res.end()` **之前**调用：end 会触发 auditLog 的响应包装器
 * 把 auditRecordWritten 置真，放之后就分不清「记录早就写出」还是「end 刚写的」。
 * Express 恒有 res.locals，测试桩未必，故全程判空——本函数绝不能替调用方抛错。
 *
 * @param {object} req Express 请求
 * @param {object} res Express 响应
 * @param {string} reason 失败原因（进更正事件 body.reason，截到 512 字符）
 */
function markResponseAbortedByError(req, res, reason) {
  const text = reason || '未知错误';
  const locals = res.locals;
  if (locals) locals.responseAbortedByError = text;
  if (!locals || !locals.auditRecordWritten) return;

  const ACTION = 'response_aborted_after_headers';
  const user = req.user || {};
  const path = (req.originalUrl || req.path || '').split('?')[0];
  try {
    require('../services/auditBuffer').push({
      action: ACTION,
      category: 'security',
      userId: user.userId,
      username: user.username || 'anonymous',
      method: req.method,
      path,
      body: { reason: stripControlChars(String(text), 512), reqId: req.id || null },
      ip: req.ip,
      statusCode: res.statusCode,
      success: false,
      riskLevel: 'medium',
      riskFactors: [ACTION],
    });
  } catch (err) {
    // 更正事件本身失败：既不能掩盖原始错误，也不能让调用方（错误处理器/导出控制器）抛出
    logger.warn(`截断响应的更正审计写入失败：${errText(err)}`);
  }
}

module.exports = errorHandler;
module.exports.asyncHandler = asyncHandler;
module.exports.markResponseAbortedByError = markResponseAbortedByError;
