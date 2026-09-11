/**
 * 请求 ID 追踪中间件
 * 为每个请求生成唯一 ID，贯穿日志、响应头和审计日志，便于链路追踪
 */

const crypto = require('crypto');
const { runWithLogContext } = require('../utils/logContext');

const HEADER_NAME = 'X-Request-Id';

/**
 * 生成短请求 ID（16 位十六进制，足够唯一且不冗长）
 */
const generateRequestId = () => crypto.randomBytes(8).toString('hex');

/**
 * 请求 ID 中间件
 * - 若客户端传入 X-Request-Id 则复用（便于跨服务追踪）
 * - 否则生成新 ID
 * - 挂载到 req.id 和 res.locals.requestId
 * - 响应头返回 X-Request-Id
 * - 将请求包进 AsyncLocalStorage 上下文（报告 O-5）：
 *   后续任何日志经 logger format 自动合并 requestId，业务代码零改动
 */
const requestId = (req, res, next) => {
  const incomingId = req.get(HEADER_NAME);
  const id =
    incomingId && /^[a-zA-Z0-9-_]{1,64}$/.test(incomingId) ? incomingId : generateRequestId();

  req.id = id;
  res.locals.requestId = id;
  res.setHeader(HEADER_NAME, id);
  runWithLogContext({ requestId: id }, next);
};

module.exports = requestId;
