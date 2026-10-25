/**
 * 请求 ID 追踪中间件
 * 为每个请求生成唯一 ID，贯穿日志、响应头和审计日志，便于链路追踪
 *
 * 安全口径：X-Request-Id 完全由客户端写入，而 req.id 会作为关联主键进入日志与审计。
 * 直接复用来值等于让攻击者自选一个"看起来像服务端签发"的 ID（甚至与他人请求撞号），
 * 事后按 reqId 取证时无法区分两条链路。因此：
 *  - req.id / 响应头一律使用服务端生成的 16 位十六进制 ID；
 *  - 客户端值经严格校验后另存 req.clientRequestId，只进日志上下文供跨服务关联，
 *    不参与审计主键，也不回填到 req.id。
 */

const crypto = require('crypto');
const { runWithLogContext } = require('../utils/logContext');

const HEADER_NAME = 'X-Request-Id';
const CLIENT_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * 生成短请求 ID（16 位十六进制，足够唯一且不冗长）
 */
const generateRequestId = () => crypto.randomBytes(8).toString('hex');

/**
 * 请求 ID 中间件
 * - 服务端生成唯一 ID（客户端来值不再复用，见文件头）
 * - 挂载到 req.id 和 res.locals.requestId
 * - 响应头返回 X-Request-Id
 * - 将请求包进 AsyncLocalStorage 上下文（报告 O-5）：
 *   后续任何日志经 logger format 自动合并 requestId，业务代码零改动
 */
const requestId = (req, res, next) => {
  const incomingId = req.get(HEADER_NAME);
  const clientRequestId = incomingId && CLIENT_ID_RE.test(incomingId) ? incomingId : undefined;
  const id = generateRequestId();

  req.id = id;
  req.clientRequestId = clientRequestId;
  res.locals.requestId = id;
  res.setHeader(HEADER_NAME, id);
  runWithLogContext(clientRequestId ? { requestId: id, clientRequestId } : { requestId: id }, next);
};

module.exports = requestId;
