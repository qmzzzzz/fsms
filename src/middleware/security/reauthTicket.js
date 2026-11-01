/**
 * 审计读取二次验证：会话窗口优先，票据一次性兜底（窗口细节见 services/reauthGrantStore，消费判据见 services/reauthTicketStore）。
 * 失败方向：窗口查询失败按无窗口处理退回票据（丢的是便利）；票据消费存储不可用 ⇒ 500 fail-closed（丢的是唯一性判据）；校验挂在权限码之后，不因"没票"泄露端点存在性。
 */

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../errorHandler');
const { inspectReauthTicket } = require('../../utils/reauthTicket');
const { consumeReauthTicketJti } = require('../../services/reauthTicketStore');
const { hasLiveReauthGrant } = require('../../services/reauthGrantStore');

const REAUTH_TICKET_HEADER = 'x-reauth-ticket';

/** 取单个请求头值：重复头在 Node 里可能表现为数组，只认第一个 */
const readTicketHeader = (req) => {
  const value = req.headers?.[REAUTH_TICKET_HEADER];
  return Array.isArray(value) ? value[0] : value;
};

/** 票据路径：校验 → 消费 jti。true = 本次请求可以用票据放行 */
async function ticketAllows(req, res) {
  const ticket = readTicketHeader(req);
  if (!ticket) {
    ApiResponse.codeError(res, 'REAUTH_TICKET_REQUIRED');
    return false;
  }
  const inspected = inspectReauthTicket(ticket, {
    userId: req.user?.userId,
    sessionId: req.user?.sessionId ?? null,
  });
  if (!inspected.valid) {
    logger.warn('审计读取被拒：二次验证票据无效或已过期', { username: req.user?.username });
    ApiResponse.codeError(res, 'REAUTH_TICKET_INVALID');
    return false;
  }

  // false = 这张票之前用过（重放）。对外仍报同一个码 REAUTH_TICKET_INVALID：可行动作与"票据无效/过期"一样，区分会给重放者额外信号位；重放事实只进日志。
  const consumed = await consumeReauthTicketJti({
    jti: inspected.jti,
    userId: req.user?.userId,
    expiresAt: new Date(inspected.exp),
  });
  if (!consumed) {
    logger.warn('审计读取被拒：二次验证票据已被使用（重放）', {
      username: req.user?.username,
      path: req.originalUrl,
    });
    ApiResponse.codeError(res, 'REAUTH_TICKET_INVALID');
    return false;
  }
  return true;
}

const requireReauthTicket = () =>
  asyncHandler(async (req, res, next) => {
    // 会话窗口优先（按设备会话 sid 查：refresh 不换 sid，jti 每次签发都换）：窗口内的请求既不要求票据，也不产生票据消费记录
    if (await hasLiveReauthGrant({ userId: req.user?.userId, sid: req.user?.sid ?? null })) {
      return next();
    }
    if (await ticketAllows(req, res)) return next();
    return undefined;
  });

module.exports = {
  REAUTH_TICKET_HEADER,
  requireReauthTicket,
};
