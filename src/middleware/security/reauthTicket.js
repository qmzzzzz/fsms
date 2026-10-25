/**
 * 审计读取的二次验证票据校验（配合 utils/reauthTicket.js）
 *
 * GET 请求无法携带请求体凭据，故读取端点改用「先 POST /security/reauth 换票、
 * 再带 X-Reauth-Ticket 请求头」的两步流程。票据校验放在权限码之后：
 * 无权限者先吃 403，不会因为"没票"泄露端点存在性差异。
 */

const ApiResponse = require('../../utils/apiResponse');
const logger = require('../../utils/logger');
const { verifyReauthTicket } = require('../../utils/reauthTicket');

const REAUTH_TICKET_HEADER = 'x-reauth-ticket';

/** 取单个请求头值：重复头在 Node 里可能表现为数组，只认第一个 */
const readTicketHeader = (req) => {
  const value = req.headers?.[REAUTH_TICKET_HEADER];
  return Array.isArray(value) ? value[0] : value;
};

const requireReauthTicket = () => (req, res, next) => {
  const ticket = readTicketHeader(req);
  if (!ticket) {
    return ApiResponse.codeError(res, 'REAUTH_TICKET_REQUIRED');
  }
  const valid = verifyReauthTicket(ticket, {
    userId: req.user?.userId,
    sessionId: req.user?.sessionId ?? null,
  });
  if (!valid) {
    logger.warn('审计读取被拒：二次验证票据无效或已过期', {
      username: req.user?.username,
    });
    return ApiResponse.codeError(res, 'REAUTH_TICKET_INVALID');
  }
  return next();
};

module.exports = {
  REAUTH_TICKET_HEADER,
  requireReauthTicket,
};
