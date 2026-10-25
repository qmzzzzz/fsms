/**
 * 二次验证票据签发
 *
 * 本端点本身不读业务数据，只是把「刚通过的 step-up」换成一个短期、绑定会话的票据，
 * 供无法携带请求体凭据的审计读取端点复用。
 */

const ApiResponse = require('../../utils/apiResponse');
const { asyncHandler } = require('../../middleware/errorHandler');
const { issueReauthTicket: issueTicket } = require('../../utils/reauthTicket');

const issueReauthTicket = asyncHandler(async (req, res) => {
  const issued = issueTicket({
    userId: req.user.userId,
    sessionId: req.user.sessionId ?? null,
  });
  return ApiResponse.success(res, issued, '二次验证通过');
});

module.exports = { issueReauthTicket };
