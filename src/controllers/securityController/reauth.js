/**
 * 二次验证：把刚通过的 step-up 落成两样东西——会话级窗口（models/ReauthGrant，绑 sid，5 分钟 TTL）
 * 与一次性票据（jti）。窗口放在服务端而不是让客户端继续拿票据：客户端不持任何可重放凭据，授权跟着该会话的访问令牌走（换设备/被踢即失效）。
 */

const ApiResponse = require('../../utils/apiResponse');
const { asyncHandler } = require('../../middleware/errorHandler');
const { issueReauthTicket: issueTicket } = require('../../utils/reauthTicket');
const { recordReauthGrant } = require('../../services/reauthGrantStore');

const issueReauthTicket = asyncHandler(async (req, res) => {
  const sessionId = req.user.sessionId ?? null;
  // 窗口绑设备会话 sid（refresh 不换、登出按同一把键撤销），票据仍绑本次令牌的 jti；落库失败不阻断签发（内部只告警）。
  await recordReauthGrant({ userId: req.user.userId, sid: req.user.sid ?? null });
  const issued = issueTicket({ userId: req.user.userId, sessionId });
  return ApiResponse.success(res, issued, '二次验证通过');
});

module.exports = { issueReauthTicket };
