/**
 * 管理面账户救济的专用审计（P1-2）：从 securityController/admin.js 抽出（其体积已贴 max-lines 棘轮）。MFA 重置与
 * 口令重置都是"业务状态已改变 ⇒ 审计先持久化再回成功"，且都不得把凭据（TOTP 密钥/临时口令）带进审计/日志。
 */

'use strict';

const { recordDurably } = require('./auditOutbox');
const { auditClientAddress } = require('../utils/ipUtils');

/**
 * 管理员重置 MFA 的专用审计（admin_reset_mfa）。
 * 调用方须在本次留痕成功之后置位 res.locals.skipGlobalAudit = true（响应时刻读取）。
 */
const recordAdminMfaReset = async (req, user) => {
  await recordDurably(
    {
      action: 'admin_reset_mfa',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      targetUserId: user._id,
      targetUsername: user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'high',
      riskFactors: ['admin_mfa_reset'],
      reason: `管理员重置用户 ${user.username} 的两步验证并强制下线`,
    },
    { auditAction: 'admin_reset_mfa', req }
  );
};

/** 管理员重置口令后的专用审计（admin_reset_password）；临时口令绝不进审计/日志，只进一次性响应体。 */
const recordAdminPasswordReset = async (req, user, reason) => {
  await recordDurably(
    {
      action: 'admin_reset_password',
      category: 'security',
      userId: req.user.userId,
      username: req.user.username,
      targetUserId: user._id,
      targetUsername: user.username,
      ...auditClientAddress(req),
      userAgent: req.get('user-agent'),
      success: true,
      riskLevel: 'high',
      riskFactors: ['admin_password_reset', 'forced_password_change'],
      reason: reason || `管理员重置用户 ${user.username} 的口令，并要求首次登录改密`,
    },
    { auditAction: 'admin_reset_password', req }
  );
};

module.exports = { recordAdminMfaReset, recordAdminPasswordReset };
