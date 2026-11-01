/**
 * 失败触发的人机挑战闸门：同一用户名的连续失败达阈值后，登录前置层要求人机验证（不读验证码静态开关）。闸门先于口令比对，被拦下的尝试不推进失败计数，因此「知道用户名就能把账户传入 10 分钟锁定」的可用性 DoS 不成立；判据走 AuditLog 的失败行（不存在的用户名同样写），故与账户存在性无关。判据读不到时 fail-closed（要求挑战）：那种情况登录本来就查不到用户，同一个依赖。闸门拦下的尝试落一条独立审计 login_captcha_rejected（留痕但不推进任何失败计数，见 recordCaptchaRejected），取舍、未采纳方案与残余见 docs/adr/ADR-015-登录失败触发的人机挑战与锁定收口.md
 */
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { onAuditWriteFailure } = require('../utils/auditWriteFailure');

/** 触发挑战的连续失败次数（先于 MAX_FAILED_LOGINS 生效）；判据窗口 15 分钟，与凭据型限流（loginUserLimiter）对齐 */
const CHALLENGE_AFTER_FAILURES = 3;
const CHALLENGE_WINDOW_MS = 15 * 60 * 1000;
/** 与 securityAlert.checkBruteForce 统计同一批失败动作，避免两处口径分叉；闸门自身拦下的尝试写 login_captcha_rejected，刻意不进本清单——否则「被拦下」会变成新的失败计数，闸门自己把自己焊死 */
const FAILURE_ACTIONS = ['login_failed', 'auth_failed'];
const CAPTCHA_REJECTED_ACTION = 'login_captcha_rejected'; // 留痕专用动作：与 FAILURE_ACTIONS 分账，写它不推进挑战/爆破任何一方的计数
const CAPTCHA_TRIGGERS = Object.freeze({
  SWITCH: 'captcha_switch',
  CHALLENGE: 'challenge_required',
}); // 拦下它的那一层，写进 reason 供取证分辨「开关常开」与「连续失败触发」

/** 该用户名当前是否需要人机挑战；判据不可读时返回 true（fail-closed） */
const isChallengeRequired = async (username) => {
  if (typeof username !== 'string' || !username.trim()) return false;
  const windowStart = new Date(Date.now() - CHALLENGE_WINDOW_MS);
  try {
    const collation = AuditLog.AUDIT_USERNAME_COLLATION;
    const lastSuccess = await AuditLog.findOne({
      username,
      action: 'login_success',
      timestamp: { $gte: windowStart },
    })
      .collation(collation)
      .sort({ timestamp: -1 })
      .select('timestamp')
      .lean();
    // 只数"最近一次成功登录之后"的失败行；窗口内没有成功记录就从窗口起点数
    const since =
      lastSuccess && lastSuccess.timestamp > windowStart ? lastSuccess.timestamp : windowStart;
    const failures = await AuditLog.countDocuments({
      username,
      action: { $in: FAILURE_ACTIONS },
      timestamp: { $gt: since },
    }).collation(collation);
    return failures >= CHALLENGE_AFTER_FAILURES;
  } catch (err) {
    logger.warn(`人机挑战判据不可读，按需要挑战处理：${err.message}`);
    return true;
  }
};

const REJECT_REASONS = Object.freeze([
  CAPTCHA_TRIGGERS.SWITCH,
  CAPTCHA_TRIGGERS.CHALLENGE,
  'unspecified',
]);
const reasonOf = (trigger) => (REJECT_REASONS.includes(trigger) ? trigger : 'unspecified');
/** 闸门拦下时落一条失败审计（审计二-3「失败尝试落库留痕」）：写失败走 onAuditWriteFailure（error 日志 + audit_write_failed/high）且永不 reject、同步抛（模型未就绪/CastError）同样就地吞下——调用方在登录路径上，一个异常就把 400 变成 500。`reason` 是自由文本字段、schema 侧无清洗，而本函数是导出件 ⇒ 只写闭集（`captcha_switch` / `challenge_required` / `unspecified`）里的值，调用方传什么都不会原样落库 */
const recordCaptchaRejected = async ({
  username,
  ip,
  userAgent,
  fingerprint,
  trigger,
  captchaSubmitted,
}) => {
  if (typeof username !== 'string' || !username.trim()) return null;
  const reason = reasonOf(trigger);
  try {
    return await AuditLog.create({
      action: CAPTCHA_REJECTED_ACTION,
      category: 'auth',
      userId: null,
      username,
      ip,
      userAgent,
      fingerprint: fingerprint || null,
      success: false,
      riskLevel: 'medium',
      riskFactors: [captchaSubmitted ? 'captcha_mismatch' : 'captcha_absent'],
      reason,
    });
  } catch (err) {
    onAuditWriteFailure('login_captcha_rejected_audit', { user: { username } })(err);
    return null;
  }
};

module.exports = {
  isChallengeRequired,
  recordCaptchaRejected,
  CAPTCHA_REJECTED_ACTION,
  CAPTCHA_TRIGGERS,
  CHALLENGE_AFTER_FAILURES,
  CHALLENGE_WINDOW_MS,
  FAILURE_ACTIONS,
};
