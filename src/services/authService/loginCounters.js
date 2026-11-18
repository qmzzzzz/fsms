/**
 * 登录失败计数的共享原子写（P1-1）：口令路径与 MFA 路径必须共用同一份并发判据。
 * User 由调用方传入（两处均已持有模型引用，避免新增顶层依赖边）。
 */
const loginGuard = require('../../config/loginGuard');
const logger = require('../../utils/logger');
const AuditLog = require('../../models/AuditLog');
const { auditRequestContext } = require('../../models/auditLogWriteStatics');

// 与 failureAndMfa.js 的 LOCK_DURATION_MS 同源（config/loginGuard）：
// 锁定时长只有一份口径，helper 自取而不是让调用方再传一遍
const LOCK_DURATION_MS = loginGuard.lockMs;

async function applyLoginFailureCountAtomic(User, user) {
  const now = new Date();
  const lockExpired = user.lockUntil && user.lockUntil <= now;
  let updated = null;
  if (lockExpired) {
    updated = await User.findOneAndUpdate(
      { _id: user._id, lockUntil: { $lte: now } },
      { $set: { failedLoginCount: 1, lockUntil: null } },
      { new: true }
    ).catch(() => null);
  }
  if (!updated) {
    updated = await User.findByIdAndUpdate(
      user._id,
      { $inc: { failedLoginCount: 1 } },
      { new: true }
    ).catch(() => null);
  }
  return updated;
}

/**
 * 账户临时锁定收口：落库 + 缓存失效 + 日志 + account_temp_locked 审计
 * （login.js 口令主路径与 failureAndMfa.js 的 MFA/恢复码路径共用）。
 *
 * 此前两条路径各写一遍锁定块且已漂移：MFA/恢复码路径只写 logger.warn、漏写
 * account_temp_locked 审计，合规检索会系统性漏掉该通道触发的锁定。
 *
 * 锁定写失败时 lockApplied=false：缓存不失效，日志与审计必须如实说「防线未生效」，
 * 不得宣称一道并不存在的防线（与 mfaService 的 lockApplied 同口径）。
 *
 * @returns {Promise<boolean>} 锁定是否成功落库
 */
async function applyAccountTempLock(User, user, { username, failedCount, lockReason, ctx }) {
  let lockApplied = true;
  await User.findByIdAndUpdate(user._id, {
    lockUntil: new Date(Date.now() + LOCK_DURATION_MS),
  }).catch((err) => {
    lockApplied = false;
    logger.error(`账户临时锁定写入失败（防爆破防线未生效）：${err.message}`, { username });
  });
  if (lockApplied) {
    // 锁定生效后必须失效认证缓存：authenticate 读的是缓存快照（TTL 60s），
    // 不失效则已签发的 access token 在窗口内仍能带着旧 lockUntil 通过校验。
    // 惰性 require：middleware/auth 的依赖链会绕回 authService，顶层引用会成环。
    const { invalidateUserCache } = require('../../middleware/auth');
    invalidateUserCache(user._id);
  }
  logger.warn(`账户临时锁定（${lockReason}）`, {
    username,
    failedCount,
    lockMinutes: 10,
    // 锁到底有没有落库：读日志的人据此判断防线是否还在，而不是信一句断言
    lockApplied,
  });
  // 阈值如今只能被「能连续通过人机验证」的一方触达（见 loginChallenge），不再是被动可触发的 DoS 面。
  AuditLog.record({
    action: 'account_temp_locked',
    category: 'auth',
    userId: user._id,
    username,
    // 请求上下文补采（见 auditRequestContext）：机器触发的锁定事件也带上发起请求的溯源；
    // 直连调用（如并发边界测试）不带 ctx 时退化为只写主体字段，不得因此中断锁定流程
    ...(ctx?.req ? auditRequestContext(ctx.req) : {}),
    ip: ctx?.ip,
    userAgent: ctx?.userAgent,
    fingerprint: ctx?.fingerprint,
    success: false,
    riskLevel: 'high',
    riskFactors: ['excessive_failed_logins'],
    reason: lockApplied
      ? `连续登录失败 ${failedCount} 次，账户临时锁定 10 分钟`
      : `连续登录失败 ${failedCount} 次，但锁定未能写入数据库，防爆破防线当前未生效`,
  }).catch(() => {});
  return lockApplied;
}

module.exports = { applyLoginFailureCountAtomic, applyAccountTempLock };
