/**
 * 会话级二次验证窗口：POST /security/reauth 成功即开 5 分钟窗口（幂等续期、绑 sid）。
 * 方向：记录/查询失败一律 fail-open 到票据路径（丢的只是便利，不是唯一性判据）；原委见 tests/security/reauthTicketEnforcement.test.js。
 */

const logger = require('../utils/logger');
const { incSecurityAlert } = require('../utils/metrics');
const ReauthGrant = require('../models/ReauthGrant');
const { REAUTH_TICKET_TTL_MS } = require('../utils/reauthTicket');

/** 开/续窗口（幂等：重复 step-up 只刷新到期时刻）；返回 true = 窗口已落库。 */
async function recordReauthGrant({ userId, sid }) {
  if (!sid) return false; // 存量令牌/未走设备会话：不落窗口，只能继续走一次性票据
  const expiresAt = new Date(Date.now() + REAUTH_TICKET_TTL_MS);
  try {
    await ReauthGrant.updateOne(
      { sid: String(sid) },
      { $set: { userId, expiresAt }, $setOnInsert: { grantedAt: new Date() } },
      { upsert: true }
    );
    return true;
  } catch (err) {
    logger.warn(`二次验证窗口未能落库（该会话本次仍按票据路径校验）：${err.message}`);
    incSecurityAlert('reauth_grant_store_degraded', 'medium'); // 降级只写日志等于没有可告警信号（constants/failOpenSites.js）
    return false;
  }
}

/** 该会话当前是否处在二次验证窗口内（查询失败按「无窗口」处理）。 */
async function hasLiveReauthGrant({ userId, sid }) {
  if (!sid || !userId) return false;
  try {
    const grant = await ReauthGrant.findOne(
      { sid: String(sid), userId, expiresAt: { $gt: new Date() } },
      { _id: 1 }
    ).lean();
    return Boolean(grant);
  } catch (err) {
    logger.warn(`二次验证窗口查询失败，按"未验证"处理（需重新 step-up）：${err.message}`);
    incSecurityAlert('reauth_grant_store_degraded', 'medium'); // 同上：一次库抖动会让全体用户被反复要求 step-up，运维需要看见
    return false;
  }
}

/**
 * 主动撤销某会话的窗口（登出/会话被踢）：不清也不是安全洞（sid 已失效），但登出即清是运维可核对的事实；失败只告警，不拖住登出主流程。
 */
async function revokeReauthGrant(sid) {
  if (!sid) return;
  try {
    await ReauthGrant.deleteOne({ sid: String(sid) });
  } catch (err) {
    logger.warn(`二次验证窗口清理失败（到期由 TTL 索引兜底）：${err.message}`);
  }
}

module.exports = { recordReauthGrant, hasLiveReauthGrant, revokeReauthGrant };
