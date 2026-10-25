/**
 * 每用户设备会话配额收敛
 *
 * 自 sessionService 拆出：该文件已触及 max-lines 棘轮上限，而配额逻辑与
 * 会话创建是两件事——前者是"登录后的清理"，后者是"登录本身的落库"。
 * 缓存失效作为参数注入，避免与本模块的调用方形成循环依赖。
 */

const UserSession = require('../models/UserSession');
const logger = require('../utils/logger');
const { notifySessionRevoked } = require('./sessionRevocationEvents');

/** 每个用户同时可用的设备会话上限；超出时按 lastSeenAt 淘汰最旧的 */
const MAX_ACTIVE_SESSIONS_PER_USER = 20;

/**
 * 保留最近活动的 MAX_ACTIVE_SESSIONS_PER_USER 条会话，其余置为 revoked。
 *
 * keepSid 是刚创建的会话（它自己占一个名额）。淘汰按 lastSeenAt 升序：
 * 最久未活动的先踢，用户当前在用的设备不会被误伤。
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.keepSid
 * @param {(sid: string) => void} params.invalidateSession 单会话缓存失效
 * @returns {Promise<number>} 本次淘汰的会话数
 */
const enforceSessionCap = async ({ userId, keepSid, invalidateSession }) => {
  const others = await UserSession.find({ userId, status: 'active', sid: { $ne: keepSid } })
    .sort({ lastSeenAt: 1 })
    .select('sid')
    .lean();
  const excess = others.length - (MAX_ACTIVE_SESSIONS_PER_USER - 1);
  if (excess <= 0) return 0;

  const sids = others.slice(0, excess).map((s) => String(s.sid));
  const result = await UserSession.updateMany(
    { sid: { $in: sids }, status: 'active' },
    { $set: { status: 'revoked', revokedAt: new Date(), revokeReason: 'session_cap' } }
  );
  for (const sid of sids) invalidateSession(sid);

  const count = result.modifiedCount || 0;
  if (count > 0) {
    notifySessionRevoked({
      sids,
      userId: String(userId),
      all: false,
      reason: 'session_cap',
    });
    logger.info('会话配额收敛', { userId, count, keepSid: String(keepSid).slice(0, 8) });
  }
  return count;
};

module.exports = {
  MAX_ACTIVE_SESSIONS_PER_USER,
  enforceSessionCap,
};
