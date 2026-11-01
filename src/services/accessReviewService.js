/**
 * 定期权限复核（C-08）：统计与超期清单。复核对象是「临时授予」而不是角色定义——角色是常态配置，
 * 临时授予是例外通道，必须有人在到期前确认它仍被需要；超期判据取 grantedAt（生效时刻）而不是
 * createdAt：申请挂了三天才批，复核时钟应从真正拿到权限那一刻开始算。
 */

'use strict';

const PrivilegeGrant = require('../models/PrivilegeGrant');
const {
  REVIEW_OVERDUE_DAYS,
  EXPIRING_SOON_HOURS,
  GRANT_LIST_FIELDS,
} = require('../constants/privilegeGrant');

const HOUR_MS = 3600 * 1000;

/** 超期未复核的生效授予清单（只读，不改状态） */
function listOverdueGrants({
  now = new Date(),
  overdueDays = REVIEW_OVERDUE_DAYS,
  limit = 100,
} = {}) {
  const deadline = new Date(now.getTime() - overdueDays * 24 * HOUR_MS);
  return PrivilegeGrant.find({
    status: 'active',
    expiresAt: { $gt: now },
    grantedAt: { $lte: deadline },
    reviewedAt: null,
  })
    .select(GRANT_LIST_FIELDS)
    .sort({ grantedAt: 1 })
    .limit(limit)
    .lean();
}

/** 复核汇总：供复核脚本、看板与告警取数（单一入口，避免多处各写一套口径） */
async function reviewSummary({ now = new Date(), overdueDays = REVIEW_OVERDUE_DAYS } = {}) {
  const soon = new Date(now.getTime() + EXPIRING_SOON_HOURS * HOUR_MS);
  const overdueDeadline = new Date(now.getTime() - overdueDays * 24 * HOUR_MS);
  const [active, expiringSoon, highRiskActive, overdue, pending] = await Promise.all([
    PrivilegeGrant.countDocuments({ status: 'active', expiresAt: { $gt: now } }),
    PrivilegeGrant.countDocuments({ status: 'active', expiresAt: { $gt: now, $lte: soon } }),
    PrivilegeGrant.countDocuments({ status: 'active', expiresAt: { $gt: now }, highRisk: true }),
    PrivilegeGrant.countDocuments({
      status: 'active',
      expiresAt: { $gt: now },
      grantedAt: { $lte: overdueDeadline },
      reviewedAt: null,
    }),
    PrivilegeGrant.countDocuments({ status: 'pending' }),
  ]);
  return { asOf: now, overdueDays, active, expiringSoon, highRiskActive, overdue, pending };
}

/** 登记复核结论（复核人留痕；只在生效期内允许） */
async function markReviewed({ grantId, operator, now = new Date() }) {
  const updated = await PrivilegeGrant.findOneAndUpdate(
    { _id: grantId, status: 'active', expiresAt: { $gt: now } },
    { $set: { reviewedAt: now, reviewedBy: operator.userId } },
    { new: true }
  );
  if (!updated) {
    const ApiError = require('../utils/ApiError');
    const latest = await PrivilegeGrant.findById(grantId).select('status').lean();
    const current = latest ? latest.status : 'deleted';
    throw new ApiError(
      '该授权当前不在生效期，无法登记复核（当前：' + current + '）',
      409,
      { currentStatus: current },
      'PRIVILEGE_GRANT_NOT_ACTIVE'
    );
  }
  return updated;
}

module.exports = { reviewSummary, listOverdueGrants, markReviewed };
