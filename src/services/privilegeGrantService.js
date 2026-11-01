/**
 * 临时权限授予服务（C-08 / C-09）。三条不变量：1. 到期即失效：读侧只取 status=active 且 expiresAt>now，不依赖后台任务；
 * 2. 职责分离：申请人不得自审，高敏授予需两名**不同**审批人（按 by 去重计数，存量同人重复签批一律不采纳），且审批人必须自持拟授予的权限；
 * 3. 变更即失效缓存（否则最长 30 秒旧权限集仍放行）。
 * A1/A2/A3（2026-10-30）：签批与状态推进改为基于**库内现值**的条件更新；保留通配权限码不得经本通道申请、未登记模块前缀一律判高敏；A4：激活竞态输给驳回/撤销时必须显式 409（旧行为返回 200 + 非 active 文档，被读成「审批成功」）。
 * 到期即失效只由「读侧判定 + 缓存 TTL 收敛到最近到期时刻」这一条腿保证：expireDue 的调用方是独立进程，与在线进程不共享进程内缓存。
 */

'use strict';

const PrivilegeGrant = require('../models/PrivilegeGrant');
const User = require('../models/User');
const ApiError = require('../utils/ApiError'); // 业务码只认 utils/errorCodes.js 那份注册表
const logger = require('../utils/logger');
const { approvalPolicyOf, EXPIRING_SOON_HOURS } = require('../constants/privilegeGrant');
const { GRANT_LIST_FIELDS } = require('../constants/privilegeGrant');

const {
  setPermissionCacheInvalidator,
  setPermissionChecker,
  invalidatePermissionCache,
  hasPermission,
} = require('./privilegeGrantHooks'); // 两个外部钩子（缓存失效/持权判定）拆到独立模块：本体只做业务规则

/** 权限解析读路径：一次取回多个用户的生效权限码，并带出各自最近一条授予的到期时刻（读侧缓存 TTL 据此收敛，见 userPermissionService） */
async function activeGrantsForUsers(userIds, now = new Date()) {
  const ids = (Array.isArray(userIds) ? userIds : [userIds])
    .map((id) => String(id || ''))
    .filter(Boolean);
  const result = new Map(ids.map((id) => [id, { codes: [], expiresAt: null }]));
  if (ids.length === 0) return result;
  const filter = { userId: { $in: ids }, status: 'active', expiresAt: { $gt: now } };
  const grants = await PrivilegeGrant.find(filter, 'userId permissionCodes expiresAt').lean();
  for (const grant of grants) {
    const bucket = result.get(String(grant.userId));
    if (!bucket) continue;
    for (const code of grant.permissionCodes || []) {
      if (!bucket.codes.includes(code)) bucket.codes.push(code);
    }
    const expiresAt = grant.expiresAt ? new Date(grant.expiresAt) : null;
    if (expiresAt && (!bucket.expiresAt || expiresAt < bucket.expiresAt))
      bucket.expiresAt = expiresAt;
  }
  return result;
}

const activeCodesForUsers = async (userIds, now = new Date()) => {
  const grants = await activeGrantsForUsers(userIds, now); // 只取权限码的入口，与上面的 rich 版同源（口径不允许出现第二份实现）
  return new Map([...grants].map(([key, bucket]) => [key, bucket.codes]));
};

const {
  grantError,
  clampDurationHours,
  normalizeCodes,
  assertCodesGrantable,
} = require('./privilegeGrantValidation'); // 入参校验与错误构造的单一出口

/** 申请：只落一条 pending 记录，不产生任何授权效果 */
async function requestGrant({ targetUserId, permissionCodes, reason, durationHours, operator }) {
  const codes = normalizeCodes(permissionCodes);
  const hours = clampDurationHours(durationHours);
  const text = String(reason || '').trim();
  if (!text) throw grantError('申请理由不能为空', 400, 'PRIVILEGE_GRANT_INVALID');

  const target = await User.findById(targetUserId).select('username status').lean();
  if (!target) throw ApiError.notFound('被授权用户不存在');
  if (target.status !== 'active') {
    throw ApiError.badRequest('被授权用户当前不可用，无法授予临时权限');
  }

  await assertCodesGrantable(codes);
  const policy = approvalPolicyOf(codes);
  const now = new Date();
  const grant = await PrivilegeGrant.create({
    userId: target._id,
    username: target.username || '',
    permissionCodes: codes,
    reason: text.slice(0, 200),
    requestedBy: operator.userId,
    requestedByName: operator.username || '',
    requestedAt: now,
    requiredApprovals: policy.requiredApprovals,
    highRisk: policy.highRisk,
    durationHours: hours,
    status: 'pending',
  });
  logger.info('临时权限授予申请已创建', {
    grantId: String(grant._id),
    targetUserId: String(target._id),
    highRisk: policy.highRisk,
    requiredApprovals: policy.requiredApprovals,
  });
  return grant;
}

async function getGrant(grantId) {
  const grant = await PrivilegeGrant.findById(grantId);
  if (!grant) throw grantError('授权记录不存在', 404, 'PRIVILEGE_GRANT_NOT_FOUND');
  return grant;
}

/** 审批人资格：不得是申请人、不得是已签批人，且必须自己持有全部拟授予的码 */
async function assertApproverEligible(grant, operator) {
  const operatorId = String(operator.userId);
  if (String(grant.requestedBy) === operatorId) {
    throw grantError('申请人不得审批自己提交的授权申请', 403, 'PRIVILEGE_SELF_APPROVAL_FORBIDDEN');
  }
  if (grant.approvals.some((item) => String(item.by) === operatorId)) {
    throw grantError('同一审批人不得重复签批', 409, 'PRIVILEGE_GRANT_NOT_PENDING');
  }
  for (const code of grant.permissionCodes) {
    const owned = await hasPermission(operator.userId, code);
    if (!owned) {
      const detail = '审批人须自行持有拟授予的权限：' + code;
      throw grantError(detail, 403, 'PRIVILEGE_APPROVAL_FORBIDDEN');
    }
  }
}

const distinctApproverCount = (approvals) =>
  new Set((approvals || []).map((item) => String(item && item.by))).size; // 人数口径：同一审批人的重复条目只算一票

const hasDuplicateApprovers = (approvals) =>
  distinctApproverCount(approvals) !== (approvals || []).length; // 存量脏形态：approvals 里同一人出现多条

const assertPending = (grant) => {
  if (grant.status !== 'pending') {
    throw grantError('该授权申请已处理，不能重复审批', 409, 'PRIVILEGE_GRANT_NOT_PENDING');
  }
};

const logGrantApproved = (grant) =>
  logger.info('临时权限授予已签批', {
    grantId: String(grant._id),
    approvals: grant.approvals.length,
    requiredApprovals: grant.requiredApprovals,
    status: grant.status,
  });

/** 审批：签批与状态推进都是基于**库内现值**的条件更新（filter 里求值 + 文档级串行化），落库成功后才失效权限缓存。
 * 旧实现是读-改-写内存副本：并发下同一审批人可被写进多条签批、两人各签一次后 approvals 有 2 条而 status 仍是 pending——已批准的权限永远不生效，而每个请求都返回成功。 */
async function approveGrant({ grantId, operator }) {
  const operatorId = String(operator.userId);
  const name = operator.username || '';
  const now = new Date();
  const snapshot = await getGrant(grantId); // 只用于「未持权 403」与 404 的快速失败：pending/自审/重复签批一律由下面的条件更新按库内现值判定
  await assertApproverEligible(snapshot, operator);

  let grant = await PrivilegeGrant.findOneAndUpdate(
    {
      _id: grantId,
      status: 'pending',
      requestedBy: { $ne: operatorId }, // 不得自我审批
      'approvals.by': { $ne: operatorId }, // 不得重复签批：并发下由数据库拦住，approvals 里不会出现同一个人第二条
      $expr: { $eq: [{ $size: '$approvals.by' }, { $size: { $setUnion: ['$approvals.by', []] } }] }, // 存量同人重复签批不得再凑一票：现有 approvals 无重复才命中
    },
    { $push: { approvals: { by: operatorId, name, at: now } } },
    { new: true }
  );
  if (!grant) {
    const latest = await getGrant(grantId); // 没签上：409/403 由断言报出；断言全过仍等于本次没写进任何签批（_id 不匹配会先 404），绝不能按内存副本回成功
    assertPending(latest);
    await assertApproverEligible(latest, operator);
    throw grantError(
      hasDuplicateApprovers(latest.approvals)
        ? '该授权记录存在同一审批人重复签批，须先人工清洗；本次未写入任何签批'
        : '签批未写入库（并发窗口），本次未写入任何签批，拒绝报告成功',
      409,
      'PRIVILEGE_GRANT_NOT_PENDING'
    );
  }

  if (distinctApproverCount(grant.approvals) < grant.requiredApprovals) {
    logGrantApproved(grant);
    return grant;
  }
  const activateFilter = {
    _id: grantId,
    status: 'pending',
    $expr: { $gte: [{ $size: { $setUnion: ['$approvals.by', []] } }, '$requiredApprovals'] }, // 激活：库内现值 + 按 by 去重后的人数；旧写法 $size 比条数，同一人重复签批即可凑满阈值
  };
  const active = await PrivilegeGrant.findOneAndUpdate(
    activateFilter,
    {
      $set: {
        status: 'active',
        grantedAt: now,
        expiresAt: new Date(now.getTime() + grant.durationHours * 3600 * 1000),
        decidedBy: operatorId,
        decidedByName: name,
        decidedAt: now,
      },
    },
    { new: true }
  );
  if (!active) {
    const latest = await getGrant(grantId); // 同一拍被另一路改写：判定必须取库内现值，不能按内存副本
    if (latest.status === 'active' || latest.status === 'expired') {
      invalidatePermissionCache(latest.userId);
      return latest; // 另一名审批人已把同一授予推进生效：幂等成功（200 + 库内现值），不是失败
    }
    if (latest.status !== 'pending') {
      throw grantError(
        '签批未生效：本次签批与状态推进之间，该授予已被驳回或撤销（库内当前状态：' +
          latest.status +
          '）。本次签批已落库但授予不会生效，请按库内现值处置，不得据此报告审批成功',
        409,
        'PRIVILEGE_GRANT_NOT_PENDING'
      );
    }
    return latest; // 库内仍是 pending：激活判据未满足（存量同人重复签批那类脏形态），如实返回，不谎报已生效
  }
  invalidatePermissionCache(active.userId); // 先落库、后失效：反过来会留下「读到生效前权限集」的空窗
  logGrantApproved(active);
  return active;
}

const decisionFields = (operator, reason, now) => ({
  decidedBy: operator.userId,
  decidedByName: operator.username || '',
  decidedAt: now,
  decisionReason: String(reason || '')
    .trim()
    .slice(0, 200),
});

// 撤销留痕独立成组（revoked*）：撤销不得覆写决定留痕（decided*）——「谁批的」在撤销后仍须可回答
const revocationFields = (operator, reason, now) => ({
  revokedBy: operator.userId,
  revokedByName: operator.username || '',
  revokedAt: now,
  revokeReason: String(reason || '')
    .trim()
    .slice(0, 200),
});

/** 驳回/撤销共用：状态机判据写在 filter 里（只看库内现值），是否失效缓存只看条件更新返回的**更新前文档**的 status；写哪组留痕字段由调用方传入（驳回 decided*，撤销 revoked*） */
async function decideGrant({ grantId, fromStatuses, toStatus, operator, reason, fields }) {
  const before = await PrivilegeGrant.findOneAndUpdate(
    { _id: grantId, status: { $in: fromStatuses } },
    { $set: { status: toStatus, ...fields(operator, reason, new Date()) } },
    { new: false }
  );
  if (!before) return null;
  if (before.status === 'active') invalidatePermissionCache(before.userId); // 先落库、后失效：与 activate 同一顺序
  return { before, after: await getGrant(grantId) };
}

async function rejectGrant({ grantId, operator, reason }) {
  const snapshot = await getGrant(grantId); // 只用于 404 与「自审/无持权」403 的快速失败
  assertPending(snapshot);
  await assertApproverEligible(snapshot, operator);
  const outcome = await decideGrant({
    grantId,
    fromStatuses: ['pending'],
    toStatus: 'rejected',
    operator,
    reason,
    fields: decisionFields,
  });
  if (!outcome) {
    assertPending(await getGrant(grantId)); // 没改成：库内已不是 pending ⇒ 409；本次未写入，不得按读快照回成功
    throw grantError('驳回未写入库（并发窗口）', 409, 'PRIVILEGE_GRANT_NOT_PENDING');
  }
  logger.info('临时权限授予已驳回', {
    grantId: String(outcome.after._id),
    from: outcome.before.status,
    to: 'rejected',
  });
  return outcome.after;
}

async function revokeGrant({ grantId, operator, reason }) {
  const outcome = await decideGrant({
    grantId,
    fromStatuses: ['pending', 'active'],
    toStatus: 'revoked',
    operator,
    reason,
    fields: revocationFields,
  });
  if (!outcome) {
    const latest = await getGrant(grantId); // 404 由它抛；其余按库内现值给出稳定错误码
    throw grantError(
      '该授权当前状态不可撤销（当前：' + latest.status + '）',
      409,
      'PRIVILEGE_GRANT_NOT_ACTIVE',
      { currentStatus: latest.status }
    );
  }
  logger.info('临时权限授予已撤销', {
    grantId: String(outcome.after._id),
    from: outcome.before.status,
    to: 'revoked',
    wasActive: outcome.before.status === 'active',
  });
  return outcome.after;
}

/** 到期回收：由独立进程的巡检脚本（scripts/access-review.js --expire）调用，只把到期的 active 置为 expired 并写自己的 expiredAt（记录留存，不删除）；decidedAt/decidedBy/decisionReason 是批准/驳回留下的既成事实，这里一个字都不改；**不**失效权限缓存——调用方是独立进程，进程内缓存/钩子不跨进程共享，到期即失效由读侧判据与缓存 TTL 收敛保证 */
async function expireDue(now = new Date()) {
  const result = await PrivilegeGrant.updateMany(
    { status: 'active', expiresAt: { $lte: now } },
    { $set: { status: 'expired', expiredAt: now } }
  );
  return result.modifiedCount || 0;
}

async function listGrants({ status, userId, page = 1, limit = 20 }) {
  const query = {};
  if (status) query.status = status;
  if (userId) query.userId = userId;
  const [items, total] = await Promise.all([
    PrivilegeGrant.find(query)
      .select(GRANT_LIST_FIELDS) // 显式投影：未知字段一律不下发（白名单见 constants/privilegeGrant.js）
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    PrivilegeGrant.countDocuments(query),
  ]);
  return { items, total };
}

module.exports = {
  activeGrantsForUsers,
  activeCodesForUsers,
  requestGrant,
  approveGrant,
  rejectGrant,
  revokeGrant,
  expireDue,
  listGrants,
  getGrant,
  setPermissionCacheInvalidator,
  setPermissionChecker,
  EXPIRING_SOON_HOURS,
};
