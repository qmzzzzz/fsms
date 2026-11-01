/**
 * 临时权限授予模型（C-08）：申请 → 审批 → 生效 → 到期自动失效 / 撤销
 *
 * 与角色授权（Role.permissions）的分工：角色授权是常态、无期限；本模型是
 * 有时间盒的例外通道，读侧按 expiresAt 过滤，超期即失效，不靠人工回收。
 * approvals 保留每条审批人与时间的完整序列（高敏授予需两条），
 * 事后可回答「谁批的、什么时候批的、批了几人」。
 */

const mongoose = require('mongoose');
const { PRIVILEGE_GRANT_STATUSES, MAX_GRANT_CODES } = require('../constants/privilegeGrant');

const approvalSchema = new mongoose.Schema(
  {
    by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, trim: true, maxlength: 50, default: '' },
    at: { type: Date, required: true },
  },
  { _id: false }
);

const privilegeGrantSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    // 用户名快照：用户改名或被删除后，审计与列表仍要能读出「当时是谁」
    username: { type: String, trim: true, maxlength: 50, default: '' },
    permissionCodes: {
      type: [String],
      required: true,
      validate: {
        validator: (v) => Array.isArray(v) && v.length > 0 && v.length <= MAX_GRANT_CODES,
        message: '授予的权限码数量应在 1-' + MAX_GRANT_CODES + ' 之间',
      },
    },
    reason: { type: String, required: true, trim: true, maxlength: 200 },
    requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    requestedByName: { type: String, trim: true, maxlength: 50, default: '' },
    requestedAt: { type: Date, required: true },
    approvals: { type: [approvalSchema], default: [] },
    requiredApprovals: { type: Number, enum: [1, 2], required: true },
    highRisk: { type: Boolean, default: false },
    durationHours: { type: Number, required: true, min: 1, max: 168 },
    status: { type: String, enum: PRIVILEGE_GRANT_STATUSES, default: 'pending', index: true },
    grantedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null, index: true },
    expiredAt: { type: Date, default: null }, // 巡检实际回收时刻：与 decidedAt（批准/驳回的决定时刻）分开留痕，互不覆写
    decidedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    decidedByName: { type: String, trim: true, maxlength: 50, default: '' },
    decidedAt: { type: Date, default: null },
    decisionReason: { type: String, trim: true, maxlength: 200, default: '' },
    revokedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    revokedByName: { type: String, trim: true, maxlength: 50, default: '' },
    revokedAt: { type: Date, default: null },
    revokeReason: { type: String, trim: true, maxlength: 200, default: '' },
    reviewedAt: { type: Date, default: null },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  },
  { timestamps: true }
);

// 权限解析读路径：按用户 + 生效态 + 未过期取码
privilegeGrantSchema.index({ userId: 1, status: 1, expiresAt: 1 });
// 到期回收与「即将到期」巡检：按状态 + 到期时间扫描
privilegeGrantSchema.index({ status: 1, expiresAt: 1, createdAt: -1 });

module.exports = mongoose.model('PrivilegeGrant', privilegeGrantSchema);
