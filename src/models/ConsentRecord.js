/**
 * 隐私政策同意记录（审计一-7）：一条记录 = 某账号对某一版隐私告知的一次同意。为什么落库：同意必须**可被证明**（《个人信息保护法》），前端勾选框只是提交动作；告知改版后还要能区分"同意的是旧版"。三条不变式见 tests/models/ConsentRecord.test.js。
 */

const mongoose = require('mongoose');

const consentRecordSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    // 账号名冗余快照：用户被匿名化后，这条同意仍要答得出"属于谁"
    username: { type: String, required: true },
    policy: { type: String, required: true, enum: ['privacy'] }, // 政策标识用固定枚举而非自由字符串，避免拼写漂移出第二类记录
    version: { type: String, required: true }, // 告知版本号（如 '2026-11-01'）：改版必须升版，旧同意不得自动覆盖新版
    // 覆盖的数据范围：取自 constants/dataClassification 的 CONSENT_SCOPES 键
    scopes: { type: [String], required: true, default: [] },
    acceptedAt: { type: Date, required: true },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    source: {
      type: String,
      required: true,
      enum: ['self-register', 'profile-renew', 'admin-recorded'],
    },
  },
  { timestamps: true, collection: 'consentrecords' }
);

// 同一账号 × 政策 × 版本只记一条：重复提交是幂等，不是第二次同意
consentRecordSchema.index({ userId: 1, policy: 1, version: 1 }, { unique: true });
consentRecordSchema.index({ userId: 1, acceptedAt: -1 });

// append-only：与 auditLogHooks 的 9 项写入口同宽（批量篡改路径不能成为后门）。测试清理靠 NODE_ENV=test + 显式 bypassAppendOnly（与审计链护栏同一契约）。
const APPEND_ONLY = [
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'replaceOne',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndReplace',
  'bulkWrite',
];

const bypassed = (query) => {
  const options = (query.getOptions && query.getOptions()) || {};
  return process.env.NODE_ENV === 'test' && options.bypassAppendOnly === true;
};

consentRecordSchema.pre('save', function (next) {
  if (!this.isNew) return next(new Error('同意记录为 append-only，禁止修改已入库记录'));
  return next();
});

consentRecordSchema.pre(APPEND_ONLY, function (next) {
  if (bypassed(this)) return next();
  next(new Error('同意记录为 append-only，禁止修改/删除'));
});

module.exports = mongoose.model('ConsentRecord', consentRecordSchema);
