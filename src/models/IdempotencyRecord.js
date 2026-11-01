/**
 * 幂等键落库记录（ADR-014）：一条记录 = 一次已受理的提交。
 * 判据落库而非进程内存——"只有一个进程"是部署形态的偶然事实，不是安全判据。
 */

const mongoose = require('mongoose');

const idempotencyRecordSchema = new mongoose.Schema({
  // 哈希已含 scope + userId，故这里单列唯一即可
  keyHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  scope: { type: String, required: true },
  requestHash: { type: String, required: true },
  state: {
    type: String,
    required: true,
    enum: ['in_progress', 'completed'],
    default: 'in_progress',
  },
  statusCode: { type: Number, default: null },
  responseBody: { type: mongoose.Schema.Types.Mixed, default: null },
  contentType: { type: String, default: null }, // 非 JSON 响应的媒体类型：回放要连 Content-Type 一起还原
  responseLocation: { type: String, default: null }, // 首次响应给的 Location：重放要还原指针，但绝不伪造
  replayOmitted: { type: Boolean, default: false }, // true = 已完成但无体可回放（超限/流式/无体）
  createdAt: { type: Date, default: Date.now },
  // 保留窗口；TTL 索引只负责回收，判据本身另带 expiresAt
  expiresAt: { type: Date, required: true },
});

idempotencyRecordSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('IdempotencyRecord', idempotencyRecordSchema);
