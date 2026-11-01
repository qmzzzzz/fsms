/**
 * 已消费的二次验证票据登记（一次性消费）：jti 唯一索引即「这张票用过没有」的判据，并发下只有一个 create 成功（E11000）；TTL 只管空间，清理延迟不影响判据。
 * 为什么落 Mongo 而非进程内 Set（多实例不共享）等原委见 tests/security/reauthTicketOneTimeUse.test.js。
 */

const mongoose = require('mongoose');

const reauthTicketUseSchema = new mongoose.Schema({
  // 票据载荷里的 jti（32 位 hex）；唯一索引即"这张票用过没有"的唯一判据
  jti: {
    type: String,
    required: true,
    unique: true,
  },
  // 消费方（绑定关系的审计留痕；票据本身已绑定 userId，这里只做可读性）
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
  },
  usedAt: {
    type: Date,
    default: Date.now,
  },
  // 票据自身的过期时刻：到点即可清理（判据不依赖本字段）
  expiresAt: {
    type: Date,
    required: true,
  },
});

// TTL 索引：票据过期后自动清理（与 TokenBlacklist 同形）
reauthTicketUseSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('ReauthTicketUse', reauthTicketUseSchema);
