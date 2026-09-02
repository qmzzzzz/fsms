/**
 * Token 黑名单模型
 * 持久化存储已注销/失效的 JWT Token
 */

const mongoose = require('mongoose');

const tokenBlacklistSchema = new mongoose.Schema({
  tokenHash: {
    type: String,
    required: true,
    unique: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  reason: {
    type: String,
    default: 'logout',
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// TTL 索引：token 过期后自动清理
tokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('TokenBlacklist', tokenBlacklistSchema);
