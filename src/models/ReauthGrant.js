/** 会话级 sudo 窗口：sid 唯一、5 分钟不续期、TTL 到期即删；绑 sid ⇒ 换设备/换会话即失效。原委见 tests/security/reauthTicketEnforcement.test.js。 */

const mongoose = require('mongoose');

const reauthGrantSchema = new mongoose.Schema({
  // 设备会话标识（登录/刷新期间不变，refresh 换 jti 不换它）。唯一索引 ⇒ 一个会话只有一条有效窗口
  sid: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  grantedAt: { type: Date, default: Date.now },
  // 窗口结束时刻；TTL 索引到点清理（判据本身另带 expiresAt > now 条件）
  expiresAt: { type: Date, required: true },
});

reauthGrantSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('ReauthGrant', reauthGrantSchema);
