#!/usr/bin/env node

/**
 * 指定用户全量会话吊销（WB-1）
 *
 * 场景：内置/初始凭据（如首次部署的超管初始口令）完成重置后，
 * 曾用旧凭据登录产生的会话必须全部作废——否则旧会话在令牌自然过期前仍然有效。
 *
 * 用法：
 *   node scripts/revoke-user-sessions.js <username>           # 演练（只看不动）
 *   node scripts/revoke-user-sessions.js <username> --apply   # 执行
 *
 * 动作（--apply 时）：
 *   1. tokenVersion +1 —— 所有已签发的该用户 JWT 立即失效（鉴权每请求校验）；
 *   2. revokeAllSessions —— 吊销 UserSession 中该用户全部活跃会话（含 WebSocket 侧）。
 *
 * 约定（P2-27 运维脚本安全惯例）：默认演练、显式 --apply 才动手；
 * 连接串只从环境/`.env` 读取，不接受命令行传入。
 */

'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

const argv = process.argv.slice(2);
const username = argv.find((a) => !a.startsWith('--'));
const apply = argv.includes('--apply');

if (!username) {
  console.error('用法: node scripts/revoke-user-sessions.js <username> [--apply]');
  process.exit(1);
}

if (!process.env.MONGODB_URI) {
  console.error('缺少 MONGODB_URI（.env 或环境变量）');
  process.exit(1);
}

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  try {
    const User = require('../src/models/User');
    const { revokeAllSessions } = require('../src/services/sessionService');
    const UserSession = require('../src/models/UserSession');

    const user = await User.findByUsername(username);
    if (!user) {
      console.error(`用户不存在：${username}`);
      process.exit(1);
    }

    const activeCount = await UserSession.countDocuments({
      userId: user._id,
      expiresAt: { $gt: new Date() },
    });

    console.log(`目标用户：${username}（${user._id}）`);
    console.log(`当前活跃会话：${activeCount} 个`);
    console.log(`当前 tokenVersion：${user.tokenVersion ?? 0}`);

    if (!apply) {
      console.log('\n[演练] 未执行任何变更。确认后加 --apply 重跑。');
      return;
    }

    await User.updateOne({ _id: user._id }, { $inc: { tokenVersion: 1 } });
    const revoked = await revokeAllSessions(String(user._id), 'default_credential_reset');
    console.log(`\n已执行：tokenVersion +1，吊销会话 ${revoked ?? activeCount} 个`);
    console.log('该用户的既有令牌与 cookie 会话均已失效，需重新登录。');
  } finally {
    await mongoose.disconnect();
  }
})().catch((err) => {
  console.error(`执行失败：${err.message}`);
  process.exit(1);
});
