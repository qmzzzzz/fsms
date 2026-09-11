/**
 * 认证边界测试（第三批审计 #8/#9）
 * - #8：passwordChangedAt(毫秒) 与 token iat(整秒) 同秒边界 —— 改密后同秒新签发的令牌必须放行，
 *        早于改密秒的令牌必须拒绝
 * - #9：MFA 开关后必须失效 authenticate 的 60s 用户缓存（防保护延迟生效窗口）
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');

const secret = process.env.JWT_SECRET || 'test-jwt-secret-for-testing-only';

const buildProtectedApp = () => {
  const { authenticate } = require('../../middleware/auth');
  // authenticate 的 loadValidUser 会 populate('roles')，必须先注册 Role 模型，
  // 否则 MissingSchemaError → 500（同 auth.test.js 的处理）
  require('../../models/Role');
  const app = express();
  app.use(express.json());
  app.get('/protected', authenticate, (req, res) => res.json({ success: true }));
  return app;
};

describe('认证边界（第三批审计）', () => {
  let User;
  let app;
  const createdUsers = [];

  // 本项目 jsonwebtoken 版本在 payload 已含 iat 时保留原值（实测验证），
  // 直接放 payload 即可控制 iat；注意不能用 noTimestamp（它会删除 payload.iat）
  const makeToken = (user, iat) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        type: 'access',
        tokenVersion: 0,
        jti: crypto.randomUUID(),
        ...(iat !== undefined ? { iat } : {}),
      },
      secret,
      { expiresIn: '1h' }
    );

  const createUser = async (suffix) => {
    const u = await User.create({
      username: `iat_edge_${suffix}_${Date.now()}`,
      email: `iat_edge_${suffix}_${Date.now()}@test.local`,
      password: 'E!d1' + crypto.randomBytes(8).toString('hex'),
    });
    createdUsers.push(u);
    return u;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    app = buildProtectedApp();
  });

  afterAll(async () => {
    for (const u of createdUsers) await u.deleteOne();
    // T-1：关闭连接，避免遗留连接拖住 jest worker 优雅退出
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('#8 改密后同秒新签发的令牌应放行（秒级比较不误拒）', async () => {
    const user = await createUser('same');
    const changedAt = new Date();
    await User.findByIdAndUpdate(user._id, { passwordChangedAt: changedAt });

    const token = makeToken(user, Math.floor(changedAt.getTime() / 1000));
    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('#8 早于改密秒的令牌应被拒绝（401 密码已修改）', async () => {
    // 独立用户：避免上一测试认证留下的 60s 用户缓存干扰本测试的改密断言
    const user = await createUser('older');
    const changedAt = new Date();
    await User.findByIdAndUpdate(user._id, { passwordChangedAt: changedAt });

    const olderIat = Math.floor(changedAt.getTime() / 1000) - 30; // 改密前 30 秒
    const token = makeToken(user, olderIat);

    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.message).toContain('密码已修改');
  });

  test('#9 MFA 开关后用户缓存立即失效（无 60s 延迟窗口）', async () => {
    const { invalidateUserCache } = require('../../middleware/auth');
    const user = await createUser('mfa');

    // 触发缓存填充：一次成功认证
    const token = makeToken(user);
    const warm = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(warm.status).toBe(200);

    // 模拟 mfaEnable/mfaDisable 路径：更新库 + 失效缓存（与 controller 一致）
    await User.findByIdAndUpdate(user._id, { mfaEnabled: true });
    invalidateUserCache(String(user._id));

    // 再借 tokenVersion 验证同一缓存通道：改库+失效后旧令牌立即 401（无 60s 缓存延迟）
    await User.findByIdAndUpdate(user._id, { tokenVersion: 1 });
    invalidateUserCache(String(user._id));

    const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });
});
