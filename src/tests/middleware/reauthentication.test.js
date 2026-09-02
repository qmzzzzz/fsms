/**
 * 安全中间件测试 —— requireReAuthentication 二次验证（I-06 MFA 分支）
 * 覆盖：无凭证拒绝 / 密码正误 / MFA 码路径（已开启+正确码通过、未开启拒绝、错误码拒绝）
 *
 * 测试口令不落源码：优先环境变量，缺省时进程内随机生成（满足强度策略），
 * 仅存在于内存数据库的临时用户上，用例结束即删除。
 */

const express = require('express');
const request = require('supertest');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { generateSecret, hotp, base32Decode } = require('../../utils/totp');

// 满足强度策略（大小写+数字+特殊字符）的随机口令；可用环境变量覆盖
const buildTestPassword = () =>
  process.env.TEST_REAUTH_PASSWORD || `R!a1${crypto.randomBytes(12).toString('hex')}`;

describe('requireReAuthentication（敏感操作二次验证）', () => {
  let app;
  let User;
  let userNoMfa;
  let userWithMfa;
  let mfaSecret;
  let testPassword;

  const buildApp = () => {
    const { requireReAuthentication } = require('../../middleware/security');
    const a = express();
    a.use(express.json());
    // 模拟 authenticate 已注入的 req.user
    a.use((req, res, next) => {
      req.user = { userId: req.body.__targetUserId, username: 'tester' };
      next();
    });
    a.post('/sensitive', requireReAuthentication(), (req, res) => {
      res.json({ success: true, reAuthenticated: req.reAuthenticated === true });
    });
    return a;
  };

  const currentTotp = () => {
    const counter = Math.floor(Date.now() / 1000 / 30);
    return hotp(base32Decode(mfaSecret), counter);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    testPassword = buildTestPassword();

    userNoMfa = await User.create({
      username: 'reauth_nomfa_' + Date.now(),
      email: `reauth_nomfa_${Date.now()}@test.local`,
      password: testPassword,
    });

    mfaSecret = generateSecret();
    userWithMfa = await User.create({
      username: 'reauth_mfa_' + Date.now(),
      email: `reauth_mfa_${Date.now()}@test.local`,
      password: testPassword,
      mfaSecret,
      mfaEnabled: true,
    });

    app = buildApp();
  });

  afterAll(async () => {
    if (userNoMfa) await userNoMfa.deleteOne();
    if (userWithMfa) await userWithMfa.deleteOne();
    // T-1：关闭连接，避免遗留连接拖住 jest worker 优雅退出
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('未提供任何凭证 → 403 要求重新验证', async () => {
    const res = await request(app).post('/sensitive').send({ __targetUserId: userNoMfa._id });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('重新验证');
  });

  test('当前密码正确 → 通过并标记 reAuthenticated', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      currentPassword: testPassword,
    });
    expect(res.status).toBe(200);
    expect(res.body.reAuthenticated).toBe(true);
  });

  test('当前密码错误 → 403', async () => {
    const res = await request(app)
      .post('/sensitive')
      .send({
        __targetUserId: userNoMfa._id,
        currentPassword: `W!r0ng${crypto.randomBytes(6).toString('hex')}`,
      });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('当前密码错误');
  });

  test('MFA 动态口令正确（已开启用户）→ 通过', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userWithMfa._id,
      mfaCode: currentTotp(),
    });
    expect(res.status).toBe(200);
    expect(res.body.reAuthenticated).toBe(true);
  });

  test('MFA 动态口令但用户未开启 MFA → 403 引导使用密码', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      mfaCode: '123456',
    });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('未开启两步验证');
  });

  test('MFA 动态口令错误（已开启用户）→ 403', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userWithMfa._id,
      mfaCode: '000000',
    });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('MFA 验证码错误');
  });

  test('用户不存在（令牌签发后被删除）→ 401，不得放行', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: new mongoose.Types.ObjectId().toString(),
      currentPassword: testPassword,
    });
    expect(res.status).toBe(401);
    expect(res.body.message).toContain('用户不存在');
    expect(res.body.reAuthenticated).not.toBe(true);
  });

  test('用户查询内部异常 → 500，不得静默放行（fail-closed）', async () => {
    // 中间件链路是 findById(...).select('+password')：必须 mock 成 query 形态，
    // 让拒绝发生在被 await 的链上（裸 Promise 拒绝会变成 unhandled rejection）
    const spy = jest.spyOn(User, 'findById').mockImplementationOnce(() => ({
      select: () => Promise.reject(new Error('db down')),
    }));
    const res = await request(app).post('/sensitive').send({
      __targetUserId: String(userNoMfa._id),
      currentPassword: testPassword,
    });
    spy.mockRestore();
    expect(res.status).toBe(500);
    expect(res.body.message).toContain('身份验证过程出错');
  });
});
