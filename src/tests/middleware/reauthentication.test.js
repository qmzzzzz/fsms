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
const { buildLoginEnvelope } = require('../helpers/buildLoginEnvelope');

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
    // 模拟 authenticate 已注入的 req.user。`req.body?.`：真实 authenticate 不读 body，
    // 这里若直读，"无 body"的用例会先在本 stub 上炸掉，测到的是夹具而不是被测中间件。
    a.use((req, res, next) => {
      req.user = { userId: req.body?.__targetUserId, username: 'tester' };
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
    // 关闭连接，避免遗留连接拖住 jest worker 优雅退出
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

  test('密码通道成功后清零共享失败计数（与 MFA 通道同口径）', async () => {
    // 失败计数与 MFA 通道共享：成功不清零时，计数会一直贴着阈值，
    // 用户下一次误输就被立刻锁 10 分钟。
    await User.updateOne({ _id: userNoMfa._id }, { $set: { mfaFailCount: 3 } });
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      currentPassword: testPassword,
    });
    expect(res.status).toBe(200);
    const fresh = await User.findById(userNoMfa._id).select('+mfaFailCount');
    expect(fresh.mfaFailCount).toBe(0);
  });

  test('密码通道处于 MFA 失败锁定期内 → 429，连比对都不做', async () => {
    // 密码通道与 MFA 通道共用同一把失败锁：锁定期内必须先拒，否则
    // 「猜中会话 + 在线猜密码」仍可无限次尝试（MFA 锁定形同虚设）。
    await User.updateOne(
      { _id: userNoMfa._id },
      { $set: { mfaLockUntil: new Date(Date.now() + 60 * 1000) } }
    );
    try {
      const res = await request(app).post('/sensitive').send({
        __targetUserId: userNoMfa._id,
        currentPassword: testPassword,
      });
      expect(res.status).toBe(429);
      expect(res.body.errors?.errorCode).toBe('MFA_ATTEMPTS_EXCEEDED');
      expect(res.body.reAuthenticated).not.toBe(true);
    } finally {
      await User.updateOne({ _id: userNoMfa._id }, { $set: { mfaLockUntil: null } });
    }
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

  test('当前口令密文（PASSWORD_CURRENT 用途）正确 → 通过，明文不上行', async () => {
    const encCurrentPassword = await buildLoginEnvelope(testPassword, {
      aad: 'password:current',
    });
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      encCurrentPassword,
    });
    expect(res.status).toBe(200);
    expect(res.body.reAuthenticated).toBe(true);
  });

  test('当前口令密文正确但用户密码错误 → 403（解密后仍走真实比对）', async () => {
    const encCurrentPassword = await buildLoginEnvelope(
      `W!r0ng${crypto.randomBytes(6).toString('hex')}`,
      {
        aad: 'password:current',
      }
    );
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      encCurrentPassword,
    });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('当前密码错误');
  });

  test('密文用途不符（用 LOGIN 信封冒充 step-up）→ 400，不得回落明文放行', async () => {
    // AAD 绑定点端用途：跨端点重放必须认证失败。同请求再带正确明文也不得
    // 触发「解密失败 → 退回明文」的降级路径（否则坏信封可绕过密文轨）。
    const encCurrentPassword = await buildLoginEnvelope(testPassword, { aad: 'login' });
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      encCurrentPassword,
      currentPassword: testPassword,
    });
    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    expect(res.body.reAuthenticated).not.toBe(true);
  });

  test('畸形密文信封 → 400 AUTH_ENCRYPTED_CREDENTIAL_INVALID（fail-closed）', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userNoMfa._id,
      encCurrentPassword: '!!!not-an-envelope!!!',
    });
    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('已开启 MFA 的用户仅提供正确密码 → 403，必须使用动态口令', async () => {
    const res = await request(app).post('/sensitive').send({
      __targetUserId: userWithMfa._id,
      currentPassword: testPassword,
    });
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('动态口令');
    expect(res.body.reAuthenticated).not.toBe(true);
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

  test('MFA 通道：令牌签发后用户被删除 → 401，不得放行', async () => {
    const res = await request(app)
      .post('/sensitive')
      .send({ __targetUserId: new mongoose.Types.ObjectId().toString(), mfaCode: '123456' });
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
    const res = await request(app)
      .post('/sensitive')
      .send({
        __targetUserId: String(userNoMfa._id),
        currentPassword: testPassword,
      });
    spy.mockRestore();
    expect(res.status).toBe(500);
    expect(res.body.message).toContain('身份验证过程出错');
  });

  // Express 5 在 body 解析器跳过时（无 Content-Type / 非 JSON）把 req.body 置为 **undefined**
  // （v4 恒为 {}）。中间件里 `const { currentPassword, mfaCode } = req.body` 因此抛 TypeError，
  // 并被它自己的 catch 吞成 500「身份验证过程出错」——一次"客户端根本没带凭证"的正常拒绝
  // 被伪装成服务端故障（还会按 UnhandledError 记 error 日志）。与上一条构成对照：
  // 真的是查询异常才 500；缺 body 属于"无凭证"，必须落 403 分支。
  test('没有请求体（req.body 为 undefined）→ 403 要求重新验证，不得变成 500', async () => {
    const res = await request(app).post('/sensitive');
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('重新验证');
  });

  test('非 JSON 请求体（解析器跳过）→ 同样按无凭证处理', async () => {
    const res = await request(app)
      .post('/sensitive')
      .set('Content-Type', 'text/plain')
      .send('currentPassword=whatever');
    expect(res.status).toBe(403);
    expect(res.body.message).toContain('重新验证');
  });
});
