/**
 * S5 改密密文轨分支补齐（securityController.changePasswordSecure 99-119）
 *
 * 并行开发为 /api/security/change-password 增加了与 /api/auth/password 同口径的
 * ECDH 信封密文轨（encCurrentPassword / encNewPassword），新增分支未测导致
 * securityController branches 跌破棘轮基线（91%）。本套件经真实 HTTP +
 * 真实 WebCrypto 信封（buildLoginEnvelope 镜像前端流程）覆盖：
 *   - 当前口令密文无效 → AUTH_ENCRYPTED_CREDENTIAL_INVALID
 *   - 新口令密文无效 → 同上
 *   - 密文轨下明文 confirmPassword 与解密结果不一致 → 400
 *   - 全密文轨成功改密（confirmPassword 缺省以解密结果为准）
 *
 * 注意 passwordChangeLimiter 为 5 次/15 分钟（userId+IP 组合键）：
 * 本套件恰好 4 个请求，不得再往同用户追加改密请求。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { buildLoginEnvelope, randomPassword } = require('../helpers/buildLoginEnvelope');

describe('S5 改密密文轨（/api/security/change-password）', () => {
  let app;
  let User;
  let user;
  let token;
  const PASSWORD = randomPassword();
  const NEW_PASSWORD = randomPassword();
  const stamp = `ec${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    user = await User.create({
      username: `${stamp}enc`,
      email: `${stamp}enc@example.com`,
      password: PASSWORD,
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const put = (body) =>
    request(app)
      .put('/api/security/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send(body);

  test('encCurrentPassword 密文无效 → 400 AUTH_ENCRYPTED_CREDENTIAL_INVALID', async () => {
    const garbage = await buildLoginEnvelope('', { raw: { v: 999, x: 'a', y: 'b' } });
    const res = await put({ encCurrentPassword: garbage, encNewPassword: 'whatever' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('encNewPassword 密文无效 → 400 AUTH_ENCRYPTED_CREDENTIAL_INVALID', async () => {
    const goodCurrent = await buildLoginEnvelope(PASSWORD);
    const garbage = await buildLoginEnvelope('', { raw: { v: 1, x: 'not-a-key' } });
    const res = await put({ encCurrentPassword: goodCurrent, encNewPassword: garbage });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('密文轨下明文 confirmPassword 与解密结果不一致 → 400', async () => {
    const goodCurrent = await buildLoginEnvelope(PASSWORD);
    const goodNew = await buildLoginEnvelope(NEW_PASSWORD);
    const res = await put({
      encCurrentPassword: goodCurrent,
      encNewPassword: goodNew,
      confirmPassword: 'TotallyDifferent1!x',
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('不一致');
  });

  test('全密文轨成功改密（confirmPassword 缺省以解密结果为准）', async () => {
    const goodCurrent = await buildLoginEnvelope(PASSWORD);
    const goodNew = await buildLoginEnvelope(NEW_PASSWORD);
    const res = await put({ encCurrentPassword: goodCurrent, encNewPassword: goodNew });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const after = await User.findById(user._id).select('+password +tokenVersion');
    expect(await after.comparePassword(NEW_PASSWORD)).toBe(true);
    // 改密后全部会话被吊销（与明文轨同口径）
    expect(after.tokenVersion).toBe(1);
  });
});
