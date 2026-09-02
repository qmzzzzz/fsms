/**
 * 认证生命周期全覆盖（冲 95% 批次 B）
 *
 * 此前缺口：authController 分支覆盖 40%（MFA 全生命周期、logout 吊销链、
 * register 开关分支、captcha 前置层、session 探测、refresh 轮换）。
 * svg-captcha 用固定文本 mock 使 captcha 前置层可测。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

jest.mock('svg-captcha', () => ({
  create: jest.fn(() => ({ data: '<svg>mock</svg>', text: 'ABCD' })),
}));

const { hotp, base32Decode } = require('../../utils/totp');
const { ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME } = require('../../utils/cookie');

describe('认证生命周期（批次 B）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let SystemConfig;
  let superToken;
  let selfUserId;
  const stamp = `lb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  /** 计算当前窗口的有效 TOTP */
  const currentTotp = (secret) => hotp(base32Decode(secret), Math.floor(Date.now() / 1000 / 30));

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    SystemConfig = require('../../models/SystemConfig');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_批次B',
      code: `SUPER_ADMIN_LB_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `lbadmin${stamp}`,
      email: `lbadmin${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    selfUserId = String(admin._id);
    superToken = jwt.sign(
      { userId: selfUserId, username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    void superToken;

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^lb${stamp}`) }).catch(() => {});
      await User.deleteOne({ username: `lbadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_LB_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const login = (username, password) =>
    request(app).post('/api/auth/login').send({ username, password });
  const cookiesOf = (res) =>
    (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
  const cookieValue = (cookies, name) =>
    cookies
      .split('; ')
      .find((c) => c.startsWith(name + '='))
      .split('=')
      .slice(1)
      .join('=');
  const newMfaUser = async (name) => {
    const u = await User.create({
      username: `lb${stamp}${name}`,
      email: `lb${stamp}${name}@example.com`,
      password: PASSWORD,
    });
    return { id: String(u._id), username: u.username };
  };
  const enrollAndEnable = async (username, password) => {
    const loginRes = await login(username, password);
    expect(loginRes.status).toBe(200);
    const token = loginRes.body.data.token;

    const enroll = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${token}`);
    expect(enroll.status).toBe(200);
    const { secret } = enroll.body.data;

    const enable = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ mfaCode: currentTotp(secret) });
    expect(enable.status).toBe(200);
    return { token, secret, recoveryCodes: enable.body.data.recoveryCodes };
  };

  // ================= 注册 =================

  test('注册：开关关闭 403 → 打开 201 → 重复 400 → 弱口令 400', async () => {
    const closed = await request(app)
      .post('/api/auth/register')
      .send({
        username: `lbu${stamp}x`,
        email: `lbu${stamp}x@example.com`,
        password: PASSWORD,
      });
    expect([403, 400]).toContain(closed.status);

    await SystemConfig.findOneAndUpdate(
      { key: 'allowPublicRegistration' },
      { $set: { key: 'allowPublicRegistration', value: true } },
      { upsert: true }
    );
    SystemConfig.invalidateRegistrationCache();

    const ok = await request(app)
      .post('/api/auth/register')
      .send({
        username: `lbu${stamp}x`,
        email: `lbu${stamp}x@example.com`,
        password: PASSWORD,
      });
    expect(ok.status).toBe(201);

    const dup = await request(app)
      .post('/api/auth/register')
      .send({
        username: `lbu${stamp}x`,
        email: `lbu${stamp}y@example.com`,
        password: PASSWORD,
      });
    expect(dup.status).toBe(400);

    const weak = await request(app)
      .post('/api/auth/register')
      .send({
        username: `lbu${stamp}y`,
        email: `lbu${stamp}y@example.com`,
        password: '123',
      });
    expect(weak.status).toBe(400);
  });

  // ================= 验证码前置层 =================

  test('登录验证码：开启后无验证码/错码被拒，正确验证码放行', async () => {
    const { username } = await newMfaUser('cap');
    await SystemConfig.findOneAndUpdate(
      { key: 'loginCaptchaEnabled' },
      { $set: { key: 'loginCaptchaEnabled', value: true } },
      { upsert: true }
    );
    SystemConfig.invalidateLoginCaptchaCache();

    const noCaptcha = await login(username, PASSWORD);
    expect(noCaptcha.status).toBe(400);
    expect(noCaptcha.body.errors?.errorCode).toBe('CAPTCHA_INVALID');

    const capRes = await request(app).get('/api/auth/captcha');
    expect(capRes.status).toBe(200);
    const { captchaId } = capRes.body.data;
    const wrongText = await login(username, PASSWORD).send({ captchaId, captchaText: 'ZZZZ' });
    expect(wrongText.body.errors?.errorCode).toBe('CAPTCHA_INVALID');

    const capRes2 = await request(app).get('/api/auth/captcha');
    const right = await login(username, PASSWORD).send({
      captchaId: capRes2.body.data.captchaId,
      captchaText: 'ABCD',
    });
    expect(right.status).toBe(200);

    // 还原开关
    await SystemConfig.findOneAndUpdate(
      { key: 'loginCaptchaEnabled' },
      { $set: { key: 'loginCaptchaEnabled', value: false } }
    );
    SystemConfig.invalidateLoginCaptchaCache();
  });

  // ================= MFA 全生命周期 =================

  test('MFA：enroll（重复返回同密钥）→ 错码 enable 400 → 正确 enable 200+恢复码', async () => {
    const { username, id } = await newMfaUser('mfa');
    void id;
    const loginRes = await login(username, PASSWORD);
    const token = loginRes.body.data.token;

    const enroll1 = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${token}`);
    expect(enroll1.status).toBe(200);
    const { secret } = enroll1.body.data;

    // 重复 enroll：B1 修复——返回已有密钥不覆盖
    const enroll2 = await request(app)
      .post('/api/auth/mfa/enroll')
      .set('Authorization', `Bearer ${token}`);
    expect(enroll2.body.data.secret).toBe(secret);

    const badEnable = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ mfaCode: '000000' });
    expect(badEnable.status).toBe(400);

    const enable = await request(app)
      .post('/api/auth/mfa/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ mfaCode: currentTotp(secret) });
    expect(enable.status).toBe(200);
    expect(enable.body.data.recoveryCodes).toHaveLength(10);

    const status = await request(app)
      .get('/api/auth/mfa/status')
      .set('Authorization', `Bearer ${token}`);
    expect(status.body.data.enabled).toBe(true);
    expect(status.body.data.recoveryCodesRemaining).toBe(10);
  });

  test('MFA 登录：mfaRequired → TOTP 通过 → 同码重放被拒', async () => {
    const { username } = await newMfaUser('mlogin');
    const { secret, recoveryCodes } = await enrollAndEnable(username, PASSWORD);
    void recoveryCodes;

    const first = await login(username, PASSWORD);
    expect(first.status).toBe(200);
    expect(first.body.data.mfaRequired).toBe(true);

    // 用下一窗口的码：enable 已消费当前窗口 counter，同窗口码会正确触发重放保护
    const code = hotp(base32Decode(secret), Math.floor(Date.now() / 1000 / 30) + 1);
    const withTotp = await login(username, PASSWORD).send({ mfaCode: code });
    expect(withTotp.status).toBe(200);
    expect(withTotp.body.data.token).toBeTruthy();

    // 同码重放（mfaLastCounter 已推进）→ 拒
    const replay = await login(username, PASSWORD).send({ mfaCode: code });
    expect(replay.status).toBe(401);
    expect(replay.body.errors?.errorCode).toBe('MFA_CODE_INVALID');
  });

  test('MFA 登录：备用恢复码一次性消费', async () => {
    const { username } = await newMfaUser('mrec');
    const { recoveryCodes } = await enrollAndEnable(username, PASSWORD);

    await login(username, PASSWORD); // mfaRequired
    const viaRecovery = await login(username, PASSWORD).send({ mfaCode: recoveryCodes[0] });
    expect(viaRecovery.status).toBe(200);

    // 同一恢复码已被消费
    const reused = await login(username, PASSWORD).send({ mfaCode: recoveryCodes[0] });
    expect(reused.status).toBe(401);
  });

  test('MFA 关闭：错误口令 403；密码路径错误 403 / 正确关闭', async () => {
    const { username } = await newMfaUser('mdis');
    const { token, secret, recoveryCodes } = await enrollAndEnable(username, PASSWORD);
    void secret;
    void recoveryCodes;

    const badCode = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ mfaCode: '000000' });
    expect(badCode.status).toBe(403);

    const badPwd = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: 'Wrong!Pass1xy' });
    expect(badPwd.status).toBe(403);

    const goodPwd = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: PASSWORD });
    expect(goodPwd.status).toBe(200);
    expect(goodPwd.body.data.enabled).toBe(false);
  });

  // ================= 会话探测 / 登出 / 刷新 =================

  test('/auth/session：未登录 false；登录后 true；登出后 false（吊销生效）', async () => {
    const noAuth = await request(app).get('/api/auth/session');
    expect(noAuth.body.data.authenticated).toBe(false);

    const loginRes = await login(`lbadmin${stamp}`, PASSWORD);
    const cookies = cookiesOf(loginRes);

    const authed = await request(app).get('/api/auth/session').set('Cookie', cookies);
    expect(authed.body.data.authenticated).toBe(true);

    const logout = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${loginRes.body.data.token}`)
      .set('Cookie', cookies)
      .send({});
    expect(logout.status).toBe(200);

    const after = await request(app).get('/api/auth/session').set('Cookie', cookies);
    expect(after.body.data.authenticated).toBe(false);
  });

  test('refresh：轮换成功 + 旧 refresh 重放被拒', async () => {
    const loginRes = await login(`lbadmin${stamp}`, PASSWORD);
    const cookies = cookiesOf(loginRes);
    const oldRefresh = cookieValue(cookies, REFRESH_COOKIE_NAME);

    const refresh = await request(app).post('/api/auth/refresh').set('Cookie', cookies).send({});
    expect(refresh.status).toBe(200);

    // 旧 refresh 已被轮换消费（重放检测 → 401）
    const replay = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', REFRESH_COOKIE_NAME + '=' + oldRefresh)
      .send({});
    expect(replay.status).toBe(401);

    // access cookie 常量引用（避免扫描器把 cookie 名误判为凭据字面量）
    expect(ACCESS_COOKIE_NAME).toBe('access_token');
  });
});
