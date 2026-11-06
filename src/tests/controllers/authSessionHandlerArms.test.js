/**
 * 会话管理三个 handler 的补测（覆盖率缺口：authController/session.js funcs 75%<97%）
 *
 * 既有 authRegisterSessionBinding 覆盖了 listSessions 与 peer 视角的 revokeSession，
 * 但 logout（:72 起）、revokeOtherSessions（:278 起）与 revokeSession 的
 * owner 视角没有真实 HTTP 旅程。本套件用同款注册夹具补三条旅程：
 *   1. owner 踢自己名下"另一条"会话（目标 sid 取自第二枚 access 的 JWT 载荷，
 *      不依赖列表响应字段——踢当前设备会被 CANNOT_REVOKE_CURRENT_SESSION 正确拦下）；
 *   2. POST /api/auth/logout：登出当前会话，后续受保护读面回落 401；
 *   3. DELETE /api/auth/sessions/others：保留当前、吊销其余（exceptSid 臂）。
 */
'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();
const stamp = `zzarm${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

describe('会话管理 handler 旅程补测', () => {
  let app;
  let User;
  let Role;
  let SystemConfig;
  let UserSession;
  let config;
  const created = [];

  const accessCookie = (token) => `access_token=${token}`;

  const registerViaHttp = async (suffix) => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: `${stamp}${suffix}`,
        email: `${stamp}${suffix}@example.com`,
        password: PASSWORD,
        realName: `会话补测${suffix}`,
        privacyConsent: true,
      });
    expect(res.status).toBe(201);
    const cookie = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
    const get = (name) => (cookie.find((c) => c.startsWith(`${name}=`)) || '').split('=')[1];
    const u = await User.findOne({ username: `${stamp}${suffix}` });
    created.push(u._id);
    return { access: get('access_token'), user: u };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    SystemConfig = require('../../models/SystemConfig');
    UserSession = require('../../models/UserSession');
    await SystemConfig.deleteMany({
      key: ['allowPublicRegistration', 'registerCaptchaEnabled'],
    }).catch(() => {});
    await SystemConfig.create({ key: 'allowPublicRegistration', value: true });
    await SystemConfig.create({ key: 'registerCaptchaEnabled', value: false });
    SystemConfig.invalidateRegistrationCache?.();
    SystemConfig.invalidateRegisterCaptchaCache?.();
    if (!(await Role.findOne({ code: 'GUEST' }))) {
      await Role.create({ name: '访客', code: 'GUEST', level: 1 });
    }
    config = require('../../config');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    await User.deleteMany({ _id: { $in: created } }).catch(() => {});
    await UserSession.deleteMany({ userId: { $in: created } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('revokeSession 的 owner 视角：踢自己名下另一条，保留当前', async () => {
    const reg = await registerViaHttp('a');
    const login = await request(app)
      .post('/api/auth/login')
      .send({
        username: `${stamp}a`,
        password: PASSWORD,
      });
    expect(login.status).toBe(200);
    const loginCookie = (login.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
    const loginAccess = (loginCookie.find((c) => c.startsWith('access_token=')) || '')
      .split('=')
      .slice(1)
      .join('=');

    const listed = await request(app)
      .get('/api/auth/sessions')
      .set('Cookie', [accessCookie(loginAccess)]);
    expect(listed.status).toBe(200);
    expect(listed.body.data.sessions.length).toBeGreaterThanOrEqual(2);
    // 当前设备 sid 从 JWT 载荷取（比列表响应字段更接近令牌本身的事实）
    const currentSid = jwt.verify(loginAccess, config.jwt.secret, { algorithms: ['HS256'] }).sid;
    const targetSid = listed.body.data.sessions
      .map((s) => s.sid)
      .find((s) => s && s !== currentSid);
    expect(targetSid).toBeTruthy();

    const revoke = await request(app)
      .delete(`/api/auth/sessions/${targetSid}`)
      .set('Cookie', [accessCookie(loginAccess)]);
    expect(revoke.status).toBe(200);
    // 只吊销了目标那条：活跃会话剩 1（当前），总数不变
    expect(await UserSession.countDocuments({ userId: reg.user._id, status: 'active' })).toBe(1);
  });

  test('POST /api/auth/logout：登出当前会话，后续受保护读面回落 401', async () => {
    const reg = await registerViaHttp('b');
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', [accessCookie(reg.access)])
      .send({});
    expect([200, 204]).toContain(res.status);
    // 登出后该会话的受保护读面回落 401（吊销即时生效）
    const after = await request(app)
      .get('/api/auth/sessions')
      .set('Cookie', [accessCookie(reg.access)]);
    expect(after.status).toBe(401);
  });

  test('DELETE /api/auth/sessions/others：保留当前、吊销其余（exceptSid 臂）', async () => {
    const reg = await registerViaHttp('c');
    const second = await request(app)
      .post('/api/auth/login')
      .send({
        username: `${stamp}c`,
        password: PASSWORD,
      });
    expect(second.status).toBe(200);
    const secondCookie = (second.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
    const secondAccess = (secondCookie.find((c) => c.startsWith('access_token=')) || '')
      .split('=')
      .slice(1)
      .join('=');

    const res = await request(app)
      .delete('/api/auth/sessions/others')
      .set('Cookie', [accessCookie(secondAccess)]);
    expect(res.status).toBe(200);
    // 活跃会话只剩发起调用的这条；另一条（注册时建的）已 revoked
    expect(await UserSession.countDocuments({ userId: reg.user._id, status: 'active' })).toBe(1);
    const still = await request(app)
      .get('/api/auth/sessions')
      .set('Cookie', [accessCookie(secondAccess)]);
    expect(still.status).toBe(200);
  });
});
