/**
 * 注册必须明示同意隐私告知（一-7）：HTTP 层强制 + 落库证据
 *
 * 守护的不变式：`POST /api/auth/register` 缺少 `privacyConsent: true` 时**不得创建账号**；
 * 成功时必须留下一条与现行告知版本一致的 ConsentRecord，且这条记录在**签发令牌之前**已存在。
 * 为什么必须打真实 HTTP：校验层（routes/authRoutes.js 的 registerValidation）与服务层
 * （authService.registerUser 的 fail-closed 复判）是两道独立闸，只有整条链跑起来才看得见
 * "只挂了一道"的形态；只测服务层会漏掉「路由没接校验器」，只测路由会漏掉「绕过路由的调用」。
 * 可证伪点：缺字段那条同时断言 User 集合里没有新账号（拒绝发生在写库之前）。
 */
'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('注册必须明示同意隐私告知（一-7）', () => {
  let app;
  let User;
  let ConsentRecord;
  let SystemConfig;
  const stamp = `consent${Date.now().toString(36)}`.slice(0, 20);

  const register = (extra = {}) =>
    request(app)
      .post('/api/auth/register')
      .send({
        username: `${stamp}u${Math.random().toString(36).slice(2, 6)}`,
        email: `${stamp}${Math.random().toString(36).slice(2, 8)}@consent.example.com`,
        password: randomPassword(),
        ...extra,
      });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    ConsentRecord = require('../../models/ConsentRecord');
    SystemConfig = require('../../models/SystemConfig');
    require('../../models/Role');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');
    // 测试库每文件全新空库：公开注册与注册验证码都默认关闭/开启，必须显式放开两把闸
    await SystemConfig.updateOne(
      { key: 'allowPublicRegistration' },
      { $set: { value: true, valueType: 'boolean' } },
      { upsert: true }
    );
    SystemConfig.invalidateRegistrationCache();
    await SystemConfig.updateOne(
      { key: 'registerCaptchaEnabled' },
      { $set: { value: false, valueType: 'boolean' } },
      { upsert: true }
    );
    SystemConfig.invalidateRegisterCaptchaCache();
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await ConsentRecord.deleteMany({ username: new RegExp(`^${stamp}`) }, null, {
      bypassAppendOnly: true,
    }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 字段级拒绝走 VALIDATION_FAILED（与其余字段同口径），但必须点名「隐私告知」而不是泛泛的"参数错误" */
  const consentFieldErrors = (res) =>
    (res.body?.errors?.fieldErrors || []).filter((f) => /privacyConsent/.test(f.path || ''));

  test('缺 privacyConsent ⇒ 400，账号未创建，且字段级错误点名隐私告知', async () => {
    const body = {
      username: `${stamp}nobody`,
      email: `${stamp}nobody@consent.example.com`,
      password: randomPassword(),
    };
    const res = await request(app).post('/api/auth/register').send(body);
    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('VALIDATION_FAILED');
    expect(consentFieldErrors(res).length).toBeGreaterThan(0);
    expect(
      consentFieldErrors(res)
        .map((f) => f.msg)
        .join('|')
    ).toContain('隐私告知');
    expect(await User.findOne({ username: body.username }).lean()).toBeNull();
    expect(await ConsentRecord.countDocuments({ username: body.username })).toBe(0);
  });

  test('privacyConsent 非布尔真值（"true"/1/{} /null/false）一律拒绝，账号一个都不建', async () => {
    for (const bad of ['true', 1, {}, null, false]) {
      const res = await register({ privacyConsent: bad });
      expect({ bad: JSON.stringify(bad), status: res.status }).toEqual({
        bad: JSON.stringify(bad),
        status: 400,
      });
      expect(consentFieldErrors(res).length).toBeGreaterThan(0);
    }
    // 前提自证：上面五次提交确实一个账号都没留下（不是"恰好用户名重复"才 400）
    expect(await User.countDocuments({ username: new RegExp(`^${stamp}u`) })).toBe(0);
  });

  /** 服务层 fail-closed：绕过路由校验直接调业务函数时，同样不得创建账号 */
  test('绕过路由直接调 registerUser：outcome=CONSENT_REQUIRED，且不创建账号', async () => {
    const authService = require('../../services/authService');
    const username = `${stamp}direct`;
    const result = await authService.registerUser({
      username,
      email: `${stamp}direct@consent.example.com`,
      password: randomPassword(),
    });
    expect(result.outcome).toBe('CONSENT_REQUIRED');
    expect(await User.findOne({ username }).lean()).toBeNull();
  });

  test('privacyConsent: true ⇒ 201，且留下与现行告知版本一致的同意记录', async () => {
    const res = await register({ privacyConsent: true });
    expect(res.status).toBe(201);
    const { username } = res.body.data;
    const doc = await ConsentRecord.findOne({ username }).lean();
    expect(doc).toBeTruthy();
    const consentService = require('../../services/consentService');
    expect(doc.version).toBe(consentService.PRIVACY_NOTICE_VERSION);
    expect(doc.policy).toBe('privacy');
    expect(doc.source).toBe('self-register');
    expect(doc.scopes.slice().sort()).toEqual(
      consentService.scopesForPrivacyNotice().slice().sort()
    );
    // 证据必须挂在刚创建的那个账号上（不是任意账号）
    expect(String(doc.userId)).toBe(String(res.body.data.userId));
  });

  test('同意记录落库失败 ⇒ 注册整体失败并回滚账号（不留"有账号、无同意证据"的用户）', async () => {
    const consentService = require('../../services/consentService');
    const spy = jest
      .spyOn(consentService, 'recordConsent')
      .mockRejectedValueOnce(new Error('模拟同意库写入失败'));
    const username = `${stamp}rollback`;
    try {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username,
          email: `${stamp}rollback@consent.example.com`,
          password: randomPassword(),
          privacyConsent: true,
        });
      expect(res.status).toBe(503);
      expect(res.body.errors?.errorCode).toBe('REGISTER_SERVICE_UNAVAILABLE');
      expect(await User.findOne({ username }).lean()).toBeNull();
      expect(await ConsentRecord.countDocuments({ username })).toBe(0);
    } finally {
      spy.mockRestore();
    }
  });
});
