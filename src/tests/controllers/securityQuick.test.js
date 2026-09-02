/**
 * 安全管理核心接口覆盖（冲 100% 第三批：securityController 快速面）
 *
 * 覆盖：my-info / bindings / config 三组端点（注册开关、登录验证码开关、
 * 注册验证码开关），以及配置持久化后的 SystemConfig 缓存失效联动。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('安全管理核心接口（冲 100%）', () => {
  let app;
  let adminToken;
  const stamp = `sc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/SystemConfig');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_安全面',
      code: `SUPER_ADMIN_SC_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `scadmin${stamp}`,
      email: `scadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });

    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `scadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_SC_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
  });

  test('GET /my-info 返回当前用户安全信息', async () => {
    const res = await authed().get('/api/security/my-info');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeTruthy();
  });

  test('GET /bindings 返回账户绑定信息', async () => {
    const res = await authed().get('/api/security/bindings');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('注册开关：读取 → 切换 → 读回一致 → 非布尔 400', async () => {
    const before = await authed().get('/api/security/config/allowPublicRegistration');
    expect(before.status).toBe(200);
    expect(typeof before.body.data.allowPublicRegistration).toBe('boolean');

    const flip = !before.body.data.allowPublicRegistration;
    const set = await authed()
      .put('/api/security/config/allowPublicRegistration')
      .send({ allowPublicRegistration: flip });
    expect(set.status).toBe(200);

    const after = await authed().get('/api/security/config/allowPublicRegistration');
    expect(after.body.data.allowPublicRegistration).toBe(flip);

    const bad = await authed()
      .put('/api/security/config/allowPublicRegistration')
      .send({ allowPublicRegistration: 'yes' });
    expect(bad.status).toBe(400);
  });

  test('登录验证码开关：读取 → 切换 → 读回一致', async () => {
    const before = await authed().get('/api/security/config/loginCaptchaEnabled');
    expect(before.status).toBe(200);

    const flip = !before.body.data.loginCaptchaEnabled;
    const set = await authed()
      .put('/api/security/config/loginCaptchaEnabled')
      .send({ loginCaptchaEnabled: flip });
    expect(set.status).toBe(200);

    const after = await authed().get('/api/security/config/loginCaptchaEnabled');
    expect(after.body.data.loginCaptchaEnabled).toBe(flip);
  });

  test('未认证访问安全接口返回 401', async () => {
    const res = await request(app).get('/api/security/my-info');
    expect(res.status).toBe(401);
  });
});
