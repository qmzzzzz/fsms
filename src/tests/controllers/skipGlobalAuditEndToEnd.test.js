/**
 * P0-5 端到端回归：skipGlobalAudit 必须让「控制器手写审计」成为唯一留痕
 *
 * 背景（审计报告 §8.2 / §15 P0-5）：这条缺陷最初无人拦得住——当时的
 * `src/tests/controllers/securityConfigHandlers.test.js` 只在**无中间件环境**下断言
 * `res.locals.skipGlobalAudit === true`，那只证明「控制器最终置过位」，
 * 不能证明它早于响应读取点——而 P0-5 恰恰是时序缺陷：中间件在请求入口读取该
 * 标志，控制器的赋值永远晚于检查，标志 100% 失效，每个这类操作被双写
 * （控制器手写 1 条 + 全局中间件按路由再写 1 条，action/category 不同）。
 * （那条盲区后来按 P1-29 补上了：src/tests/controllers/securityConfigHandlers.test.js:65
 *  在 json() 时刻记录标志值，src/tests/controllers/securityConfigHandlers.test.js:122 断言之。
 *  本文件承担的仍是"真实 app + 真实中间件链"那一层，两者不互相替代。）
 *
 * 本文件用**真实 app + 真实控制器 + 真实中间件链**，stub 掉 auditBuffer.push
 * 后断言：命中 skipGlobalAudit 的写操作在全局审计侧恰好 0 条，而控制器手写
 * 的那 1 条确实落库。中间件级正反配对见 middleware/securityBranches.test.js；
 * 单控制器时序见 middleware/skipGlobalAuditTiming.test.js。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const auditBuffer = require('../../services/auditBuffer');
const spyPush = jest.spyOn(auditBuffer, 'push');

const tick = () => new Promise((resolve) => setImmediate(resolve));

/** 取本次改动 push 调用中命中指定 path 的记录 */
const pushedForPath = (fullPath) =>
  spyPush.mock.calls.map(([doc]) => doc).filter((doc) => doc && doc.path === fullPath);

describe('P0-5 端到端：skipGlobalAudit 命中路径不再双写', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let admin;
  let adminToken;
  const stamp = `p05e2e${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');
    require('../../models/SystemConfig');

    const pConfig = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      {
        $setOnInsert: {
          name: '安全配置',
          code: 'security:config',
          type: 'api',
          module: 'security',
        },
      },
      { upsert: true, new: true }
    );
    // 对照用例需要一个「不设 skipGlobalAudit」的写端点：PUT /api/users/:id
    const pUpdate = await Permission.findOneAndUpdate(
      { code: 'user:update' },
      {
        $setOnInsert: {
          name: '改用户',
          code: 'user:update',
          type: 'api',
          module: 'user',
        },
      },
      { upsert: true, new: true }
    );
    const adminRole = await Role.create({
      name: `P05E2E 配置管理员_${stamp}`,
      code: `P05E2E_${stamp}`,
      level: 9,
      status: 'active',
      permissions: [pConfig._id, pUpdate._id],
    });
    admin = await User.create({
      username: `p05e2e${stamp}`,
      email: `p05e2e${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '总部',
      roles: [adminRole._id],
      tokenVersion: 0,
    });
    adminToken = jwt.sign(
      {
        userId: String(admin._id),
        username: admin.username,
        email: admin.email,
        roles: [`P05E2E_${stamp}`],
        tokenVersion: 0,
        jti: 'j',
        sid: null,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const rx = new RegExp(stamp);
      await User.deleteMany({ username: rx }).catch(() => {});
      await Role.deleteMany({ code: rx }).catch(() => {});
      await AuditLog.deleteMany({ username: rx }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    spyPush.mockClear();
  });

  afterAll(() => {
    spyPush.mockRestore();
  });

  test('PUT /api/security/config/loginCaptchaEnabled：全局侧 0 条，控制器手写 1 条', async () => {
    const res = await request(app)
      .put('/api/security/config/loginCaptchaEnabled')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ loginCaptchaEnabled: true });

    expect(res.status).toBe(200);
    expect(res.body.data.loginCaptchaEnabled).toBe(true);

    await tick();
    await tick();

    // 全局派生的 security_config_loginCaptchaEnabled 不得入 buffer
    expect(pushedForPath('/api/security/config/loginCaptchaEnabled')).toEqual([]);

    // 唯一留痕：控制器手写的 login_captcha_enabled 仍在库中
    const recorded = await AuditLog.findOne({
      action: 'login_captcha_enabled',
      username: admin.username,
    }).lean();
    expect(recorded).not.toBeNull();
    expect(recorded.category).toBe('system');
  });

  test('PUT /api/security/config/registerCaptchaEnabled：全局侧 0 条，控制器手写 1 条', async () => {
    const res = await request(app)
      .put('/api/security/config/registerCaptchaEnabled')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ registerCaptchaEnabled: false });

    expect(res.status).toBe(200);

    await tick();
    await tick();

    expect(pushedForPath('/api/security/config/registerCaptchaEnabled')).toEqual([]);

    const recorded = await AuditLog.findOne({
      action: 'register_captcha_disabled',
      username: admin.username,
    }).lean();
    expect(recorded).not.toBeNull();
    expect(recorded.category).toBe('system');
  });

  test('对照：未置 skipGlobalAudit 的写操作仍恰好产生 1 条全局审计', async () => {
    // PUT /api/users/:id 的合法路径（同部门改真实姓名）不设 skipGlobalAudit，
    // 必须照常产生 1 条全局审计 —— 证明上面的 0 条来自标志生效，而非中间件被短路。
    const target = await User.create({
      username: `p05target${stamp}`,
      email: `p05target${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '总部',
      roles: [],
      tokenVersion: 0,
    });

    const res = await request(app)
      .put(`/api/users/${target._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ realName: 'P05 对照' });

    expect(res.status).toBe(200);
    await tick();
    await tick();

    const pushed = pushedForPath(`/api/users/${target._id}`);
    expect(pushed).toHaveLength(1);
    expect(pushed[0].action).toBe('user_update');
    expect(pushed[0].category).toBe('user');
  });
});
