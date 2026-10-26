'use strict';

/**
 * 路由层校验分支的补测（T-3，2026-10-26）
 *
 * 审计原文：`src/routes` 分支覆盖 79.5%，缺口集中在**只在特定配置下才走到的守卫**——
 * 它们恰恰是安全开关，长期无人执行等于"写了但从没被验证过"：
 *
 *   ① 口令加密传输 strict 档（`LOGIN_ENCRYPT_STRICT=true`）的两条守卫：
 *      - 明文轨直接拒绝（`rejectPlaintextInStrict`）；
 *      - 密文与明文并存视为协议违规（`rejectEncPlaintextCoexistence`）。
 *      这两条**只有在生产切到 strict 后才会执行**，而那时改错的代价最高。
 *   ② 巡检计划的时间窗倒置（`planEndTime <= planStartTime`）：不拦会让
 *      dashboard/report 的 overdue 与完成率永久失真（创建/更新两条链各一份判据）。
 *   ③ `POST /reports/export/pii` 的类型白名单：非 PII 类型必须在步进验证**之前**
 *      拒绝，否则"注定 400"的请求白白消耗一次二次验证。
 *   ④ 创建用户时的口令长度上限。
 *
 * 每条都配**反向对照**：把开关关掉 / 把时间窗改正 / 换成合法类型，同一个请求
 * 必须不再出现那条错误——否则"红转绿"可能只是断言写错了。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `rbc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

describe('路由校验分支（T-3）', () => {
  let app;
  let config;
  let User;
  let Role;
  let Permission;
  let Inspection;
  let SystemConfig;
  let originalRegistrationConfig = null;
  let token;
  let savedStrict;

  const msgs = (res) => (res.body?.errors?.fieldErrors || []).map((e) => e.msg);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    config = require('../../config');
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    Inspection = require('../../models/Inspection');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');

    // 注册开关默认是"关"（库里无 doc ⇒ false），而 `POST /register` 的处理器在
    // **校验结果被消费之前**就返回 403 PUBLIC_REGISTRATION_DISABLED —— 于是
    // authRoutes 那两条 strict 守卫永远执行不到。这里临时打开注册（并在 afterAll
    // 还原），让校验链真正走到 validationResult。
    SystemConfig = require('../../models/SystemConfig');
    originalRegistrationConfig = await SystemConfig.findOne({
      key: 'allowPublicRegistration',
    }).lean();
    await SystemConfig.updateOne(
      { key: 'allowPublicRegistration' },
      { $set: { value: 'true' } },
      { upsert: true }
    );

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `路由分支_${stamp}`,
      code: `ROUTE_BRANCH_${stamp}`.toUpperCase(),
      level: 10,
      isBuiltIn: false,
      permissions: [wildcard._id],
    });
    const admin = await User.create({
      username: `${stamp}admin`,
      email: `${stamp}admin@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    token = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    app = require('../../app').createApp();
  });

  beforeEach(() => {
    savedStrict = config.loginEncryptStrict;
  });

  afterEach(() => {
    // 配置是模块级可变对象：不还原会把 strict 档泄漏给后续用例（含其它文件）
    config.loginEncryptStrict = savedStrict;
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: /^T3-/ }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(stamp.toUpperCase()) }).catch(() => {});
    // 还原注册开关：测试库在同一 worker 的套件间共享，留下 'true' 会让
    // "注册关闭"的用例在后续套件里变绿/变红，属于最难查的跨文件污染
    if (SystemConfig) {
      if (originalRegistrationConfig) {
        await SystemConfig.updateOne(
          { key: 'allowPublicRegistration' },
          { $set: { value: originalRegistrationConfig.value } }
        ).catch(() => {});
      } else {
        await SystemConfig.deleteOne({ key: 'allowPublicRegistration' }).catch(() => {});
      }
    }
    // 套件级收尾（mongooseTeardownLedger 门禁）：连了内存 Mongo 就必须自己关。
    // 不关会留下 hasRef()===true 的 Socket，jest-worker 在最后一个文件后 500ms 强杀 worker，
    // 强杀会吞掉本套件输出 —— 正是"最需要看结果的时候看不见结果"。
    // 守卫式而非无条件：本套件在 readyState 非 0 时**没有**建连（复用上游连接），
    // 那种情况下关掉别人的连接会炸后续套件。
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const withAuth = () => ({ Authorization: `Bearer ${token}` });

  describe('口令加密 strict 档（authRoutes / securityRoutes 同口径）', () => {
    const strongPassword = 'Str0ng!Passw0rd#2026';
    const registerPayload = (extra = {}) => ({
      username: `${stamp}r${Math.random().toString(36).slice(2, 8)}`,
      email: `${stamp}r${Math.random().toString(36).slice(2, 8)}@example.com`,
      realName: '分支测试',
      ...extra,
    });

    test('strict 开：注册携带明文口令被拒（文案点名"已启用口令加密传输"）', async () => {
      config.loginEncryptStrict = true;
      const res = await request(app)
        .post('/api/auth/register')
        .send(registerPayload({ password: strongPassword }));

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('已启用口令加密传输');
    });

    test('strict 开：密文与明文并存被拒（协议违规，不是降级）', async () => {
      config.loginEncryptStrict = true;
      const res = await request(app)
        .post('/api/auth/register')
        .send(
          registerPayload({
            encPassword: 'test',
            password: strongPassword,
          })
        );

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('禁止同时携带明文字段');
    });

    test('反向对照：strict 关时同一条明文请求不再出现那两条文案', async () => {
      config.loginEncryptStrict = false;
      const res = await request(app)
        .post('/api/auth/register')
        .send(registerPayload({ password: strongPassword }));

      const text = msgs(res).join('|');
      expect(text).not.toContain('已启用口令加密传输');
      expect(text).not.toContain('禁止同时携带明文字段');
    });

    test('strict 开：改密接口的明文口令同样被拒', async () => {
      config.loginEncryptStrict = true;
      const res = await request(app).put('/api/security/change-password').set(withAuth()).send({
        currentPassword: PASSWORD,
        newPassword: strongPassword,
        confirmPassword: strongPassword,
      });

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('已启用口令加密传输');
    });
  });

  describe('巡检时间窗倒置（创建 / 更新两条链各一份判据）', () => {
    const basePlan = () => ({
      title: `T3-时间窗-${stamp}-${Math.random().toString(36).slice(2, 7)}`,
      inspectionType: 'daily',
      checkItems: [{ name: '灭火器压力', standard: '指针在绿区' }],
    });

    test('创建：结束时间早于开始时间 ⇒ 400，且点名跨字段判据', async () => {
      const res = await request(app)
        .post('/api/inspections')
        .set(withAuth())
        .send({
          ...basePlan(),
          planStartTime: '2026-11-10T09:00:00.000Z',
          planEndTime: '2026-11-09T09:00:00.000Z',
        });

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('计划结束时间必须晚于开始时间');
    });

    test('更新：同一条跨字段判据在 PUT 链上同样生效', async () => {
      const created = await request(app)
        .post('/api/inspections')
        .set(withAuth())
        .send({
          ...basePlan(),
          planStartTime: '2026-11-10T09:00:00.000Z',
          planEndTime: '2026-11-11T09:00:00.000Z',
        });
      // 前提自证：合法时间窗必须真的创建成功，否则下面那条 400 可能来自别处
      expect([200, 201]).toContain(created.status);

      const res = await request(app)
        .put(`/api/inspections/${created.body.data._id}`)
        .set(withAuth())
        .send({
          planStartTime: '2026-11-10T09:00:00.000Z',
          planEndTime: '2026-11-09T09:00:00.000Z',
        });

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('计划结束时间必须晚于开始时间');
    });
  });

  describe('未脱敏导出的类型白名单（步进验证之前拒绝）', () => {
    test('非 PII 类型（devices）⇒ 400 REPORT_TYPE_UNSUPPORTED', async () => {
      const res = await request(app)
        .post('/api/reports/export/pii?type=devices')
        .set(withAuth())
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('REPORT_TYPE_UNSUPPORTED');
    });

    test('反向对照：缺省类型按 alarms 处理，不得被白名单拦下', async () => {
      // 不带 type 时 requirePiiExportType 取默认 'alarms'（PII 类型）⇒ 继续往下走。
      // 这里断言"不是那条错误码"，而不是断言 200——后续二次验证会拦住，
      // 但那已经不是本判据的职责。
      const res = await request(app).post('/api/reports/export/pii').set(withAuth()).send({});

      expect(res.body?.errors?.errorCode).not.toBe('REPORT_TYPE_UNSUPPORTED');
    });
  });

  describe('创建用户的口令长度上限', () => {
    test('超过 64 字符 ⇒ 400 且点名长度', async () => {
      const res = await request(app)
        .post('/api/users')
        .set(withAuth())
        .send({
          username: `${stamp}longpwd`,
          email: `${stamp}longpwd@example.com`,
          password: `Aa1!${'x'.repeat(80)}`,
          realName: '长度测试',
        });

      expect(res.status).toBe(400);
      expect(msgs(res).join('|')).toContain('密码长度不能超过 64 个字符');
    });
  });
});
