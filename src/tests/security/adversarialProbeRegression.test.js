const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

/**
 * 对抗性探针场景的**行为断言**固化（P1-30 转化）
 *
 * 背景：`src/tests/zzz-*.test.js`（8 个文件 / 51 test）是审计期的临时探针，
 * 全部 0 expect、只 console.log 观察结果，却被 Jest 收集并计入覆盖率分母；
 * 其中两个文件还打印完整 JWT。它们承载的**复现证据**（P0 越权链、WS 绕过等）
 * 有价值，但作为测试文件不合格。
 *
 * 本文件把其中「唯一可复现某个 P0/高价值安全结论」的场景转为真实断言，
 * 其余场景已在既有跟踪测试中覆盖（见各用例注释引用的对应文件）。
 * 原 zzz-* 文件已删除（P1-30）。
 *
 * 覆盖清单（对应被删除探针的编号与去向）：
 *  - 设备列表数据范围隔离 + 按 ID 横向越权拒绝（zzz-adversarial-r2/r4/r5）
 *  - 自助改 department 被数据范围校验拒绝（zzz-adversarial-r3/r4/r5 → P0-1 修复回归）
 *  - 自我锁定防护：改自身 status 被拒（zzz-adversarial-r3 R3-4）
 *  - 同部门内 allowedIPs 变更放行（zzz-adversarial-r3 R3-3，P0-1 修复口径的另一半）
 *  - 跨部门删除设备被拒（zzz-adversarial-r2 R2-9）
 *  - 审计不含明文口令（zzz-adversarial-r2 R2-6）
 *  - NoSQL 注入形态的登录请求（zzz-adversarial-audit P5，此前无跟踪覆盖）
 *  - 原型污染端到端（zzz-adversarial-audit P7，中间件级另有 securityBranches.test.js）
 *
 * 未在本文件重复的场景（已在跟踪测试中覆盖，故对应探针直接删除）：
 *  - WS 认证对「已吊销 sid」「allowedIPs 不匹配」的拒绝（zzz-adversarial-r6 →
 *    services/websocketAuthScope.test.js，P0-2 修复后由 Rawls 新建）
 *  - XFF 伪造无法绕过 /metrics 内网判定（zzz-adversarial-r2 R2-4 →
 *    middleware/metricsAuth.test.js:97-108 同口径用例）
 *  - 部门主管访问审计日志被拒（zzz-adversarial-r2 R2-10 →
 *    controllers/auditReportFixes.test.js:261 等 security:audit 权限用例）
 *  - 非法 ObjectId / 恶意 Origin / 无令牌 / alg:none / 错误密钥 / 省略 tokenVersion
 *    （zzz-adversarial-audit P1/P8/P9/P10/P11/P16 → 分别见 authRest / auth /
 *    originCheck / infraParamRateLimitFailClosed / userPermBranches 等既有套件）
 */

describe('对抗性探针场景固化（P1-30：原 zzz-* 探针 → 行为断言）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let FireDevice;
  let AuditLog;
  let mgrToken;
  let mgr;
  let boss;
  let lowToken;
  let lowUser;
  const stamp = `probe${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

    app = require('../../app').createApp();

    // 部门主管（level 8 → dataScope=department），持设备读 + 用户更新
    const pUpd = await Permission.findOneAndUpdate(
      { code: 'user:update' },
      { $setOnInsert: { name: '改用户', code: 'user:update', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    const pDev = await Permission.findOneAndUpdate(
      { code: 'device:read' },
      { $setOnInsert: { name: '设备读', code: 'device:read', type: 'api', module: 'device' } },
      { upsert: true, new: true }
    );
    const pRead = await Permission.findOneAndUpdate(
      { code: 'user:read' },
      { $setOnInsert: { name: '用户读', code: 'user:read', type: 'api', module: 'user' } },
      { upsert: true, new: true }
    );
    const mgrRole = await Role.create({
      name: `探针主管_${stamp}`,
      code: `PROBE_MGR_${stamp}`,
      level: 8,
      status: 'active',
      permissions: [pUpd._id, pRead._id, pDev._id],
    });
    // 消防员（level 4 → dataScope=self）
    const lowRole = await Role.create({
      name: `探针消防员_${stamp}`,
      code: `PROBE_LOW_${stamp}`,
      level: 4,
      status: 'active',
      permissions: [pDev._id],
    });

    mgr = await User.create({
      username: `pmgr${stamp}`,
      email: `pmgr${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '东区',
      roles: [mgrRole._id],
      tokenVersion: 0,
    });
    boss = await User.create({
      username: `pboss${stamp}`,
      email: `pboss${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '总部',
      roles: [],
      tokenVersion: 0,
    });
    lowUser = await User.create({
      username: `plow${stamp}`,
      email: `plow${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '东区',
      roles: [lowRole._id],
      tokenVersion: 0,
    });

    const mk = (u, roles) =>
      jwt.sign(
        {
          userId: String(u._id),
          username: u.username,
          email: u.email,
          roles,
          tokenVersion: 0,
          jti: 'j',
          sid: null,
        },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '24h' }
      );
    mgrToken = mk(mgr, [`PROBE_MGR_${stamp}`]);
    lowToken = mk(lowUser, [`PROBE_LOW_${stamp}`]);

    await FireDevice.create({
      deviceName: `总部机密设备_${stamp}`,
      deviceCode: `HQ-${stamp}`,
      location: { building: '总部', floor: 1 },
      status: 'normal',
      deviceType: 'smoke_detector',
      installDate: new Date(),
      createdBy: boss._id,
    });
    await FireDevice.create({
      deviceName: `东区设备_${stamp}`,
      deviceCode: `EAST-${stamp}`,
      location: { building: '东区', floor: 1 },
      status: 'normal',
      deviceType: 'smoke_detector',
      installDate: new Date(),
      createdBy: mgr._id,
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const rx = new RegExp(stamp);
      await User.deleteMany({ username: rx }).catch(() => {});
      await Role.deleteMany({ code: rx }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: rx }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('设备列表：部门主管只见本部门设备（不泄漏总部设备）', async () => {
    const res = await request(app).get('/api/devices').set('Authorization', `Bearer ${mgrToken}`);
    expect(res.status).toBe(200);
    const list = res.body.data || [];
    const buildings = list.map((d) => d.location?.building);
    expect(buildings).not.toContain('总部');
    // deviceCode 有 uppercase:true 转换（schema 层），断言须用大写形态
    expect(list.some((d) => d.deviceCode === `EAST-${stamp}`.toUpperCase())).toBe(true);
  });

  test('设备详情：按 ID 直取跨部门设备 → 403（横向越权拦截）', async () => {
    const hq = await FireDevice.findOne({ deviceCode: `HQ-${stamp}` });
    const res = await request(app)
      .get(`/api/devices/${hq._id}`)
      .set('Authorization', `Bearer ${mgrToken}`);
    expect(res.status).toBe(403);
    // 403 必须点名设备数据范围闸：与「无权操作」等通用 403 区分
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
  });

  test('设备列表：self 范围用户看不到任何非本人创建的设备', async () => {
    const res = await request(app).get('/api/devices').set('Authorization', `Bearer ${lowToken}`);
    expect(res.status).toBe(200);
    const list = res.body.data || [];
    expect(list.map((d) => d.deviceCode)).not.toContain(`HQ-${stamp}`);
    expect(list.map((d) => d.deviceCode)).not.toContain(`EAST-${stamp}`);
  });

  test('P0-1 回归：自助改 department 被数据范围校验拒绝（USER_SCOPE_FIELD_FORBIDDEN）', async () => {
    const res = await request(app)
      .put(`/api/users/${mgr._id}`)
      .set('Authorization', `Bearer ${mgrToken}`)
      .send({ department: '总部' });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FIELD_FORBIDDEN');

    // 数据库中部门未变：越权链在第一步就被截断
    const after = await User.findById(mgr._id).select('department');
    expect(after.department).toBe('东区');
  });

  test('P0-1 回归：改他人 department 跨部门同样被拒', async () => {
    const other = await User.create({
      username: `pother${stamp}`,
      email: `pother${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '东区',
      roles: [],
      tokenVersion: 0,
    });
    const res = await request(app)
      .put(`/api/users/${other._id}`)
      .set('Authorization', `Bearer ${mgrToken}`)
      .send({ department: '西区' });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('USER_SCOPE_FIELD_FORBIDDEN');
    const after = await User.findById(other._id).select('department');
    expect(after.department).toBe('东区');
  });

  test('跨部门删除设备 → 403，且记录仍在', async () => {
    const hq = await FireDevice.findOne({ deviceCode: `HQ-${stamp}` });
    const res = await request(app)
      .delete(`/api/devices/${hq._id}`)
      .set('Authorization', `Bearer ${mgrToken}`);
    expect(res.status).toBe(403);
    const still = await FireDevice.findById(hq._id);
    expect(still).toBeTruthy();
  });

  test('审计日志不含明文口令（登录失败路径的 body 已脱敏）', async () => {
    const secret = randomPassword();
    await request(app)
      .post('/api/auth/login')
      .send({ username: `pghost${stamp}`, password: secret });
    const recent = await AuditLog.find({ username: `pghost${stamp}` })
      .sort({ _id: -1 })
      .limit(5)
      .lean();
    for (const rec of recent) {
      expect(JSON.stringify(rec.body || {})).not.toContain(secret);
    }
  });

  test('设备统计：部门主管的统计口径与列表一致（不把总部设备算进 total）', async () => {
    const res = await request(app)
      .get('/api/devices/stats')
      .set('Authorization', `Bearer ${mgrToken}`);
    expect(res.status).toBe(200);
    // 本部门只有 1 台设备（EAST-<stamp>）；总部设备不得进入统计口径
    expect(res.body.data.total).toBe(1);
  });

  test('用户列表：不返回 password / tokenVersion 等敏感字段', async () => {
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${mgrToken}`);
    expect(res.status).toBe(200);
    const list = res.body.data || [];
    expect(list.length).toBeGreaterThan(0);
    const forbidden = [
      'password',
      'tokenVersion',
      'mfaSecret',
      'failedLoginCount',
      'lockUntil',
      'passwordChangedAt',
    ];
    for (const field of forbidden) {
      expect(Object.prototype.hasOwnProperty.call(list[0], field)).toBe(false);
    }
  });

  test('NoSQL 注入：登录 username/password 传操作符对象 → 校验层就拒，不进入查询构造', async () => {
    // 原 zzz-adversarial-audit.test.js P5：审计期用 { $ne: null } 形态探测登录接口。
    // 该场景此前**无任何跟踪测试覆盖**，故迁移为真实断言（其余探针场景已由
    // 既有套件覆盖，见文件头清单）。
    // 断言从 401 收紧到 400：body 类型闸门前该形态能穿过校验进入认证（查询构造了、
    // 匹配不到 ⇒ 401），现在在路由校验层就被点名拒掉，同一安全性质拒得更早。
    // 401 轨道仍由下面「原型污染」那条用例覆盖（字符串凭据走完整认证）。
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: { $ne: null }, password: { $ne: null } });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    const paths = res.body.errors.fieldErrors.map((e) => e.path);
    expect(paths).toEqual(expect.arrayContaining(['username', 'password']));
    // 不得因操作符对象绕过查询而误判为「凭据正确」
    expect(res.body.success).toBe(false);
  });

  test('原型污染：登录体携带 __proto__ / constructor.prototype → 401 且全局原型未被污染', async () => {
    // 原 zzz-adversarial-audit.test.js P7：中间件层的键剔除已由
    // securityBranches.test.js（sanitizeMongo 分支）覆盖，但**端到端**从未验证
    // 「恶意体穿过完整中间件链后 Object.prototype 仍干净」，故补此断言。
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'x',
        password: 'y',
        __proto__: { isAdmin: true },
        constructor: { prototype: { polluted: true } },
      });
    expect(res.status).toBe(401);
    expect({}.polluted).toBeUndefined();
    expect({}.isAdmin).toBeUndefined();
  });

  test('自我锁定防护：管理员改自己的 status → 400 CANNOT_CHANGE_OWN_STATUS', async () => {
    // 原 zzz-adversarial-r3.test.js R3-4。该错误码此前**无任何跟踪测试覆盖**
    // （userController.js:247-249 的 isSelf 分支），且它保护的是「把自己改 inactive
    // 后无人能解锁」的自锁死路径，属高价值回归。
    const res = await request(app)
      .put(`/api/users/${mgr._id}`)
      .set('Authorization', `Bearer ${mgrToken}`)
      .send({ status: 'inactive' });
    // 实测：errorCodes.js:592-595 将该码定义为 400（与 USER_SCOPE_FIELD_FORBIDDEN 的 403 不同）
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('CANNOT_CHANGE_OWN_STATUS');
    const after = await User.findById(mgr._id).select('status');
    expect(after.status).toBe('active');
  });
  test('数据范围口径：department 范围操作者改本部门他人 allowedIPs → 允许（本部门内）', async () => {
    // 原 zzz-adversarial-r3.test.js R3-3 的实测结论固化。
    // P0-1 修复口径（userController.js:291-298）：dataScope=department 允许
    // **本部门内**的 scope 字段变更；只有越部门 / self、none 范围才拒绝。
    // 本用例锁定「同部门内放行」这一半，越界拒绝由本文件前面两条 P0-1 用例覆盖。
    // 用独立目标用户而非 mgr 自身：避免改动共享 fixture 造成用例间顺序耦合。
    const peer = await User.create({
      username: `ppeer${stamp}`,
      email: `ppeer${stamp}@example.com`,
      password: randomPassword(),
      status: 'active',
      department: '东区',
      roles: [],
      tokenVersion: 0,
    });
    const res = await request(app)
      .put(`/api/users/${peer._id}`)
      .set('Authorization', `Bearer ${mgrToken}`)
      .send({ allowedIPs: '10.0.0.0/8' });
    expect(res.status).toBe(200);
    const after = await User.findById(peer._id).select('allowedIPs');
    expect(after.allowedIPs).toBe('10.0.0.0/8');
  });
});
