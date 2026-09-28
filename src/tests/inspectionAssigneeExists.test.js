/**
 * 巡检执行人必须真实存在
 *
 * 创建/更新巡检的校验链只到 `assignedTo.*.isMongoId()`：格式对就行。
 * 于是"指向不存在用户的执行人"能直接落库，而这条计划**永远无法开工**——
 * startInspection 要求 `assignedTo` 含操作者，或 `assignedTo.0` 不存在，
 * 单元素幽灵数组两个条件都不满足；它还继续计入 pending 并拖住 completionRate。
 * 报警侧（AlarmService.dispatchAlarm）早就校验"存在且启用"，巡检这一路是漏的。
 *
 * 反向保护同样钉住：不传 assignedTo 的正常更新不得被这道闸拦下。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('巡检执行人引用必须存在且启用', () => {
  let app;
  let User;
  let Inspection;
  let token;
  let activeUserId;
  const stamp = `zzia${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Inspection = require('../models/Inspection');
    const Permission = require('../models/Permission');
    const Role = require('../models/Role');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    const perm = await Permission.create({ name: '通配', code: '*:*', module: 'system' });
    const role = await Role.create({
      name: `${stamp} 超级角色`,
      code: `ZZIA_${stamp}`.toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
      level: 10,
      permissions: [perm._id],
    });
    const operator = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    const active = await User.create({
      username: `${stamp}_ok`,
      email: `${stamp}_ok@example.com`,
      password: randomPassword(),
    });
    activeUserId = String(active._id);

    const jwt = require('jsonwebtoken');
    token = jwt.sign(
      {
        userId: String(operator._id),
        username: operator.username,
        tokenVersion: operator.tokenVersion,
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // 每条用例用独立 title：双 seed 随机顺序门禁会打乱用例顺序，
  // 任何"依赖上一条留下的数据"的写法都会变成偶发假红。
  const create = (assignedTo, tag) =>
    require('supertest')(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: `${stamp}-${tag}`,
        inspectionType: 'daily',
        planStartTime: '2026-09-20T08:00:00.000Z',
        planEndTime: '2026-09-20T10:00:00.000Z',
        // 路由要求至少一个检查项目；缺了会得到另一条 400，
        // 那样"400"就不再证明执行人校验生效（首轮实跑即暴露）。
        checkItems: [{ name: `${stamp} 检查项` }],
        assignedTo,
      });

  const mkPlan = (fields) =>
    Inspection.create({
      title: `${stamp}-own`,
      inspectionType: 'daily',
      ...fields,
    });

  test('悬空执行人 ID → 400，且不落库', async () => {
    const ghost = new mongoose.Types.ObjectId();
    const res = await create([String(ghost)], 'ghost');
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toContain('执行人');
    expect(await Inspection.countDocuments({ title: `${stamp}-ghost` })).toBe(0);
  });

  test('已停用的账户同样不能作为执行人（存在 ≠ 可用）', async () => {
    const dormant = await User.create({
      username: `${stamp}_off`,
      email: `${stamp}_off@example.com`,
      password: randomPassword(),
      status: 'inactive',
    });
    const res = await create([String(dormant._id)], 'off');
    expect(res.status).toBe(400);
    // 必须是"执行人不可用"这条 400，而不是任何其他校验失败
    expect(JSON.stringify(res.body)).toContain('执行人');
    expect(await Inspection.countDocuments({ title: `${stamp}-off` })).toBe(0);
  });

  test('反向保护：真实启用的执行人照常创建成功', async () => {
    const res = await create([activeUserId], 'ok');
    expect(res.status).toBe(201);
    const saved = await Inspection.findOne({ title: `${stamp}-ok` });
    expect(saved.assignedTo.map(String)).toEqual([activeUserId]);
  });

  test('更新路径同样收口，且不得改动原记录', async () => {
    const saved = await mkPlan({ title: `${stamp}-upd`, assignedTo: [activeUserId] });
    const res = await require('supertest')(app)
      .put(`/api/inspections/${saved._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ assignedTo: [String(new mongoose.Types.ObjectId())] });

    expect(res.status).toBe(400);
    const after = await Inspection.findById(saved._id);
    expect(after.assignedTo.map(String)).toEqual([activeUserId]);
  });

  test('反向保护：不带 assignedTo 的普通更新不受这道闸影响', async () => {
    const saved = await mkPlan({ title: `${stamp}-plain`, assignedTo: [activeUserId] });
    const res = await require('supertest')(app)
      .put(`/api/inspections/${saved._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ remark: `${stamp} 只改备注` });

    expect(res.status).toBe(200);
  });
});
