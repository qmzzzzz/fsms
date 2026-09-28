/**
 * 巡检的四个数组入参必须有长度上限
 *
 * 原状：`checkItems` 只有 `{min:1}`，`devices`/`locations`/`assignedTo` 连 min 都没有——
 * 1MB body 限制下一次请求就能塞进上万个元素。落库之后每次列表/详情读取都要对它们
 * 做 populate（devices→4 字段、assignedTo→2 字段），于是"一次写入"变成"每次读都付代价"；
 * 子文档数组无限增长最终把文档顶到 16MB，那条记录连 save 都做不了。
 * 同族的 `findings` 早就钉在 100，本次把缺的四个补齐并对齐到 200（见 routes 里的取值说明）。
 *
 * 反向保护同样重要：恰好 200 必须放行（收口不能变成一刀切），
 * 且既有的 findings=100 上限不能被这次改动悄悄放宽。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('巡检数组入参的长度上限', () => {
  let app;
  let request;
  let User;
  let Inspection;
  let token;
  const stamp = `ac${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);
  const LIMIT = 200;
  const oid = () => String(new mongoose.Types.ObjectId());
  const manyItems = (n) => Array.from({ length: n }, (_, i) => ({ name: `项${i}` }));

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

    const perm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '通配', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `${stamp} 超管`,
      code: `ZZAC_${stamp}`.toUpperCase(),
      level: 10,
      permissions: [perm._id],
    });
    const user = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    request = require('supertest');
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

  /**
   * 逐用例清掉本文件可能已建出的计划。
   *
   * 拒绝类用例的收尾断言是「`countDocuments({title: '<stamp> 计划'}) === 0`」，
   * 而"反向保护：恰好 200 个检查项目仍然创建成功"那条用例创建的就是**同一个标题**。
   * `--randomize` 会打散文件内顺序：成功用例先跑，拒绝用例就拿 1 去比 0 必红
   * （单文件 + 同 seed 即可复现，与跨套件污染无关）。"拒绝时不落库"这条断言本身是对的，
   * 需要的是每条用例都从"没有本用例命名的计划"这个起点出发。
   */
  beforeEach(async () => {
    await Inspection.deleteMany({ title: `${stamp} 计划` });
  });

  // 双 seed 随机顺序门禁下用例不得互相依赖：需要一条已存在的计划时各自建
  const mkPlan = () =>
    Inspection.create({
      title: `${stamp}-own`,
      inspectionType: 'daily',
      checkItems: manyItems(LIMIT),
    });

  const post = (body) =>
    request(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: `${stamp} 计划`,
        inspectionType: 'daily',
        // 计划起止时间是必填 ISO8601：缺了会得到另一组 400，
        // 那时"400 + 文案含数字"就不再证明长度上限生效
        planStartTime: '2026-09-25T08:00:00.000Z',
        planEndTime: '2026-09-25T10:00:00.000Z',
        ...body,
      });

  test.each([
    ['checkItems 超出上限', { checkItems: manyItems(LIMIT + 1) }, '检查项目', 'checkItems'],
    [
      'devices 超出上限',
      { checkItems: manyItems(1), devices: Array(501).fill(oid()) },
      '设备',
      'devices',
    ],
    [
      'assignedTo 超出上限',
      { checkItems: manyItems(1), assignedTo: Array(501).fill(oid()) },
      '执行人',
      'assignedTo',
    ],
    [
      'locations 超出上限',
      { checkItems: manyItems(1), locations: Array(501).fill({ building: 'A' }) },
      '区域',
      'locations',
    ],
  ])('%s → 400 且是该字段的长度校验在拦', async (_label, body, expectWord, path) => {
    const res = await post(body);
    expect(res.status).toBe(400);
    const text = JSON.stringify(res.body);
    expect(text).toContain(expectWord);
    expect(text).toContain(String(LIMIT));
    // 必须是这个字段的长度错误在起作用，而不是别的校验顺带红了
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain(path);
    expect(await Inspection.countDocuments({ title: `${stamp} 计划` })).toBe(0);
  });

  test('反向保护：恰好 200 个检查项目仍然创建成功（不是把窗口一起收窄）', async () => {
    // 不带 devices：本用例的主角是 checkItems 的窗口，随手塞一个不存在的设备 id
    // 会被写路径的范围闸（inspectionGuards）判 DEVICE_NOT_FOUND，掩蔽真正要测的东西
    const res = await post({ checkItems: manyItems(LIMIT) });
    expect(res.status).toBe(201);
    const saved = await Inspection.findOne({ title: `${stamp} 计划` });
    expect(saved.checkItems).toHaveLength(LIMIT);
  });

  test('反向保护：既有 findings 上限仍是 100（本次改动不得放宽任何已有上限）', async () => {
    const saved = await mkPlan();
    const res = await request(app)
      .put(`/api/inspections/${saved._id}/complete`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        result: 'abnormal',
        findings: Array.from({ length: 101 }, (_, i) => ({ issue: `问题${i}` })),
      });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toContain('100');
  });

  test('更新路径同样收口（201 个检查项目 → 400，且不改动原记录）', async () => {
    const saved = await mkPlan();
    const res = await request(app)
      .put(`/api/inspections/${saved._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ checkItems: manyItems(LIMIT + 1) });

    expect(res.status).toBe(400);
    const after = await Inspection.findById(saved._id);
    expect(after.checkItems).toHaveLength(LIMIT);
  });
});
