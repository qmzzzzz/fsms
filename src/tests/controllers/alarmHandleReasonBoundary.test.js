'use strict';

/**
 * 报警"处理类描述"的长度上限：误报标记 / 取消 两条写入口
 *
 * 缺陷本体：`PUT /api/alarms/:id/false-alarm` 与 `/:id/cancel` 的路由只挂了
 * `mongoIdParamValidation`（alarmRoutes.js:184-190 / :197-202），控制器
 * （alarmController.js:314 / :338）却把 `req.body.reason` 原样传进服务层：
 *   · false-alarm 写 `FireAlarm.handleResult`，schema 有 `maxlength: 1000`
 *     （models/FireAlarm.js:103-106），但 `AlarmService.markAsFalseAlarm` 用的是
 *     `findOneAndUpdate(..., { new: true })` —— **Mongoose 的 update 路径默认不跑校验**，
 *     于是那道上限在这条链上根本不存在，1MB 请求体上限内的任意长度原样落库；
 *   · cancel 写 `processLog[].remark`，而 `remark: String`（models/FireAlarm.js:124）
 *     连上限都没声明，`processLog` 又是只增数组 ⇒ 单条报警可被撑到 16MB 文档上限。
 * 同一份 schema 字段在 `/resolve` 上是被严格钉住的（resolveValidation 的 1-1000），
 * 属同一口径的两个漏装出口。
 *
 * 判据分工（缺一条就留有假绿空间）：
 * 1. 反向对照先行：500 字符必须 200 且**逐字**落库——否则"把 reason 整个丢掉/一律拒绝"
 *    也能让后面的拒绝断言变绿；
 * 2. 超长在路由层就被点名：400 + `fieldErrors` 含 `reason`（状态码 400 不是判据，
 *    update 路径开了 runValidators 后 schema 也给 400，但生产环境没有字段明细）；
 * 3. 非法值不得留下半个写入：文档 handleResult / processLog 长度都不变；
 * 4. 1000/1001 的双向边界（与 schema 上限同值，防"路由比 schema 更紧"误伤合法输入）；
 * 5. 服务层直连（绕过路由）同样不得写入超长值：证明 update 路径真的跑了校验，
 *    而不是只把闸装在唯一一条 HTTP 入口上；
 * 6. 缺省与空串 reason 仍走服务层的默认文案：新挂的规则只许管长度，
 *    一旦写成"必须有值"，`reason || '确认为误报'` 这条路会静默变成 400；
 * 7. 非字符串 reason 明确拒绝：不钉这一条，规则里的 isString 被删掉也无人发现，
 *    对象会被 Cast 成字符串落库（remark 形如 `[object Object]`）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const stamp = `zhr${Date.now()}`.slice(-10);

describe('误报/取消的 reason 长度上限（路由层 + update 校验）', () => {
  let app;
  let FireAlarm;
  let tokenAll;
  let operatorId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/TokenBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `ZZHR_ALL${stamp}`,
      code: `ZZHR_ALL${stamp}`,
      level: 10,
      permissions: [wildcard._id],
    });
    const user = await User.create({
      username: `zzhr_all${stamp}`,
      email: `zzhr_all${stamp}@example.com`,
      password: 'Test@1234567',
      department: `ZZHR-D-${stamp}`,
      roles: [role._id],
    });
    operatorId = String(user._id);
    tokenAll = jwt.sign(
      { userId: operatorId, username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: `zzhr_all${stamp}` }).catch(() => {});
      await Role.deleteMany({ code: `ZZHR_ALL${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 真发 HTTP 建一条 pending 报警，返回其 _id（不走 FireAlarm.create：必填口径交给模型自己定） */
  const newAlarm = async () => {
    const res = await request(app)
      .post('/api/alarms/report')
      .set('Authorization', `Bearer ${tokenAll}`)
      .send({ alarmType: 'smoke', description: `ZZHR 上报 ${stamp}` });
    expect(res.status).toBe(201);
    return res.body.data._id;
  };

  const put = (id, path, body) =>
    request(app)
      .put(`/api/alarms/${id}/${path}`)
      .set('Authorization', `Bearer ${tokenAll}`)
      .send(body);

  const reload = (id) => FireAlarm.findById(id).lean();

  test('1 反向对照：500 字符 reason 必须放行并逐字落库', async () => {
    const id = await newAlarm();
    const reason = '说'.repeat(500);
    const res = await put(id, 'false-alarm', { reason });
    expect(res.status).toBe(200);
    expect((await reload(id)).handleResult).toBe(reason);
  });

  test('2 误报：5000 字符 reason 在路由层被点名拒绝', async () => {
    const id = await newAlarm();
    const before = await reload(id);
    const res = await put(id, 'false-alarm', { reason: 'x'.repeat(5000) });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
    // 3 非法值不留半个写入：状态与处理结果都保持原样
    const after = await reload(id);
    expect(after.status).toBe(before.status);
    expect(after.handleResult).toBe(before.handleResult);
  });

  test('4 误报：1000 放行 / 1001 拒绝（与 schema 上限同值的双向边界）', async () => {
    const okId = await newAlarm();
    expect((await put(okId, 'false-alarm', { reason: 'y'.repeat(1000) })).status).toBe(200);
    expect((await reload(okId)).handleResult).toHaveLength(1000);

    const overId = await newAlarm();
    const res = await put(overId, 'false-alarm', { reason: 'y'.repeat(1001) });
    expect(res.status).toBe(400);
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
    expect((await reload(overId)).status).toBe('pending');
  });

  test('5 取消：超长 reason 同样被拒（processLog.remark 在 schema 里连上限都没有）', async () => {
    const okId = await newAlarm();
    const okRes = await put(okId, 'cancel', { reason: 'z'.repeat(1000) });
    expect(okRes.status).toBe(200);
    const okDoc = await reload(okId);
    expect(okDoc.processLog.at(-1).remark).toHaveLength(1000);

    const overId = await newAlarm();
    const before = await reload(overId);
    const res = await put(overId, 'cancel', { reason: 'z'.repeat(5000) });
    expect(res.status).toBe(400);
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
    const after = await reload(overId);
    expect(after.status).toBe(before.status);
    expect(after.processLog).toHaveLength(before.processLog.length);
  });

  test('6 服务层直连（绕过路由）也不得把超长值写进 update 路径', async () => {
    const alarmService = require('../../services/AlarmService');
    const id = await newAlarm();
    await expect(
      alarmService.markAsFalseAlarm(String(id), 'w'.repeat(5000), operatorId)
    ).rejects.toThrow();
    const doc = await reload(id);
    expect(doc.status).toBe('pending');
    expect(doc.handleResult ?? '').not.toHaveLength(5000);
  });

  test('7 缺省/空串 reason 仍走服务层默认文案（新规则只许管长度）', async () => {
    const omitted = await newAlarm();
    expect((await put(omitted, 'false-alarm', {})).status).toBe(200);
    expect((await reload(omitted)).handleResult).toBe('确认为误报');

    const blank = await newAlarm();
    expect((await put(blank, 'cancel', { reason: '' })).status).toBe(200);
    expect((await reload(blank)).processLog.at(-1).remark).toBe('取消报警');
  });

  test('8 非字符串 reason 明确拒绝，不得被 Cast 成 [object Object] 落库', async () => {
    for (const bad of [{ nested: 'x' }, 12345, ['x']]) {
      const id = await newAlarm();
      const res = await put(id, 'false-alarm', { reason: bad });
      expect(res.status).toBe(400);
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
      const doc = await reload(id);
      expect(doc.status).toBe('pending');
      expect(doc.handleResult ?? '').not.toMatch(/\[object /);
    }
  });
});
