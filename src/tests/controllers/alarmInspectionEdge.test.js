/**
 * T-3：alarmController / inspectionController 错误与边界分支补齐
 *
 * businessFlow.test.js 走通了两大业务的 happy path，但控制器的
 * 错误/边界分支覆盖偏低（inspection 39.7% / alarm 43.4%）。本套件补：
 *  1. 不存在记录的 404 分支（全部读/写端点）
 *  2. 数据范围外记录的 403 分支（self 范围用户访问他人记录，含正向对照）
 *  3. 非法状态迁移的 409 分支（服务层条件更新未命中 → 冲突）
 *  4. 路由校验 400 分支（validationResult 非空路径）
 *  5. 路由层拦不到的防御性分支（列表/统计的非法日期、resolve 缺 handleResult）
 *     ——经 HTTP 不可达，直接调用导出的 handler 覆盖
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('T-3 报警/巡检控制器错误与边界分支', () => {
  let app;
  let FireAlarm;
  let Inspection;
  let adminToken;
  let scopedToken;
  let adminId;
  let scopedUserId;
  let User;
  let Role;
  let Permission;
  const stamp = `ei${Date.now()}`.replace(/\d/g, (d) => 'klmnopqrst'[Number(d)]);
  const ghostId = () => String(new mongoose.Types.ObjectId());
  const createdPermIds = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    require('../../models/TokenBlacklist');

    // ===== 超管（*:*，数据范围 all）：制造「他人记录」 =====
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: `超管_边界_${stamp}`,
      code: `SUPER_EDGE_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `edgeadmin${stamp}`,
      email: `edgeadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminId = String(admin._id);
    adminToken = jwt.sign(
      { userId: adminId, username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // ===== self 范围用户（level 4 + 具名权限）：制造 403 与正向对照 =====
    const permCodes = ['alarm:read', 'alarm:create', 'inspection:read', 'inspection:create'];
    const permIds = [];
    for (const code of permCodes) {
      const existed = await Permission.findOne({ code });
      if (existed) {
        permIds.push(existed._id);
      } else {
        const [module] = code.split(':');
        const created = await Permission.create({ name: code, code, type: 'api', module });
        permIds.push(created._id);
        createdPermIds.push(created._id);
      }
    }
    const scopedRole = await Role.create({
      name: `消防员_边界_${stamp}`,
      code: `SCOPED_EDGE_${stamp}`,
      level: 4,
      isBuiltIn: false,
      permissions: permIds,
    });
    const scopedUser = await User.create({
      username: `edgefire${stamp}`,
      email: `edgefire${stamp}@example.com`,
      password: randomPassword(),
      roles: [scopedRole._id],
    });
    scopedUserId = String(scopedUser._id);
    scopedToken = jwt.sign(
      { userId: scopedUserId, username: scopedUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      await User.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(stamp) }).catch(() => {});
      if (createdPermIds.length) {
        await Permission.deleteMany({ _id: { $in: createdPermIds } }).catch(() => {});
      }
      await mongoose.connection.close();
    }
  });

  const as = (token) => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${token}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${token}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${token}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${token}`),
  });
  const admin = () => as(adminToken);
  const scoped = () => as(scopedToken);

  // 直接调用导出的 handler（绕过路由），覆盖路由层拦不到的控制器防御分支
  const invoke = (handler, req) =>
    new Promise((resolve, reject) => {
      const res = {
        statusCode: null,
        body: null,
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(payload) {
          this.body = payload;
          resolve(this);
          return this;
        },
      };
      handler(req, res, reject);
    });

  // ==================== 报警：404 / 400 ====================

  test('报警：不存在的 ObjectId 在全部端点返回 404', async () => {
    const id = ghostId();
    expect((await admin().get(`/api/alarms/${id}`)).status).toBe(404);
    expect(
      (await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId })).status
    ).toBe(404);
    expect((await admin().put(`/api/alarms/${id}/arrive`).send({})).status).toBe(404);
    expect(
      (await admin().put(`/api/alarms/${id}/resolve`).send({ handleResult: 'x' })).status
    ).toBe(404);
    expect((await admin().put(`/api/alarms/${id}/false-alarm`).send({})).status).toBe(404);
    expect((await admin().put(`/api/alarms/${id}/cancel`).send({})).status).toBe(404);
  });

  test('报警：非法 :id 格式被路由校验拒绝（400）', async () => {
    expect((await admin().get('/api/alarms/not-an-objectid')).status).toBe(400);
    expect((await admin().put('/api/alarms/not-an-objectid/arrive').send({})).status).toBe(400);
  });

  test('报警：路由校验 400 分支（错误枚举/格式）', async () => {
    // reportAlarm：alarmType 非法
    const report = await admin()
      .post('/api/alarms/report')
      .send({ alarmType: 'bogus', description: `x_${stamp}` });
    expect(report.status).toBe(400);
    // dispatch：handlerId 非 ObjectId
    const rep = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `校验载体_${stamp}`,
        level: 'info',
      });
    const alarmId = String(rep.body.data._id || rep.body.data.id);
    const dispatch = await admin()
      .put(`/api/alarms/${alarmId}/dispatch`)
      .send({ handlerId: 'not-an-id' });
    expect(dispatch.status).toBe(400);
    // resolve：cause 非法枚举
    const resolve = await admin()
      .put(`/api/alarms/${alarmId}/resolve`)
      .send({ handleResult: 'ok', cause: 'bogus' });
    expect(resolve.status).toBe(400);
    // 列表：status 非法枚举（路由层）
    const list = await admin().get('/api/alarms?status=bogus');
    expect(list.status).toBe(400);
    // 收尾
    await admin().put(`/api/alarms/${alarmId}/cancel`).send({ reason: stamp });
  });

  test('报警：统计接口非法日期返回 400（控制器防御分支）', async () => {
    expect((await admin().get('/api/alarms/stats?startDate=not-a-date')).status).toBe(400);
    expect((await admin().get('/api/alarms/stats?endDate=not-a-date')).status).toBe(400);
  });

  // ==================== 报警：409 状态迁移冲突 ====================

  test('报警：非法状态迁移一律 409（pending 到场/结单；结单后指派/误报/取消）', async () => {
    const rep = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `状态机_${stamp}`,
        level: 'info',
      });
    expect(rep.status).toBe(201);
    const id = String(rep.body.data._id || rep.body.data.id);

    // pending 状态：到场/结单都不允许（M-1 需先指派）
    expect((await admin().put(`/api/alarms/${id}/arrive`).send({})).status).toBe(409);
    expect(
      (await admin().put(`/api/alarms/${id}/resolve`).send({ handleResult: 'x' })).status
    ).toBe(409);

    // 走通 pending → processing → resolved
    expect(
      (await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId })).status
    ).toBe(200);
    expect((await admin().put(`/api/alarms/${id}/arrive`).send({})).status).toBe(200);
    expect(
      (
        await admin()
          .put(`/api/alarms/${id}/resolve`)
          .send({ handleResult: `已处置_${stamp}` })
      ).status
    ).toBe(200);

    // resolved 之后：指派/误报/取消全部冲突
    expect(
      (await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId })).status
    ).toBe(409);
    expect((await admin().put(`/api/alarms/${id}/false-alarm`).send({ reason: 'x' })).status).toBe(
      409
    );
    expect((await admin().put(`/api/alarms/${id}/cancel`).send({ reason: 'x' })).status).toBe(409);
  });

  test('#11 对象级授权：pending+已指派（脏状态/并发窗口）仅处理人本人可取消', async () => {
    // 正常状态机里 handler 与 processing 原子落库，pending 必然未指派；
    // 归属护栏防的是「库内已有 handler 但状态仍 pending」的脏数据/并发窗口
    //（与权限树 32 层环用例同款模型层直造手法）。
    const others = await FireAlarm.create({
      alarmType: 'other',
      description: `取消归属_他人_${stamp}`,
      level: 'info',
      status: 'pending',
      handler: scopedUserId, // 处理人是 scopedUser
    });
    const mine = await FireAlarm.create({
      alarmType: 'other',
      description: `取消归属_本人_${stamp}`,
      level: 'info',
      status: 'pending',
      handler: adminId, // 处理人是操作者本人
    });

    // 非处理人（admin 持 *:* 通过权限层，但对象级归属不匹配）→ 409
    expect(
      (await admin().put(`/api/alarms/${others._id}/cancel`).send({ reason: '越权取消' })).status
    ).toBe(409);

    // 处理人本人取消 → 200
    expect(
      (await admin().put(`/api/alarms/${mine._id}/cancel`).send({ reason: '本人取消' })).status
    ).toBe(200);
  });

  // ==================== 报警：数据范围 403 ====================

  test('报警：self 范围用户看他人记录 403，看自己记录 200', async () => {
    // 他人的记录（超管上报，reporter.userId=超管）
    const foreign = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `他人报警_${stamp}`,
        level: 'info',
      });
    expect(foreign.status).toBe(201);
    const foreignId = String(foreign.body.data._id || foreign.body.data.id);
    expect((await scoped().get(`/api/alarms/${foreignId}`)).status).toBe(403);

    // 自己的记录（正向对照：范围校验不得过严）
    const own = await scoped()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `本人报警_${stamp}`,
        level: 'info',
      });
    expect(own.status).toBe(201);
    const ownId = String(own.body.data._id || own.body.data.id);
    const ownDetail = await scoped().get(`/api/alarms/${ownId}`);
    expect(ownDetail.status).toBe(200);
  });

  // ==================== 巡检：404 / 400 ====================

  test('巡检：不存在的 ObjectId 在全部端点返回 404', async () => {
    const id = ghostId();
    expect((await admin().get(`/api/inspections/${id}`)).status).toBe(404);
    expect((await admin().put(`/api/inspections/${id}`).send({ description: 'x' })).status).toBe(
      404
    );
    expect((await admin().put(`/api/inspections/${id}/start`).send({})).status).toBe(404);
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' })).status
    ).toBe(404);
    expect(
      (await admin().put(`/api/inspections/${id}/review`).send({ reviewResult: 'approved' })).status
    ).toBe(404);
    expect((await admin().put(`/api/inspections/${id}/cancel`).send({ reason: 'x' })).status).toBe(
      404
    );
    expect((await admin().delete(`/api/inspections/${id}`)).status).toBe(404);
  });

  test('巡检：非法 :id 格式与错误枚举被路由校验拒绝（400）', async () => {
    expect((await admin().get('/api/inspections/not-an-objectid')).status).toBe(400);
    // update：inspectionType 非法枚举
    const create = await admin()
      .post('/api/inspections')
      .send({
        title: `校验载体_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: 'x' }],
      });
    expect(create.status).toBe(201);
    const id = String(create.body.data._id || create.body.data.id);
    expect(
      (await admin().put(`/api/inspections/${id}`).send({ inspectionType: 'bogus' })).status
    ).toBe(400);
    // complete：result 非法枚举
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'bogus' })).status
    ).toBe(400);
    // review：result 非法枚举
    expect(
      (await admin().put(`/api/inspections/${id}/review`).send({ result: 'bogus' })).status
    ).toBe(400);
    await admin().delete(`/api/inspections/${id}`);
  });

  test('巡检：统计接口非法日期返回 400（控制器防御分支）', async () => {
    expect((await admin().get('/api/inspections/stats?startDate=not-a-date')).status).toBe(400);
    expect((await admin().get('/api/inspections/stats?endDate=not-a-date')).status).toBe(400);
  });

  // ==================== 巡检：服务层抛错的 catch 分支 ====================

  const createInspection = async (title) => {
    const res = await admin()
      .post('/api/inspections')
      .send({
        title: `${title}_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: 'x' }],
      });
    expect(res.status).toBe(201);
    return String(res.body.data._id || res.body.data.id);
  };

  test('巡检：已开始不可更新（400）、重复开始冲突（409）', async () => {
    const id = await createInspection('更新拒绝');
    expect((await admin().put(`/api/inspections/${id}/start`).send({})).status).toBe(200);
    // 更新：服务层抛 badRequest → 控制器 catch → err.statusCode=400
    expect((await admin().put(`/api/inspections/${id}`).send({ description: 'x' })).status).toBe(
      400
    );
    // 重复开始：服务层抛 conflict → 控制器 catch → 409
    expect((await admin().put(`/api/inspections/${id}/start`).send({})).status).toBe(409);
    // in_progress 不允许删除（服务层 badRequest → 400）
    expect((await admin().delete(`/api/inspections/${id}`)).status).toBe(400);
    // 收尾：先完成再取消不可行（已完成不能取消），直接置回删除路径
    await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' });
  });

  test('巡检：pending 直接提交 → 409；已完成再取消/再审 → 409', async () => {
    const id = await createInspection('状态冲突');
    // 未开始不能提交
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' })).status
    ).toBe(409);
    // 走通 start → complete
    expect((await admin().put(`/api/inspections/${id}/start`).send({})).status).toBe(200);
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' })).status
    ).toBe(200);
    // 已完成：取消冲突
    expect((await admin().put(`/api/inspections/${id}/cancel`).send({ reason: 'x' })).status).toBe(
      409
    );
    // 审核：reviewResult 非法值由服务层拒绝（路由仅校验 result 字段）→ 400
    expect(
      (await admin().put(`/api/inspections/${id}/review`).send({ reviewResult: 'bogus' })).status
    ).toBe(400);
    // 正常审核通过后重复审核冲突
    expect(
      (
        await admin()
          .put(`/api/inspections/${id}/review`)
          .send({ result: 'approved', reviewResult: 'approved' })
      ).status
    ).toBe(200);
    expect(
      (
        await admin()
          .put(`/api/inspections/${id}/review`)
          .send({ result: 'approved', reviewResult: 'approved' })
      ).status
    ).toBe(409);
  });

  // ==================== 巡检：数据范围 403 ====================

  test('巡检：self 范围用户看他人计划 403，看自己参与的 200', async () => {
    // 他人的计划（超管创建、指派给自己）
    const foreign = await admin()
      .post('/api/inspections')
      .send({
        title: `他人巡检_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: 'x' }],
        assignedTo: [adminId],
      });
    expect(foreign.status).toBe(201);
    const foreignId = String(foreign.body.data._id || foreign.body.data.id);
    expect((await scoped().get(`/api/inspections/${foreignId}`)).status).toBe(403);
    expect((await scoped().put(`/api/inspections/${foreignId}/start`).send({})).status).toBe(403);

    // 自己参与的计划（正向对照）
    const own = await admin()
      .post('/api/inspections')
      .send({
        title: `本人巡检_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: 'x' }],
        assignedTo: [scopedUserId],
      });
    expect(own.status).toBe(201);
    const ownId = String(own.body.data._id || own.body.data.id);
    expect((await scoped().get(`/api/inspections/${ownId}`)).status).toBe(200);
  });

  // ==================== 路由层拦不到的控制器防御分支（直接调用） ====================

  test('列表处理器：非法日期在控制器层被拒（路由先行拦截，HTTP 不可达）', async () => {
    const alarmController = require('../../controllers/alarmController');
    const inspectionController = require('../../controllers/inspectionController');

    const badStart = await invoke(alarmController.getAlarms, {
      query: { startDate: 'not-a-date' },
      user: { userId: adminId },
    });
    expect(badStart.statusCode).toBe(400);

    const badEnd = await invoke(inspectionController.getInspections, {
      query: { endDate: 'not-a-date' },
      user: { userId: adminId },
    });
    expect(badEnd.statusCode).toBe(400);
  });

  test('resolveAlarm：缺 handleResult 时控制器直接 400（路由已强制，此为防御分支）', async () => {
    const alarmController = require('../../controllers/alarmController');

    const out = await invoke(alarmController.resolveAlarm, {
      params: { id: ghostId() },
      body: {},
      user: { userId: adminId },
    });
    expect(out.statusCode).toBe(400);
  });
});
