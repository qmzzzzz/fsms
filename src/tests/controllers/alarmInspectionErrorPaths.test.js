/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：alarmController / inspectionController 的错误与边界分支
 * 守护的不变式：不存在记录 404、数据范围外 403（含正向对照）、非法状态迁移 409、路由校验 400 必须按契约落点
 * 可证伪性：2026-09-20 变异基线（N=8）：alarmController 杀 5/12、inspectionController 杀 4/12。
 *   2026-10-21 强化后定向复核（断言改为精确 状态码+errorCode+字段路径+落库状态，含正向对照）：
 *   删除 cancelAlarm 的 canOperateAlarm 守卫、删除 updateInspection 的 isInspectionInScope 守卫，
 *   对应用例均转红（200 而非 403），不再出现“越权也返回成功却全绿”
 *
 * 命名沿革：2026-09-20 由 `alarmInspectionEdge.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * alarmController / inspectionController 错误与边界分支补齐
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

describe('报警/巡检控制器错误与边界分支', () => {
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
      { expiresIn: '24h' }
    );

    // ===== self 范围用户（level 4 + 具名权限）：制造 403 与正向对照 =====
    // 写端点的权限必须真的授予：否则请求先被 checkPermission 拦成 PERMISSION_DENIED，
    // 控制器的数据范围闸根本跑不到——那会把「范围闸没设防」测成「权限层挡住了」。
    const permCodes = [
      'alarm:read',
      'alarm:create',
      'alarm:dispatch',
      'alarm:handle',
      'inspection:read',
      'inspection:create',
      'inspection:execute',
      'inspection:review',
      'inspection:delete',
    ];
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
      { expiresIn: '24h' }
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

  const errorCodeOf = (res) =>
    res.body && res.body.errors && res.body.errors.errorCode ? res.body.errors.errorCode : null;

  // 只断 404/409 状态码时，把错误码改坏、或删掉某条端点的存在性判断
  //（落到别的 404 出口）都能保持绿色。统一用「状态 + 错误码」成对断言。
  const expectStatusAndCode = (res, status, code) => {
    expect({ status: res.status, code: errorCodeOf(res) }).toEqual({ status, code });
  };

  // 服务层抛出的 ApiError 没有业务错误码，但 message 是专门写给调用方的语义
  //（如「已开始的巡检计划不能修改」）。只断状态码会让文案被压成通用错误仍全绿。
  const expectStatusAndMessage = (res, status, message) => {
    expect({ status: res.status, message: res.body && res.body.message }).toEqual({
      status,
      message,
    });
  };

  // ==================== 报警：404 / 400 ====================

  test('报警：不存在的 ObjectId 在全部端点返回 404 且错误码一致', async () => {
    const id = ghostId();
    expectStatusAndCode(await admin().get(`/api/alarms/${id}`), 404, 'ALARM_NOT_FOUND');
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId }),
      404,
      'ALARM_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/arrive`).send({}),
      404,
      'ALARM_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/resolve`).send({ handleResult: 'x' }),
      404,
      'ALARM_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/false-alarm`).send({}),
      404,
      'ALARM_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/cancel`).send({}),
      404,
      'ALARM_NOT_FOUND'
    );
  });

  test('报警：非法 :id 格式被路由校验拒绝（400）', async () => {
    expect((await admin().get('/api/alarms/not-an-objectid')).status).toBe(400);
    // 两个端点都必须被同一道 :id 形状校验拒绝（点名错误码，排除「被别的 400 挡下」）
    expect((await admin().get('/api/alarms/not-an-objectid')).body.errors.errorCode).toBe(
      'PARAM_MUST_BE_VALID_OBJECT_ID'
    );
    expect((await admin().put('/api/alarms/not-an-objectid/arrive').send({})).status).toBe(400);
  });

  test('报警：路由校验 400 分支（错误枚举/格式）', async () => {
    // reportAlarm：alarmType 非法
    const report = await admin()
      .post('/api/alarms/report')
      .send({ alarmType: 'bogus', description: `x_${stamp}` });
    expect(report.status).toBe(400);
    // 三个 400 分别落在自己的字段上，证明是各自的路由校验器拦下的
    expect(report.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(report.body.errors.fieldErrors[0].path).toBe('alarmType');
    // dispatch：handlerId 非 ObjectId
    const rep = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `校验载体_${stamp}`,
        level: 'info',
        location: { building: 'A栋' },
      });
    const alarmId = String(rep.body.data._id || rep.body.data.id);
    const dispatch = await admin()
      .put(`/api/alarms/${alarmId}/dispatch`)
      .send({ handlerId: 'not-an-id' });
    expect(dispatch.status).toBe(400);
    expect(dispatch.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(dispatch.body.errors.fieldErrors[0].path).toBe('handlerId');
    // resolve：cause 非法枚举
    const resolve = await admin()
      .put(`/api/alarms/${alarmId}/resolve`)
      .send({ handleResult: 'ok', cause: 'bogus' });
    expectStatusAndCode(resolve, 400, 'VALIDATION_FAILED');
    expect(resolve.body.errors.fieldErrors[0].path).toBe('cause');
    // 列表：status 非法枚举（路由层）
    const list = await admin().get('/api/alarms?status=bogus');
    expectStatusAndCode(list, 400, 'VALIDATION_FAILED');
    expect(list.body.errors.fieldErrors[0].path).toBe('status');
    // 收尾
    await admin().put(`/api/alarms/${alarmId}/cancel`).send({ reason: stamp });
  });

  test('报警：统计接口非法日期返回 400（控制器防御分支）', async () => {
    expect((await admin().get('/api/alarms/stats?startDate=not-a-date')).status).toBe(400);
    // 「控制器防御分支」的判据是点名 DATE_PARAM_INVALID（路由未挂该校验，只能由控制器产出）
    expect(
      (await admin().get('/api/alarms/stats?startDate=not-a-date')).body.errors.errorCode
    ).toBe('DATE_PARAM_INVALID');
    expect((await admin().get('/api/alarms/stats?endDate=not-a-date')).status).toBe(400);
    // startDate 与 endDate 是两个独立条件：任一侧漏判都会让本行转红
    expect((await admin().get('/api/alarms/stats?endDate=not-a-date')).body.errors.errorCode).toBe(
      'DATE_PARAM_INVALID'
    );
    // F-157：'123' 是 helpers.isValidDateParam 判例点名的形态——裸 isNaN(new Date(x)) 放行它，
    // 经 parseDateBoundary 变成 0122-12-31 的窗口 ⇒ 200 + 一个静默窄到看不见的结果集。
    // 控制器改接单一判据后必须 400。
    for (const q of ['startDate=123', 'endDate=123', 'endDate=2026']) {
      const bad = await admin().get(`/api/alarms/stats?${q}`);
      expect(bad.status).toBe(400);
      expect(bad.body.errors.errorCode).toBe('DATE_PARAM_INVALID');
    }
    // 反向对照（闸门不得过严）：合法区间照常 200
    expect(
      (await admin().get('/api/alarms/stats?startDate=2026-01-01&endDate=2026-01-31')).status
    ).toBe(200);
  });

  // ==================== 报警：409 状态迁移冲突 ====================

  test('报警：非法状态迁移一律 409（pending 到场/结单；结单后指派/误报/取消）', async () => {
    const rep = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `状态机_${stamp}`,
        level: 'info',
        location: { building: 'A栋' },
      });
    expect(rep.status).toBe(201);
    const id = String(rep.body.data._id || rep.body.data.id);

    // pending 状态：到场/结单都不允许（需先指派）
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/arrive`).send({}),
      409,
      'ALARM_STATUS_NOT_ALLOWED_SHORT'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/resolve`).send({ handleResult: 'x' }),
      409,
      'ALARM_STATUS_NOT_ALLOWED'
    );

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
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId }),
      409,
      'ALARM_ALREADY_HANDLED'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/false-alarm`).send({ reason: 'x' }),
      409,
      'ALARM_STATUS_NOT_ALLOWED'
    );
    expectStatusAndCode(
      await admin().put(`/api/alarms/${id}/cancel`).send({ reason: 'x' }),
      409,
      'ALARM_STATUS_NOT_ALLOWED'
    );
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
    expectStatusAndCode(
      await admin().put(`/api/alarms/${others._id}/cancel`).send({ reason: '越权取消' }),
      409,
      'ALARM_STATUS_NOT_ALLOWED'
    );
    // 拒绝后不得写库：脏状态记录仍是 pending、handler 仍指向原处理人
    const untouched = await FireAlarm.findById(others._id).lean();
    expect(untouched.status).toBe('pending');
    expect(String(untouched.handler)).toBe(scopedUserId);

    // 处理人本人取消 → 200
    expect(
      (await admin().put(`/api/alarms/${mine._id}/cancel`).send({ reason: '本人取消' })).status
    ).toBe(200);
    // 正向对照必须真的落库，而不是"响应 200、状态没变"
    const cancelled = await FireAlarm.findById(mine._id).lean();
    expect(cancelled.status).toBe('cancelled');
  });

  test('报警：误报标记走通并落库（正向对照，防止“一律拒绝”也算绿）', async () => {
    const rep = await admin()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `误报正向_${stamp}`,
        level: 'info',
        location: { building: 'A栋' },
      });
    expect(rep.status).toBe(201);
    const id = String(rep.body.data._id || rep.body.data.id);

    expect(
      (await admin().put(`/api/alarms/${id}/dispatch`).send({ handlerId: adminId })).status
    ).toBe(200);
    expect((await admin().put(`/api/alarms/${id}/arrive`).send({})).status).toBe(200);

    const reason = `误报说明_${stamp}`;
    expect((await admin().put(`/api/alarms/${id}/false-alarm`).send({ reason })).status).toBe(200);
    const stored = await FireAlarm.findById(id).lean();
    expect({ status: stored.status, handleResult: stored.handleResult }).toEqual({
      status: 'false_alarm',
      handleResult: reason,
    });
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
        location: { building: 'A栋' },
      });
    expect(foreign.status).toBe(201);
    const foreignId = String(foreign.body.data._id || foreign.body.data.id);
    expectStatusAndCode(
      await scoped().get(`/api/alarms/${foreignId}`),
      403,
      'ALARM_VIEW_FORBIDDEN'
    );
    // 写端点必须由控制器自己的数据范围/归属闸拦下（权限已在角色里授予，
    // 若这里的 code 变成 PERMISSION_DENIED，说明拦点根本不是范围闸）。
    for (const [label, send] of [
      [
        'dispatch',
        () => scoped().put(`/api/alarms/${foreignId}/dispatch`).send({ handlerId: adminId }),
      ],
      ['arrive', () => scoped().put(`/api/alarms/${foreignId}/arrive`).send({})],
      [
        'resolve',
        () => scoped().put(`/api/alarms/${foreignId}/resolve`).send({ handleResult: 'x' }),
      ],
      [
        'false-alarm',
        () => scoped().put(`/api/alarms/${foreignId}/false-alarm`).send({ reason: 'x' }),
      ],
      ['cancel', () => scoped().put(`/api/alarms/${foreignId}/cancel`).send({ reason: 'x' })],
    ]) {
      const res = await send();
      expect({ label, status: res.status, code: errorCodeOf(res) }).toEqual({
        label,
        status: 403,
        code: 'ALARM_OPERATE_FORBIDDEN',
      });
    }
    // 全部被拒后记录必须原样：未指派、未终结
    const foreignAfter = await FireAlarm.findById(foreignId).lean();
    expect(foreignAfter.status).toBe('pending');
    expect(foreignAfter.handler == null).toBe(true);

    // 自己的记录（正向对照：范围校验不得过严）
    const own = await scoped()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `本人报警_${stamp}`,
        level: 'info',
        location: { building: 'A栋' },
      });
    expect(own.status).toBe(201);
    const ownId = String(own.body.data._id || own.body.data.id);
    const ownDetail = await scoped().get(`/api/alarms/${ownId}`);
    expect(ownDetail.status).toBe(200);
  });

  // ==================== 巡检：404 / 400 ====================

  test('巡检：不存在的 ObjectId 在全部端点返回 404 且错误码一致', async () => {
    const id = ghostId();
    expectStatusAndCode(await admin().get(`/api/inspections/${id}`), 404, 'INSPECTION_NOT_FOUND');
    expectStatusAndCode(
      await admin().put(`/api/inspections/${id}`).send({ description: 'x' }),
      404,
      'INSPECTION_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/inspections/${id}/start`).send({}),
      404,
      'INSPECTION_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' }),
      404,
      'INSPECTION_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/inspections/${id}/review`).send({ reviewResult: 'approved' }),
      404,
      'INSPECTION_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().put(`/api/inspections/${id}/cancel`).send({ reason: 'x' }),
      404,
      'INSPECTION_NOT_FOUND'
    );
    expectStatusAndCode(
      await admin().delete(`/api/inspections/${id}`),
      404,
      'INSPECTION_NOT_FOUND'
    );
  });

  test('巡检：非法 :id 格式与错误枚举被路由校验拒绝（400）', async () => {
    expectStatusAndCode(
      await admin().get('/api/inspections/not-an-objectid'),
      400,
      'PARAM_MUST_BE_VALID_OBJECT_ID'
    );
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
    const badUpdate = await admin().put(`/api/inspections/${id}`).send({ inspectionType: 'bogus' });
    expectStatusAndCode(badUpdate, 400, 'VALIDATION_FAILED');
    expect(badUpdate.body.errors.fieldErrors[0].path).toBe('inspectionType');
    // complete：result 非法枚举
    const badComplete = await admin()
      .put(`/api/inspections/${id}/complete`)
      .send({ result: 'bogus' });
    expectStatusAndCode(badComplete, 400, 'VALIDATION_FAILED');
    expect(badComplete.body.errors.fieldErrors[0].path).toBe('result');
    // review：reviewResult 非法枚举（控制器消费的是 reviewResult，不是 result）
    const badReview = await admin()
      .put(`/api/inspections/${id}/review`)
      .send({ reviewResult: 'bogus' });
    expectStatusAndCode(badReview, 400, 'VALIDATION_FAILED');
    expect(badReview.body.errors.fieldErrors[0].path).toBe('reviewResult');
    await admin().delete(`/api/inspections/${id}`);
  });

  test('巡检：统计接口非法日期返回 400（控制器防御分支）', async () => {
    expect((await admin().get('/api/inspections/stats?startDate=not-a-date')).status).toBe(400);
    expect(
      (await admin().get('/api/inspections/stats?startDate=not-a-date')).body.errors.errorCode
    ).toBe('DATE_PARAM_INVALID');
    expect((await admin().get('/api/inspections/stats?endDate=not-a-date')).status).toBe(400);
    expect(
      (await admin().get('/api/inspections/stats?endDate=not-a-date')).body.errors.errorCode
    ).toBe('DATE_PARAM_INVALID');
    // F-157 同一缺陷的第二处（列表与统计各有一份裸判据，两条路由都没挂日期校验链）
    for (const q of ['startDate=123', 'endDate=123', 'endDate=2026']) {
      const bad = await admin().get(`/api/inspections/stats?${q}`);
      expect(bad.status).toBe(400);
      expect(bad.body.errors.errorCode).toBe('DATE_PARAM_INVALID');
    }
    expect(
      (await admin().get('/api/inspections/stats?startDate=2026-01-01&endDate=2026-01-31')).status
    ).toBe(200);
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
    // 更新：服务层抛 badRequest → errorHandler 透出专门文案（F-173 后不再压成“操作失败”）
    expectStatusAndMessage(
      await admin().put(`/api/inspections/${id}`).send({ description: 'x' }),
      400,
      '已开始的巡检计划不能修改'
    );
    // 重复开始：服务层抛 conflict → 409
    expectStatusAndMessage(
      await admin().put(`/api/inspections/${id}/start`).send({}),
      409,
      '巡检当前状态不允许执行或您不是被指派人'
    );
    // in_progress 不允许删除（服务层 badRequest → 400）
    expectStatusAndMessage(
      await admin().delete(`/api/inspections/${id}`),
      400,
      '正在执行的巡检不能删除'
    );
    // 收尾：先完成再取消不可行（已完成不能取消），直接置回删除路径
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' })).status
    ).toBe(200);
    const completed = await Inspection.findById(id).lean();
    expect({ status: completed.status, result: completed.result }).toEqual({
      status: 'completed',
      result: 'normal',
    });
  });

  test('巡检：pending 直接提交 → 409；已完成再取消/再审 → 409', async () => {
    const id = await createInspection('状态冲突');
    // 未开始不能提交
    expectStatusAndMessage(
      await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' }),
      409,
      '巡检未开始、已完成或您不是被指派人'
    );
    // 走通 start → complete
    expect((await admin().put(`/api/inspections/${id}/start`).send({})).status).toBe(200);
    expect(
      (await admin().put(`/api/inspections/${id}/complete`).send({ result: 'normal' })).status
    ).toBe(200);
    // 已完成：取消冲突
    expectStatusAndMessage(
      await admin().put(`/api/inspections/${id}/cancel`).send({ reason: 'x' }),
      409,
      '已完成或已取消的巡检不能重复操作'
    );
    // 审核：reviewResult 缺省的语义由服务层拒绝（路由只校验存在时的枚举）→ 400
    expectStatusAndMessage(
      await admin().put(`/api/inspections/${id}/review`).send({}),
      400,
      '审核结论必须为 approved（通过）或 rejected（不通过）'
    );
    // 正常审核通过后重复审核冲突
    expect(
      (
        await admin()
          .put(`/api/inspections/${id}/review`)
          .send({ result: 'approved', reviewResult: 'approved' })
      ).status
    ).toBe(200);
    const reviewed = await Inspection.findById(id).lean();
    expect(reviewed.reviewResult).toBe('approved');
    expectStatusAndMessage(
      await admin()
        .put(`/api/inspections/${id}/review`)
        .send({ result: 'approved', reviewResult: 'approved' }),
      409,
      '只能审核已完成且未审核的巡检，且被指派人不能自审'
    );
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
    expectStatusAndCode(
      await scoped().get(`/api/inspections/${foreignId}`),
      403,
      'INSPECTION_VIEW_FORBIDDEN'
    );
    // 写端点：角色已授予对应权限，因此必须由控制器的 INSPECTION_OPERATE_FORBIDDEN
    // 拦下。若这里变成 PERMISSION_DENIED，说明权限层先挡了，范围闸根本没被测到。
    for (const [label, send] of [
      ['update', () => scoped().put(`/api/inspections/${foreignId}`).send({ description: 'x' })],
      ['start', () => scoped().put(`/api/inspections/${foreignId}/start`).send({})],
      [
        'complete',
        () => scoped().put(`/api/inspections/${foreignId}/complete`).send({ result: 'normal' }),
      ],
      [
        'review',
        () =>
          scoped().put(`/api/inspections/${foreignId}/review`).send({ reviewResult: 'approved' }),
      ],
      ['cancel', () => scoped().put(`/api/inspections/${foreignId}/cancel`).send({ reason: 'x' })],
      ['delete', () => scoped().delete(`/api/inspections/${foreignId}`)],
    ]) {
      const res = await send();
      expect({ label, status: res.status, code: errorCodeOf(res) }).toEqual({
        label,
        status: 403,
        code: 'INSPECTION_OPERATE_FORBIDDEN',
      });
    }
    // 全部被拒后计划必须原样：仍 pending、执行人未被改动
    const foreignAfter = await Inspection.findById(foreignId).lean();
    expect(foreignAfter.status).toBe('pending');
    expect(foreignAfter.assignedTo.map(String)).toEqual([adminId]);

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

  test('巡检：更新/取消/删除在合法状态走通并落库（正向对照）', async () => {
    const updateId = await createInspection('正向更新');
    const description = `更新描述_${stamp}`;
    expect((await admin().put(`/api/inspections/${updateId}`).send({ description })).status).toBe(
      200
    );
    expect((await Inspection.findById(updateId).lean()).description).toBe(description);

    const cancelId = await createInspection('正向取消');
    const reason = `取消原因_${stamp}`;
    expect((await admin().put(`/api/inspections/${cancelId}/cancel`).send({ reason })).status).toBe(
      200
    );
    expect((await Inspection.findById(cancelId).lean()).status).toBe('cancelled');

    const deleteId = await createInspection('正向删除');
    expect((await admin().delete(`/api/inspections/${deleteId}`)).status).toBe(200);
    expect(await Inspection.findById(deleteId).lean()).toBeNull();
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
    // 直调控制器：状态码 400 必须来自 DATE_PARAM_INVALID 这条防御分支
    expect(badStart.body.errors.errorCode).toBe('DATE_PARAM_INVALID');

    const badEnd = await invoke(inspectionController.getInspections, {
      query: { endDate: 'not-a-date' },
      user: { userId: adminId },
    });
    expect(badEnd.statusCode).toBe(400);
    expect(badEnd.body.errors.errorCode).toBe('DATE_PARAM_INVALID');

    // F-157：列表侧的裸判据与统计侧同病——'123' / '2026' 曾一律放行（静默翻译成公元 0122 年窗口）
    // 错误码前缀带上处理器名：两条循环共用同一行断言，红了也要能看出是哪一侧漏判
    for (const [handler, name] of [
      [alarmController.getAlarms, '报警列表'],
      [inspectionController.getInspections, '巡检列表'],
    ]) {
      for (const q of [{ startDate: '123' }, { endDate: '2026' }]) {
        const out = await invoke(handler, { query: q, user: { userId: adminId } });
        expect(out.statusCode).toBe(400);
        expect(`${name}:${out.body.errors.errorCode}`).toBe(`${name}:DATE_PARAM_INVALID`);
      }
      // 反向对照：合法日期要放行到下一道（数据范围/分页），不能被判据误拦
      const ok = await invoke(handler, {
        query: { startDate: '2026-01-01', endDate: '2026-01-31', page: 1, limit: 10 },
        user: { userId: adminId },
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.body.success).toBe(true);
    }
  });

  test('resolveAlarm：缺 handleResult 时控制器直接 400（路由已强制，此为防御分支）', async () => {
    const alarmController = require('../../controllers/alarmController');

    const out = await invoke(alarmController.resolveAlarm, {
      params: { id: ghostId() },
      body: {},
      user: { userId: adminId },
    });
    expect(out.statusCode).toBe(400);
    // 「控制器直接 400」必须点名 ALARM_HANDLE_RESULT_REQUIRED：
    // 否则「缺 handleResult」与「报警不存在」等其它 400 无法区分
    expect(out.body.errors.errorCode).toBe('ALARM_HANDLE_RESULT_REQUIRED');
  });
});
