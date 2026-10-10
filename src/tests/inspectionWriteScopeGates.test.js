/**
 * 巡检写路径的对象级范围闸（assignedTo / devices / locations）
 *
 * 修复前路由只判格式（`isMongoId`、字符串长度），三条臂都能越界写：
 * 把计划指派给别的部门的人（而 startInspection 恰按"assignedTo 含操作者"放行）、
 * 引用别人的设备（getInspectionById 会 populate 出设备编码/名称/类型/位置）、
 * 以及把 `locations.building`（就是 inspection 的 departmentField）填成别的楼栋。
 * 更新路径还多一层：此前只判"改前这条在不在范围内"，写进来的新值一律不判。
 *
 * 每条拒绝都有对应的反向对照，防止把闸做成"一律拒绝"。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const DEVICE_TYPE = Object.values(require('../utils/constants').DEVICE_TYPE)[0];

const DEPT_A = 'ZZIS-A';
const DEPT_B = 'ZZIS-B';
const stamp = `zzis${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('巡检计划的三类引用必须落在操作者数据范围内', () => {
  let app;
  let User;
  let Role;
  let Inspection;
  let deptToken; // level 7 ⇒ department 档
  let selfToken; // level 4 ⇒ self 档
  let operator;
  let peerB; // 其他部门的用户
  let devA; // DEPT_A 楼栋里的设备
  let devB; // DEPT_B 楼栋里的设备（别人建档）
  let mateUser; // 同部门用户（可指派反例）
  let selfUser; // self 档操作者

  const mkUser = async (username, roles, department) =>
    User.create({
      username,
      email: `${username}@example.com`,
      password: randomPassword(),
      department,
      roles,
    });

  const sign = (u) =>
    jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../models/User');
    Role = require('../models/Role');
    Inspection = require('../models/Inspection');
    const Permission = require('../models/Permission');
    const FireDevice = require('../models/FireDevice');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    // 权限轴与数据范围轴是两条独立的轴：用 *:* 通过 checkPermission，
    // 数据范围仍由角色 level 决定（7 ⇒ department，4 ⇒ self）
    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const mkRole = (code, level) =>
      Role.create({
        name: `${stamp} ${code}`,
        code: `${stamp}_${code}`,
        level,
        permissions: [wildcard._id],
      });
    const deptRole = await mkRole('DEPT', 7);
    const selfRole = await mkRole('SELF', 4);

    operator = await mkUser(`${stamp}_op`, [deptRole._id], DEPT_A);
    mateUser = await mkUser(`${stamp}_mate`, [deptRole._id], DEPT_A);
    peerB = await mkUser(`${stamp}_peerB`, [deptRole._id], DEPT_B);
    selfUser = await mkUser(`${stamp}_self`, [selfRole._id], DEPT_A);
    deptToken = sign(operator);
    selfToken = sign(selfUser);

    const mkDev = (deviceCode, building, createdBy) =>
      FireDevice.create({
        deviceCode,
        deviceName: `${deviceCode} 灭火器`,
        deviceType: DEVICE_TYPE,
        installDate: new Date('2026-01-01'),
        location: { building },
        createdBy,
      });
    devA = await mkDev(`${stamp.toUpperCase()}-A`, DEPT_A, operator._id);
    devB = await mkDev(`${stamp.toUpperCase()}-B`, DEPT_B, peerB._id);

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await mongoose.connection.collections.firedevices?.deleteMany({
      deviceCode: new RegExp(`^${stamp.toUpperCase()}`),
    });
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await Role.deleteMany({ name: new RegExp(`^${stamp} `) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const base = () => ({
    inspectionType: 'daily',
    planStartTime: '2026-09-20T08:00:00.000Z',
    planEndTime: '2026-09-20T10:00:00.000Z',
    checkItems: [{ name: `${stamp} 检查项` }],
  });

  const create = (token, tag, extra) =>
    request(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${token}`)
      .send({ ...base(), title: `${stamp}-${tag}`, ...extra });

  const countFor = (tag) => Inspection.countDocuments({ title: `${stamp}-${tag}` });

  test('指派给其他部门的用户：403 且不落库', async () => {
    const res = await create(deptToken, 'peer', { assignedTo: [String(peerB._id)] });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('INSPECTION_OPERATE_FORBIDDEN');
    expect(await countFor('peer')).toBe(0);
  });

  test('反向对照：同部门用户可以指派', async () => {
    const res = await create(deptToken, 'mate', { assignedTo: [String(mateUser._id)] });
    expect(res.status).toBe(201);
    expect(await countFor('mate')).toBe(1);
  });

  test('引用其他楼栋的设备：DEVICE_VIEW_FORBIDDEN', async () => {
    const res = await create(deptToken, 'devb', { devices: [String(devB._id)] });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
    expect(await countFor('devb')).toBe(0);
  });

  test('引用不存在的设备：DEVICE_NOT_FOUND（格式合法也不放行）', async () => {
    const res = await create(deptToken, 'ghost', {
      devices: [String(new mongoose.Types.ObjectId())],
    });
    expect(res.status).toBe(404);
    expect(res.body.errors.errorCode).toBe('DEVICE_NOT_FOUND');
    expect(await countFor('ghost')).toBe(0);
  });

  test('反向对照：本楼栋设备可以引用', async () => {
    const res = await create(deptToken, 'deva', { devices: [String(devA._id)] });
    expect(res.status).toBe(201);
  });

  test('楼栋写别的部门：403；写本部门或留空：放行', async () => {
    const bad = await create(deptToken, 'locbad', { locations: [{ building: DEPT_B }] });
    expect(bad.status).toBe(403);
    expect(bad.body.errors.errorCode).toBe('INSPECTION_OPERATE_FORBIDDEN');

    const ok = await create(deptToken, 'locok', { locations: [{ building: DEPT_A }] });
    expect(ok.status).toBe(201);

    const blank = await create(deptToken, 'locblank', { locations: [{ floor: '3F' }] });
    expect(blank.status).toBe(201);
  });

  test('更新路径判的是新值：改前在范围内、把楼栋改到别的部门必须被拒', async () => {
    const created = await create(deptToken, 'upd', { locations: [{ building: DEPT_A }] });
    expect(created.status).toBe(201);
    const id = created.body.data._id || created.body.data.id;

    const res = await request(app)
      .put(`/api/inspections/${id}`)
      .set('Authorization', `Bearer ${deptToken}`)
      .send({ locations: [{ building: DEPT_B }] });
    expect(res.status).toBe(403);
    const after = await Inspection.findById(id).lean();
    expect(after.locations.map((l) => l.building)).toEqual([DEPT_A]);
  });

  test('self 档不被过度收紧：指派自己 + 自己维护的设备（别的楼栋）可创建', async () => {
    const FireDevice = require('../models/FireDevice');
    // createdBy 为空、由本人维护 ⇒ 设备属主臂的数组那一支必须仍然放行；
    // 指派自己则依赖 isRecordInScope 的"自己的记录永远在自己范围内"短路。
    const mine = await FireDevice.create({
      deviceCode: `${stamp.toUpperCase()}-MINE`,
      deviceName: '我自己维护的设备',
      deviceType: DEVICE_TYPE,
      installDate: new Date('2026-01-01'),
      location: { building: DEPT_B },
      createdBy: null,
      maintenanceRecord: [{ operator: selfUser._id }],
    });
    const res = await create(selfToken, 'selfok', {
      assignedTo: [String(selfUser._id)],
      devices: [String(mine._id)],
      locations: [{ building: DEPT_B }],
    });
    expect(res.status).toBe(201);
  });

  // ================= 提交结果（complete）路径 =================
  //
  // complete 此前**完全没调** rejectOutOfScopeReferences —— 三臂只在 create/update 接了线，
  // findings 这条路连守卫都没挂。而 completeInspection 的
  // `findOneAndUpdate(...).populate(INSPECTION_POPULATE)` 会把 `findings[].deviceId` 的
  // `deviceCode/deviceName` 一起回给调用方（InspectionService.js:49 与 :293）⇒ 持
  // `inspection:execute`（通常 self 档）者借**本人范围内**的巡检，就能把范围外设备台账读回来。
  // 这是本仓最高价值的缺陷族："已修的同类漏了一处"。

  /** 造一条 in_progress 的巡检：create（指派给操作者）→ start。两跳都走真实路由。 */
  // 必须带 locations.building：inspection 的 departmentField 就是 `locations.building`
  // （constants/dataScopeFields.js:38），不填楼栋的巡检对 department 档操作者不在范围内，
  // start 会先被 INSPECTION_OPERATE_FORBIDDEN 拦掉——那样本组用例就测不到 complete 这条闸了。
  const mkInProgress = async (token, tag, assigneeId, extra = {}) => {
    const created = await create(token, tag, {
      locations: [{ building: DEPT_A }],
      assignedTo: [String(assigneeId)],
      ...extra,
    });
    expect(created.status).toBe(201);
    const id = created.body.data._id || created.body.data.id;
    const started = await request(app)
      .put(`/api/inspections/${id}/start`)
      .set('Authorization', `Bearer ${token}`);
    expect(started.status).toBe(200);
    return id;
  };

  const complete = (token, id, body) =>
    request(app)
      .put(`/api/inspections/${id}/complete`)
      .set('Authorization', `Bearer ${token}`)
      .send({ result: 'abnormal', ...body });

  test('complete：findings 引用其他楼栋设备 ⇒ 403 且不落库', async () => {
    const id = await mkInProgress(deptToken, 'cmb', operator._id);
    const res = await complete(deptToken, id, {
      findings: [{ deviceId: String(devB._id), issue: `${stamp} 消火栓无水`, severity: 'high' }],
    });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
    // 不落库：状态未变、findings 未写入（拒绝必须是"没发生"，不是"先写后删"）
    const after = await Inspection.findById(id).lean();
    expect(after.status).toBe('in_progress');
    expect(after.findings || []).toHaveLength(0);
    // 响应体里不得出现对方设备的编码——"把台账读回来"正是本闸要堵的后果
    expect(JSON.stringify(res.body)).not.toContain(devB.deviceCode);
  });

  test('complete：findings 引用不存在的设备 ⇒ DEVICE_NOT_FOUND', async () => {
    const id = await mkInProgress(deptToken, 'cmg', operator._id);
    const res = await complete(deptToken, id, {
      findings: [{ deviceId: String(new mongoose.Types.ObjectId()), issue: `${stamp} 悬空` }],
    });
    expect(res.status).toBe(404);
    expect(res.body.errors.errorCode).toBe('DEVICE_NOT_FOUND');
  });

  test('反向对照：findings 引用本楼栋设备 ⇒ 200 且 populate 出 deviceCode', async () => {
    const id = await mkInProgress(deptToken, 'cma', operator._id);
    const res = await complete(deptToken, id, {
      findings: [{ deviceId: String(devA._id), issue: `${stamp} 压力不足`, severity: 'medium' }],
    });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('completed');
    expect(res.body.data.findings[0].deviceId.deviceCode).toBe(devA.deviceCode);
  });

  test('反向对照：findings 不带 deviceId 的纯文字问题描述不得被误伤', async () => {
    const id = await mkInProgress(deptToken, 'cmn', operator._id);
    const res = await complete(deptToken, id, {
      findings: [{ issue: `${stamp} 通道畅通`, severity: 'low' }],
    });
    expect(res.status).toBe(200);
    expect(res.body.data.findings).toHaveLength(1);
  });

  test('self 档：借本人范围内的巡检读范围外设备 ⇒ 403（报告威胁模型原样复现）', async () => {
    const id = await mkInProgress(selfToken, 'cmself', selfUser._id);
    const res = await complete(selfToken, id, {
      findings: [{ deviceId: String(devB._id), issue: `${stamp} 借读`, severity: 'high' }],
    });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
    expect(JSON.stringify(res.body)).not.toContain(devB.deviceCode);
  });
});
