/**
 * 报警上报（POST /api/alarms/report）的两个写入侧越权面
 *
 * ① deviceId：FireAlarm.deviceId 是 ref→FireDevice，且 GET /api/alarms/:id 会 populate 出
 *   deviceCode/deviceName/deviceType。修复前路由只判 `isMongoId`（格式），于是
 *     · 指向不存在的设备 ⇒ 引用静默悬空，工单上没有一个可核对的点位；
 *     · 指向他人设备 ⇒ 上报方自己 GET 这条报警就能读到他人设备的编码/名称/类型。
 *   判据复用 assertRecordInScope + DATA_SCOPE_FIELDS.device，不另起一份；
 *   因此「维护过该设备」这条属主臂（数组字段）也必须继续有效——见反向对照。
 * ② location.building：它就是 DATA_SCOPE_FIELDS.alarm 的 departmentField，
 *   决定了这条报警出现在哪个部门的清单/统计/导出里。修复前只判了 ① ⇒ department 档
 *   账号仍可直写他人楼栋投毒。判据复用 rbac.isDepartmentValueAllowed，
 *   与 deviceController.rejectOutOfScopeBuilding 同档位语义（self 放行、all 不限）。
 * 两道闸的共同点：**读路径一直是对的，洞在写入侧不收口**。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const DEVICE_TYPE_VALUES = Object.values(require('../../utils/constants').DEVICE_TYPE);
const DEPT_A = 'ZZQAR-A';
const DEPT_C = 'ZZQAR-C';

describe('reportAlarm 的 deviceId 存在性与数据范围闸', () => {
  let app;
  let FireAlarm;
  let tokenDept; // department 档（level 7）
  let tokenSelf; // self 档（level 4）
  let tokenAll; // all 档（level 10）
  let devA; // createdBy = department 档用户，楼栋 DEPT_A
  let devC; // 属于别人、楼栋 DEPT_C
  let report;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    const FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/TokenBlacklist');

    const createPerm = await Permission.create({
      name: '上报报警',
      code: 'alarm:create',
      type: 'api',
      module: 'alarm',
    });
    const mkRole = (code, level) =>
      Role.create({ name: `ZZQAR ${code}`, code, level, permissions: [createPerm._id] });
    const deptRole = await mkRole('ZZQAR_DEPT', 7);
    const selfRole = await mkRole('ZZQAR_SELF', 4);
    const allRole = await mkRole('ZZQAR_ALL', 10);

    const mkUser = (username, roles, department) =>
      User.create({
        username,
        email: `${username}@example.com`,
        password: 'Test@1234567',
        department,
        roles,
      });
    const deptUser = await mkUser('zzqar_dept', [deptRole._id], DEPT_A);
    const selfUser = await mkUser('zzqar_self', [selfRole._id], DEPT_A);
    const allUser = await mkUser('zzqar_all', [allRole._id], DEPT_C);
    const otherOwner = await mkUser('zzqar_other', [selfRole._id], DEPT_C);

    const sign = (u) =>
      jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
    tokenDept = sign(deptUser);
    tokenSelf = sign(selfUser);
    tokenAll = sign(allUser);

    const mkDevice = (deviceCode, building, extra) =>
      FireDevice.create({
        deviceCode,
        deviceName: `${deviceCode} 名称`,
        deviceType: DEVICE_TYPE_VALUES[0],
        installDate: new Date('2026-01-01'),
        location: { building },
        ...extra,
      });
    devA = await mkDevice('ZZQAR-DEV-A', DEPT_A, { createdBy: deptUser._id });
    devC = await mkDevice('ZZQAR-DEV-C', DEPT_C, { createdBy: otherOwner._id });

    const { createApp } = require('../../app');
    app = createApp();

    report = (token, body) =>
      request(app)
        .post('/api/alarms/report')
        .set('Authorization', `Bearer ${token}`)
        .send({ alarmType: 'smoke', description: '测试上报', ...body });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const alarmCount = () => FireAlarm.countDocuments({ description: '测试上报' });

  test('范围内设备可上报：201 且 deviceId 落库', async () => {
    const res = await report(tokenDept, { deviceId: String(devA._id) });
    expect(res.status).toBe(201);
    expect(String(res.body.data.deviceId)).toBe(String(devA._id));
  });

  test('不传 deviceId 不受影响（闸只管可选字段）', async () => {
    const before = await alarmCount();
    const res = await report(tokenDept, {});
    expect(res.status).toBe(201);
    expect(res.body.data.deviceId).toBeUndefined();
    expect(await alarmCount()).toBe(before + 1);
  });

  test('不存在的设备：DEVICE_NOT_FOUND，且不留下一条悬空报警', async () => {
    const before = await alarmCount();
    const ghost = new mongoose.Types.ObjectId();
    const res = await report(tokenDept, { deviceId: String(ghost) });
    expect(res.status).toBe(404);
    expect(res.body.errors.errorCode).toBe('DEVICE_NOT_FOUND');
    expect(await alarmCount()).toBe(before);
  });

  test('部门档引用他人部门设备：DEVICE_VIEW_FORBIDDEN', async () => {
    const before = await alarmCount();
    const res = await report(tokenDept, { deviceId: String(devC._id) });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
    expect(await alarmCount()).toBe(before);
  });

  test('self 档引用他人建档设备同样被拒', async () => {
    const res = await report(tokenSelf, { deviceId: String(devC._id) });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
  });

  test('all 档不限设备归属（闸不能顺手把超管也拦掉）', async () => {
    const res = await report(tokenAll, { deviceId: String(devC._id) });
    expect(res.status).toBe(201);
  });

  test('反向对照：数组属主臂（maintenanceRecord.operator）仍然算在范围内', async () => {
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const FireDevice = require('../../models/FireDevice');
    // 关键：维护人**部门与楼栋都不同**，否则 department 臂先放行，
    // 这条用例就测不到数组属主臂本身（变异"只看 createdBy"当时照样绿）。
    // 用 self 档：数组属主臂只在 self 分支参与判定（department 分支只看楼栋，
    // 且 buildDataScopeFilter 与 isRecordInScope 在这一条上口径一致，已核对）。
    // 同时让楼栋/部门都不同，否则别的臂先放行，这条用例就测不到属主臂本身
    // （变异"只看 createdBy"当初照样绿，就是这个原因）。
    const maintainer = await User.create({
      username: 'zzqar_maint',
      email: 'zzqar_maint@example.com',
      password: 'Test@1234567',
      department: 'ZZQAR-E',
      roles: [],
    });
    maintainer.roles = (await Role.find({ code: 'ZZQAR_SELF' })).map((r) => r._id);
    await maintainer.save();
    const maintained = await FireDevice.create({
      deviceCode: 'ZZQAR-DEV-MAINT',
      deviceName: '他人建档、由我维护',
      deviceType: DEVICE_TYPE_VALUES[0],
      installDate: new Date('2026-01-01'),
      location: { building: 'ZZQAR-D' },
      createdBy: new mongoose.Types.ObjectId(),
      maintenanceRecord: [{ operator: maintainer._id }],
    });
    const token = jwt.sign(
      { userId: String(maintainer._id), username: 'zzqar_maint', tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const res = await report(token, { deviceId: String(maintained._id) });
    expect(res.status).toBe(201);
  });

  // ==== 第二道闸：location.building 是报警的 departmentField，写侧必须收口 ====
  // 上报一条报警 = 决定它出现在哪个部门的清单/统计/导出里。只判 deviceId 时，
  // department 档账号照样能往他人部门的报警列表里投毒（挂不挂设备都一样）。

  test('部门档把报警种到他人楼栋：403 且一条都不落库', async () => {
    const before = await alarmCount();
    const res = await report(tokenDept, { location: { building: DEPT_C, floor: '3F' } });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('ALARM_OPERATE_FORBIDDEN');
    expect(await alarmCount()).toBe(before);
  });

  test('两道闸互不遮蔽：设备在自己范围内、楼栋是别人的，仍然被拒', async () => {
    const before = await alarmCount();
    const res = await report(tokenDept, {
      deviceId: String(devA._id),
      location: { building: DEPT_C },
    });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('ALARM_OPERATE_FORBIDDEN');
    expect(await alarmCount()).toBe(before);
  });

  test('正向对照：部门档写自己楼栋的 building 正常落库（闸不是"一律拒绝"）', async () => {
    const res = await report(tokenDept, { location: { building: DEPT_A, floor: '1F' } });
    expect(res.status).toBe(201);
    expect(res.body.data.location.building).toBe(DEPT_A);
  });

  test('self 档填任意楼栋放行：不因位置把自己锁死（与设备侧同档位语义）', async () => {
    const res = await report(tokenSelf, { location: { building: DEPT_C } });
    expect(res.status).toBe(201);
  });

  test('all 档不限楼栋', async () => {
    const res = await report(tokenAll, { location: { building: DEPT_A } });
    expect(res.status).toBe(201);
  });

  test('未填楼栋不受影响（闸只管本次真的写了值的字段）', async () => {
    const res = await report(tokenDept, { location: { floor: '2F' } });
    expect(res.status).toBe(201);
  });
});
