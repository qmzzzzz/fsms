/**
 * 计数与比率的非退化判据（第 17 轮 P0-1/P0-2）。缺陷本体：
 * ① totalMaintenance 原先用 $unwind 展开 maintenanceRecord 再 $sum:1，而该数组只留最新
 *    RECORD_TAIL_CAP(200) 条（models/FireDevice.js:256-259 自己写着"不能拿数组长度假装全部历史"，
 *    :142 也早已提供 maintenanceRecordCount）⇒ 第 201 条起总数不再增长，5000 次维护与 200 次同形。
 *    变异 MAINT_TOTAL_ABSURD 当时 6/6 套件 47/47 全绿。
 * ② 巡检 completionRate 在全仓 src/tests 零断言：变异 COMPLETION_RATE_ZERO 当时 5/5 套件 86/86 全绿。
 * 判据用 self 档把可见集锁死在本套件自建的文档上（all 档会数进并发套件的设备），并各配一条反向对照。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `ZR17mvx0q4nq`.toUpperCase().replace(/[^A-Z0-9]/g, '');
const CODES = [`${stamp}_A`];
/** 严格大于 RECORD_TAIL_CAP(200)：只有越过上限，被截断的计数才会分叉 */
const OVER_CAP = 201;
const INSPECTION_TITLES = ['一', '二', '三', '四', '五'];

const seedDevice = (deviceCode, userId) => ({
  deviceCode,
  deviceName: `${stamp} 计数用设备`,
  deviceType: 'extinguisher',
  installDate: new Date('2026-01-01'),
  expiryDate: new Date('2027-01-01'),
  location: { building: `${stamp}栋`, floor: '1F', detail: deviceCode },
  createdBy: userId,
});

describe('报表计数与比率的非退化判据（第 17 轮 P0-1 / P0-2）', () => {
  let app;
  let FireDevice;
  let Inspection;
  let token;
  let userId;
  let role;
  let user;

  const asUser = (path) => request(app).get(path).set('Authorization', `Bearer ${token}`);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/TokenBlacklist');
    FireDevice = require('../../models/FireDevice');
    Inspection = require('../../models/Inspection');

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    const perm = await Permission.findOneAndUpdate(
      { code: 'report:read' },
      { $setOnInsert: { name: '报表读取', code: 'report:read', type: 'api', module: 'report' } },
      { upsert: true, new: true }
    );
    role = await Role.create({
      name: `报表计数_${stamp}`,
      code: `REPORT_COUNT_${stamp}`,
      level: 4,
      isBuiltIn: false,
      permissions: [perm._id],
    });
    user = await User.create({
      username: `repcount${stamp}`.toLowerCase(),
      email: `repcount${stamp.toLowerCase()}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    userId = user._id;
    token = jwt.sign(
      { userId: String(userId), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    await FireDevice.insertMany(CODES.map((code) => seedDevice(code, userId)));
    // 走真实的实例方法写记录：它同时推进数组与 maintenanceRecordCount，
    // 直接 $push 会绕过计数，测出来的就不是生产路径
    const device = await FireDevice.findOne({ deviceCode: CODES[0] });
    for (let i = 0; i < OVER_CAP; i += 1) {
      await device.addMaintenanceRecord({ type: 'repair', description: `第 ${i + 1} 次` });
    }

    await Inspection.insertMany(
      INSPECTION_TITLES.map((label, i) => ({
        inspectionType: 'daily',
        title: `${stamp} 巡检 ${label}`,
        status: i < 3 ? 'completed' : 'pending',
        result: i < 3 ? 'normal' : null,
        inspector: userId,
        createdBy: userId,
      }))
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: { $in: CODES } }).catch(() => {});
      await Inspection.deleteMany({ title: { $regex: `^${stamp}` } }).catch(() => {});
      await require('../../models/User')
        .deleteMany({ _id: userId })
        .catch(() => {});
      await require('../../models/Role')
        .deleteMany({ _id: role._id })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('前提自证：种子真的越过了数组上限（否则下面的断言是空跑）', async () => {
    const device = await FireDevice.findOne({ deviceCode: CODES[0] }).lean();
    expect(device.maintenanceRecord.length).toBe(200); // 数组被截断
    expect(device.maintenanceRecordCount).toBe(OVER_CAP); // 计数没有
    expect(device.maintenanceRecordCount).toBeGreaterThan(device.maintenanceRecord.length);
  });

  test('P0-1：totalMaintenance 必须是维护记录总次数，不是被截断的数组长度', async () => {
    const res = await asUser('/api/reports/devices').expect(200);
    // 展开数组只能数到 200：少报的那一条就是"截断不可数"本身
    expect(res.body.data.totalMaintenance).toBe(OVER_CAP);
  });

  test('P0-1 反向对照：再写一条记录，总数必须跟着变成 202（防硬编码常量）', async () => {
    const device = await FireDevice.findOne({ deviceCode: CODES[0] });
    await device.addMaintenanceRecord({ type: 'repair', description: '第 202 次' });
    const res = await asUser('/api/reports/devices').expect(200);
    expect(res.body.data.totalMaintenance).toBe(OVER_CAP + 1);
  });

  test('P0-2：巡检完成率必须能算出来（total=5 / completed=3 / rate=60）', async () => {
    const res = await asUser('/api/reports/inspections').expect(200);
    // 全仓此前对这个比率零断言 ⇒ 把它改成恒 0 也不会有任何东西变红
    expect(res.body.data.total).toBe(5);
    expect(res.body.data.completed).toBe(3);
    expect(res.body.data.completionRate).toBe(60);
  });

  test('P0-2 反向对照：把一条 completed 改成 pending，比率必须降到 40（防恒 0/恒 100）', async () => {
    const target = await Inspection.findOne({ title: `${stamp} 巡检 三` });
    target.status = 'pending';
    await target.save();
    const res = await asUser('/api/reports/inspections').expect(200);
    expect(res.body.data.completed).toBe(2);
    expect(res.body.data.completionRate).toBe(40);
  });
});
