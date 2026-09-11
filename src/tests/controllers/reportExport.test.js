/**
 * 报表与导出覆盖（冲 95% 批次 D1）
 *
 * 此前缺口：reportController 语句 50.8%（四张报表 94-417 与导出 700-800 未执行）。
 * 造最小业务数据后驱动 dashboard（含缓存命中）/devices/alarms/inspections
 * 四张报表与四类 Excel 导出。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('报表与导出（批次 D1）', () => {
  let app;
  let FireDevice;
  let FireAlarm;
  let Inspection;
  let adminToken;
  const stamp = `rp${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_报表',
      code: `SUPER_ADMIN_RP_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `rpadmin${stamp}`,
      email: `rpadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 最小业务数据：设备/报警/巡检各一
    const now = new Date();
    await FireDevice.create({
      deviceCode: `RP-${stamp}-001`,
      deviceName: '报表设备',
      deviceType: 'hydrant',
      status: 'normal',
      installDate: now,
      expiryDate: new Date(now.getTime() + 90 * 86400000),
      location: { building: 'R栋' },
    });
    await FireAlarm.create({
      alarmType: 'other',
      level: 'warning',
      description: `报表报警_${stamp}`,
      status: 'resolved',
      location: { building: 'R栋' },
      receivedAt: now,
      dispatchedAt: now,
      resolvedAt: now,
      reporter: { name: 'rp' },
      processLog: [{ time: now, action: 'alarm_received', remark: 'x' }],
    });
    await Inspection.create({
      inspectionType: 'daily',
      title: `报表巡检_${stamp}`,
      planStartTime: new Date(now.getTime() - 3600000),
      planEndTime: new Date(now.getTime() + 3600000),
      status: 'completed',
      checkItems: [{ name: '消火栓' }],
      executionLog: [{ userId: admin._id, action: 'completed', timestamp: now }],
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: `RP-${stamp}-001` }).catch(() => {});
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `rpadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_RP_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const get = (path) => request(app).get(path).set('Authorization', `Bearer ${adminToken}`);

  test('dashboard：首次计算 + 二次命中缓存', async () => {
    const first = await get('/api/reports/dashboard');
    expect(first.status).toBe(200);
    expect(first.body.data.devices).toBeTruthy();

    const second = await get('/api/reports/dashboard');
    expect(second.status).toBe(200);
    expect(second.body.data).toEqual(first.body.data); // 缓存命中返回同对象
  });

  test('devices 报表：汇总 + 趋势 + 即将过期', async () => {
    const res = await get('/api/reports/devices?days=30');
    expect(res.status).toBe(200);
    expect(res.body.data).toBeTruthy();
  });

  test('alarms 报表：筛选参数与统计', async () => {
    const res = await get('/api/reports/alarms?level=warning&days=30');
    expect(res.status).toBe(200);
    expect(res.body.data).toBeTruthy();
  });

  test('inspections 报表：完成率与明细', async () => {
    const res = await get('/api/reports/inspections?days=30');
    expect(res.status).toBe(200);
    expect(res.body.data).toBeTruthy();
  });

  test('Excel 导出：四类全部 200 + 非法类型 400', async () => {
    for (const type of ['devices', 'alarms', 'inspections', 'audit']) {
      const res = await get(`/api/reports/export?type=${type}&format=xlsx`);
      expect(res.status).toBe(200);
    }
    const bad = await get('/api/reports/export?type=bogus&format=xlsx');
    expect(bad.status).toBe(400);
  });
});
