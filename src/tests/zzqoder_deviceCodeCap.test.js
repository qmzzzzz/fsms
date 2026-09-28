/**
 * 设备编号长度上限必须与模型一致，且不一致要在**路由层**就说清楚
 *
 * 原状：路由校验 `deviceCode` ≤ 64，模型 `maxlength` 是 50。51~64 字符能通过路由，
 * 落在模型上抛 Mongoose ValidationError → 仍走 errorHandler，但它对 ValidationError
 * **在生产环境刻意不回传字段级明细**（`isDev ? errors : undefined`，避免泄露 schema）。
 * 于是运维/用户看到的是一句笼统的"数据验证失败"，不知道是哪个字段、为什么。
 *
 * 结论不是"多一层校验而已"：**只有路由校验层能给出"哪个字段、为什么"**，
 * 所以边界必须写在路由上，且与存储契约取同一个值。
 *
 * 同时钉住反向：恰好 50 字符必须放行（收口不得变成一刀切）。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('deviceCode 上限：路由与模型同一口径', () => {
  let app;
  let token;
  let User;
  let FireDevice;
  const stamp = `zzdc${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    FireDevice = require('../models/FireDevice');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    // 建号需要 device:create；无权限的账户会在 checkPermission 处 403，
    // 那样测的就不是校验边界而是授权了（首轮实跑即暴露）。
    const Permission = require('../models/Permission');
    const Role = require('../models/Role');
    const perm = await Permission.create({
      name: '设备新增',
      code: 'device:create',
      module: 'device',
    });
    const role = await Role.create({
      name: `${stamp} 设备操作员`,
      code: `ZZDC_${stamp.toUpperCase()}`.replace(/[^A-Z0-9_]/g, '_'),
      level: 8,
      permissions: [perm._id],
    });
    const user = await User.create({
      username: `${stamp}_u`,
      email: `${stamp}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    const jwt = require('jsonwebtoken');
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${stamp.toUpperCase()}`) }).catch(
      () => {}
    );
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const post = (deviceCode) =>
    require('supertest')(app)
      .post('/api/devices')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceCode,
        deviceName: `${stamp} 探测器`,
        deviceType: 'smoke_detector',
        // installDate 是模型必填项。缺了它得到的是"模型层 ValidationError"，
        // 而非 development 环境下 errorHandler 刻意不回传字段明细 → 用例变成无因失败。
        // （这恰好也是本文件要修的同一个可观测性问题。）
        installDate: '2026-01-01',
        location: { floor: `${stamp}层` },
      });

  test('51 字符（超过模型 maxlength）→ 400，且原因点名设备编号与 50', async () => {
    const res = await post(`${stamp}${'Z'.repeat(51 - stamp.length)}`);
    expect(res.status).toBe(400);
    const text = JSON.stringify(res.body);
    // 必须可读：不能只剩一句"数据验证失败"（那正是 64/50 不一致时的生产形态）
    expect(text).toContain('设备编号');
    expect(text).toContain('50');
  });

  test('反向保护：恰好 50 字符放行（收口不得变成一刀切）', async () => {
    const code = `${stamp}${'Y'.repeat(50 - stamp.length)}`;
    const res = await post(code);
    if (res.status !== 201) console.log('ZZDEBUG', JSON.stringify(res.body));
    expect(res.status).toBe(201);
    const stored = await FireDevice.findOne({ deviceCode: code });
    expect(stored).not.toBeNull();
    expect(stored.deviceCode).toHaveLength(50);
  });
});
