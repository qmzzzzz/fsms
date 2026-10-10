/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：PUT /api/devices/:id/status 的**错误分派路径**
 *          （deviceController.updateDeviceStatus → 全局 errorHandler）
 *
 * 守护的不变式：控制器不得在本地吞错再自己编响应。
 *   错误到 HTTP 的映射只有**一处**实现（middleware/errorHandler.js），因为只有它
 *   知道"这个错是谁的错"：客户端可自愈的（乐观并发冲突）要给可执行的文案，
 *   业务拒绝的（ApiError）要把服务层专门写给用户的那句话原样送到，
 *   服务端故障（驱动/网络/模型）必须是 5xx 且必须留下 error 日志。
 *   控制器里一个 `catch { ApiResponse.error(res, '操作失败', err.statusCode || 400) }`
 *   会同时破坏这三条：故障被伪装成 400（监控看不到、客户端以为重试无用），
 *   专门写好的业务文案被压成"操作失败"，并且**一行日志都不留**。
 *   asyncHandler 的 JSDoc 就是这么写的："避免在 async 函数中使用 try-catch"。
 *
 * 可证伪性（F-173 变异实测，见台账 §81）：
 *   复原本地 catch ⇒ 前三条红；删掉 errorHandler 的 VersionError 臂 ⇒ 第二条红；
 *   把成功路径一起改掉 ⇒ 第四条（反向保护）红。
 *
 * 为什么走真实 HTTP 而不是直调控制器：缺陷正是"本地 catch 抢在全局映射之前"，
 *   不经过 errorHandler 的用例结构上看不见它。
 * ──────────────────────────────────────────────────────────────────────────
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('设备状态变更的错误分派：本地不得吞错，映射唯一实现在 errorHandler', () => {
  let app;
  let FireDevice;
  let deviceService;
  let logger;
  let adminToken;
  let deviceId;
  const stamp = `dse${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  const putStatus = (status) =>
    request(app)
      .put(`/api/devices/${deviceId}/status`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status });

  let errorLogs;
  let warnLogs;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    deviceService = require('../../services/DeviceService');
    logger = require('../../utils/logger');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_状态错误分派',
      code: `SUPER_ADMIN_DSE_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `dseadmin${stamp}`,
      email: `dseadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const created = await FireDevice.create({
      deviceCode: `DSE-${stamp}-001`,
      deviceName: `烟感_状态错误分派_${stamp}`,
      deviceType: 'smoke_detector',
      installDate: new Date(),
      location: { building: 'A栋', floor: '3F' },
    });
    deviceId = String(created._id);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    jest.restoreAllMocks();
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^DSE-${stamp}`) }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `dseadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_DSE_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    // 只捕获、不落盘：本仓有"跑绿但 stderr 有噪音"的门禁
    errorLogs = [];
    warnLogs = [];
    jest.spyOn(logger, 'error').mockImplementation((m) => errorLogs.push(String(m)));
    jest.spyOn(logger, 'warn').mockImplementation((m) => warnLogs.push(String(m)));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  /**
   * 缺陷本体。`device.save()` / `device.transitionTo()` 抛出的驱动级错误没有
   * statusCode，落到本地 catch 就是 `err.statusCode || 400` ⇒ 一次数据库故障被
   * 报成"你这个请求有问题"，而 logger.error 一次都没调用（errorHandler 的兜底臂
   * 根本没机会跑）。双击"保存"就能复现 VersionError：两个请求各自载入同一文档，
   * 后写者的 update filter（含它读到的 __v）不再命中。
   */
  test('服务端故障必须是 5xx 且必须留下 error 日志：不得伪装成客户端错误后静默', async () => {
    const outage = new Error('ECONNRESET connection to 127.0.0.1:27017 was reset');
    jest.spyOn(deviceService, 'updateDeviceStatus').mockRejectedValue(outage);

    const res = await putStatus('fault');

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    // 对外不回显内部错误信息（这是 errorHandler 兜底臂的既有口径）
    expect(JSON.stringify(res.body)).not.toContain('ECONNRESET');
    // 关键的一半：日志必须留下痕迹（修复前这个 catch 一行都不写）
    expect(errorLogs.join('\n')).toContain('ECONNRESET');
  });

  /**
   * 乐观并发冲突是"客户端刷新即可自愈"，errorHandler 为此专门写了可执行文案并
   * 记 warn。本地 catch 把它压成"操作失败"：同样的 400，用户看不出该刷新还是该改数据。
   */
  test('乐观并发冲突（VersionError）走全局映射：可自愈的文案不能被压成「操作失败」', async () => {
    const conflict = new Error('No matching document found for id "' + deviceId + '" version 3');
    conflict.name = 'VersionError';
    jest.spyOn(deviceService, 'updateDeviceStatus').mockRejectedValue(conflict);

    const res = await putStatus('warning');

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('该记录已被其他操作变更，请刷新后重试');
    expect(res.body.message).not.toBe('操作失败');
    expect(warnLogs.join('\n')).toContain('乐观并发冲突');
  });

  /**
   * 服务层为这三条业务拒绝专门写了给用户看的话（'设备已报废，不能再变更状态' 等），
   * errorHandler 的 isApiError 臂负责透传。压成通用文案后，前端只剩一个"操作失败"，
   * 用户无法知道"报废过的设备要走报废接口"这类可执行信息。
   */
  test('服务层写给用户的业务文案原样到客户端（ApiError 透传，不降级为通用文案）', async () => {
    // 大小写必须与磁盘一致（src/utils/ApiError.js）。Windows 的文件系统不区分大小写，
    // 写成 apiError 在本地照样 require 得到，但 Linux runner 会直接
    // `Cannot find module '../../utils/apiError'` —— CI 的 20.x 腿就是这么红的。
    const ApiError = require('../../utils/ApiError');
    jest
      .spyOn(deviceService, 'updateDeviceStatus')
      .mockRejectedValue(ApiError.badRequest('设备已报废，不能再变更状态'));

    const res = await putStatus('normal');

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('设备已报废，不能再变更状态');
    expect(warnLogs.join('\n')).toContain('ApiError');
  });

  /**
   * 反向保护：去掉本地 catch 不能把成功路径一起改掉。
   * 真实服务 + 真实库（不 mock），断言状态确实落库。
   */
  test('反向保护：正路仍然 200 且状态真的写进库', async () => {
    const res = await putStatus('fault');
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('fault');
    const raw = await FireDevice.collection.findOne({ _id: new mongoose.Types.ObjectId(deviceId) });
    expect(raw.status).toBe('fault');
  });
});
