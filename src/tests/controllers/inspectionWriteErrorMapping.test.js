/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：巡检写路径（PUT /:id/cancel、DELETE /:id、PUT /:id/start）的**错误分派**
 * 守护的不变式：与 deviceStatusErrorMapping.test.js 同一条（F-173 同一缺陷类的另一半）——
 *   控制器不得本地吞错；错误→HTTP 的映射唯一实现在 middleware/errorHandler.js。
 *
 * 为什么单独一份：巡检这一侧的代价更直观。InspectionService.deleteInspection 特意
 * 把"删除没命中"拆成两条臂（'正在执行的巡检不能删除' 400 / '巡检不存在或已被删除' 404，
 * 见其 TOCTOU 注释），而旧的控制器 catch 把它们压回 '操作失败' / '记录不存在'——
 * 服务层做区分工作的价值全部丢在最后一米。这里用**真实链路**（不 mock 服务）钉住
 * 这两条臂确实能原样到达客户端。
 *
 * 可证伪性：复原任一 catch ⇒ 第 1、2 条红（文案退回"操作失败"）；
 * 把 startInspection 的 catch 复原 ⇒ 第 3 条红（500 变 400 且零日志）。
 * ──────────────────────────────────────────────────────────────────────────
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('巡检写路径的错误分派：服务层写给用户的文案必须原样到客户端', () => {
  let app;
  let Inspection;
  let inspectionService;
  let logger;
  let adminToken;
  const stamp = `iwm${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  let errorLogs;
  let warnLogs;

  const authed = () => ({
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${adminToken}`),
  });

  /** 建一条巡检计划并返回 id（真实 HTTP，与既有闭环用例同口径） */
  const createInspection = async (tag) => {
    const res = await request(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        title: `巡检错误分派_${tag}_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        planEndTime: new Date(Date.now() + 7200 * 1000).toISOString(),
        locations: [{ building: 'C栋' }],
        checkItems: [{ name: '灭火器压力', standard: '指针位于绿区' }],
      });
    expect(res.status).toBe(201);
    return String(res.body.data._id || res.body.data.id);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    Inspection = require('../../models/Inspection');
    inspectionService = require('../../services/InspectionService');
    logger = require('../../utils/logger');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_巡检错误分派',
      code: `SUPER_ADMIN_IWM_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `iwmadmin${stamp}`,
      email: `iwmadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    jest.restoreAllMocks();
    if (mongoose.connection.readyState !== 0) {
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `iwmadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_IWM_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    errorLogs = [];
    warnLogs = [];
    jest.spyOn(logger, 'error').mockImplementation((m) => errorLogs.push(String(m)));
    jest.spyOn(logger, 'warn').mockImplementation((m) => warnLogs.push(String(m)));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('二次取消：409 与服务层的可执行文案一起到达客户端（真实链路，不 mock 服务）', async () => {
    const id = await createInspection('cancel');
    const first = await authed().put(`/api/inspections/${id}/cancel`).send({ reason: '计划变更' });
    expect(first.status).toBe(200);

    const second = await authed()
      .put(`/api/inspections/${id}/cancel`)
      .send({ reason: '再取消一次' });

    expect(second.status).toBe(409);
    // 修复前这里是 '操作失败'：状态码碰巧没变，所以只看状态码的用例全都放行
    expect(second.body.message).toBe('已完成或已取消的巡检不能重复操作');
  });

  test('删除正在执行的巡检：服务层区分的 400 臂原样到客户端（不是 404、不是「操作失败」）', async () => {
    const id = await createInspection('del');
    const started = await authed().put(`/api/inspections/${id}/start`);
    expect(started.status).toBe(200);

    const del = await authed().delete(`/api/inspections/${id}`);

    expect(del.status).toBe(400);
    expect(del.body.message).toBe('正在执行的巡检不能删除');
  });

  test('驱动级故障（无 statusCode）必须是 5xx 且留下 error 日志：任何一条写路径都不例外', async () => {
    const id = await createInspection('boom');
    const outage = new Error('WriteConflict: batched op failed on primary');
    jest.spyOn(inspectionService, 'startInspection').mockRejectedValue(outage);

    const res = await authed().put(`/api/inspections/${id}/start`);

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(JSON.stringify(res.body)).not.toContain('WriteConflict');
    expect(errorLogs.join('\n')).toContain('WriteConflict');
  });
});
