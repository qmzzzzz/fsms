'use strict';

/**
 * POST /api/auth/register 的「开关 → 校验」顺序契约
 *
 * 不变式：**注册开关的判定必须发生在字段校验之前**。
 *   · 开关关闭 ⇒ 403 PUBLIC_REGISTRATION_DISABLED，请求体再离谱也不该跑校验链，
 *     更不该有任何一行走到 authService.registerUser；
 *   · 开关开启 ⇒ 校验照常生效，非法请求体仍是 400 VALIDATION_FAILED 且点名到字段
 *     （顺序修正不能变成"绕过校验"）；
 *   · 开关读不出来（DB 故障）⇒ 503 REGISTER_SERVICE_UNAVAILABLE，fail-closed，
 *     同样不得进入注册服务。
 *
 * 为什么必须打真实 HTTP 而不是直接调中间件：顺序是**路由装配**的性质，
 * 单测一个中间件函数永远看不到它被排在 registerValidation 的哪一侧。
 *
 * 历史：本文件诞生于 2026-10-29。此前顺序是 registerValidation 先跑、开关判定在
 * 处理器里后跑，关闭态每个请求都白跑一遍校验链（结果被 403 丢弃），
 * 且 `routeGuardBranches.test.js` 里一条注释据此断言"strict 守卫永远执行不到"——
 * 那句在当时是错的（守卫会执行，只是结果不被消费）。顺序修正后该断言才成立。
 */

const mongoose = require('mongoose');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('POST /api/auth/register：注册开关先于字段校验', () => {
  let app;
  let SystemConfig;
  let authService;
  let originalDoc;
  let registerSpy;

  // 三条字段各自非法：用户名过短、邮箱格式错、口令强度不足。
  // 只要校验链被执行，就一定产生 fieldErrors —— 用它区分"被开关挡住"与"被校验挡住"。
  const INVALID_BODY = { username: 'a', email: 'not-an-email', password: '123' };

  const validBody = () => {
    const stamp = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    return {
      username: `sworder${stamp}`,
      email: `sworder${stamp}@example.com`,
      realName: '顺序契约',
      password: randomPassword(),
      privacyConsent: true,
    };
  };

  // 30 秒进程内缓存：同一进程里连续切开关，不失效就会读到上一次的值
  const setRegistration = async (value) => {
    await SystemConfig.updateOne(
      { key: 'allowPublicRegistration' },
      { $set: { value, valueType: 'boolean' } },
      { upsert: true }
    );
    SystemConfig.invalidateRegistrationCache();
  };

  const fieldErrors = (res) => res.body?.errors?.fieldErrors || [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    SystemConfig = require('../../models/SystemConfig');
    require('../../models/User');
    require('../../models/Role');
    require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');
    authService = require('../../services/authService');

    originalDoc = await SystemConfig.findOne({ key: 'allowPublicRegistration' }).lean();
    app = require('../../app').createApp();
  });

  afterEach(() => {
    if (registerSpy) {
      registerSpy.mockRestore();
      registerSpy = null;
    }
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    // 还原开关：测试库在同一 worker 的套件间共享，留下 'true' 会让"注册关闭"
    // 的用例在后续套件里变绿/变红，属于最难查的跨文件污染
    if (originalDoc) {
      await SystemConfig.updateOne(
        { key: 'allowPublicRegistration' },
        { $set: { value: originalDoc.value, valueType: originalDoc.valueType } }
      ).catch(() => {});
    } else {
      await SystemConfig.deleteOne({ key: 'allowPublicRegistration' }).catch(() => {});
    }
    SystemConfig.invalidateRegistrationCache();

    // 套件级收尾（mongooseTeardownLedger 门禁）：连了内存 Mongo 就必须自己关，
    // 否则 worker 在最后一个文件后被强杀，正好吞掉本套件输出
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('开关关闭：完全非法的请求体也只返回 403，且不携带字段级校验错误', async () => {
    await setRegistration('false');
    registerSpy = jest.spyOn(authService, 'registerUser');

    const res = await request(app).post('/api/auth/register').send(INVALID_BODY);

    expect(res.status).toBe(403);
    expect(res.body.errors?.errorCode).toBe('PUBLIC_REGISTRATION_DISABLED');
    // 关键断言：403 分支不得顺带泄露校验明细
    expect(fieldErrors(res)).toHaveLength(0);
    expect(registerSpy).not.toHaveBeenCalled();
  });

  test('开关关闭：合法请求体同样 403（拒绝来自开关，不是校验失败）', async () => {
    await setRegistration('false');
    registerSpy = jest.spyOn(authService, 'registerUser');

    const res = await request(app).post('/api/auth/register').send(validBody());

    expect(res.status).toBe(403);
    expect(res.body.errors?.errorCode).toBe('PUBLIC_REGISTRATION_DISABLED');
    expect(registerSpy).not.toHaveBeenCalled();
  });

  test('开关读取失败：fail-closed 返回 503，且不进入注册服务', async () => {
    jest.spyOn(SystemConfig, 'isRegistrationAllowed').mockRejectedValueOnce(new Error('db down'));
    registerSpy = jest.spyOn(authService, 'registerUser');

    const res = await request(app).post('/api/auth/register').send(validBody());

    expect(res.status).toBe(503);
    expect(res.body.errors?.errorCode).toBe('REGISTER_SERVICE_UNAVAILABLE');
    expect(registerSpy).not.toHaveBeenCalled();
  });

  test('开关开启：非法请求体落到校验，400 且点名字段（顺序修正没有绕过校验）', async () => {
    await setRegistration('true');
    registerSpy = jest.spyOn(authService, 'registerUser');

    const res = await request(app).post('/api/auth/register').send(INVALID_BODY);

    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('VALIDATION_FAILED');
    expect(fieldErrors(res).length).toBeGreaterThan(0);
    expect(registerSpy).not.toHaveBeenCalled();
  });

  /**
   * 结构断言：为什么必须有这一条
   *
   * 上面四条行为用例**都拦不住顺序回退**。把 registerValidation 挪回守卫之前，
   * 关闭态的响应依旧是 403、依旧没有 fieldErrors、registerUser 依旧不被调用
   * ——因为校验结果本来就只有控制器会消费，被 403 丢弃是同样的结果。
   * 换言之"顺序"在这个端点上是**纯装配性质**，只能看装配。
   *
   * 链形：strictLimiter → registerIpLimiter → requireRegistrationEnabled
   *      → registerValidation(...) → authController.register
   * 守卫索引固定为 2（前两个是限流器）；控制器恒为最后一环。二者同时成立，
   * 就等于"没有任何校验器排在守卫之前"。
   */
  test('结构断言：守卫紧跟两个限流器、且排在所有校验器之前', () => {
    const collectRoutes = (router, path, out = []) => {
      for (const layer of router?.stack || []) {
        if (layer.route && layer.route.path === path) out.push(layer.route);
        else if (layer.handle?.stack) collectRoutes(layer.handle, path, out);
      }
      return out;
    };

    // Express 5 用 app.router（app._router 已移除）；这里两种都兜住，
    // 免得升级/降级 express 时这条断言变成"永远找不到路由"的空跑
    const rootRouter = app.router || app._router;
    const routes = collectRoutes(rootRouter, '/register');
    expect(routes).toHaveLength(1);

    const handlers = routes[0].stack.map((layer) => layer.handle);
    const guardIndex = handlers.findIndex((fn) => fn.name === 'requireRegistrationEnabled');

    expect(guardIndex).toBe(2);
    expect(handlers.length).toBeGreaterThan(guardIndex + 1);
  });
});
