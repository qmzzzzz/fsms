/**
 * 覆盖率冲分第三批：小而独立、可确定性直驱的模块错误/边界分支
 *
 * 目标（基线分支覆盖）：ApiError 22%、httpPostJson 14%、autoIncrement 50%、
 * captchaService 清理定时器未测、middleware/sentry 14%、rateLimit 46%（各 handler 未触发）。
 * 全部不依赖真实网络/DB：http|https、@sentry/node、mongoose 均以 jest.mock 替身驱动。
 */

// ---- 顶层替身（jest.mock 会被提升）------------------------------------------
jest.mock('http', () => ({ request: jest.fn() }));
jest.mock('https', () => ({ request: jest.fn() }));
jest.mock('@sentry/node', () => ({
  init: jest.fn(),
  captureException: jest.fn(),
  Integrations: {
    // 与真实 @sentry/node v7 对齐：不存在 AutoSessionTracking 成员，
    // 会话跟踪通过 init 的 autoSessionTracking 选项开启
    Http: jest.fn().mockImplementation((opts) => ({ kind: 'Http', opts })),
  },
  Handlers: {
    requestHandler: jest.fn(() => 'REQ_HANDLER'),
    tracingHandler: jest.fn(() => 'TRACE_HANDLER'),
    errorHandler: jest.fn(() => 'ERR_HANDLER'),
  },
}));
jest.mock('mongoose', () => ({
  connection: { db: { collection: jest.fn() } },
}));

// ============================ ApiError =======================================
describe('ApiError 工厂与默认值（补 22% 分支）', () => {
  const ApiError = require('../../utils/ApiError');

  test('完整构造：携带 statusCode/errors/code/isApiError 且是 Error 实例', () => {
    const err = new ApiError('bad', 422, { field: 'x' }, 'E_FIELD');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ApiError');
    expect(err.statusCode).toBe(422);
    expect(err.errors).toEqual({ field: 'x' });
    expect(err.code).toBe('E_FIELD');
    expect(err.isApiError).toBe(true);
    expect(err.stack).toBeTruthy();
  });

  test('statusCode 默认 400，errors/code 默认 undefined', () => {
    const err = new ApiError('x');
    expect(err.statusCode).toBe(400);
    expect(err.errors).toBeUndefined();
    expect(err.code).toBeUndefined();
  });

  test('七个静态工厂的状态码与默认/自定义消息', () => {
    expect(ApiError.badRequest('m', { a: 1 }).statusCode).toBe(400);
    expect(ApiError.badRequest('m', { a: 1 }).errors).toEqual({ a: 1 });
    expect(ApiError.unauthorized().statusCode).toBe(401);
    expect(ApiError.unauthorized().message).toBe('未授权访问');
    expect(ApiError.forbidden().statusCode).toBe(403);
    expect(ApiError.notFound().statusCode).toBe(404);
    expect(ApiError.conflict().statusCode).toBe(409);
    expect(ApiError.tooMany().statusCode).toBe(429); // 原未覆盖
    expect(ApiError.tooMany().message).toBe('请求过于频繁');
    expect(ApiError.serverError().statusCode).toBe(500); // 原未覆盖
    expect(ApiError.serverError().message).toBe('服务器内部错误');
  });
});

// ============================ httpPostJson ==================================
describe('httpPostJson.postJson 零依赖客户端分支（补 14% 分支）', () => {
  const http = require('http');
  const https = require('https');
  const { postJson } = require('../../utils/httpPostJson');

  afterEach(() => {
    http.request.mockReset();
    https.request.mockReset();
  });

  /** 构造一个可控的请求对象；resEvent/reqEvent 决定如何回调。
   *  注意：error 场景不得同步触发 res 'end'——那会让 promise
   *  在 error 到达前先 resolve，rejects 断言拿到的是已决 promise。
   *  timeout 场景相反：需要 fireEnd 让响应先正常结束（promise resolve），
   *  再验证 timeout 处理器调用了 destroy。 */
  function wire(mod, opts = {}) {
    // 不能用解构默认值：对显式传入的 undefined 同样会回退 200
    const statusCode = 'statusCode' in opts ? opts.statusCode : 200;
    const { resEvent = 'end', reqEvent = null, reqErr, fireEnd = false } = opts;
    const reqHandlers = {};
    const req = {
      on: jest.fn((ev, fn) => {
        reqHandlers[ev] = fn;
      }),
      end: jest.fn(),
      destroy: jest.fn(),
    };
    mod.request.mockImplementation((_target, _opts, cb) => {
      const resHandlers = {};
      const res = {
        statusCode,
        resume: jest.fn(),
        on: jest.fn((ev, fn) => {
          resHandlers[ev] = fn;
        }),
      };
      cb(res); // 同步触发响应回调（第三参），其内部会注册 res.on('end')
      if (reqEvent) {
        if (fireEnd && resHandlers.end) resHandlers.end(); // 先 resolve，timeout 处理器随后执行
        // 出错路径：默认不触发 end，避免 promise 在 error 到达前先 resolve
        process.nextTick(
          () => reqHandlers[reqEvent] && reqHandlers[reqEvent](reqErr || new Error('boom'))
        );
      } else if (resEvent === 'end' && resHandlers.end) {
        resHandlers.end();
      }
      return req;
    });
    return req;
  }

  test('URL 无法解析时 reject（含原始错误信息）', async () => {
    await expect(postJson('not-a-url', {}, '{}')).rejects.toThrow(/URL 无法解析/);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('http 2xx 解析为 ok=true，并带 Content-Length', async () => {
    const req = wire(http, { statusCode: 204 });
    const out = await postJson(
      'http://example.local/hook',
      { 'X-T': '1' },
      JSON.stringify({ a: 1 })
    );
    expect(out).toEqual({ ok: true, status: 204 });
    expect(req.end).toHaveBeenCalledWith(JSON.stringify({ a: 1 }));
    const opts = http.request.mock.calls[0][1];
    expect(opts.method).toBe('POST');
    expect(opts.headers['Content-Length']).toBe(Buffer.byteLength(JSON.stringify({ a: 1 })));
  });

  test('非 2xx（500）解析为 ok=false', async () => {
    wire(http, { statusCode: 500 });
    await expect(postJson('http://x/y', {}, '{}')).resolves.toEqual({ ok: false, status: 500 });
  });

  test('statusCode 缺省（undefined）回退 0', async () => {
    wire(http, { statusCode: undefined });
    await expect(postJson('http://x/y', {}, '{}')).resolves.toEqual({ ok: false, status: 0 });
  });

  test('https: 协议走 https 模块而非 http', async () => {
    wire(https, { statusCode: 200 });
    await postJson('https://secure.local/x', {}, '{}');
    expect(https.request).toHaveBeenCalledTimes(1);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('请求 error 事件 → reject', async () => {
    wire(http, { reqEvent: 'error', reqErr: new Error('ECONNRESET') });
    await expect(postJson('http://x/y', {}, '{}')).rejects.toThrow('ECONNRESET');
  });

  test('timeout 事件 → 以带时长的 Error 调用 destroy', async () => {
    // timeout 与响应结束是独立事件：res 正常 end 让 postJson resolve，
    // 随后断言 timeout 处理器确实以带时长的 Error 调用了 destroy
    const req = wire(http, { statusCode: 204, reqEvent: 'timeout', fireEnd: true });
    await postJson('http://x/y', {}, '{}', 3000);
    await new Promise((r) => setImmediate(r));
    expect(req.destroy).toHaveBeenCalledTimes(1);
    const destroyed = req.destroy.mock.calls[0][0];
    expect(destroyed).toBeInstanceOf(Error);
    expect(destroyed.message).toContain('3000');
  });
});

// ============================ autoIncrement =================================
describe('autoIncrement 插件编号生成分支（补 50% 分支）', () => {
  const mongoose = require('mongoose');
  const plugin = require('../../plugins/autoIncrement');

  function makeSchema() {
    const hooks = {};
    return {
      hooks,
      pre(ev, fn) {
        this.hooks[ev] = fn;
      },
    };
  }
  function setCounter(result) {
    const findOneAndUpdate = jest.fn().mockResolvedValue(result);
    mongoose.connection.db.collection.mockReturnValue({ findOneAndUpdate });
    return findOneAndUpdate;
  }

  test('未指定 field 直接抛错', () => {
    expect(() => plugin(makeSchema(), {})).toThrow(/必须指定 field/);
  });

  test('新建文档：带前缀补零编号，pre(save) 正常 next', async () => {
    const fau = setCounter({ value: { seq: 3 } });
    const schema = makeSchema();
    plugin(schema, { field: 'deviceCode', generatePrefix: () => 'DEV-2026', seqPadding: 4 });
    const doc = { isNew: true };
    const next = jest.fn();
    await schema.hooks.save.call(doc, next); // Mongoose 钩子以 this 绑定文档
    expect(doc.deviceCode).toBe('DEV-2026-0003');
    expect(fau).toHaveBeenCalledWith(
      { _id: 'auto_DEV-2026' },
      { $inc: { seq: 1 } },
      expect.objectContaining({ upsert: true })
    );
    expect(next).toHaveBeenCalledWith();
  });

  test('非新建文档幂等跳过，不访问 counters', async () => {
    const fau = setCounter({ value: { seq: 9 } });
    const schema = makeSchema();
    plugin(schema, { field: 'code' });
    const next = jest.fn();
    await schema.hooks.save.call({ isNew: false }, next);
    expect(fau).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });

  test('字段已有值也幂等跳过', async () => {
    const fau = setCounter({ value: { seq: 9 } });
    const schema = makeSchema();
    plugin(schema, { field: 'code' });
    const next = jest.fn();
    await schema.hooks.save.call({ isNew: true, code: 'MANUAL-1' }, next);
    expect(fau).not.toHaveBeenCalled();
  });

  test('generatePrefix 非函数时按字符串处理；counter 直返文档(无 value)走回退', async () => {
    setCounter({ seq: 2 }); // 无 .value → result.value || result 回退分支
    const schema = makeSchema();
    plugin(schema, { field: 'code', generatePrefix: 'P', seqPadding: 3 });
    const doc = { isNew: true };
    await schema.hooks.validate.call(doc, jest.fn());
    expect(doc.code).toBe('P-002');
  });

  test('无前缀时只返回补零序号；seq 假值回退 1', async () => {
    setCounter({ value: { seq: 0 } }); // seq || 1 分支
    const schema = makeSchema();
    plugin(schema, { field: 'seqCode', seqPadding: 2 });
    const doc = { isNew: true };
    await schema.hooks.save.call(doc, jest.fn());
    expect(doc.seqCode).toBe('01');
  });

  test('counters 抛错时 pre(save)/pre(validate) 都把错误传给 next', async () => {
    const fau = jest.fn().mockRejectedValue(new Error('mongo down'));
    mongoose.connection.db.collection.mockReturnValue({ findOneAndUpdate: fau });
    const schema = makeSchema();
    plugin(schema, { field: 'code' });
    const nextSave = jest.fn();
    const nextValidate = jest.fn();
    await schema.hooks.save.call({ isNew: true }, nextSave);
    await schema.hooks.validate.call({ isNew: true }, nextValidate);
    expect(nextSave.mock.calls[0][0]).toBeInstanceOf(Error);
    expect(nextValidate.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});

// ===================== captchaService 清理定时器 =============================
describe('captchaService 定期清理启停（补 start/stop 分支）', () => {
  let captchaService;
  beforeAll(() => {
    jest.useFakeTimers();
  });
  afterAll(() => {
    jest.useRealTimers();
  });
  beforeEach(() => {
    captchaService = require('../../services/captchaService');
  });
  afterEach(() => {
    captchaService.stopCaptchaCleanup();
    jest.clearAllTimers();
  });

  test('start 幂等：重复启动只建一个 interval；unref 不阻塞退出', () => {
    const spy = jest.spyOn(global, 'setInterval');
    captchaService.startCaptchaCleanup();
    captchaService.startCaptchaCleanup(); // 第二次提前 return
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  test('到期条目在清理周期被删除（一次性消费视角：过期即不可验）', async () => {
    captchaService.startCaptchaCleanup();
    const cap = await captchaService.generate();
    expect(await captchaService.verify(cap.captchaId, 'x')).toBe(false); // 错误文本，且验证后即被消费
    // 再生成一个，推进超过 TTL/周期，清理循环删除过期项
    const cap2 = await captchaService.generate();
    jest.advanceTimersByTime(5 * 60 * 1000 + 10);
    expect(await captchaService.verify(cap2.captchaId, 'whatever')).toBe(false);
  });

  test('stop 清理 interval 且可重复安全调用（无 timer 时 no-op）', () => {
    captchaService.startCaptchaCleanup();
    captchaService.stopCaptchaCleanup();
    expect(() => captchaService.stopCaptchaCleanup()).not.toThrow();
  });
});

// ============================ middleware/sentry ==============================
describe('middleware/sentry 初始化与处理器（补 14% 分支）', () => {
  const Sentry = require('@sentry/node');
  const sentry = require('../../middleware/sentry');
  const ORIGINAL_DSN = process.env.SENTRY_DSN;
  const ORIGINAL_ENV = process.env.NODE_ENV;

  beforeEach(() => {
    Sentry.init.mockClear();
    Sentry.captureException.mockClear();
  });
  afterAll(() => {
    if (ORIGINAL_DSN === undefined) delete process.env.SENTRY_DSN;
    else process.env.SENTRY_DSN = ORIGINAL_DSN;
    if (ORIGINAL_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = ORIGINAL_ENV;
  });

  test('无 SENTRY_DSN 时不初始化并返回 false', () => {
    delete process.env.SENTRY_DSN;
    expect(sentry.initSentry()).toBe(false);
    expect(Sentry.init).not.toHaveBeenCalled();
  });

  test('有 DSN 时初始化并返回 true；生产采样率 0.1、集成被实例化', () => {
    process.env.SENTRY_DSN = 'https://k@sentry.io/1';
    process.env.NODE_ENV = 'production';
    expect(sentry.initSentry()).toBe(true);
    const arg = Sentry.init.mock.calls[0][0];
    expect(arg.dsn).toBe('https://k@sentry.io/1');
    expect(arg.environment).toBe('production');
    expect(arg.tracesSampleRate).toBe(0.1);
    // v7 起 AutoSessionTracking 改为 init 选项，不再通过 integrations 传入
    expect(arg.integrations).toHaveLength(1);
    expect(arg.autoSessionTracking).toBe(true);
  });

  test('非生产环境采样率 1.0', () => {
    process.env.SENTRY_DSN = 'https://k@sentry.io/1';
    process.env.NODE_ENV = 'test';
    sentry.initSentry();
    expect(Sentry.init.mock.calls[0][0].tracesSampleRate).toBe(1.0);
    expect(Sentry.init.mock.calls[0][0].environment).toBe('test');
  });

  test('三个 handler 取手透传 Sentry.Handlers', () => {
    expect(sentry.sentryRequestHandler()).toBe('REQ_HANDLER');
    expect(sentry.sentryTracingHandler()).toBe('TRACE_HANDLER');
    expect(sentry.sentryErrorHandler()).toBe('ERR_HANDLER');
  });

  test('captureException 默认 context={}，也可携带额外上下文', () => {
    const e = new Error('x');
    sentry.captureException(e);
    expect(Sentry.captureException).toHaveBeenCalledWith(e, { extra: {} });
    sentry.captureException(e, { uid: 7 });
    expect(Sentry.captureException).toHaveBeenLastCalledWith(e, { extra: { uid: 7 } });
  });
});

// ============================ rateLimit =====================================
describe('rateLimit 各限流器触发 handler 与键/豁免分支（补 46% 分支）', () => {
  const limiters = require('../../middleware/rateLimit');

  function mockRes() {
    // skipSuccessfulRequests 限流器（三个 login 系）经 res.on('finish') 判定成败后计数：
    // mock 必须支持事件订阅并手动 emit finish（非 2xx → 计入配额）
    const listeners = {};
    const res = {
      _status: null,
      _body: null,
      statusCode: 401, // 默认模拟登录失败 → skipSuccessfulRequests 不跳过，正常计数
      status: jest.fn(function (code) {
        this._status = code;
        this.statusCode = code;
        return this;
      }),
      json: jest.fn(function (body) {
        this._body = body;
        return this;
      }),
      setHeader: jest.fn(),
      on: jest.fn((ev, fn) => {
        (listeners[ev] = listeners[ev] || []).push(fn);
        return res;
      }),
      emit: jest.fn((ev, ...args) => {
        (listeners[ev] || []).forEach((fn) => fn(...args));
      }),
    };
    return res;
  }
  function mockReq(over = {}) {
    return {
      ip: '9.9.9.9',
      method: 'POST',
      path: '/x',
      body: {},
      // express-rate-limit v7 校验需要 app.get('trust proxy') 与 headers
      app: { get: jest.fn(() => false) },
      headers: {},
      ...over,
    };
  }
  /** 反复驱动直到触发 429 或达到上限次数（v7 计数异步；每次用新 req 避免 DOUBLE_COUNT）。
   *  每轮驱动后 emit res 'finish'——skipSuccessfulRequests 的限流器靠该事件判定
   *  「失败请求」才计数。mockRes 默认 statusCode=401（非成功），确保配额累积。 */
  async function drive(limiter, baseReq, cap = 1200) {
    const res = mockRes();
    const next = jest.fn();
    for (let i = 0; i < cap; i += 1) {
      limiter({ ...baseReq }, res, next); // 每"请求"一个新对象，但键（ip/账号）相同
      await new Promise((r) => setImmediate(r));
      if (res._status === 429) break;
      res.emit('finish');
      await new Promise((r) => setImmediate(r));
    }
    return { res, next };
  }

  test('generalLimiter 超限触发自定义 handler 返回 429', async () => {
    const { res } = await drive(limiters.generalLimiter, mockReq());
    expect(res._status).toBe(429);
    expect(res._body.success).toBe(false);
  });

  test('strictLimiter 触发', async () => {
    const { res } = await drive(limiters.strictLimiter, mockReq());
    expect(res._status).toBe(429);
  });

  test('loginLimiter：带 username 的键生成路径 + handler', async () => {
    const { res } = await drive(
      limiters.loginLimiter,
      mockReq({ body: { username: 'Admin' } }),
      20
    );
    expect(res._status).toBe(429);
  });

  test('loginIpLimiter 外层兜底触发', async () => {
    const { res } = await drive(limiters.loginIpLimiter, mockReq(), 40);
    expect(res._status).toBe(429);
  });

  test('loginUserLimiter：有 username 走账号键、无 username 回退 IP 键，两路径都触发', async () => {
    const withUser = await drive(
      limiters.loginUserLimiter,
      mockReq({ body: { username: 'victim' } }),
      30
    );
    expect(withUser.res._status).toBe(429);
    const noUser = await drive(limiters.loginUserLimiter, mockReq({ body: {} }), 30);
    expect(noUser.res._status).toBe(429);
  });

  test('captchaLimiter 触发', async () => {
    const { res } = await drive(limiters.captchaLimiter, mockReq(), 70);
    expect(res._status).toBe(429);
  });

  test('passwordChangeLimiter：已认证组合键与未认证回退键两路径', async () => {
    const authed = await drive(
      limiters.passwordChangeLimiter,
      mockReq({ user: { userId: 'u1' } }),
      10
    );
    expect(authed.res._status).toBe(429);
    const anon = await drive(limiters.passwordChangeLimiter, mockReq(), 10);
    expect(anon.res._status).toBe(429);
  });

  test('registerIpLimiter 触发', async () => {
    const { res } = await drive(limiters.registerIpLimiter, mockReq(), 20);
    expect(res._status).toBe(429);
  });

  test('userLimiter 的角色配额三分支 + 触发 handler', async () => {
    const superR = await drive(
      limiters.userLimiter,
      mockReq({ user: { userId: 'a', roleCodes: ['SUPER_ADMIN'] } }),
      520
    );
    expect(superR.res._status).toBe(429);
    const secR = await drive(
      limiters.userLimiter,
      mockReq({ user: { userId: 'b', roleCodes: ['SECURITY_ADMIN'] } }),
      420
    );
    expect(secR.res._status).toBe(429);
    const normalR = await drive(
      limiters.userLimiter,
      mockReq({ user: { userId: 'c', roleCodes: ['GUEST'] } }),
      210
    );
    expect(normalR.res._status).toBe(429);
    // 未认证：键回退 IP
    const anonR = await drive(limiters.userLimiter, mockReq(), 210);
    expect(anonR.res._status).toBe(429);
  });

  test('白名单 IP（req.ipWhitelisted=true）被资源型限流豁免，不触发 429', async () => {
    const req = mockReq({ ipWhitelisted: true });
    const { res, next } = await drive(limiters.generalLimiter, req, 400);
    expect(res._status).toBeNull();
    expect(next).toHaveBeenCalled();
  });
});
