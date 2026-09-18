/**
 * originCheck 中间件测试（CSRF 纵深：写操作 Origin/Referer 白名单校验）
 * 覆盖：白名单 Origin 放行 / 非白名单 Origin 403 / 无来源放行 /
 *       Referer 提取 origin 命中白名单放行 / Referer 非白名单 403 /
 *       Referer 非法语法按无来源放行 / GET·OPTIONS 直接放行 / DELETE（写方法）受校验
 */

const express = require('express');
const request = require('supertest');

const { createOriginCheck } = require('../../middleware/originCheck');
const {
  TEST_FRONTEND_ORIGIN_LOCALHOST,
  TEST_FRONTEND_ORIGIN_LOOPBACK,
  EVIL_ORIGIN,
} = require('../fixtures');
const AuditLog = require('../../models/AuditLog');

const WHITELIST = [TEST_FRONTEND_ORIGIN_LOCALHOST, TEST_FRONTEND_ORIGIN_LOOPBACK];

const buildApp = (whitelist) => {
  const originCheck = createOriginCheck(whitelist);
  const app = express();
  app.use(express.json());
  app.use(originCheck);
  const echo = (req, res) => res.json({ success: true, method: req.method });
  app.post('/resource', echo);
  app.put('/resource', echo);
  app.patch('/resource', echo);
  app.delete('/resource', echo);
  app.get('/resource', echo);
  app.options('/resource', echo);
  return app;
};

describe('createOriginCheck 中间件', () => {
  beforeAll(() => {
    jest.spyOn(AuditLog, 'record').mockResolvedValue(null);
  });

  afterAll(() => {
    AuditLog.record.mockRestore();
  });

  test('写方法携带白名单 Origin 放行', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('写方法携带非白名单 Origin 返回 403 且响应体为约定结构', async () => {
    const res = await request(buildApp(WHITELIST)).post('/resource').set('Origin', EVIL_ORIGIN);
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('来源校验失败');
  });

  test('无 Origin 无 Referer（非浏览器客户端）放行', async () => {
    const res = await request(buildApp(WHITELIST)).post('/resource');
    expect(res.status).toBe(200);
    // 放行的判据是「请求真的进了业务处理器」（不是被某个中间件吞掉后返回 200）
    expect(res.body).toEqual({ success: true, method: 'POST' });
  });

  test('Origin 头存在但为空串 → 403（异常来源，不得靠 falsy 绕过白名单）', async () => {
    // 空串是 falsy：若实现用真值判断，会静默落入「无来源放行」或 Referer 回退。
    // 该分支与「非白名单来源」在 HTTP 层完全同形（同为 403 + 同文案），
    // 唯一可观测差异是审计留痕的 riskFactors 里多一个 empty_origin：
    // 变异验证：删掉 originCheck.js:110 的 `if (origin === '')` 分支，本用例必须转红。
    // 记录调用基线：下面只接受「本次请求发起之后」新产生的审计调用
    const baseCalls = AuditLog.record.mock.calls.length;
    const res = await request(buildApp(WHITELIST)).post('/resource').set('Origin', '');
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ success: false, message: '来源校验失败' });

    // recordEarlyRejection 经 setImmediate 异步落库（middleware/security.js：
    // setImmediate 内调 AuditLog.record），且该回调可能在响应返回前就跑完。
    // 判据必须钉在「本请求产生的那条记录」上：在基线之后、riskFactors 含
    // empty_origin 的记录才是本用例的产物（empty_origin 仅本用例触达）。
    // 不能用 calls.at(-1)：随机顺序下会读到同文件别的用例留下的记录（如非白名单
    // Origin 的 csrf_origin_violation）。
    let entry = null;
    for (let i = 0; i < 50 && !entry; i++) {
      await new Promise((r) => setImmediate(r));
      entry = AuditLog.record.mock.calls
        .slice(baseCalls)
        .map((call) => call[0])
        .find((e) => e.riskFactors?.includes('empty_origin'));
    }
    expect(entry).toBeTruthy();
    expect(entry).toMatchObject({ action: 'csrf_origin_denied', success: false, statusCode: 403 });
    expect(entry.riskFactors).toEqual(['csrf_origin_violation', 'empty_origin']);
  });

  test('无 Origin 时从 Referer 提取 origin：命中白名单放行', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Referer', `${TEST_FRONTEND_ORIGIN_LOCALHOST}/login?redirect=%2F`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'POST' });
  });

  test('无 Origin 时从 Referer 提取 origin：非白名单 403', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Referer', `${EVIL_ORIGIN}/attack`);
    expect(res.status).toBe(403);
    expect(res.body.message).toBe('来源校验失败');
  });

  test('Referer 非法语法（不可解析为 URL）按无来源处理放行', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Referer', 'not-a-valid-url');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'POST' });
  });

  test('GET（非写方法）携带任意 Origin 放行', async () => {
    const res = await request(buildApp(WHITELIST)).get('/resource').set('Origin', EVIL_ORIGIN);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'GET' });
  });

  test('OPTIONS 预检跳过校验', async () => {
    const res = await request(buildApp(WHITELIST))
      .options('/resource')
      .set('Origin', EVIL_ORIGIN)
      .set('Access-Control-Request-Method', 'POST');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'OPTIONS' });
  });

  test('DELETE 属于写方法：非白名单 Origin 403，白名单 Origin 放行', async () => {
    const blocked = await request(buildApp(WHITELIST))
      .delete('/resource')
      .set('Origin', EVIL_ORIGIN);
    expect(blocked.status).toBe(403);
    const allowed = await request(buildApp(WHITELIST))
      .delete('/resource')
      .set('Origin', TEST_FRONTEND_ORIGIN_LOOPBACK);
    expect(allowed.status).toBe(200);
    // 白名单侧同样要验证「确实放行了 DELETE」而非被别的原因放行
    expect(allowed.body).toEqual({ success: true, method: 'DELETE' });
  });

  test('PUT / PATCH 与 POST 同口径：非白名单 403', async () => {
    // 两个方法都要验「拒绝来自来源校验这条路径」：403 在本模块只可能由
    // Origin 拒绝产生，但同文件其它 403 用例已证明文案是「来源校验失败」——
    // 此处逐方法点名文案，防 WRITE_METHODS 数组被误删 PUT/PATCH 后
    // 请求穿透到处理器（那时会是 200 而非 403，本断言同样能抓住）。
    const put = await request(buildApp(WHITELIST)).put('/resource').set('Origin', EVIL_ORIGIN);
    expect(put.status).toBe(403);
    expect(put.body).toEqual({ success: false, message: '来源校验失败' });
    const patch = await request(buildApp(WHITELIST)).patch('/resource').set('Origin', EVIL_ORIGIN);
    expect(patch.status).toBe(403);
    expect(patch.body).toEqual({ success: false, message: '来源校验失败' });
  });

  test('Origin 头存在时优先于 Referer（Origin 白名单命中即放行，无论 Referer）', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST)
      .set('Referer', `${EVIL_ORIGIN}/attack`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'POST' });
  });

  test('无参调用且当前为 development 时回退本地白名单：localhost:3001 放行、外部 Origin 403', async () => {
    const app = buildApp();
    const ok = await request(app).post('/resource').set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST);
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ success: true, method: 'POST' });
    const bad = await request(app).post('/resource').set('Origin', EVIL_ORIGIN);
    expect(bad.status).toBe(403);
    // 非白名单 403 必须点名「来源校验失败」：与其它 403 区分
    expect(bad.body).toEqual({ success: false, message: '来源校验失败' });
  });

  test('无参调用且当前为 staging 时不回退开发白名单：写来源 403', async () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevCorsOrigin = process.env.CORS_ORIGIN;
    process.env.NODE_ENV = 'staging';
    delete process.env.CORS_ORIGIN;
    // 只在隔离的模块注册表内加载 originCheck，让它拿到 staging 环境下求值的 config
    //（CORS_ORIGIN 已删除 → 无白名单可回退）。
    // 不能用 jest.resetModules()：它会清空**全局**模块注册表，使 originCheck 内部
    // 对 security / AuditLog 的惰性 require（originCheck → ./security →
    // ../models/AuditLog）落到全新副本，与 beforeAll 里 spy 的 AuditLog 脱钩——
    // 随机顺序下其它用例（如空 Origin 的审计留痕断言）便读不到自己的记录；
    // 新副本还会带上未连接的新 mongoose 实例。
    let isolatedCreateOriginCheck;
    jest.isolateModules(() => {
      isolatedCreateOriginCheck = require('../../middleware/originCheck').createOriginCheck;
    });
    try {
      const app = express();
      app.use(isolatedCreateOriginCheck());
      app.post('/resource', (_req, res) => res.json({ success: true }));

      const res = await request(app)
        .post('/resource')
        .set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST);
      expect(res.status).toBe(403);
      // 必须是「来源校验失败」这条本地拒绝路径，而不是别的 403
      expect(res.body.message).toBe('来源校验失败');
      expect(res.body.success).toBe(false);
    } finally {
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
      if (prevCorsOrigin === undefined) delete process.env.CORS_ORIGIN;
      else process.env.CORS_ORIGIN = prevCorsOrigin;
    }
  });
});
