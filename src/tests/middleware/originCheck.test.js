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
  });

  test('无 Origin 时从 Referer 提取 origin：命中白名单放行', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Referer', `${TEST_FRONTEND_ORIGIN_LOCALHOST}/login?redirect=%2F`);
    expect(res.status).toBe(200);
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
  });

  test('GET（非写方法）携带任意 Origin 放行', async () => {
    const res = await request(buildApp(WHITELIST)).get('/resource').set('Origin', EVIL_ORIGIN);
    expect(res.status).toBe(200);
  });

  test('OPTIONS 预检跳过校验', async () => {
    const res = await request(buildApp(WHITELIST))
      .options('/resource')
      .set('Origin', EVIL_ORIGIN)
      .set('Access-Control-Request-Method', 'POST');
    expect(res.status).toBe(200);
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
  });

  test('PUT / PATCH 与 POST 同口径：非白名单 403', async () => {
    const put = await request(buildApp(WHITELIST)).put('/resource').set('Origin', EVIL_ORIGIN);
    expect(put.status).toBe(403);
    const patch = await request(buildApp(WHITELIST)).patch('/resource').set('Origin', EVIL_ORIGIN);
    expect(patch.status).toBe(403);
  });

  test('Origin 头存在时优先于 Referer（Origin 白名单命中即放行，无论 Referer）', async () => {
    const res = await request(buildApp(WHITELIST))
      .post('/resource')
      .set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST)
      .set('Referer', `${EVIL_ORIGIN}/attack`);
    expect(res.status).toBe(200);
  });

  test('无参调用且当前为 development 时回退本地白名单：localhost:3001 放行、外部 Origin 403', async () => {
    const app = buildApp();
    const ok = await request(app).post('/resource').set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST);
    expect(ok.status).toBe(200);
    const bad = await request(app).post('/resource').set('Origin', EVIL_ORIGIN);
    expect(bad.status).toBe(403);
  });

  test('无参调用且当前为 staging 时不回退开发白名单：写来源 403', async () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevCorsOrigin = process.env.CORS_ORIGIN;
    process.env.NODE_ENV = 'staging';
    delete process.env.CORS_ORIGIN;
    jest.resetModules();
    const {
      createOriginCheck: isolatedCreateOriginCheck,
    } = require('../../middleware/originCheck');
    try {
      const app = express();
      app.use(isolatedCreateOriginCheck());
      app.post('/resource', (_req, res) => res.json({ success: true }));

      const res = await request(app)
        .post('/resource')
        .set('Origin', TEST_FRONTEND_ORIGIN_LOCALHOST);
      expect(res.status).toBe(403);
    } finally {
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
      if (prevCorsOrigin === undefined) delete process.env.CORS_ORIGIN;
      else process.env.CORS_ORIGIN = prevCorsOrigin;
      jest.resetModules();
    }
  });
});
