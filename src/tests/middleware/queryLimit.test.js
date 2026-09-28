/**
 * 查询参数长度限制中间件测试
 * 覆盖：正常放行 / 超长值拒绝并指明参数名 / 数组值逐项校验 / 自定义上限
 */

const express = require('express');
const request = require('supertest');

describe('queryLengthLimit 中间件', () => {
  const buildApp = (max) => {
    const queryLengthLimit = require('../../middleware/queryLimit');
    const app = express();
    app.get('/list', queryLengthLimit(max), (req, res) => {
      res.json({ success: true, query: req.query });
    });
    return app;
  };

  test('正常长度参数放行', async () => {
    const res = await request(buildApp()).get('/list?keyword=abc&page=1');
    expect(res.status).toBe(200);
    expect(res.body.query.keyword).toBe('abc');
  });

  test('恰好等于上限放行，超限拒绝（边界）', async () => {
    const app = buildApp(5);
    const ok = await request(app).get('/list?k=abcde');
    expect(ok.status).toBe(200);
    // 边界「恰好等于」必须原样透传（不是被截断后放行）
    expect(ok.body.query.k).toBe('abcde');
    const bad = await request(app).get('/list?k=abcdef');
    expect(bad.status).toBe(400);
  });

  test('超长参数拒绝并在响应中指明参数名与上限', async () => {
    const res = await request(buildApp()).get(`/list?keyword=${'a'.repeat(201)}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('keyword');
    expect(res.body.message).toContain('200');
  });

  test('数组型参数逐项校验：任一超长即拒绝', async () => {
    const res = await request(buildApp()).get(`/list?status=ok&status=${'x'.repeat(300)}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toContain('status');
  });

  test('无查询参数的请求直接放行', async () => {
    const res = await request(buildApp()).get('/list');
    expect(res.status).toBe(200);
    // 放行的判据是业务处理器真的执行了（req.query 为空对象）
    expect(res.body.query).toEqual({});
  });

  // 两处拒绝日志的 `url` 字段必须过 redactUrlQuery（同 app.js:236 morgan 的 safe-url、
  // errorHandler.js:26/100/107）。本中间件只在"参数可疑"时打日志，而未打码的
  // req.originalUrl 里正是攻击者可控、且常含凭据的那一段。
  describe('拒绝日志不得落明文凭据', () => {
    const SECRET = 'REAL_TOKEN_9f3a';
    const logger = require('../../utils/logger');
    let spy;
    beforeEach(() => {
      spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    });
    afterEach(() => spy.mockRestore());
    const loggedUrls = () =>
      spy.mock.calls
        .map((c) => c[1])
        .filter(Boolean)
        .map((m) => m.url);

    const buildScalarApp = () => {
      const { queryScalarGuard } = require('../../middleware/queryLimit');
      const app = express();
      // 必须与生产同形：app.js:123 显式把 query parser 设回 'extended'（Express 5 默认
      // 收窄为 simple，会让 `status[$ne]=1` 停在字符串上）。不设这行时本用例是**假绿**
      // ——中间件根本看不到对象形态，实测返回 200。
      app.set('query parser', 'extended');
      app.get('/list', queryScalarGuard(), (req, res) => res.json({ ok: true }));
      return app;
    };

    test('超长值分支：url 含敏感键时必须已被打码', async () => {
      const res = await request(buildApp()).get(`/list?accessToken=${SECRET}&k=${'a'.repeat(201)}`);
      expect(res.status).toBe(400);
      const urls = loggedUrls();
      expect(urls.length).toBeGreaterThan(0);
      for (const u of urls) {
        expect(u).not.toContain(SECRET);
        // 非敏感键必须原样保留，否则"打码"会变成整条 URL 丢弃而失去排障价值
        expect(u).toContain('k=');
        expect(u).toMatch(/accessToken=\*+/);
      }
    });

    test('非标量分支：url 含敏感键时必须已被打码', async () => {
      const res = await request(buildScalarApp()).get(`/list?status[$ne]=1&accessToken=${SECRET}`);
      expect(res.status).toBe(400);
      const urls = loggedUrls();
      expect(urls.length).toBeGreaterThan(0);
      for (const u of urls) {
        expect(u).not.toContain(SECRET);
        expect(u).toMatch(/accessToken=\*+/);
      }
    });
  });
});
