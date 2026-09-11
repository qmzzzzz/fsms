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
  });
});
