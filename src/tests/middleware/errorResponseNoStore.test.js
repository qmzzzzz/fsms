/**
 * 错误响应一律 Cache-Control: no-store（2026-11-01 参考研读 P0-1）
 *
 * 缺陷形态（修复前）：错误出口不设任何缓存头。401/403/429 这类鉴权与频控结论若被
 * 浏览器或反向代理按启发式缓存，下一个同 URL 的合法请求会命中缓存的失败结论——
 * 参考项目 Nu11Cyber 的 response.ts 对 error 出口统一 no-store，正是堵这一类。
 *
 * 三条出口统一口径：
 *   1. ApiResponse.error（codeError/unauthorized/forbidden/notFound/serverError 全部汇入）；
 *   2. errorHandler.respondApiError（errorHandler 里唯一的裸 res.status().json() 错误出口）；
 *   3. app.js 的 404 JSON 兜底（集成断言在文末，走真实 createApp）。
 *
 * 成功路径不受影响：本组用例同时验证 success 出口**不带** no-store，
 * 防止「顺手全站加头」把可缓存的公共发现端点（security.txt max-age=86400）一起打死。
 */

const express = require('express');
const request = require('supertest');
const mongoose = require('mongoose');

const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/ApiError');
const errorHandler = require('../../middleware/errorHandler');

describe('错误响应 Cache-Control: no-store（P0-1）', () => {
  const makeRes = () => {
    const res = {
      headers: {},
      statusCode: null,
      body: null,
      setHeader(name, value) {
        this.headers[name.toLowerCase()] = value;
        return this;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      },
    };
    return res;
  };

  test('ApiResponse.error 置 no-store（unauthorized/forbidden/notFound/serverError 同一汇入点）', () => {
    for (const call of [
      () => ApiResponse.error(makeRes(), 'x', 400),
      () => ApiResponse.unauthorized(makeRes()),
      () => ApiResponse.forbidden(makeRes()),
      () => ApiResponse.notFound(makeRes()),
      () => ApiResponse.serverError(makeRes()),
      () => ApiResponse.codeError(makeRes(), 'AUTH_TOKEN_MISSING'),
    ]) {
      const res = call();
      expect(res.headers['cache-control']).toBe('no-store');
    }
  });

  test('ApiResponse.success 不携带 no-store（可缓存端点不受牵连）', () => {
    const res = ApiResponse.success(makeRes(), { ok: 1 });
    expect(res.headers['cache-control']).toBeUndefined();
  });

  test('errorHandler 真实链路：ApiError 400 与未知错误 500 均置 no-store', async () => {
    const app = express();
    app.get('/api-err', (_req, _res, next) => next(new ApiError('业务失败', 400)));
    app.get('/unknown-err', (_req, _res, next) => next(new Error('boom')));
    app.use(errorHandler);

    const apiErr = await request(app).get('/api-err');
    expect(apiErr.status).toBe(400);
    expect(apiErr.headers['cache-control']).toBe('no-store');

    // 未知错误路径走 logUnhandledError → codeError(INTERNAL_ERROR)，同样必须 no-store；
    // 同时压制本用例的 error 日志噪音
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const unknown = await request(app).get('/unknown-err');
      expect(unknown.status).toBe(500);
      expect(unknown.headers['cache-control']).toBe('no-store');
    } finally {
      errSpy.mockRestore();
    }
  });

  describe('真实 app 的 404 JSON 兜底（app.js installStaticAndErrorHandling）', () => {
    let app;
    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      const { createApp } = require('../../app');
      app = createApp();
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test('未命中任何路由的 JSON 404 携带 no-store', async () => {
      const res = await request(app).get('/definitely-not-a-route-20261101');
      expect(res.status).toBe(404);
      expect(res.headers['cache-control']).toBe('no-store');
      // 响应体仍是 JSON 信封而非 SPA HTML（静态面未构建时直接落到 404 兜底）
      expect(res.body.success).toBe(false);
    });
  });
});
