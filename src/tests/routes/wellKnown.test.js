/**
 * 公共发现端点测试（G9 CSP 上报 / G10 security.txt / G-1 前端异常上报）
 * 覆盖：security.txt 契约字段 / 两种上报格式归一化 / 空上报不落日志 / 大体积上报拒绝 /
 *       client-errors 落日志与 Sentry 转发门禁
 */

const express = require('express');
const request = require('supertest');

jest.mock('../../middleware/sentry', () => ({
  captureException: jest.fn(),
  isSentryInitialized: jest.fn(() => false),
}));

describe('wellKnownRoutes 公共发现端点', () => {
  const buildApp = () => {
    jest.resetModules();
    const router = require('../../routes/wellKnownRoutes');
    const app = express();
    // 与 app.js 同口径：全局 JSON 解析器先于路由（/csp-report 另有专用解析器不受影响）
    app.use(express.json({ limit: '1mb' }));
    app.use('/', router);
    return app;
  };

  describe('GET /.well-known/security.txt（G10）', () => {
    test('返回 text/plain 且包含 RFC 9116 必需字段', async () => {
      const res = await request(buildApp()).get('/.well-known/security.txt');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/plain/);
      expect(res.text).toMatch(/^Contact: mailto:/m);
      expect(res.text).toMatch(/^Expires: /m);
      expect(res.text).toMatch(/^Canonical: /m);
    });

    test('Expires 为将来时间且不超过一年（RFC 9116 约束）', async () => {
      const res = await request(buildApp()).get('/.well-known/security.txt');
      const expires = new Date(res.text.match(/^Expires: (.+)$/m)[1]).getTime();
      const now = Date.now();
      expect(expires).toBeGreaterThan(now);
      expect(expires - now).toBeLessThanOrEqual(365 * 24 * 60 * 60 * 1000);
    });

    test('Contact 取环境变量 SECURITY_CONTACT_EMAIL', async () => {
      const original = process.env.SECURITY_CONTACT_EMAIL;
      process.env.SECURITY_CONTACT_EMAIL = 'sec@fire.example';
      const res = await request(buildApp()).get('/.well-known/security.txt');
      expect(res.text).toContain('Contact: mailto:sec@fire.example');
      if (original === undefined) delete process.env.SECURITY_CONTACT_EMAIL;
      else process.env.SECURITY_CONTACT_EMAIL = original;
    });

    test('根路径 /security.txt 同样可访问（规范过渡位置）', async () => {
      const res = await request(buildApp()).get('/security.txt');
      expect(res.status).toBe(200);
      expect(res.text).toMatch(/^Contact: /m);
    });
  });

  describe('POST /csp-report（G9）', () => {
    test('Level 2 格式上报返回 204', async () => {
      const res = await request(buildApp())
        .post('/csp-report')
        .set('Content-Type', 'application/csp-report')
        .send(
          JSON.stringify({
            'csp-report': {
              'violated-directive': 'script-src',
              'blocked-uri': 'https://evil.example/x.js',
              'document-uri': 'https://app.example/page',
            },
          })
        );
      expect(res.status).toBe(204);
    });

    test('Reporting API 数组格式上报返回 204', async () => {
      const res = await request(buildApp())
        .post('/csp-report')
        .set('Content-Type', 'application/reports+json')
        .send(
          JSON.stringify([
            {
              type: 'csp-violation',
              body: { effectiveDirective: 'img-src', blockedURL: 'data:image/png;base64,AAA' },
            },
          ])
        );
      expect(res.status).toBe(204);
    });

    test('空体/畸形体同样返回 204（不给客户端二次噪音）', async () => {
      const app = buildApp();
      const empty = await request(app)
        .post('/csp-report')
        .set('Content-Type', 'application/json')
        .send('{}');
      expect(empty.status).toBe(204);
    });

    test('超过 16kb 的上报体被拒绝', async () => {
      const huge = JSON.stringify({ 'csp-report': { 'blocked-uri': 'x'.repeat(20000) } });
      const res = await request(buildApp())
        .post('/csp-report')
        .set('Content-Type', 'application/csp-report')
        .send(huge);
      expect(res.status).toBe(413);
    });
  });

  describe('POST /client-errors（G-1 前端异常上报）', () => {
    afterEach(() => jest.restoreAllMocks());

    const entry = (over = {}) => ({
      t: new Date().toISOString(),
      kind: 'vue',
      message: 'render boom',
      stack: 'Error: render boom',
      url: 'https://app.example/page',
      count: 1,
      ...over,
    });

    test('异常条目返回 204 并落 warn；未初始化 Sentry 时不转发', async () => {
      const app = buildApp();
      const loggerNow = require('../../utils/logger');
      const sentryNow = require('../../middleware/sentry');
      sentryNow.isSentryInitialized.mockReturnValue(false);
      const warnSpy = jest.spyOn(loggerNow, 'warn').mockImplementation(() => {});

      const res = await request(app)
        .post('/client-errors')
        .send({ source: 'web-admin', entries: [entry()] });

      expect(res.status).toBe(204);
      expect(warnSpy).toHaveBeenCalledWith(
        '前端异常上报',
        expect.objectContaining({ kind: 'vue', message: 'render boom' })
      );
      expect(sentryNow.captureException).not.toHaveBeenCalled();
    });

    test('Sentry 已初始化时异常条目转发（带页面上下文），vitals 走 info 且不转发', async () => {
      const app = buildApp();
      const loggerNow = require('../../utils/logger');
      const sentryNow = require('../../middleware/sentry');
      sentryNow.isSentryInitialized.mockReturnValue(true);
      jest.spyOn(loggerNow, 'warn').mockImplementation(() => {});
      const infoSpy = jest.spyOn(loggerNow, 'info').mockImplementation(() => {});

      const res = await request(app)
        .post('/client-errors')
        .send({
          source: 'web-admin',
          entries: [
            entry({ message: 'caught it' }),
            entry({ kind: 'vitals', message: 'LCP=1234ms', stack: '' }),
          ],
        });

      expect(res.status).toBe(204);
      expect(sentryNow.captureException).toHaveBeenCalledTimes(1);
      const [err, ctx] = sentryNow.captureException.mock.calls[0];
      expect(err.message).toBe('[web-admin:vue] caught it');
      expect(ctx).toHaveProperty('pageUrl');
      expect(infoSpy).toHaveBeenCalledWith(
        'Web Vitals 上报',
        expect.objectContaining({ kind: 'vitals' })
      );
    });

    test('未知 kind 归一为 window；控制字符被清洗', async () => {
      const app = buildApp();
      const loggerNow = require('../../utils/logger');
      const warnSpy = jest.spyOn(loggerNow, 'warn').mockImplementation(() => {});

      await request(app)
        .post('/client-errors')
        .send({ entries: [entry({ kind: 'evil', message: 'line1\nline2' })] });

      const context = warnSpy.mock.calls[0][1];
      expect(context.kind).toBe('window');
      expect(context.message).not.toContain('\n');
    });

    test('畸形/空载荷一律 204，不落日志', async () => {
      const app = buildApp();
      const loggerNow = require('../../utils/logger');
      const warnSpy = jest.spyOn(loggerNow, 'warn').mockImplementation(() => {});

      expect((await request(app).post('/client-errors').send({})).status).toBe(204);
      expect((await request(app).post('/client-errors').send({ entries: 'nope' })).status).toBe(
        204
      );
      expect((await request(app).post('/client-errors').send({ entries: [] })).status).toBe(204);
      expect(warnSpy).not.toHaveBeenCalled();
    });

    test('单批超过 20 条只处理前 20 条（防日志放大）', async () => {
      const app = buildApp();
      const loggerNow = require('../../utils/logger');
      const warnSpy = jest.spyOn(loggerNow, 'warn').mockImplementation(() => {});

      await request(app)
        .post('/client-errors')
        .send({ entries: Array.from({ length: 30 }, (_, i) => entry({ message: `boom ${i}` })) });

      expect(warnSpy).toHaveBeenCalledTimes(20);
    });
  });

  describe('normalizeReport 归一化', () => {
    test('Level 2 优先取 effective-directive', () => {
      const { normalizeReport } = require('../../routes/wellKnownRoutes');
      const out = normalizeReport({
        'csp-report': {
          'effective-directive': 'script-src-elem',
          'violated-directive': 'script-src',
          'blocked-uri': 'inline',
        },
      });
      expect(out.directive).toBe('script-src-elem');
      expect(out.blockedUri).toBe('inline');
    });

    test('Reporting API 数组取首个含 body 的条目', () => {
      const { normalizeReport } = require('../../routes/wellKnownRoutes');
      const out = normalizeReport([
        { type: 'deprecation', body: null },
        { type: 'csp-violation', body: { effectiveDirective: 'style-src', blockedURL: 'inline' } },
      ]);
      expect(out.directive).toBe('style-src');
    });

    test('非法输入不抛异常', () => {
      const { normalizeReport } = require('../../routes/wellKnownRoutes');
      expect(() => normalizeReport(null)).not.toThrow();
      expect(() => normalizeReport(undefined)).not.toThrow();
      expect(() => normalizeReport('string')).not.toThrow();
      expect(normalizeReport(null).directive).toBeUndefined();
    });
  });
});
