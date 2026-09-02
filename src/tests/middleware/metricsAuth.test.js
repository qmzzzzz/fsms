/**
 * /metrics 应用层鉴权中间件测试（metricsAuth）
 *
 * 覆盖要点（对应可观测性审计改进项「/metrics 应用层纵深防护」）：
 * - isPrivateOrLoopback：回环/内网/IPv4-mapped IPv6/公网/非法值的段判定
 * - 中间件行为：内网放行（保持容器网络抓取零配置兼容）、公网拒绝（fail-safe）、
 *   可选 METRICS_TOKEN 的正确/错误/缺失分支、timingSafeEqual 长度不等路径
 *
 * 纯单测：不依赖数据库（globalSetup 的内存 Mongo 与本文件无交互）
 */

const express = require('express');
const request = require('supertest');
const { createMetricsAuth, isPrivateOrLoopback } = require('../../middleware/metricsAuth');
const logger = require('../../utils/logger');

/** 构建挂载了 metricsAuth 的最小应用；token 显式传参以隔离环境变量 */
function buildApp(token) {
  const app = express();
  // 信任代理头：用 X-Forwarded-For 模拟「来自公网 IP 的请求」
  app.set('trust proxy', true);
  app.get('/metrics', createMetricsAuth(token), (req, res) => {
    res.json({ ok: true });
  });
  return app;
}

describe('metricsAuth /metrics 应用层鉴权纵深', () => {
  beforeEach(() => {
    // 拒绝路径会记 warn 日志，测试中静默以免噪音
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('isPrivateOrLoopback 段判定', () => {
    test.each([
      ['127.0.0.1', true],
      ['::1', true],
      // trust proxy 关闭时 req.ip 常为 IPv4-mapped 形式，必须解包判定
      ['::ffff:127.0.0.1', true],
      ['192.168.1.5', true],
      ['10.0.0.3', true],
      ['172.16.0.9', true],
      ['fe80::1', true], // IPv6 link-local
      ['fd00::1', true], // IPv6 unique-local
      ['8.8.8.8', false],
      ['203.0.113.7', false],
      ['not-an-ip', false],
      ['', false],
      [null, false],
      [undefined, false],
    ])('%p → %p', (input, expected) => {
      expect(isPrivateOrLoopback(input)).toBe(expected);
    });
  });

  describe('中间件行为（未配置 token，退化为仅内网放行）', () => {
    const app = buildApp('');

    test('本机回环来源放行（supertest 默认 ::ffff:127.0.0.1，验证 mapped 解包）', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    test('公网来源 401 拒绝（fail-safe：Nginx 防线失守的应用层兜底）', async () => {
      const res = await request(app).get('/metrics').set('X-Forwarded-For', '8.8.8.8');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    test('非法 X-Forwarded-For 视为不确定来源 → 拒绝', async () => {
      const res = await request(app).get('/metrics').set('X-Forwarded-For', 'not-an-ip');
      expect(res.status).toBe(401);
    });
  });

  describe('中间件行为（配置 METRICS_TOKEN 后）', () => {
    const TOKEN = 'a'.repeat(64);
    const app = buildApp(TOKEN);

    test('外网来源 + 正确 Bearer 令牌放行（跨网段受控抓取）', async () => {
      const res = await request(app)
        .get('/metrics')
        .set('X-Forwarded-For', '8.8.8.8')
        .set('Authorization', `Bearer ${TOKEN}`);
      expect(res.status).toBe(200);
    });

    test('外网来源 + 错误令牌 401', async () => {
      const res = await request(app)
        .get('/metrics')
        .set('X-Forwarded-For', '8.8.8.8')
        .set('Authorization', `Bearer ${'b'.repeat(64)}`);
      expect(res.status).toBe(401);
    });

    test('外网来源 + 缺失令牌 401', async () => {
      const res = await request(app).get('/metrics').set('X-Forwarded-For', '8.8.8.8');
      expect(res.status).toBe(401);
    });

    test('令牌长度不等走短路路径，不抛错且 401（timingSafeEqual 仅接受等长）', async () => {
      const res = await request(app)
        .get('/metrics')
        .set('X-Forwarded-For', '8.8.8.8')
        .set('Authorization', 'Bearer short-token');
      expect(res.status).toBe(401);
    });

    test('内网来源无令牌仍放行（保持容器网络抓取零配置兼容）', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
    });
  });
});
