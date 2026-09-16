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

/**
 * 构建挂载了 metricsAuth 的最小应用；token 显式传参以隔离环境变量
 *
 * @param token  METRICS_TOKEN（''=未配置）
 * @param peerIp 可选：模拟 TCP 对端地址。
 *
 * 【M-07 后测试口径变更】内网判定已从 req.ip（受 X-Forwarded-For 影响）
 * 改为 req.socket.remoteAddress（取自 TCP 连接，不可伪造）。因此**不能再
 * 用 X-Forwarded-For 模拟"来自公网"**——那正是被修复的绕过向量。改为
 * 覆写 socket.remoteAddress 来模拟真实对端；XFF 保留仅用于验证它已失效。
 */
function buildApp(token, peerIp) {
  const app = express();
  // 仍信任代理头：生产环境 TRUST_PROXY_HOPS 必然启用，需复现该前提
  app.set('trust proxy', true);
  if (peerIp) {
    app.use((req, _res, next) => {
      if (req.socket) {
        Object.defineProperty(req.socket, 'remoteAddress', {
          value: peerIp,
          configurable: true,
        });
      }
      next();
    });
  }
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
    const externalApp = buildApp('', '8.8.8.8');

    test('本机回环来源放行（supertest 默认 ::ffff:127.0.0.1，验证 mapped 解包）', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    test('公网来源 401 拒绝（fail-safe：Nginx 防线失守的应用层兜底）', async () => {
      const res = await request(externalApp).get('/metrics');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    // ==================== M-07 回归：XFF 不可再绕过内网判定 ====================
    // 修复前判定用 req.ip，而 req.ip 在 trust proxy 下采纳 X-Forwarded-For：
    // 直连 app 端口的攻击者发 `X-Forwarded-For: 127.0.0.1` 即被判为内网来源，
    // 跳过令牌校验，可读取 QPS/延迟/错误计数与安全告警计数（侦察面）。
    // 修复后判定改用 req.socket.remoteAddress（取自 TCP 连接，不可伪造）。
    test('M-07 - 伪造 X-Forwarded-For: 127.0.0.1 无法伪装内网（socket 为公网 → 401）', async () => {
      const res = await request(externalApp).get('/metrics').set('X-Forwarded-For', '127.0.0.1');
      expect(res.status).toBe(401);
    });

    test('M-07 - 反向验证：socket 为回环、XFF 为公网 → 仍放行（判定只看 socket）', async () => {
      const res = await request(app).get('/metrics').set('X-Forwarded-For', '8.8.8.8');
      expect(res.status).toBe(200);
    });
  });

  describe('中间件行为（配置 METRICS_TOKEN 后）', () => {
    const TOKEN = 'a'.repeat(64);
    const app = buildApp(TOKEN);
    const externalApp = buildApp(TOKEN, '8.8.8.8');

    test('外网来源 + 正确 Bearer 令牌放行（跨网段受控抓取）', async () => {
      const res = await request(externalApp)
        .get('/metrics')
        .set('Authorization', `Bearer ${TOKEN}`);
      expect(res.status).toBe(200);
    });

    test('外网来源 + 错误令牌 401', async () => {
      const res = await request(externalApp)
        .get('/metrics')
        .set('Authorization', `Bearer ${'b'.repeat(64)}`);
      expect(res.status).toBe(401);
    });

    test('外网来源 + 缺失令牌 401', async () => {
      const res = await request(externalApp).get('/metrics');
      expect(res.status).toBe(401);
    });

    test('令牌长度不等走短路路径，不抛错且 401（timingSafeEqual 仅接受等长）', async () => {
      const res = await request(externalApp)
        .get('/metrics')
        .set('Authorization', 'Bearer short-token');
      expect(res.status).toBe(401);
    });

    test('内网来源无令牌仍放行（保持容器网络抓取零配置兼容）', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
    });
  });
});
