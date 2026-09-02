/**
 * 可观测性三件套测试（O-8 轮）
 *
 * - /metrics：Prometheus 文本格式（计数器/直方图/告警计数）
 * - /readyz：就绪探针（Mongo ping）
 * - sendNotification：投递矩阵（成功/重试/级别过滤/签名/SSRF 拒绝）
 */

const request = require('supertest');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

jest.mock('../../utils/httpPostJson', () => ({
  postJson: jest.fn(),
}));

const { postJson } = require('../../utils/httpPostJson');
const securityAlert = require('../../services/securityAlert');
const { formatPrometheus, _alertCounters } = require('../../utils/metrics');

describe('/metrics 与 /readyz（O-8）', () => {
  let app;
  let superToken;

  beforeAll(async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // /api/metrics 为管理面数据：造一个持 security:audit 的操作者
    const { randomPassword } = require('../helpers/buildLoginEnvelope');
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    const stamp = `obs${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_观测',
      code: `SUPER_ADMIN_OBS_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `obsadmin${stamp}`,
      email: `obsadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    superToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('GET /metrics 返回 Prometheus 文本格式，含 /health 的请求计数与直方图', async () => {
    // 先制造一次请求（/health 无需认证）
    await request(app).get('/health').expect(200);
    // /health 自身也被 metricsMiddleware 计数

    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');

    expect(res.text).toContain('# TYPE http_requests_total counter');
    // /health 的路由模板标签存在（route 是低基数模板而非原始 URL）
    expect(res.text).toMatch(/http_requests_total\{[^}]*route="\/health"[^}]*status_code="200"/);
    expect(res.text).toContain('# TYPE http_request_duration_seconds histogram');
    expect(res.text).toMatch(
      /http_request_duration_seconds_bucket\{[^}]*route="\/health"[^}]*le="0\.05"/
    );
    expect(res.text).toMatch(/http_request_duration_seconds_count\{[^}]*route="\/health"/);
  });

  test('未匹配路由（404）计入 unmatched 标签（防高基数）', async () => {
    await request(app).get('/no-such-route-xyz').expect(404);
    const res = await request(app).get('/metrics');
    expect(res.text).toMatch(/http_requests_total\{[^}]*route="unmatched"/);
  });

  test('GET /readyz：Mongo 可用返回 200 ready', async () => {
    const res = await request(app).get('/readyz');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
    expect(res.body.checks.mongo).toBe('ok');
    expect(res.body.timestamp).toBeTruthy();
  });

  test('GET /api/metrics（面板 JSON 半）：认证后返回 snapshot 结构', async () => {
    const res = await request(app).get('/api/metrics').set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const snap = res.body.data;
    expect(snap.summary.totalRequests).toBeGreaterThan(0);
    expect(typeof snap.summary.errorRate).toBe('number');
    expect(snap.latency).toBeTruthy();
    expect(snap.latency.byRoute['/health']).toBeTruthy();
    expect(Array.isArray(snap.routes)).toBe(true);
    // /health 的计数进入路由表
    expect(snap.routes.some((r) => r.route === '/health' && r.requests > 0)).toBe(true);
    expect(Array.isArray(snap.alerts)).toBe(true);
    expect(snap.process.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });

  test('GET /api/metrics：未认证 401（运行时指标不匿名暴露）', async () => {
    const res = await request(app).get('/api/metrics');
    expect(res.status).toBe(401);
  });
});

describe('sendNotification 投递矩阵（webhook 成熟化）', () => {
  const ENV_KEYS = [
    'SECURITY_ALERT_WEBHOOK',
    'SECURITY_ALERT_MIN_LEVEL',
    'SECURITY_ALERT_WEBHOOK_SECRET',
    'SECURITY_ALERT_WEBHOOK_ALLOWLIST',
  ];
  let savedEnv;

  beforeAll(() => {
    savedEnv = {};
    ENV_KEYS.forEach((k) => {
      savedEnv[k] = process.env[k];
    });
  });

  afterAll(() => {
    ENV_KEYS.forEach((k) => {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    });
  });

  beforeEach(() => {
    jest.clearAllMocks();
    _alertCounters.clear();
    delete process.env.SECURITY_ALERT_MIN_LEVEL;
    delete process.env.SECURITY_ALERT_WEBHOOK_SECRET;
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
  });

  test('未配置 SECURITY_ALERT_WEBHOOK 时完全不投递', async () => {
    delete process.env.SECURITY_ALERT_WEBHOOK;
    await securityAlert.sendNotification('brute_force_login', 'critical', '测试');
    expect(postJson).not.toHaveBeenCalled();
  });

  test('低于最低级别（默认 high）的告警只记日志不投递', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    await securityAlert.sendNotification('unusual_time_access', 'medium', '测试');
    expect(postJson).not.toHaveBeenCalled();
  });

  test('投递成功：一次性调用（无重试），body 为钉钉兼容结构', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    postJson.mockResolvedValueOnce({ ok: true, status: 200 });

    await securityAlert.sendNotification('brute_force_login', 'critical', '检测到爆破', {
      username: 'u1',
    });

    expect(postJson).toHaveBeenCalledTimes(1);
    const [url, headers, body] = postJson.mock.calls[0];
    expect(url).toBe('https://hooks.example.com/hook');
    const parsed = JSON.parse(body);
    expect(parsed.msgtype).toBe('text');
    expect(parsed.alert.type).toBe('brute_force_login');
    expect(parsed.alert.username).toBe('u1');
    // Content-Type 由 httpPostJson 统一补发，此处未配置密钥时应无签名头
    expect(headers['X-Webhook-Signature']).toBeUndefined();
  });

  test('首次失败自动重试，第二次成功（共 2 次调用）', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    postJson
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce({ ok: true, status: 200 });

    await securityAlert.sendNotification('bulk_data_export', 'high', '批量导出');

    expect(postJson).toHaveBeenCalledTimes(2);
  });

  test('配置 SECURITY_ALERT_WEBHOOK_SECRET 时携带 HMAC 签名头', async () => {
    const secret = 'test-webhook-secret';
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    process.env.SECURITY_ALERT_WEBHOOK_SECRET = secret;
    postJson.mockResolvedValueOnce({ ok: true, status: 200 });

    await securityAlert.sendNotification('brute_force_login', 'critical', '签名测试');

    const [, headers, body] = postJson.mock.calls[0];
    const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
    expect(headers['X-Webhook-Signature']).toBe(expected);
  });

  test('SSRF 防护：本机/私网 IP 字面量/非 http 协议/白名单外主机 一律不投递', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'http://127.0.0.1/hook';
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).not.toHaveBeenCalled();

    process.env.SECURITY_ALERT_WEBHOOK = 'http://192.168.1.5/hook';
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).not.toHaveBeenCalled();

    process.env.SECURITY_ALERT_WEBHOOK = 'http://10.0.0.8/hook';
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).not.toHaveBeenCalled();

    process.env.SECURITY_ALERT_WEBHOOK = 'ftp://hooks.example.com/hook';
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).not.toHaveBeenCalled();

    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'other-host.example.com';
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).not.toHaveBeenCalled();

    // 白名单命中时放行
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'hooks.example.com';
    postJson.mockResolvedValueOnce({ ok: true, status: 200 });
    await securityAlert.sendNotification('brute_force_login', 'critical', 't');
    expect(postJson).toHaveBeenCalledTimes(1);
  });

  test('告警计入 security_alerts_total 指标（含失败投递）', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://hooks.example.com/hook';
    postJson.mockRejectedValue(new Error('down'));

    await securityAlert.sendNotification('brute_force_login', 'critical', '指标测试');

    const prom = formatPrometheus();
    expect(prom).toMatch(/security_alerts_total\{type="brute_force_login",level="critical"\} 1/);
  });
});
