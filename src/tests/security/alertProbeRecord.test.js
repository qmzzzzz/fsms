/**
 * 告警投递探针的判据与执行器（F-09，2026-10-17）
 *
 * 缺陷本体：`ALERT_WEBHOOK_CHECK=production` 只能判"配置里还是占位 URL"，
 * 判不出"配了真实地址但打不通"。而合规检查里 SIEM 未配置时原文写的是
 * 「关闭状态（不计为缺陷，也不计为已具备）」⇒ 生产完全没接 SIEM 也判绿。
 *
 * 本套件钉三件事：
 *   ① 探针记录的四档判定（missing / invalid / failed / stale / queued-unacked / ok），
 *      尤其"入队成功但没人核对"**不得**被当成"已验证"；
 *   ② SIEM 三态（ready / misconfigured / unconfigured），未配置是 notReady 而不是绿；
 *   ③ 探针执行器真的能发出去并留下证据——用本地 http server 收 POST，
 *      不用子进程（jest 里 shell-out 会被沙箱拦，那类红与本判据无关）。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const {
  evaluateProbeRecord,
  evaluateSiemShipping,
  PROBE_WINDOW_HOURS,
} = require('../../../scripts/alertProbeRecord');
const {
  parseArgs,
  buildProbeAlert,
  postAlerts,
} = require('../../../scripts/alert-delivery-probe');

const NOW = Date.parse('2026-10-17T12:00:00Z');
const hoursAgo = (h) => new Date(NOW - h * 3600000).toISOString();

/** 一份"投递成功且已人工确认"的合法记录 */
const okRecord = (over = {}) => ({
  probedAt: hoursAgo(2),
  target: 'http://127.0.0.1:9093',
  correlationId: 'c0ffee00-0000-4000-8000-000000000000',
  ok: true,
  statusCode: 200,
  acknowledgedBy: '值班-张三',
  acknowledgedAt: hoursAgo(1),
  ...over,
});

describe('F-09 探针记录的四档判定', () => {
  test('没有记录 ⇒ missing（不判"链路坏了"，判"没有证据"）', () => {
    const v = evaluateProbeRecord({ record: null, now: NOW });
    expect(v.state).toBe('missing');
    expect(v.ok).toBe(false);
    expect(v.detail).toContain('没有任何实证');
  });

  test('记录缺字段 / 时间非法 ⇒ invalid（不能当成"验过"）', () => {
    expect(evaluateProbeRecord({ record: { probedAt: hoursAgo(1) }, now: NOW }).state).toBe(
      'invalid'
    );
    const bad = evaluateProbeRecord({ record: okRecord({ probedAt: 'not-a-date' }), now: NOW });
    expect(bad.state).toBe('invalid');
    expect(bad.detail).toContain('不是合法时间');
  });

  test('最近一次失败 ⇒ failed（优先于时效判定：失败比过期更严重）', () => {
    const v = evaluateProbeRecord({
      record: okRecord({ ok: false, error: 'ECONNREFUSED', probedAt: hoursAgo(500) }),
      now: NOW,
    });
    expect(v.state).toBe('failed');
    expect(v.detail).toContain('ECONNREFUSED');
  });

  test('超过窗口 ⇒ stale；窗口内 ⇒ 继续往下判', () => {
    expect(
      evaluateProbeRecord({ record: okRecord({ probedAt: hoursAgo(200) }), now: NOW }).state
    ).toBe('stale');
    expect(
      evaluateProbeRecord({ record: okRecord({ probedAt: hoursAgo(100) }), now: NOW }).state
    ).toBe('ok');
  });

  test('入队成功但未人工核对 ⇒ queued-unacked（**不得**判成已验证）', () => {
    const v = evaluateProbeRecord({
      record: okRecord({ acknowledgedBy: null, acknowledgedAt: null }),
      now: NOW,
    });
    expect(v.state).toBe('queued-unacked');
    expect(v.ok).toBe(false);
    // 文案必须把"入队成功 ≠ 有人收到"说清楚，否则读的人会以为验过了
    expect(v.detail).toContain('入队成功 ≠ 有人收到');
    expect(v.detail).toContain('correlationId=');
  });

  test('窗口常量是 7 天（改小会让每次巡检都刷测试告警，改大会放过已失效的 token）', () => {
    expect(PROBE_WINDOW_HOURS).toBe(168);
  });
});

describe('F-09 SIEM 三态：未配置是 notReady 而不是绿', () => {
  test('已配置且 transport 可用 ⇒ ready，既 passed 也不 notReady', () => {
    const v = evaluateSiemShipping({ urlConfigured: true, transportAvailable: true });
    expect(v).toMatchObject({ state: 'ready', passed: true, notReady: false });
  });

  test('已配置但 transport 不可用 ⇒ 红（配置与实现不符）', () => {
    const v = evaluateSiemShipping({ urlConfigured: true, transportAvailable: false });
    expect(v).toMatchObject({ state: 'misconfigured', passed: false, notReady: true });
  });

  test('未配置 ⇒ passed 仍为 true，但 notReady=true（修前这里是"关闭状态、不计缺陷"）', () => {
    const v = evaluateSiemShipping({ urlConfigured: false, transportAvailable: true });
    expect(v).toMatchObject({ state: 'unconfigured', passed: true, notReady: true });
    expect(v.detail).toContain('外部 SIEM 不可见');
  });

  test('显式豁免 ⇒ 仍是 notReady（留痕），但文案写明已豁免', () => {
    const v = evaluateSiemShipping({
      urlConfigured: false,
      transportAvailable: true,
      allowUnconfigured: true,
    });
    expect(v.notReady).toBe(true);
    expect(v.detail).toContain('ALLOW_UNCONFIGURED_LOG_SHIPPING=true');
  });
});

describe('F-09 探针执行器：参数严格性', () => {
  test('未知参数 / 缺值一律拒绝（拼错的 --ack 会静默变成投递，在群里刷测试告警）', () => {
    expect(parseArgs(['--bogus']).errors[0]).toContain('未知参数');
    expect(parseArgs(['--url']).errors).toContain('--url 缺少参数');
    expect(parseArgs(['--ack', '--url', 'x']).errors).toContain('--ack 缺少参数');
    expect(parseArgs(['--timeout-ms', 'abc']).errors[0]).toContain('不是正整数');
    expect(parseArgs(['--timeout-ms', '0']).errors[0]).toContain('不是正整数');
  });

  test('默认目标与超时', () => {
    const { args, errors } = parseArgs([]);
    expect(errors).toEqual([]);
    expect(args.url).toBe('http://127.0.0.1:9093');
    expect(args.timeoutMs).toBe(5000);
  });
});

describe('F-09 探针告警内容：必须写明"这是探针"', () => {
  test('labels 与 annotations 都带探针标记（避免值班误当真实故障）', () => {
    const [alert] = buildProbeAlert('abc-123', new Date('2026-10-17T12:00:00Z'));
    expect(alert.labels).toMatchObject({ alertname: 'FsmsDeliveryProbe', probe: 'true' });
    expect(alert.labels.probe_id).toBe('abc-123');
    expect(alert.annotations.summary).toContain('探针');
    expect(alert.annotations.description).toContain('abc-123');
    expect(alert.annotations.description).toContain('不是真实故障');
    // 不得带任何业务/身份字段：探针要能贴到任何环境而不泄露信息
    expect(JSON.stringify(alert)).not.toMatch(/password|token|user|email/i);
  });
});

describe('F-09 探针执行器：真发一次（本地 http server 收 POST）', () => {
  let server;
  let received;
  let status = 200;
  let baseUrl;

  beforeAll(
    () =>
      new Promise((resolve) => {
        server = http.createServer((req, res) => {
          const chunks = [];
          req.on('data', (c) => chunks.push(c));
          req.on('end', () => {
            received = { url: req.url, body: Buffer.concat(chunks).toString('utf8') };
            res.statusCode = status;
            res.end(status === 200 ? '' : 'rejected');
          });
        });
        server.listen(0, '127.0.0.1', () => {
          baseUrl = `http://127.0.0.1:${server.address().port}`;
          resolve();
        });
      })
  );
  afterAll(() => new Promise((resolve) => server.close(resolve)));
  beforeEach(() => {
    received = null;
    status = 200;
  });

  test('POST /api/v2/alerts，2xx ⇒ ok，body 里带 correlationId', async () => {
    const r = await postAlerts(baseUrl, buildProbeAlert('id-1'), 2000);
    expect(r.ok).toBe(true);
    expect(r.statusCode).toBe(200);
    expect(received.url).toBe('/api/v2/alerts');
    expect(received.body).toContain('FsmsDeliveryProbe');
    expect(received.body).toContain('id-1');
  });

  test('非 2xx ⇒ ok=false 且带响应体片段（排障要知道 Alertmanager 说什么）', async () => {
    status = 500;
    const r = await postAlerts(baseUrl, buildProbeAlert('id-2'), 2000);
    expect(r.ok).toBe(false);
    expect(r.statusCode).toBe(500);
    expect(r.error).toContain('rejected');
  });

  test('目标不可达 ⇒ ok=false 且错误可读（不是静默成功）', async () => {
    // 端口 1 上不会有服务；超时设短一点，避免测试挂住
    const r = await postAlerts('http://127.0.0.1:1', buildProbeAlert('id-3'), 800);
    expect(r.ok).toBe(false);
    expect(String(r.error).length).toBeGreaterThan(0);
  });
});

describe('F-09 探针记录落盘（判据读的是文件，不是内存）', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'alert-probe-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('记录文件缺失 ⇒ alertProbeVerdict 判 missing 且 notReady', () => {
    const { alertProbeVerdict } = require('../../../scripts/complianceVerdicts');
    const v = alertProbeVerdict({ recordPath: path.join(dir, 'nope.json') });
    expect(v.passed).toBe(true); // 没有证据 ≠ 链路坏了
    expect(v.notReady).toBe(true); // 但部署门禁要拦
    expect(v.detail).toContain('从未执行过');
  });

  test('记录损坏（非 JSON）⇒ 同样落到 missing 分支，不抛', () => {
    const { alertProbeVerdict } = require('../../../scripts/complianceVerdicts');
    const file = path.join(dir, 'broken.json');
    fs.writeFileSync(file, '{not json');
    expect(() => alertProbeVerdict({ recordPath: file })).not.toThrow();
    expect(alertProbeVerdict({ recordPath: file }).notReady).toBe(true);
  });

  test('记录为"已确认成功" ⇒ passed 且 notReady=false', () => {
    const { alertProbeVerdict } = require('../../../scripts/complianceVerdicts');
    const file = path.join(dir, 'ok.json');
    fs.writeFileSync(file, JSON.stringify(okRecord({ probedAt: new Date().toISOString() })));
    const v = alertProbeVerdict({ recordPath: file });
    expect(v.passed).toBe(true);
    expect(v.notReady).toBe(false);
  });
});
