const mongoose = require('mongoose');

jest.mock('../../utils/httpPostJson', () => ({
  postJson: jest.fn(),
}));

describe('securityAlert delivery and failure guards', () => {
  let securityAlert;
  let postJson;
  let AuditLog;
  const originalWebhook = process.env.SECURITY_ALERT_WEBHOOK;
  const originalAllowlist = process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
  const originalConcurrency = process.env.SECURITY_ALERT_MAX_CONCURRENT;

  beforeAll(() => {
    process.env.SECURITY_ALERT_MAX_CONCURRENT = '1';
    securityAlert = require('../../services/securityAlert');
    postJson = require('../../utils/httpPostJson').postJson;
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    if (originalWebhook === undefined) delete process.env.SECURITY_ALERT_WEBHOOK;
    else process.env.SECURITY_ALERT_WEBHOOK = originalWebhook;
    if (originalAllowlist === undefined) delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    else process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = originalAllowlist;
    if (originalConcurrency === undefined) delete process.env.SECURITY_ALERT_MAX_CONCURRENT;
    else process.env.SECURITY_ALERT_MAX_CONCURRENT = originalConcurrency;

    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    postJson.mockClear();
    postJson.mockResolvedValue({ ok: true });
    process.env.SECURITY_ALERT_WEBHOOK = 'https://alerts.example.com/hook';
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
  });

  test('skips malformed and non-http endpoints before making a request', async () => {
    const urls = ['not-a-url', 'ftp://alerts.example.com/hook'];
    for (const url of urls) {
      process.env.SECURITY_ALERT_WEBHOOK = url;
      await securityAlert.sendNotification('brute_force_login', 'critical', 'blocked', {});
    }
    expect(postJson).not.toHaveBeenCalled();
  });

  test('blocks local and private webhook destinations', async () => {
    const urls = ['http://localhost/hook', 'http://192.168.1.10/hook'];
    for (const url of urls) {
      process.env.SECURITY_ALERT_WEBHOOK = url;
      await securityAlert.sendNotification('brute_force_login', 'critical', 'blocked', {});
    }
    expect(postJson).not.toHaveBeenCalled();
  });

  test('rejects a public host that is not on the configured allowlist', async () => {
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'other.example.com';
    await securityAlert.sendNotification('brute_force_login', 'critical', 'blocked', {});
    expect(postJson).not.toHaveBeenCalled();
  });

  test('delivers an allowed high-level alert with a request body', async () => {
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'alerts.example.com';
    await securityAlert.sendNotification('brute_force_login', 'high', 'attack', {
      username: 'alice',
    });
    expect(postJson).toHaveBeenCalledTimes(1);
    const [url, headers, body] = postJson.mock.calls[0];
    expect(url).toBe('https://alerts.example.com/hook');
    expect(body).toContain('attack');
    expect(headers).toEqual({});
  });

  test('does not exceed the configured concurrent delivery limit', async () => {
    let release;
    postJson.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        })
    );

    const pending = securityAlert.sendNotification('brute_force_login', 'high', 'pending', {});
    expect(postJson).toHaveBeenCalledTimes(1);

    await securityAlert.sendNotification('brute_force_login', 'high', 'skipped', {});
    expect(postJson).toHaveBeenCalledTimes(1);

    release({ ok: true });
    await pending;
  });

  test('returns a zeroed overview when metrics aggregation fails', async () => {
    const spy = jest.spyOn(AuditLog, 'countDocuments').mockRejectedValue(new Error('db down'));
    const overview = await securityAlert.getSecurityOverview(7);
    expect(overview).toEqual({
      period: expect.stringContaining('7'),
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    });
    spy.mockRestore();
  });

  test('retries once after a non-2xx delivery response', async () => {
    postJson
      .mockResolvedValueOnce({ ok: false, status: 500 })
      .mockResolvedValueOnce({ ok: true, status: 200 });
    await securityAlert.sendNotification('brute_force_login', 'high', 'retry', {});
    expect(postJson).toHaveBeenCalledTimes(2);
  });
});
