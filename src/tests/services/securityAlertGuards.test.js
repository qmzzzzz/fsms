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

  test('checkBulkExport：告警审计落库失败不冒泡（不得把导出主流程顶成 500），且仍投递通知', async () => {
    // P1-23 同口径回归：checkBulkExport 被 reportController/auditController 的导出路径
    // `await`，其内部 AuditLog.create 若抛错必须被吞（记 error），否则一次 DB 瞬断就会让
    // 本已成功的导出返 500。pre-fix（裸 await create）→ 本用例 rejects → 红。
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'alerts.example.com';
    const spy = jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('db down'));
    await expect(
      securityAlert.checkBulkExport('bulkexport-fail-user', 'alice', 999, 'report_export_alarms')
    ).resolves.toBeUndefined();
    // 告警通知仍应尽力投递（fire-and-forget，flush 两个宏任务让 postJson 落地）
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(postJson).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });
});

/**
 * SSRF 白名单的纯函数表测。
 *
 * 为什么必须是纯函数表测而不是"起个本地服务打一发"：告警投递的目标校验是一次
 * 性的解析+分类判定，任何"这条地址算不算内网"的表达方式（IPv6 方括号、
 * IPv4 映射、CGNAT、保留段）都要当 case 钉住；走真实网络只能验证其中一种形态，
 * 而漏掉的形态正是绕过点。本次改动实测就抓到两处：
 *   1) `new URL('http://[::1]/').hostname` 保留方括号 → 旧代码的
 *      /^[0-9a-f.:]+$/ 不匹配 → **整段网域检查被跳过**（环回/ULA/linkLocal 全放行）；
 *   2) IPv4 映射地址 ::ffff:127.0.0.1 在 ipaddr.js 里 range() 是 'ipv4Mapped'，
 *      不在禁列表里 → 同样放行。
 * 反过来也钉住一条"看着像绕过其实已被防住"：十进制/十六进制/八进制 IPv4 会被
 * WHATWG URL 归一化成点分十进制，所以不需要额外代码——把它写成用例是为了
 * 下次有人"顺手加固"时知道这条已经成立。
 */
describe('isWebhookTargetAllowed：SSRF 目标判定表', () => {
  // 必须**延迟到用例内**再 require：describe 体内 require 会在"收集阶段"就加载
  // 该模块，而 securityAlertDelivery 的 MAX_ACTIVE_DELIVERIES 是在模块加载期
  // 从 process.env 取的——那时上面 beforeAll 里的 SECURITY_ALERT_MAX_CONCURRENT='1'
  // 还没设上，并发上限会退化成默认值，把上面那条限并发用例带红（实测过）。
  const allowed = (url) =>
    require('../../services/securityAlertDelivery').isWebhookTargetAllowed(url);
  const originalAllowlist = process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;

  afterEach(() => {
    if (originalAllowlist === undefined) delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    else process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = originalAllowlist;
  });

  test.each([
    // --- 环回 ---
    ['http://127.0.0.1/hook', false],
    ['http://127.1.2.3/hook', false],
    ['http://localhost/hook', false],
    ['http://anything.localhost/hook', false],
    ['http://[::1]/hook', false],
    ['http://[::ffff:127.0.0.1]/hook', false],
    // URL 归一化已覆盖的非点分 IPv4 形态（结论：全部落到 127.0.0.1 而被拦）
    ['http://2130706433/hook', false],
    ['http://0x7f000001/hook', false],
    ['http://0177.0.0.1/hook', false],
    // --- 链路本地 / 云元数据 ---
    ['http://169.254.169.254/latest/meta-data/', false],
    ['http://[fe80::1]/hook', false],
    ['http://0.0.0.0/hook', false],
    // --- 私网 / ULA / CGNAT / 保留 ---
    ['http://10.1.2.3/hook', false],
    ['http://192.168.0.7/hook', false],
    ['http://172.16.5.5/hook', false],
    ['http://[fd00::1234]/hook', false],
    ['http://100.64.0.1/hook', false],
    ['http://240.0.0.1/hook', false],
    // --- 协议与畸形输入 ---
    ['not-a-url', false],
    ['ftp://alerts.example.com/hook', false],
    ['file:///etc/passwd', false],
    ['gopher://127.0.0.1:11211/_', false],
    // --- 公网目标放行 ---
    ['https://alerts.example.com/hook', true],
    ['https://hooks.slack.com/services/T/B/X', true],
    ['http://93.184.216.34/hook', true],
    ['http://[2606:2800:220:1:248:1893:25c8:1946]/hook', true],
  ])('%s → %s', (url, expected) => {
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    expect(allowed(url)).toBe(expected);
  });

  test('白名单存在时是硬前置：白名单内的内网地址仍被后续网域检查拦下', () => {
    // 这条钉住"白名单 ≠ 放行一切"：加了白名单也不能把 127.0.0.1 送出去。
    // 若有人把顺序改成"命中白名单即 return true"，本用例必须红。
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = '127.0.0.1,internal.example.com';
    expect(allowed('http://127.0.0.1/hook')).toBe(false);
    expect(allowed('http://internal.example.com/hook')).toBe(true);
    expect(allowed('http://other.example.com/hook')).toBe(false);
  });

  // 已知缺口如实记账（不留"看起来全防住了"的错觉）：目标是**域名**时不做解析，
  // 所以 `internal.example.com → 127.0.0.1` 这类 DNS 重绑定/内网域名绕不过这一层。
  // 真正的收口需要"解析后按 IP 判 + 连接期绑定"，或干脆强制配白名单。
  test('已知上限：域名形态的内网目标当前不被拦截（记录待办，不得当作已防住）', () => {
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;
    expect(allowed('http://internal-metadata.example.com/hook')).toBe(true);
  });
});
