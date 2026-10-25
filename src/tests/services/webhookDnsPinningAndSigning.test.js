/**
 * 安全告警 webhook 出站加固：
 *   · 域名目标在投递前解析，任一 A/AAAA 落在禁止网段即整条拒绝；
 *   · 解析结果作为 lookup 传给 HTTP 客户端（连接期不再解析，防 DNS 重绑定）；
 *   · 签名覆盖「时间戳.随机数.请求体」，重放不能只靠 body 签名成立。
 */

const crypto = require('crypto');
const dns = require('dns');

jest.mock('../../utils/httpPostJson', () => ({ postJson: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const logger = require('../../utils/logger');
const { postJson } = require('../../utils/httpPostJson');
const { sendNotification } = require('../../services/securityAlertDelivery');

const WEBHOOK = 'https://hooks.example.com/hook';
const ENV_KEYS = [
  'SECURITY_ALERT_WEBHOOK',
  'SECURITY_ALERT_WEBHOOK_ALLOWLIST',
  'SECURITY_ALERT_MIN_LEVEL',
  'SECURITY_ALERT_WEBHOOK_SECRET',
  'SECURITY_ALERT_DNS_TIMEOUT_MS',
];

describe('webhook 域名解析与 IP 钉扎', () => {
  let savedEnv;
  let dnsLookup;

  beforeAll(() => {
    savedEnv = {};
    ENV_KEYS.forEach((key) => {
      savedEnv[key] = process.env[key];
    });
  });

  afterAll(() => {
    ENV_KEYS.forEach((key) => {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    });
  });

  beforeEach(() => {
    jest.clearAllMocks();
    postJson.mockResolvedValue({ ok: true, status: 200 });
    process.env.SECURITY_ALERT_WEBHOOK = WEBHOOK;
    process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST = 'hooks.example.com';
    delete process.env.SECURITY_ALERT_MIN_LEVEL;
    delete process.env.SECURITY_ALERT_WEBHOOK_SECRET;
    delete process.env.SECURITY_ALERT_DNS_TIMEOUT_MS;
    dnsLookup = jest.spyOn(dns.promises, 'lookup');
  });

  afterEach(() => {
    dnsLookup.mockRestore();
  });

  test('解析到公网地址：投递，且 lookup 把连接钉在该地址上', async () => {
    dnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);

    await sendNotification('probe_type', 'critical', '探针');

    expect(dnsLookup).toHaveBeenCalledWith('hooks.example.com', {
      all: true,
      verbatim: true,
    });
    expect(postJson).toHaveBeenCalledTimes(1);
    const options = postJson.mock.calls[0][4];
    expect(typeof options.lookup).toBe('function');

    const single = jest.fn();
    options.lookup('hooks.example.com', { all: false }, single);
    expect(single).toHaveBeenCalledWith(null, '93.184.216.34', 4);

    const all = jest.fn();
    options.lookup('hooks.example.com', { all: true }, all);
    expect(all).toHaveBeenCalledWith(null, [{ address: '93.184.216.34', family: 4 }]);
  });

  test('解析到私网/环回地址：不投递', async () => {
    for (const address of ['10.0.0.5', '127.0.0.1', '169.254.169.254', 'fd00::1']) {
      postJson.mockClear();
      dnsLookup.mockResolvedValue([{ address, family: address.includes(':') ? 6 : 4 }]);

      await sendNotification('probe_type', 'critical', '探针');

      expect(postJson).not.toHaveBeenCalled();
    }
  });

  test('多地址中只要有一条禁止：整条投递拒绝（不给轮询 DNS 挑地址的机会）', async () => {
    dnsLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '192.168.1.10', family: 4 },
    ]);

    await sendNotification('probe_type', 'critical', '探针');

    expect(postJson).not.toHaveBeenCalled();
    expect(logger.warn.mock.calls.some((c) => String(c[0]).includes('192.168.1.10'))).toBe(true);
  });

  test('解析失败：不投递', async () => {
    dnsLookup.mockRejectedValue(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));

    await sendNotification('probe_type', 'critical', '探针');

    expect(postJson).not.toHaveBeenCalled();
    expect(logger.warn.mock.calls.some((c) => String(c[0]).includes('ENOTFOUND'))).toBe(true);
  });

  test('解析超时：不投递，调用方不会被挂住', async () => {
    process.env.SECURITY_ALERT_DNS_TIMEOUT_MS = '20';
    dnsLookup.mockReturnValue(new Promise(() => {}));

    await sendNotification('probe_type', 'critical', '探针');

    expect(postJson).not.toHaveBeenCalled();
    expect(logger.warn.mock.calls.some((c) => String(c[0]).includes('ETIMEDOUT'))).toBe(true);
  });

  test('IP 字面量目标不触发 DNS，钉住的就是字面量本身', async () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'http://8.8.8.8/hook';
    delete process.env.SECURITY_ALERT_WEBHOOK_ALLOWLIST;

    await sendNotification('probe_type', 'critical', '探针');

    expect(dnsLookup).not.toHaveBeenCalled();
    expect(postJson).toHaveBeenCalledTimes(1);
    const options = postJson.mock.calls[0][4];
    const callback = jest.fn();
    options.lookup('8.8.8.8', { all: false }, callback);
    expect(callback).toHaveBeenCalledWith(null, '8.8.8.8', 4);
  });

  test('签名覆盖时间戳与随机数：同一 body 两次投递的签名不可互换', async () => {
    const secret = 'webhook-test-secret';
    process.env.SECURITY_ALERT_WEBHOOK_SECRET = secret;
    dnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);

    await sendNotification('probe_type', 'critical', '签名探针');
    await sendNotification('probe_type', 'critical', '签名探针');

    expect(postJson).toHaveBeenCalledTimes(2);
    const firstHeaders = postJson.mock.calls[0][1];
    const firstBody = postJson.mock.calls[0][2];
    const secondHeaders = postJson.mock.calls[1][1];
    expect(firstHeaders['X-Webhook-Timestamp']).toMatch(/^\d+$/);
    expect(firstHeaders['X-Webhook-Nonce']).toMatch(/^[0-9a-f]{32}$/);
    expect(secondHeaders['X-Webhook-Nonce']).not.toBe(firstHeaders['X-Webhook-Nonce']);
    expect(secondHeaders['X-Webhook-Signature']).not.toBe(firstHeaders['X-Webhook-Signature']);

    const expected =
      'sha256=' +
      crypto
        .createHmac('sha256', secret)
        .update(
          `${firstHeaders['X-Webhook-Timestamp']}.${firstHeaders['X-Webhook-Nonce']}.${firstBody}`
        )
        .digest('hex');
    expect(firstHeaders['X-Webhook-Signature']).toBe(expected);
  });
});
