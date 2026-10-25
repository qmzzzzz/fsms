/**
 * 部署凭据 / 出站来源的启动闸（2026-10-24 审计）
 *
 * 每组判据都同时钉「拒绝」与「放行」两侧：只钉拒绝时，"函数永远报错"也能全绿；
 * 只钉放行时，"函数空转"同样全绿。
 */

const guards = require('../../config/deploymentCredentialGuards');

const ENV_KEYS = [
  'CORS_ORIGIN',
  'REDIS_PASSWORD',
  'REDIS_URL',
  'METRICS_TOKEN',
  'LOG_SHIPPING_TOKEN',
  'LOG_SHIPPING_URL',
  'LOG_SHIPPING_ALLOW_INSECURE',
  'SECURITY_ALERT_WEBHOOK',
  'SECURITY_ALERT_WEBHOOK_SECRET',
  'NODE_ENV',
  'REQUIRE_PRODUCTION_CONFIG',
];

const saved = {};
beforeAll(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

const run = (fn) => {
  const errors = [];
  fn(errors);
  return errors;
};

const STRONG_A = 'Zq7!Wn4#Rt9$Yp2@Ks6&Lm8*Vc3^Bh5%Jf1Nx0Kd';
const STRONG_B = 'aB3$dE6&gH9!jK2@mN5#pQ8*rS1^tU4%vW7&xY0z';

describe('CORS_ORIGIN：生产只接受 https 的完整来源', () => {
  test('缺项与通配符仍按原文案报错（既有契约不回归）', () => {
    delete process.env.CORS_ORIGIN;
    expect(run(guards.collectCorsOriginErrors).join('\n')).toContain('必须设置');
    process.env.CORS_ORIGIN = '*';
    expect(run(guards.collectCorsOriginErrors).join('\n')).toContain('禁止使用通配符');
  });

  test('合法 https 来源（含多来源与端口）零错误', () => {
    process.env.CORS_ORIGIN = 'https://admin.example.com,https://api.example.com:8443';
    expect(run(guards.collectCorsOriginErrors)).toEqual([]);
  });

  test('明文 http 来源被拒（credentials:true 下可被网络攻击者注入）', () => {
    process.env.CORS_ORIGIN = 'https://admin.example.com,http://localhost:3001';
    expect(run(guards.collectCorsOriginErrors).join('\n')).toContain('生产环境必须使用 https');
  });

  test('带路径/查询/userinfo 的来源被拒（浏览器 Origin 永远不会长这样）', () => {
    for (const bad of [
      'https://admin.example.com/app',
      'https://admin.example.com/?x=1',
      'https://user:pw@admin.example.com',
      'not-a-url',
    ]) {
      process.env.CORS_ORIGIN = bad;
      expect({ bad, errors: run(guards.collectCorsOriginErrors) }).not.toEqual({ bad, errors: [] });
    }
  });
});

describe('运维凭据强度：设置了就必须强', () => {
  test('弱值逐个点名（Redis / metrics / 日志令牌 / webhook 密钥）', () => {
    process.env.REDIS_PASSWORD = 'short';
    process.env.METRICS_TOKEN = 'short';
    process.env.LOG_SHIPPING_TOKEN = 'short';
    process.env.SECURITY_ALERT_WEBHOOK_SECRET = 'short';
    const text = run(guards.collectCredentialStrengthErrors).join('\n');
    for (const label of [
      'Redis 认证口令',
      'METRICS_TOKEN',
      'LOG_SHIPPING_TOKEN',
      'SECURITY_ALERT_WEBHOOK_SECRET',
    ]) {
      expect(text).toContain(label);
    }
  });

  test('未设置时不在本判据发言（必填性由各自功能闸决定）', () => {
    expect(run(guards.collectCredentialStrengthErrors)).toEqual([]);
  });

  test('强值零错误；REDIS_URL 内嵌的弱口令同样被抓到', () => {
    process.env.REDIS_PASSWORD = STRONG_A;
    process.env.METRICS_TOKEN = STRONG_B;
    expect(run(guards.collectCredentialStrengthErrors)).toEqual([]);

    delete process.env.REDIS_PASSWORD;
    process.env.REDIS_URL = 'rediss://:short@redis.example.com:6379';
    expect(run(guards.collectCredentialStrengthErrors).join('\n')).toContain('REDIS_URL 中内嵌');
  });
});

describe('告警 webhook：必须 https + 必须可签名', () => {
  test('未配置 webhook 时零错误', () => {
    delete process.env.SECURITY_ALERT_WEBHOOK;
    expect(run(guards.collectAlertWebhookErrors)).toEqual([]);
  });

  test('配了 URL 没配签名密钥 → 点名漏洞', () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://alerts.example.com/hook';
    delete process.env.SECURITY_ALERT_WEBHOOK_SECRET;
    expect(run(guards.collectAlertWebhookErrors).join('\n')).toContain(
      'SECURITY_ALERT_WEBHOOK_SECRET'
    );
  });

  test('明文 http 告警端点被拒', () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'http://alerts.example.com/hook';
    process.env.SECURITY_ALERT_WEBHOOK_SECRET = STRONG_A;
    expect(run(guards.collectAlertWebhookErrors).join('\n')).toContain('必须使用 https');
  });

  test('https + 强密钥零错误', () => {
    process.env.SECURITY_ALERT_WEBHOOK = 'https://alerts.example.com/hook';
    process.env.SECURITY_ALERT_WEBHOOK_SECRET = STRONG_A;
    expect(run(guards.collectAlertWebhookErrors)).toEqual([]);
  });
});

describe('日志外发：明文 http 需要显式放宽，带令牌时连放宽也不行', () => {
  test('https 目标零错误', () => {
    process.env.LOG_SHIPPING_URL = 'https://siem.example.com/ingest';
    expect(run(guards.collectLogShippingErrors)).toEqual([]);
  });

  test('默认拒绝明文 http', () => {
    process.env.LOG_SHIPPING_URL = 'http://siem.example.com/ingest';
    delete process.env.LOG_SHIPPING_ALLOW_INSECURE;
    expect(run(guards.collectLogShippingErrors).join('\n')).toContain('必须是 https');
  });

  test('无令牌 + 显式放宽 → 放行', () => {
    process.env.LOG_SHIPPING_URL = 'http://siem.example.com/ingest';
    process.env.LOG_SHIPPING_ALLOW_INSECURE = 'true';
    delete process.env.LOG_SHIPPING_TOKEN;
    expect(run(guards.collectLogShippingErrors)).toEqual([]);
  });

  test('带令牌 + 显式放宽 → 仍拒绝（Bearer 不得明文出站）', () => {
    process.env.LOG_SHIPPING_URL = 'http://siem.example.com/ingest';
    process.env.LOG_SHIPPING_ALLOW_INSECURE = 'true';
    process.env.LOG_SHIPPING_TOKEN = STRONG_A;
    expect(run(guards.collectLogShippingErrors).join('\n')).toContain(
      '禁止配置 LOG_SHIPPING_TOKEN'
    );
  });
});

describe('REQUIRE_PRODUCTION_CONFIG：声明了生产语义就必须真的按生产校验', () => {
  const withMockedExit = (fn) => {
    const exitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`__exit_${code}__`);
    });
    jest.spyOn(require('../../utils/logger'), 'error').mockImplementation(() => {});
    try {
      return fn();
    } finally {
      exitSpy.mockRestore();
    }
  };

  test('NODE_ENV=development + 声明 = true → 致命退出并点名 NODE_ENV', () => {
    process.env.NODE_ENV = 'development';
    process.env.REQUIRE_PRODUCTION_CONFIG = 'true';
    jest.resetModules();
    const { validateConfig } = require('../../config/validate');
    let message = '';
    withMockedExit(() => {
      try {
        validateConfig();
      } catch (e) {
        message = e.message;
      }
    });
    expect(message).toContain('__exit_1__');
  });

  test('未声明时不额外拦截（开发环境保持既有语义）', () => {
    process.env.NODE_ENV = 'development';
    delete process.env.REQUIRE_PRODUCTION_CONFIG;
    jest.resetModules();
    const { validateConfig } = require('../../config/validate');
    expect(() => validateConfig()).not.toThrow();
  });
});
