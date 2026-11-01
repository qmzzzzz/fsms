/**
 * validateConfig 的预发宽松上报、API 文档凭据与 Redis 连接串闸。
 *
 * reportStagingLeniency 的 console 兜底臂（logger.warn 抛错时）从未被计数
 * （functions 96.15% < 97%）；validateDocsCredentials 的缺凭据/弱口令臂与
 * collectConnectionErrors 的协议/非法 URL 臂同样缺计数。这里按既有套件的
 * 生产合法夹具驱动 validateConfig，process.exit 一律 mock。
 */
const logger = require('../../utils/logger');

const PROD_ENV = {
  NODE_ENV: 'production',
  JWT_SECRET: 'strong-random-jwt-secret-that-is-long-enough',
  JWT_REFRESH_SECRET: 'strong-random-refresh-secret-long-enough',
  AES_SECRET_KEY: 'test-aes-key-with-32-chars-minimum!!',
  HMAC_SECRET: 'strong-random-hmac-secret-that-is-long-enough',
  MONGODB_URI: 'mongodb://prod-server:27017/db?tls=true',
  CORS_ORIGIN: 'https://example.com',
  ENABLE_HTTPS: 'true',
  ALLOWED_HOSTS: 'api.example.com',
  REDIS_URL: 'rediss://redis.example.com:6379',
  REDIS_PASSWORD: 'strong-random-redis-secret-that-is-long-enough',
  TRUSTED_PROXY_CIDRS: '172.28.0.0/16',
};

const ENV_KEYS = [
  ...Object.keys(PROD_ENV),
  'FSMS_ALLOW_STAGING_LENIENT',
  'ENABLE_API_DOCS',
  'DOCS_USERNAME',
  'DOCS_PASSWORD',
  'TRUST_PROXY_HOPS',
  'REQUIRE_PRODUCTION_CONFIG',
  'TZ_BUSINESS',
  'LOG_LEVEL',
];

const saved = {};
beforeAll(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
});
afterAll(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

const setProd = (overrides = {}) => {
  for (const [k, v] of Object.entries(PROD_ENV)) process.env[k] = v;
  for (const k of [
    'ENABLE_API_DOCS',
    'DOCS_USERNAME',
    'DOCS_PASSWORD',
    'FSMS_ALLOW_STAGING_LENIENT',
  ]) {
    delete process.env[k];
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
};

const captureExit = () => {
  const messages = [];
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called');
  });
  const errorSpy = jest.spyOn(logger, 'error').mockImplementation((m) => messages.push(String(m)));
  return {
    messages,
    restore: () => {
      exitSpy.mockRestore();
      errorSpy.mockRestore();
    },
  };
};

const runValidate = () => {
  const { validateConfig } = require('../../config/validate');
  return () => validateConfig();
};

describe('预发宽松启动的显式登记（reportStagingLeniency）', () => {
  test('logger.warn 抛错时逐行降级到 console.warn（兜底臂不得丢内容）', () => {
    process.env.NODE_ENV = 'staging';
    process.env.FSMS_ALLOW_STAGING_LENIENT = 'true';
    delete process.env.ENABLE_API_DOCS;
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {
      throw new Error('logger 通道不可用');
    });
    const warnConsole = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expect(runValidate()).not.toThrow();
      expect(warnConsole).toHaveBeenCalled();
      const text = warnConsole.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(text).toContain('预发宽松启动已显式声明');
      expect(text).toContain('FSMS_ALLOW_STAGING_LENIENT=true');
    } finally {
      warnSpy.mockRestore();
      warnConsole.mockRestore();
    }
  });

  test('ENABLE_API_DOCS=false 时登记文案里是「关闭」', () => {
    process.env.NODE_ENV = 'staging';
    process.env.FSMS_ALLOW_STAGING_LENIENT = 'true';
    process.env.ENABLE_API_DOCS = 'false';
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {
      throw new Error('logger 通道不可用');
    });
    const warnConsole = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expect(runValidate()).not.toThrow();
      const text = warnConsole.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(text).toContain('/api-docs 默认关闭');
    } finally {
      warnSpy.mockRestore();
      warnConsole.mockRestore();
    }
  });
});

describe('API 文档凭据与 Redis 连接串闸', () => {
  test('开启文档但缺 DOCS_USERNAME/DOCS_PASSWORD：启动期报错', () => {
    setProd({ ENABLE_API_DOCS: 'true' });
    const { messages, restore } = captureExit();
    try {
      expect(runValidate()).toThrow('process.exit called');
      expect(messages.join('\n')).toContain('DOCS_USERNAME');
    } finally {
      restore();
    }
  });

  test('DOCS_PASSWORD 弱值：要求 32 字符强随机', () => {
    setProd({ ENABLE_API_DOCS: 'true', DOCS_USERNAME: 'docs', DOCS_PASSWORD: 'short' });
    const { messages, restore } = captureExit();
    try {
      expect(runValidate()).toThrow('process.exit called');
      expect(messages.join('\n')).toContain('DOCS_PASSWORD 必须是至少 32 字符');
    } finally {
      restore();
    }
  });

  test('REDIS_URL 协议不是 redis:/rediss:：报协议错', () => {
    setProd({ REDIS_URL: 'http://redis.example.com:6379' });
    const { messages, restore } = captureExit();
    try {
      expect(runValidate()).toThrow('process.exit called');
      expect(messages.join('\n')).toContain('REDIS_URL 协议必须是 redis: 或 rediss:');
    } finally {
      restore();
    }
  });

  test('REDIS_URL 不是合法 URL：报解析错', () => {
    setProd({ REDIS_URL: 'not a url' });
    const { messages, restore } = captureExit();
    try {
      expect(runValidate()).toThrow('process.exit called');
      expect(messages.join('\n')).toContain('REDIS_URL 必须是有效的 Redis 连接地址');
    } finally {
      restore();
    }
  });
});
