/**
 * 启动期配置守卫（P2-36 时区 / P2-38 文档开关口径 / P1-34 加固项告警）
 *
 * 与 src/tests/config/validate.test.js 的分工：那个文件覆盖 validateConfig 的
 * 既有编排（错误收集顺序、文案、TLS 二选一）；本文件覆盖 2026-09-17 新增/修正的
 * 三处行为，且**只断言行为**（返回值、抛错、收集到的消息），不断言源码文本。
 */

const ORIGINAL_ENV = process.env;

describe('P2-36：TZ_BUSINESS 启动期校验', () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  /** 生产环境下除 TZ_BUSINESS 外全部合法 */
  const setValidProdEnv = () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'redis://redis.example.com:6379';
    process.env.TRUST_PROXY_HOPS = '1';
  };

  /** 跑一次生产校验，返回 { exited, messages } */
  const runProd = () => {
    const { validateConfig } = require('../../config/validate');
    const logger = require('../../utils/logger');
    const messages = [];
    const mockError = jest
      .spyOn(logger, 'error')
      .mockImplementation((m) => messages.push(String(m)));
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });
    let exited = false;
    try {
      validateConfig();
    } catch (e) {
      exited = e.message === 'process.exit called';
    }
    mockError.mockRestore();
    mockExit.mockRestore();
    return { exited, messages: messages.join('\n') };
  };

  test('未配置 TZ_BUSINESS → 通过（constants/timezone.js 回退 Asia/Shanghai）', () => {
    setValidProdEnv();
    delete process.env.TZ_BUSINESS;
    expect(runProd().exited).toBe(false);
  });

  test('合法 IANA 名 → 通过', () => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = 'America/Los_Angeles';
    expect(runProd().exited).toBe(false);
  });

  // 实测（Node v24.15.0）确认哪些取值 Intl 真的会拒绝——判据以实测为准，
  // 不按「看起来像不像 IANA 名」猜测。
  test.each([
    ['拼写错误（Shangai 少 h）', 'Asia/Shangai'],
    ['UTC 偏移的非法写法', 'UTC+8'],
    ['不存在的地区', 'Mars/Olympus_Mons'],
    ['纯数字串', '12345'],
  ])('%s → 启动致命错误且文案指向 TZ_BUSINESS', (_label, value) => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = value;
    const { exited, messages } = runProd();
    expect(exited).toBe(true);
    expect(messages).toContain('TZ_BUSINESS');
  });

  test('空白串视为未配置（回退默认 Asia/Shanghai），不报错', () => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = '   ';
    expect(runProd().exited).toBe(false);
  });

  test.each([
    ['IANA 名', 'Asia/Shanghai'],
    // 实测：Intl 接受 '+08:00' 形式的固定偏移（本机 Node v24.15.0 确认），
    // 且 MongoDB 的 $dateToString 同样接受该形式，故不判错。
    // 注意 constants/timezone.js 的取向是「优先 IANA」——固定偏移不承载夏令时
    // 规则，跨时区部署时应改用 IANA 名。此处只保证它不会在首次业务调用抛错。
    ['固定偏移 +08:00（Intl 接受）', '+08:00'],
  ])('%s → 通过', (_label, value) => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = value;
    expect(runProd().exited).toBe(false);
  });

  test('非生产环境不校验（validateConfig 提前返回）', () => {
    process.env.NODE_ENV = 'test';
    process.env.TZ_BUSINESS = 'Asia/Shangai';
    const { validateConfig } = require('../../config/validate');
    expect(() => validateConfig()).not.toThrow();
  });
});

describe('P2-38：ENABLE_API_DOCS 判定口径统一', () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  test.each([
    ['true', true],
    ['TRUE', true],
    ['1', true],
    [' 1 ', true],
    ['false', false],
    ['0', false],
    ['no', false],
    ['off', false],
    ['', false],
  ])('显式 ENABLE_API_DOCS=%j → isDocsEnabled=%s', (raw, expected) => {
    process.env.ENABLE_API_DOCS = raw;
    const { isDocsEnabled } = require('../../config/validate');
    expect(isDocsEnabled()).toBe(expected);
  });

  test('未显式设置时跟随 NODE_ENV（非生产默认开）', () => {
    delete process.env.ENABLE_API_DOCS;
    process.env.NODE_ENV = 'test';
    expect(require('../../config/validate').isDocsEnabled()).toBe(true);
  });

  test('未显式设置且 NODE_ENV=production → 默认关', () => {
    delete process.env.ENABLE_API_DOCS;
    process.env.NODE_ENV = 'production';
    expect(require('../../config/validate').isDocsEnabled()).toBe(false);
  });

  test('swagger.js 与 validate.js 判定一致（同一实现，防再次分叉）', () => {
    for (const raw of ['true', 'TRUE', '1', 'false', '0', 'no']) {
      process.env.ENABLE_API_DOCS = raw;
      jest.resetModules();
      const fromValidate = require('../../config/validate').isDocsEnabled();
      const fromSwagger = require('../../config/swagger').isDocsEnabled();
      expect(fromSwagger).toBe(fromValidate);
    }
  });

  test('ENABLE_API_DOCS=1 也会触发生产期的凭据必填校验（口径统一后的行为变化）', () => {
    process.env.NODE_ENV = 'production';
    process.env.ENABLE_API_DOCS = '1';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'redis://redis.example.com:6379';
    process.env.TRUST_PROXY_HOPS = '1';
    delete process.env.DOCS_USERNAME;
    delete process.env.DOCS_PASSWORD;

    const { validateConfig } = require('../../config/validate');
    const logger = require('../../utils/logger');
    const messages = [];
    const mockError = jest
      .spyOn(logger, 'error')
      .mockImplementation((m) => messages.push(String(m)));
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });

    // 修复前：'1' 不被 validate.js 认作开启 → 不校验凭据 → 文档 fail-closed 却无人知晓
    expect(() => validateConfig()).toThrow('process.exit called');
    expect(messages.join('\n')).toContain('DOCS_USERNAME');

    mockError.mockRestore();
    mockExit.mockRestore();
  });
});

describe('P1-34：加固项告警真正可达', () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  const collect = () => require('../../config/validate').collectProductionWarnings();

  test('默认（加固项齐备）→ 无告警', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    delete process.env.ALLOW_PUBLIC_REGISTRATION;
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    process.env.LOG_LEVEL = 'info';
    expect(collect()).toEqual([]);
  });

  test('ALLOW_PUBLIC_REGISTRATION=true → 告警且指明变量名', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.ALLOW_PUBLIC_REGISTRATION = 'true';
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    process.env.LOG_LEVEL = 'info';
    const w = collect();
    expect(w).toHaveLength(1);
    expect(w[0]).toContain('ALLOW_PUBLIC_REGISTRATION');
  });

  test('ALLOW_PUBLIC_REGISTRATION=false → 无告警（布尔口径，非字符串比较）', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.ALLOW_PUBLIC_REGISTRATION = 'false';
    process.env.LOG_LEVEL = 'info';
    expect(collect().some((x) => x.includes('ALLOW_PUBLIC_REGISTRATION'))).toBe(false);
  });

  test('ALLOW_LEGACY_CBC_DECRYPT=true → 告警', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
    process.env.LOG_LEVEL = 'info';
    const w = collect();
    expect(w.some((x) => x.includes('ALLOW_LEGACY_CBC_DECRYPT'))).toBe(true);
  });

  test('LOG_LEVEL=debug → 告警', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    process.env.LOG_LEVEL = 'DEBUG';
    const w = collect();
    expect(w.some((x) => x.includes('LOG_LEVEL'))).toBe(true);
  });

  test('多项缺失时全部列出（不因首个命中而短路）', () => {
    delete process.env.ALLOWED_HOSTS;
    process.env.ALLOW_PUBLIC_REGISTRATION = 'true';
    process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
    process.env.LOG_LEVEL = 'debug';
    expect(collect()).toHaveLength(4);
  });

  test('告警确实被 validateConfig 打印（生产 + 加固项缺失但致命项齐备）', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'redis://redis.example.com:6379';
    process.env.TRUST_PROXY_HOPS = '1';
    process.env.ALLOW_PUBLIC_REGISTRATION = 'true';

    const { validateConfig } = require('../../config/validate');
    const logger = require('../../utils/logger');
    const warns = [];
    jest.spyOn(logger, 'error').mockImplementation(() => {});
    const mockWarn = jest.spyOn(logger, 'warn').mockImplementation((m) => warns.push(String(m)));

    expect(() => validateConfig()).not.toThrow();
    expect(warns.join('\n')).toContain('ALLOW_PUBLIC_REGISTRATION');

    mockWarn.mockRestore();
  });
});

describe('validate.js 降级通道：flushLogsSync/logger 不可用时信息不得丢失', () => {
  // 这两条覆盖 validate.js:478-482 与 :497-499 的 catch 降级分支。
  // 为什么重要：它们是**最后一道**错误上报通道——配置校验失败是「服务不该启动」
  // 级别的判定，若因为日志端异常导致用户只看到空白退出，运维将无从定位。
  // 造法：把 loggerFlush 与 logger 都换成抛错的替身，断言 console.error 收到全文。
  const ORIGINAL = process.env;
  let consoleSpy;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL };
    consoleSpy = { error: jest.spyOn(console, 'error').mockImplementation(() => {}) };
  });

  afterEach(() => {
    consoleSpy.error.mockRestore();
    jest.dontMock('../../utils/loggerFlush');
    jest.dontMock('../../utils/logger');
    process.env = ORIGINAL;
  });

  test('致命项失败 + flushLogsSync/logger 双双抛错 → console.error 兜底输出全部错误', () => {
    // 生产环境 + 全部必填项缺失/弱值：错误集合完全确定（不依赖 harness 注入的合法值）
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'short';
    process.env.JWT_REFRESH_SECRET = 'short';
    process.env.AES_SECRET_KEY = 'short';
    process.env.HMAC_SECRET = 'short';
    delete process.env.MONGODB_URI; // 缺省即命中「不能指向 localhost」分支
    jest.doMock('../../utils/loggerFlush', () => ({
      flushLogsSync: () => {
        throw new Error('日志目录只读');
      },
    }));
    jest.doMock('../../utils/logger', () => ({
      error: () => {
        throw new Error('logger 已损坏');
      },
      warn: () => {},
      info: () => {},
    }));
    jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });

    const { validateConfig } = require('../../config/validate');
    expect(() => validateConfig()).toThrow('process.exit called');

    const output = consoleSpy.error.mock.calls.map((c) => c.map(String).join(' ')).join('\n');
    expect(output).toContain('配置校验失败：');
    // 各条明细也要落地（只打标题等于丢失定位信息）
    expect(output).toContain('JWT_SECRET 必须设置为至少 32 字符的强随机值');
    expect(output).toContain('JWT_REFRESH_SECRET 必须设置为至少 32 字符的强随机值');
    expect(output).toContain('AES_SECRET_KEY 必须设置为至少 32 字符的强随机值');
  });

  test('加固项告警 + logger 抛错 → console.warn 兜底输出告警全文', () => {
    // 生产环境 + 致命项齐备（否则提前 exit，走不到告警段）
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'redis://redis.example.com:6379';
    process.env.TRUST_PROXY_HOPS = '1';
    process.env.LOG_LEVEL = 'debug'; // 命中加固项告警
    jest.doMock('../../utils/logger', () => ({
      error: () => {},
      warn: () => {
        throw new Error('logger 已损坏');
      },
      info: () => {},
    }));
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const { validateConfig } = require('../../config/validate');
      expect(() => validateConfig()).not.toThrow(); // 告警不阻断启动

      const output = warnSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n');
      expect(output).toContain('安全加固建议：');
      expect(output).toContain('LOG_LEVEL');
    } finally {
      warnSpy.mockRestore();
    }
  });
});
describe('P2-35：.env.example 必须覆盖配置层读取的全部变量', () => {
  // 缺口检测：配置层（config/）里任何被 process.env 读取的变量，若模板中完全没有
  // 出现，运维就无从知道它存在——只能去读源码。本用例是「补齐 44 个未文档化变量」
  // 那类问题的回归闸门：新增配置项忘了写模板即变红。
  // 只断言「名字出现」（生效行或注释行均可），不锁具体取值/文案。
  const fs = require('fs');
  const path = require('path');
  const ROOT = path.join(__dirname, '..', '..', '..');
  const CONFIG_FILES = [
    'src/config/index.js',
    'src/config/validate.js',
    'src/config/swagger.js',
    'src/config/database.js',
  ];

  test('config/ 引用的 process.env.* 变量名全部出现在 .env.example 中', () => {
    const referenced = new Set();
    for (const rel of CONFIG_FILES) {
      const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      for (const m of src.matchAll(/process\.env\.([A-Z0-9_]+)/g)) referenced.add(m[1]);
    }

    const documented = new Set();
    for (const line of fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*#?\s*([A-Z][A-Z0-9_]*)\s*=/);
      if (m) documented.add(m[1]);
    }

    const missing = [...referenced].filter((v) => !documented.has(v)).sort();
    // 断言为空：任何缺失都会在失败信息里列出变量名，便于直接补模板
    expect(missing).toEqual([]);
    // 防「文件被清空后 vacuously 通过」：模板必须真的被解析出变量
    expect(documented.size).toBeGreaterThan(50);
  });

  test('P2-35 点名的四个关键变量确实在模板中（防误删）', () => {
    const env = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
    for (const name of [
      'TZ_BUSINESS',
      'MONGO_MAX_POOL_SIZE',
      'AUDIT_WAL_PATH',
      'STATS_CACHE_TTL',
    ]) {
      expect(env).toContain(name);
    }
  });
});
