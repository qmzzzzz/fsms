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
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'rediss://redis.example.com:6379';
    // 2026-10-01 Redis 认证闸：合法生产夹具须带凭据（compose 走 REDIS_PASSWORD_FILE 同值形态）
    process.env.REDIS_PASSWORD = 'strong-random-redis-' + 'secret-that-is-long-enough';
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

  test('IANA 名 → 通过', () => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = 'Asia/Shanghai';
    expect(runProd().exited).toBe(false);
  });

  // 「固定偏移 +08:00」的判定**随运行时变化**：offset 形式的时区名只有较新的 V8 认。
  // 实测（ICU 同为 78.2，差异在 V8 而非 ICU 数据）：
  //   Node v20.20.2          → new Intl.DateTimeFormat('en-CA',{timeZone:'+08:00'}) 抛 RangeError
  //   Node v22.22.2/v24.15.0 → 接受
  // 校验器的契约是「与运行期一致」（见 config/validate.js 的 collectTimezoneErrors：
  // 只有真能被 Intl 接受的名字才放行，避免"校验通过但运行期仍抛"）。故：
  //   Intl 接受 → 必须放行；Intl 拒绝 → 必须在启动期拦下。
  // 期望值因此由本运行时的探针给出，而不是写死某个 Node 版本的实测结论——
  // 写死 v24 的结论会让 CI 的 20.x 腿恒红，写死 v20 的结论则会在 22.x 上漏掉真回归。
  // （原实现写死「通过」，依据是注释自陈的「本机 Node v24.15.0 确认」。）
  const intlRejectsOffsetTz = () => {
    try {
      new Intl.DateTimeFormat('en-CA', { timeZone: '+08:00' });
      return false;
    } catch (_) {
      return true;
    }
  };

  test('固定偏移 +08:00 → 判定与运行期 Intl 一致（Node 20 拒绝 / Node 22+ 接受）', () => {
    setValidProdEnv();
    process.env.TZ_BUSINESS = '+08:00';
    const { exited, messages } = runProd();
    if (intlRejectsOffsetTz()) {
      expect(exited).toBe(true);
      expect(messages).toContain('TZ_BUSINESS');
    } else {
      expect(exited).toBe(false);
    }
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
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'rediss://redis.example.com:6379';
    // 2026-10-01 Redis 认证闸：合法生产夹具须带凭据（compose 走 REDIS_PASSWORD_FILE 同值形态）
    process.env.REDIS_PASSWORD = 'strong-random-redis-' + 'secret-that-is-long-enough';
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

  /**
   * 只保留「加固项缺失」告警，剔除恒定在场的配置代价类告警。
   *
   * 为什么要剔除而不是放宽计数：本组用例的主题是 **P1-34「加固项告警真正可达」**，
   * 而以下两条都是**恒定在场**的告警——它们描述的是配置组合的既有代价，不是"加固项缺失"。
   * 把它们算进总数会让本组每条用例都被污染：实测 2026-09-30 新增 immutable 档位
   * （口令历史 pepper 轮换）告警后，本文件 4 条用例连带变红；2026-10-10 新增
   * LOGIN_ENCRYPT_STRICT 未开告警（密文轨灰度期的既有代价，判据与取舍见
   * config/loginEncryptGuard.js）时同理。
   * 分类断言（而不是改数字）才能让后续再加一条此类告警时本组不被动红。
   */
  const hardeningWarnings = (list) =>
    list.filter((w) => !w.includes('HMAC_SECRET 轮换') && !w.includes('LOGIN_ENCRYPT_STRICT'));

  test('默认（加固项齐备）→ 无加固项告警', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    delete process.env.ALLOW_PUBLIC_REGISTRATION;
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    process.env.LOG_LEVEL = 'info';
    expect(hardeningWarnings(collect())).toEqual([]);
  });

  test('ALLOW_PUBLIC_REGISTRATION=true → 告警且指明变量名', () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.ALLOW_PUBLIC_REGISTRATION = 'true';
    delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
    process.env.LOG_LEVEL = 'info';
    const w = hardeningWarnings(collect());
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
    const w = hardeningWarnings(collect());
    // 钉"四条各在场"而不是"总数 == 4"：见 hardeningWarnings 的说明。
    expect(w.some((x) => x.includes('ALLOWED_HOSTS'))).toBe(true);
    expect(w.some((x) => x.includes('ALLOW_PUBLIC_REGISTRATION'))).toBe(true);
    expect(w.some((x) => x.includes('ALLOW_LEGACY_CBC_DECRYPT'))).toBe(true);
    expect(w.some((x) => x.includes('LOG_LEVEL'))).toBe(true);
    expect(w).toHaveLength(4);
  });

  test('告警确实被 validateConfig 打印（生产 + 加固项缺失但致命项齐备）', () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    // P2-8：合法生产夹具须带传输加密（非回环主机 tls=true / rediss:）
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'rediss://redis.example.com:6379';
    // 2026-10-01 Redis 认证闸：合法生产夹具须带凭据（compose 走 REDIS_PASSWORD_FILE 同值形态）
    process.env.REDIS_PASSWORD = 'strong-random-redis-' + 'secret-that-is-long-enough';
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
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    process.env.CORS_ORIGIN = 'https://example.com';
    process.env.ENABLE_HTTPS = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'rediss://redis.example.com:6379';
    // 2026-10-01 Redis 认证闸：合法生产夹具须带凭据（compose 走 REDIS_PASSWORD_FILE 同值形态）
    process.env.REDIS_PASSWORD = 'strong-random-redis-' + 'secret-that-is-long-enough';
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
  // 缺口检测：配置层（src/config/）里任何被读取的变量，若模板中完全没有出现，
  // 运维就无从知道它存在——只能去读源码。本用例是「补齐 44 个未文档化变量」
  // 那类问题的回归闸门：新增配置项忘了写模板即变红。
  // 只断言「名字出现」（生效行或注释行均可），不锁具体取值/文案。
  const fs = require('fs');
  const path = require('path');
  const ROOT = path.join(__dirname, '..', '..', '..');
  const CONFIG_DIR = path.join(ROOT, 'src', 'config');

  // 【扫描集由目录派生，不再硬写清单】原先这里是四条文件名字面量，而 `src/config/`
  // 实际有五个 .js（缺 `secrets.js`）：新增一个配置文件**不会**让本闸变红，
  // 只会让它看不见那个文件——静默缩小覆盖面而不是报警，与本仓"五份到期口径"同族。
  const CONFIG_FILES = fs
    .readdirSync(CONFIG_DIR)
    .filter((f) => f.endsWith('.js'))
    .sort()
    .map((f) => `src/config/${f}`);

  /**
   * 剥注释。不剥的失真方向是"凭空多出一个开关"：`src/utils/envNumber.js` 的文件头
   * 用 `Number(process.env.X)` 举例说明这个惯用法——那是一条**注释**，却会被提取器
   * 读成一个名叫 `X` 的配置项并要求文档化它。将来任何人在注释里写一句同类示例，
   * 本闸就会红在一个不存在的东西上；而"红在不存在的东西上"教会的行为是放宽判据。
   */
  function stripComments(text) {
    return text
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split('\n')
      .map((line) => {
        const t = line.trimStart();
        if (t.startsWith('//') || t.startsWith('*')) return '';
        // 行内 ` // `：排除前面是引号或冒号的情况（`'http://…'`、`key: //` 一类不是注释）
        return line.replace(/([^:"'])\/\/.*$/, '$1');
      })
      .join('\n');
  }

  /**
   * 一个变量名"被读取"的三种**字面量**形态：
   *   process.env.NAME / process.env['NAME'] / envInt('NAME', 20) 这一族辅助函数实参。
   * 第三条不是锦上添花：`src/config/database.js` 的五个 `MONGO_*` 全走 `envInt('…')`
   * （:39-43），只看点号形态时这五个真实开关对闸是隐形的——它恰好是 P2-35 点名要防的那类。
   *
   * 刻意**不含**动态拼接（`process.env[`${n}_FILE`]`、`envInt(name)` 里的形参）：
   * 那类读取的键名只存在于名单常量里，正则永远只能看到变量名。硬凑一条"能匹配
   * `FILE_BACKED_SECRETS` 数组字面量"的第四形态，实测会把闸推到 12 个 `_FILE` 变量上
   * （见下面那条用例的注释），那是文档面的活，不是判据的活。
   */
  function envNamesOf(code) {
    const out = new Set();
    for (const m of code.matchAll(/process\.env\.([A-Z0-9_]+)/g)) out.add(m[1]);
    for (const m of code.matchAll(/process\.env\[\s*['"]([A-Z0-9_]+)['"]\s*\]/g)) out.add(m[1]);
    for (const m of code.matchAll(
      /(?:envInt|envNum|envBool|readPositiveNumberEnv)\s*\(\s*['"]([A-Z0-9_]+)['"]/g
    ))
      out.add(m[1]);
    return out;
  }

  const documentedNames = () => {
    const documented = new Set();
    for (const line of fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*#?\s*([A-Z][A-Z0-9_]*)\s*=/);
      if (m) documented.add(m[1]);
    }
    return documented;
  };

  /** 闸的实际口径：剥注释 ⇒ 再提取。只此一处组合，用例与扫描共用它。 */
  const namesInSource = (raw) => envNamesOf(stripComments(raw));

  const referencedAll = () => {
    const referenced = new Set();
    for (const rel of CONFIG_FILES) {
      const raw = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      for (const n of namesInSource(raw)) referenced.add(n);
    }
    return referenced;
  };

  test('config/ 三种形态读到的变量名全部出现在 .env.example 中', () => {
    const documented = documentedNames();
    const referenced = referencedAll();
    const missing = [...referenced].filter((v) => !documented.has(v)).sort();
    // 断言为空：任何缺失都会在失败信息里列出变量名，便于直接补模板
    expect(missing).toEqual([]);
    // 防「文件被清空后 vacuously 通过」：模板必须真的被解析出变量
    expect(documented.size).toBeGreaterThan(50);
    // 同一条防空转的判据放在读取侧：2026-09-26 实测 43 个（其中 5 个只能经 envInt 看到）。
    // 提取器的任一条正则被删都会让这个数掉下来 ⇒ 这条不是装饰。
    expect(referenced.size).toBeGreaterThanOrEqual(43);
  });

  test('扫描集是 src/config/ 的目录派生，不是抄来的清单（反"硬写清单复辟"）', () => {
    // 为什么只能钉基数：`secrets.js` 的读取形态全是动态拼接，五个文件里的字面量读取
    // 恰好都在原先那四条之内 ⇒ **"少扫一个文件"在今天没有任何可观测的名字级差异**。
    // 所以这里退而钉基数（与上面 `documented.size > 50` 同一条纪律、同一个理由），
    // 它杀得住"改回四条字面量"这一族，杀不住"将来新增文件且它只用动态读取"——
    // 后者的确需要一条名字级判据才杀得住，而那要先把 FILE_BACKED_SECRETS 那族纳进提取器
    // （见下一条负结果注释），条件成熟时按那条收紧，不要现在拿基数凑数当充分。
    expect(CONFIG_FILES.length).toBeGreaterThanOrEqual(5);
    // 派生本身的可观测面：清单必须**等于**当前目录里的 .js 全集（不是子集）
    expect(CONFIG_FILES).toEqual(
      fs
        .readdirSync(CONFIG_DIR)
        .filter((f) => f.endsWith('.js'))
        .sort()
        .map((f) => `src/config/${f}`)
    );
  });

  test('提取器认识三种字面量形态（夹具自证，不依赖产品代码）', () => {
    // 这条把"三种形态"从注释变成判据：任一条正则被删，对应那个名字就从集合里消失。
    // 用合成夹具而不是产品文件，是因为产品文件将来可能改名——那时这条还会替三种形态说话。
    const names = envNamesOf(
      [
        'const a = process.env.SHAPE_DOT;',
        "const b = process.env['SHAPE_BRACKET'];",
        'const c = process.env["SHAPE_BRACKET_DQ"];',
        "const d = envInt('SHAPE_ENVINT', 20);",
        "const e = readPositiveNumberEnv('SHAPE_RPNE', 15000);",
        "const f = envNum('SHAPE_ENVNUM', 3);",
        "const g = envBool('SHAPE_ENVBOOL');",
      ].join('\n')
    );
    expect([...names].sort()).toEqual([
      'SHAPE_BRACKET',
      'SHAPE_BRACKET_DQ',
      'SHAPE_DOT',
      'SHAPE_ENVBOOL',
      'SHAPE_ENVINT',
      'SHAPE_ENVNUM',
      'SHAPE_RPNE',
    ]);
  });

  test('注释里的 process.env.X 形状不构成一个开关', () => {
    // 这条钉的是 stripComments 的必要性，形状取自真实出处（envNumber.js 文件头的示例）。
    // 少了剥注释，`GHOST` 会进 referenced ⇒ 上面那条 `missing` 用例红在一个不存在的东西上。
    const commented = [
      '// 为什么要有这个文件：本仓多处写成 `Number(process.env.GHOST) || 15000`',
      '/* 块注释里也有 process.env.GHOST_BLOCK */',
      'const REAL = process.env.NOT_A_GHOST_UNUSED; // 尾随注释 process.env.GHOST_TAIL',
    ].join('\n');
    // 先证明"不剥会读到四个"，即剥注释这一步确实改变了提取结果（否则这条判据空转）
    expect([...envNamesOf(commented)].sort()).toEqual([
      'GHOST',
      'GHOST_BLOCK',
      'GHOST_TAIL',
      'NOT_A_GHOST_UNUSED',
    ]);
    // 再证明闸的实际口径（namesInSource）只留下真开关。
    // 【已知限制】`referencedAll()` 若绕过 namesInSource 直接调 envNamesOf，这条抓不到：
    // 今天五个配置文件里没有任何"只出现在注释中的 env 形状"（实测差集为空），
    // 所以"扫描路径没剥注释"在名字级**没有可观测差异**。可观测的是这里——
    // 组合点只有一处（namesInSource），把它的任一半拆掉本条即红。
    // 收紧的确切条件：任一配置文件出现注释里的 process.env.X ⇒ 绕过路径就会红在 missing 上。
    expect([...namesInSource(commented)]).toEqual(['NOT_A_GHOST_UNUSED']);
    // 今天真实配置层里，剥注释**没有**弄丢任何一个名字（两侧集合同则相等）。
    // 这条钉的是"剥注释不是拿来掩盖真实缺口的手段"——将来谁往注释里塞一个真实存在的
    // 开关名想让它免于文档化，这一条就会红。
    const unstripped = new Set();
    for (const rel of CONFIG_FILES) {
      for (const n of envNamesOf(fs.readFileSync(path.join(ROOT, rel), 'utf8'))) unstripped.add(n);
    }
    expect([...referencedAll()].sort()).toEqual([...unstripped].sort());
  });

  test('secrets.js 在扫描集里但对提取器不可见（登记已测的负结果）', () => {
    // 本批把扫描集改成目录派生，secrets.js 因此**进了**扫描集；实测它对 referenced 的贡献
    // 是 **0 个名字**——它的读取全是 `process.env[`${name}_FILE`]`（:65/:101/:108）。
    // 把这条写成断言，是为了下一个人不把"文件已入扫描集"读成"它已被覆盖"。
    //
    // 要真覆盖它，得把 `FILE_BACKED_SECRETS` 那 14 个名字纳进提取器（第四形态）。
    // 实测挡在前面：那 14 个里 `MONGO_ROOT_PASSWORD` 在 .env.example 中**根本不存在**，
    // 且 14 个的 `_FILE` 形态只有 `LOGIN_ECDH_PRIVATE_KEY_FILE` 以注释示例出现过
    // （缺 12 个）。⇒ 那是补模板的活（一次文档面改动，且要先回答"MONGO_ROOT_PASSWORD
    // 是不是死条目"：全仓除这张表和 ADR-003 的一行之外无人读它，compose 用的是
    // `MONGO_INITDB_ROOT_PASSWORD_FILE`）。本批不擅自改 .env.example 与 secrets.js，
    // 也不为了少一行注释把判据改成"只查已文档化的那些"。
    // 收紧的确切条件：上面两格补齐后，加第四形态并把这条换成"14 个名字全部已文档化"。
    expect(CONFIG_FILES).toContain('src/config/secrets.js');
    const secretsCode = stripComments(fs.readFileSync(path.join(CONFIG_DIR, 'secrets.js'), 'utf8'));
    expect([...envNamesOf(secretsCode)]).toEqual([]);
    expect(secretsCode).toMatch(/FILE_BACKED_SECRETS/); // 前提自证：它确实还是动态那一族
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
