/**
 * 传输加密启动断言（P2-⑧，2026-09-30）
 *
 * 审计缺口核查（deliverables/安全缺口核查-2026-09-30.md P2-⑧）指出：
 * Mongo/Redis 的连接串在生产里可以指向非回环主机而完全不加密（明文过网）。
 * 同宿主 docker 网络内风险有限——所以判据是 fail-closed + **显式命名的豁免旗**：
 *   - MONGODB_URI 指向非回环主机 ⇒ URI 必须带 ?tls=true，否则启动期硬错误；
 *   - REDIS_URL 指向非回环主机 ⇒ 必须是 rediss:；
 *   - 确属同宿主受信容器网络 ⇒ 显式 MONGODB_TLS_EXEMPT=true / REDIS_TLS_EXEMPT=true，
 *     且 compose（docker-compose.yml）正是这么做的——拓扑拆分忘摘旗标会被这里拦下。
 *
 * 判据的关键形状（每条都有对应用例）：
 *   - 回环地址（127.0.0.1/localhost/::1）不出网卡 ⇒ 明文放行，不要旗标；
 *     否则 prod-drill（127.0.0.1 内存 Mongo）与单机部署会被误杀；
 *   - hostname 解析不出（替身/畸形 URI）⇒ 本断言沉默——URI 格式由驱动兜底，
 *     compose 契约测试的 secrets 替身（"DUMMY:mongodb_uri"）必须能照常通过；
 *   - 断言只在生产语义下生效（validateConfig 的既有分叉），开发环境不误伤。
 *
 * 替身密钥用运行期拼接而非字面量：与 validate.test.js 既有夹具同值（32+ 字符、
 * 通过 isWeakSecret 的强值形态），但避免在源码里出现"看起来像在泄露凭据"的串。
 */
const DUMMY_JWT = 'strong-random-jwt-' + 'secret-that-is-long-enough';
const DUMMY_REFRESH = 'strong-random-refresh-' + 'secret-long-enough';
const DUMMY_AES = 'test-aes-key-' + 'with-32-chars-minimum!!';
const DUMMY_HMAC = 'strong-random-hmac-' + 'secret-that-is-long-enough';
// Redis 认证替身：由既有替身派生（与 DUMMY_JWT 同一"运行期拼接、不像真实凭据"的纪律）
const DUMMY_REDIS_AUTH = `${DUMMY_HMAC}-redis`;

const VALID_PROD_BASELINE = () => ({
  NODE_ENV: 'production',
  JWT_SECRET: DUMMY_JWT,
  JWT_REFRESH_SECRET: DUMMY_REFRESH,
  AES_SECRET_KEY: DUMMY_AES,
  HMAC_SECRET: DUMMY_HMAC,
  // P2-8：合法生产基线自带传输加密
  MONGODB_URI: 'mongodb://prod-server:27017/db?tls=true',
  CORS_ORIGIN: 'https://example.com',
  ENABLE_HTTPS: 'true',
  ALLOWED_HOSTS: 'api.example.com',
  REDIS_URL: 'rediss://redis.example.com:6379',
  // 2026-10-01 认证闸：生产 compose 拓扑经 REDIS_PASSWORD_FILE 注入（同值形态）
  REDIS_PASSWORD: DUMMY_REDIS_AUTH,
  TRUST_PROXY_HOPS: '1',
});

const TOUCHED_KEYS = Object.keys(VALID_PROD_BASELINE()).concat([
  'MONGODB_TLS_EXEMPT',
  'REDIS_TLS_EXEMPT',
]);

describe('传输加密启动断言（P2-⑧）', () => {
  const saved = {};
  beforeAll(() => {
    for (const key of TOUCHED_KEYS) saved[key] = process.env[key];
  });
  afterAll(() => {
    for (const key of TOUCHED_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });

  /** 跑一次真实 validateConfig：返回是否以非零退出终止 + 期间 error 级日志的行 */
  const runValidate = () => {
    jest.resetModules();
    const { validateConfig } = require('../../config/validate');
    const lines = [];
    // validateConfig 的致命项走 logger.error（降级通道才是 console.error）——
    // 两个都捕，别让"日志通道换了"把断言变成空集假绿
    const push = (...a) => lines.push(a.join(' '));
    const logger = require('../../utils/logger');
    const logSpy = jest.spyOn(logger, 'error').mockImplementation(push);
    const errSpy = jest.spyOn(console, 'error').mockImplementation(push);
    const exitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`__exit_${code}__`);
    });
    try {
      validateConfig();
      return { fatal: false, lines };
    } catch (e) {
      if (String(e.message).startsWith('__exit_')) return { fatal: true, lines };
      throw e;
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
      exitSpy.mockRestore();
    }
  };

  const withEnv = (overrides) => {
    for (const key of TOUCHED_KEYS) delete process.env[key];
    Object.assign(process.env, VALID_PROD_BASELINE(), overrides);
    // 值为 undefined 的覆盖项必须真删键：Object.assign 会把 undefined 强转成
    // 字符串 "undefined"（process.env 的既有陷阱），让「未设置」分支永远测不到
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) delete process.env[key];
    }
  };

  test('基线（tls=true + rediss:）生产校验通过', () => {
    withEnv({});
    expect(runValidate().fatal).toBe(false);
  });

  test('非回环 Mongo 无 tls=true ⇒ 硬错误且点名补法', () => {
    withEnv({ MONGODB_URI: 'mongodb://prod-server:27017/db' });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(true);
    expect(lines.join('\n')).toContain('MONGODB_URI');
    expect(lines.join('\n')).toContain('tls=true');
  });

  test('豁免旗 MONGODB_TLS_EXEMPT=true 放行（同宿主受信网络的显式出口）', () => {
    withEnv({ MONGODB_URI: 'mongodb://prod-server:27017/db', MONGODB_TLS_EXEMPT: 'true' });
    expect(runValidate().fatal).toBe(false);
  });

  test('回环 Mongo 明文放行（不出网卡：prod-drill 的内存 Mongo 形态）', () => {
    withEnv({ MONGODB_URI: 'mongodb://127.0.0.1:27017/db' });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(false);
    expect(lines.join('\n')).not.toContain('tls=true');
  });

  test('非回环明文 redis: ⇒ 硬错误并指向 rediss:', () => {
    withEnv({ REDIS_URL: 'redis://redis.example.com:6379' });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(true);
    expect(lines.join('\n')).toContain('rediss:');
  });

  test('豁免旗 REDIS_TLS_EXEMPT=true 放行', () => {
    withEnv({ REDIS_URL: 'redis://redis.example.com:6379', REDIS_TLS_EXEMPT: 'true' });
    expect(runValidate().fatal).toBe(false);
  });

  test('回环 redis: 明文放行（单机部署形态）', () => {
    withEnv({ REDIS_URL: 'redis://127.0.0.1:6379' });
    expect(runValidate().fatal).toBe(false);
  });

  test('hostname 解析不出 ⇒ 本断言沉默（URI 格式归驱动管，compose 替身形态不被误杀）', () => {
    withEnv({ MONGODB_URI: 'not-a-parseable-uri-but-compose-contract-uses-this-shape' });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(false);
    expect(lines.join('\n')).not.toContain('tls=true');
  });

  test('断言只在生产语义下生效（开发环境无 tls 也不拦）', () => {
    withEnv({ NODE_ENV: 'development', MONGODB_URI: 'mongodb://prod-server:27017/db' });
    expect(runValidate().fatal).toBe(false);
  });

  /**
   * 未指定地址（:: / 0.0.0.0）= 任意接口，与回环恰好相反。
   * 修前 `::` 被当成回环而 `0.0.0.0` 没有——同一条"可能出网卡"的事实给出两种口径，
   * 于是 mongodb://[::]/ 形态静默跳过 TLS 断言。两侧一并钉住，防止再单边回归。
   */
  test('未指定地址不是回环：:: 与 0.0.0.0 口径对称', () => {
    const { isLoopbackHostname } = require('../../config/transportSecurity');
    for (const unspecified of ['::', '[::]', '0.0.0.0']) {
      expect(isLoopbackHostname(unspecified)).toBe(false);
    }
    for (const loopback of ['::1', '[::1]', '127.0.0.1', 'localhost', '::ffff:127.0.0.1']) {
      expect(isLoopbackHostname(loopback)).toBe(true);
    }
  });

  test('Mongo 指向 [::] 且无 tls ⇒ 硬错误（曾因被误判回环而静默放行）', () => {
    withEnv({ MONGODB_URI: 'mongodb://[::]:27017/db' });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(true);
    expect(lines.join('\n')).toContain('MONGODB_URI');
  });

  test('Redis 指向 [::] 明文 ⇒ 硬错误', () => {
    withEnv({ REDIS_URL: 'redis://[::]:6379' });
    expect(runValidate().fatal).toBe(true);
  });

  // ===== Redis 认证闸（2026-10-01，collectRedisAuthErrors）=====

  test('认证闸：无凭据且无 REDIS_PASSWORD ⇒ 硬错误并点名两种补法', () => {
    withEnv({ REDIS_PASSWORD: undefined });
    const { fatal, lines } = runValidate();
    expect(fatal).toBe(true);
    const joined = lines.join('\n');
    expect(joined).toContain('Redis 必须启用认证');
    expect(joined).toContain('REDIS_PASSWORD_FILE');
    expect(joined).toContain('REDIS_AUTH_EXEMPT');
  });

  test('认证闸：URL userinfo 凭据放行（redis://:pass@host 形态）', () => {
    withEnv({
      REDIS_PASSWORD: undefined,
      REDIS_URL: `rediss://:${DUMMY_REDIS_AUTH}@redis.example.com:6379`,
    });
    expect(runValidate().fatal).toBe(false);
  });

  test('认证闸：REDIS_AUTH_EXEMPT=true 显式豁免放行（受信内网免认证的唯一出口）', () => {
    withEnv({ REDIS_PASSWORD: undefined, REDIS_AUTH_EXEMPT: 'true' });
    expect(runValidate().fatal).toBe(false);
  });

  test('认证闸：REDIS_PASSWORD 携带即放行（生产 compose 的 REDIS_PASSWORD_FILE 同值形态）', () => {
    withEnv({});
    expect(runValidate().fatal).toBe(false);
    withEnv({ REDIS_URL: 'rediss://redis.example.com:6379' }); // 基线 REDIS_PASSWORD 仍在
    expect(runValidate().fatal).toBe(false);
  });
});
