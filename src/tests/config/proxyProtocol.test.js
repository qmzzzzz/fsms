/**
 * PROXY_PROTOCOL 配置解析与启动闸（config/proxyProtocol.js + validate.js 接线）
 *
 * 四段（与 trustedProxyCidrs.test.js 同型）：
 *   1. 解析与取值域 —— off/on 大小写与空白容忍、未配置默认、非法值 fail-closed；
 *   2. 生产启动闸 —— on 必配 TRUSTED_PROXY_CIDRS（validateConfig 全夹具跑法，
 *      与 validate.test.js 的 TRUST_PROXY_HOPS 组同构）；
 *   3. memoize 与重置 —— resolveProxyProtocol 缓存语义（接线点与测试都依赖）；
 *   4. 接线面静态核对 —— index.js 必须真的消费这个开关（off 时零改动的承诺
 *      只能靠「on 分支存在且在 listen 之前」来钉，行为面由
 *      proxyProtocolFrontServer.test.js 的真实 socket 集成覆盖）。
 *
 * 非法值刻意解析为 enabled=false（fail-closed）而非抛错的原因见模块头注释；
 * 生产面由第 2 段的启动闸出声。
 */

'use strict';

const proxyProtocol = require('../../config/proxyProtocol');

describe('PROXY_PROTOCOL 解析与取值域', () => {
  afterEach(() => {
    delete process.env[proxyProtocol.ENV_KEY];
    proxyProtocol.resetProxyProtocolCache();
  });

  test('未配置 → configured=false 且不启用（默认 off）', () => {
    const parsed = proxyProtocol.parseProxyProtocolMode(undefined);
    expect(parsed).toEqual({ configured: false, enabled: false, errors: [] });
  });

  test('空串/纯空白 → 与未配置同判', () => {
    expect(proxyProtocol.parseProxyProtocolMode('')).toEqual({
      configured: false,
      enabled: false,
      errors: [],
    });
    expect(proxyProtocol.parseProxyProtocolMode('   ')).toEqual({
      configured: false,
      enabled: false,
      errors: [],
    });
  });

  test.each([['off'], ['OFF'], [' On ']])('%s → 合法取值（enabled=%s）', (raw) => {
    const parsed = proxyProtocol.parseProxyProtocolMode(raw);
    expect(parsed.configured).toBe(true);
    expect(parsed.errors).toEqual([]);
    expect(parsed.enabled).toBe(raw.trim().toLowerCase() === 'on');
  });

  test.each([
    ['true（布尔别名刻意不收，见模块头）'],
    ['1'],
    ['enabled'],
    ['onn（手滑形态，fail-closed 为 off 并在生产闸出声）'],
  ])('%s → 非法值：enabled=false + errors 非空', (raw) => {
    const parsed = proxyProtocol.parseProxyProtocolMode(raw);
    expect(parsed.enabled).toBe(false);
    expect(parsed.errors.length).toBeGreaterThan(0);
    expect(parsed.errors[0]).toContain(proxyProtocol.ENV_KEY);
  });
});

describe('PROXY_PROTOCOL=on 的生产启动闸（validateConfig 全夹具）', () => {
  /** 生产环境下除 PROXY_PROTOCOL / TRUSTED_PROXY_CIDRS 外全部配置合法
   *  （与 validate.test.js 的 TRUST_PROXY_HOPS 组同夹具，便于两侧结论可比） */
  const setValidProdEnv = () => {
    process.env.NODE_ENV = 'production';
    process.env.JWT_SECRET = 'strong-random-jwt-secret-that-is-long-enough';
    process.env.JWT_REFRESH_SECRET = 'strong-random-refresh-secret-long-enough';
    process.env.AES_SECRET_KEY = 'test-aes-key-with-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'strong-random-hmac-secret-that-is-long-enough';
    process.env.MONGODB_URI = 'mongodb://prod-server:27017/db?tls=true';
    process.env.CORS_ORIGIN = 'https://example.com';
    // TLS 终结声明用 TLS_TERMINATED_UPSTREAM 而不是 ENABLE_HTTPS：
    // PROXY_PROTOCOL=on 与 ENABLE_HTTPS=true 是启动硬闸拒绝的组合（ADR-021 决定 ⑥），
    // 夹具若带 ENABLE_HTTPS=true，所有 on 分支都会被组合闸拦下而非测到目标判据
    delete process.env.ENABLE_HTTPS;
    process.env.TLS_TERMINATED_UPSTREAM = 'true';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    process.env.REDIS_URL = 'rediss://redis.example.com:6379';
    process.env.REDIS_PASSWORD = 'strong-random-redis-' + 'secret-that-is-long-enough';
    process.env.TRUST_PROXY_HOPS = '1';
    process.env.TRUSTED_PROXY_CIDRS = '172.28.0.0/16';
  };

  /**
   * 以指定 PROXY_PROTOCOL / TRUSTED_PROXY_CIDRS 跑校验，返回收集到的错误消息。
   * 用 `in` 区分「未传（保持夹具默认值）」与「显式 undefined（删除该变量）」——
   * 两语义不分会让 runWith({}) 把夹具名单删掉，报出与被测开关无关的假错。
   */
  const runWith = (overrides = {}) => {
    setValidProdEnv();
    if ('proxyProtocolValue' in overrides) {
      if (overrides.proxyProtocolValue === undefined) delete process.env[proxyProtocol.ENV_KEY];
      else process.env[proxyProtocol.ENV_KEY] = overrides.proxyProtocolValue;
    }
    if ('trustedProxyCidrs' in overrides) {
      if (overrides.trustedProxyCidrs === undefined) delete process.env.TRUSTED_PROXY_CIDRS;
      else process.env.TRUSTED_PROXY_CIDRS = overrides.trustedProxyCidrs;
    }
    if ('enableHttps' in overrides) {
      if (overrides.enableHttps === undefined) delete process.env.ENABLE_HTTPS;
      else process.env.ENABLE_HTTPS = overrides.enableHttps;
    }

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

  test('未配置（默认 off）→ 不产生任何 PROXY_PROTOCOL 相关错误', () => {
    const { exited, messages } = runWith({ proxyProtocolValue: undefined });
    expect(exited).toBe(false);
    expect(messages).not.toContain('PROXY_PROTOCOL');
  });

  test('on 且名单已配置 → 通过校验', () => {
    const { exited, messages } = runWith({
      proxyProtocolValue: 'on',
      trustedProxyCidrs: '10.60.0.0/16',
    });
    expect(exited).toBe(false);
    expect(messages).not.toContain('PROXY_PROTOCOL');
  });

  test('on 但未配 TRUSTED_PROXY_CIDRS → 启动致命错误（名单是重写权凭据）', () => {
    const { exited, messages } = runWith({
      proxyProtocolValue: 'on',
      trustedProxyCidrs: undefined,
    });
    expect(exited).toBe(true);
    expect(messages).toContain('PROXY_PROTOCOL');
    expect(messages).toContain('TRUSTED_PROXY_CIDRS');
  });

  test('非法值 → 启动致命错误（非生产的 fail-closed 不替代生产面出声）', () => {
    const { exited, messages } = runWith({ proxyProtocolValue: 'onn' });
    expect(exited).toBe(true);
    expect(messages).toContain('PROXY_PROTOCOL');
  });

  test('on 与 ENABLE_HTTPS=true 组合 → 启动致命错误（TLS 句柄级读取的硬限制）', () => {
    // ADR-021 决定 ⑥：三条探针实测 TLSSocket 看不见流缓冲里已消费的头字节，
    // 组合的失败形态是「连接被接受、TLS 握手永久悬挂」——半可用路径直接拒启
    const { exited, messages } = runWith({ proxyProtocolValue: 'on', enableHttps: 'true' });
    expect(exited).toBe(true);
    expect(messages).toContain('ENABLE_HTTPS');
    expect(messages).toContain('PROXY_PROTOCOL');
  });

  test('off（显式）→ 通过校验（off 路径与未引入本功能前一致）', () => {
    const { exited, messages } = runWith({
      proxyProtocolValue: 'off',
      trustedProxyCidrs: undefined,
    });
    // off 时不要求名单（那是 trust proxy 自己的闸，不在本配置的管辖内）
    expect(exited).toBe(true); // TRUST_PROXY_HOPS=1 + 无名单仍会被既有闸拦下
    expect(messages).not.toContain('PROXY_PROTOCOL=on');
  });
});

describe('memoize 与重置（resolveProxyProtocol）', () => {
  afterEach(() => {
    delete process.env[proxyProtocol.ENV_KEY];
    proxyProtocol.resetProxyProtocolCache();
  });

  test('首次解析后缓存：改 env 不影响已解析结果，重置后重新读取', () => {
    process.env[proxyProtocol.ENV_KEY] = 'off';
    expect(proxyProtocol.resolveProxyProtocol().enabled).toBe(false);
    process.env[proxyProtocol.ENV_KEY] = 'on';
    expect(proxyProtocol.resolveProxyProtocol().enabled).toBe(false); // 缓存生效
    proxyProtocol.resetProxyProtocolCache();
    expect(proxyProtocol.resolveProxyProtocol().enabled).toBe(true); // 重置后重读
  });
});

describe('接线面静态核对（off 时零改动的承诺）', () => {
  const fs = require('fs');
  const path = require('path');
  const indexSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'index.js'), 'utf8');

  test('index.js 在 listen 之前按开关创建前置服务器，且监听/错误兜底走 listenServer', () => {
    // 行为面由 proxyProtocolFrontServer.test.js 的真实 socket 集成覆盖；
    // 这里钉接线形状：开关判定必须先于 listen，error 兜底必须挂在实际 listen 者
    expect(indexSrc).toContain('resolveProxyProtocol().enabled');
    expect(indexSrc).toContain('createProxyProtocolFrontServer(server,');
    expect(indexSrc).toContain('const listenServer = frontServer || server;');
    expect(indexSrc).toContain("listenServer.on('error'");
    expect(indexSrc).toContain('listenServer.listen(PORT');
  });

  test('优雅关闭先停前置层 accept（不 await 存量排空，注释写明理由）', () => {
    expect(indexSrc).toContain('frontServer.close(() => {})');
    expect(indexSrc.indexOf('frontServer.close')).toBeGreaterThan(
      indexSrc.indexOf('gracefulShutdown')
    );
  });

  test('拒绝留痕走 incSecurityAlert（台账 proxy_protocol_header_rejected 的调用点）', () => {
    // failOpenLedgerGate ① 按文件扫描调用点并与台账闭合；这里把接线形状钉住，
    // 防止回调被改名/搬文件后台账条目悬空
    expect(indexSrc).toContain("incSecurityAlert('proxy_protocol_header_rejected', 'high')");
  });

  test('非生产兜底守卫：on + ENABLE_HTTPS 组合在接线面也直接拒启（ADR-021 决定 ⑥）', () => {
    // 生产闸在 validateConfig；非生产（本地 dev 直跑 index.js）没人拦组合，
    // 静默悬挂是最难排查的故障形态——接线面必须引用同一文案的守卫
    // （长文案常量放 config 模块：index.js 的 max-lines 棘轮贴边放不下）
    expect(indexSrc).toContain('HTTPS_COMBO_UNSUPPORTED_MESSAGE');
  });
});
