/**
 * 白名单豁免标记（req.ipWhitelisted）的可信边界（2026-09-26 审计 Top-3）
 *
 * 缺陷原文：白名单双豁免（限流 + CSRF），`originCheck.js:98` / `rateLimit.js:25`，
 * 修复面「改用 socket 地址（照抄 metricsAuth）」。
 *
 * 修复已落地（security.js 的 `isWhitelistExemptionTrustworthy`，把"发放豁免标记"
 * 这一步按不可伪造的 socket 对端门控），但**本文件补的是它缺的那一半**：
 * 修复当时没有任何断言锁住它——`grep isWhitelistExemptionTrustworthy src/tests/`
 * 为空。删掉 security.js 里 `if (isWhitelistExemptionTrustworthy(req))` 这一层，
 * 全仓测试仍全绿，而一次伪造 XFF 就能重新拿到限流 + CSRF + query 长度三重豁免。
 *
 * 本文件钉三件事：
 *   ① 判据本身：四种组合（trust proxy × 有无 XFF × 对端是否内网）逐条断言；
 *   ② 发放侧：伪造 XFF 冒充白名单 IP 时**标记不下发**，但请求仍放行
 *      （只损失"不该有的豁免"，不产生可用性回退）；
 *   ③ 消费侧：标记缺失时，限流豁免与 CSRF 来源校验都必须恢复生效
 *      ——判据正确但消费方仍读别的字段，等于没修。
 *
 * 为什么不照抄审计建议的"一律改用 socket 地址"：白名单是给**办公网 IP** 用的功能，
 * 而经 nginx 进来的流量 socket 对端恒为 nginx/容器地址。一律用 socket 地址会把
 * 整个白名单功能变成"豁免所有经代理的请求"——比原缺陷更糟。故正确解是
 * 「门控发放」而非「换字段判定」，本文件的第 2 组用例把这条语义钉住。
 */

'use strict';

const mongoose = require('mongoose');

jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve(null)),
}));

const { checkIPBlacklist, isWhitelistExemptionTrustworthy } = require('../../middleware/security');

/** 极简 req 替身：只含判据真正读到的字段，其余留空以免"测试替身自己造出结论" */
const makeReq = (overrides = {}) => {
  const headers = overrides.headers || {};
  return {
    ip: '203.0.113.77', // TEST-NET-3 文档段 = 语义上的"外部请求"
    socket: { remoteAddress: '203.0.113.77' },
    connection: { remoteAddress: '203.0.113.77' },
    method: 'POST',
    path: '/api/devices',
    originalUrl: '/api/devices',
    params: {},
    query: {},
    body: {},
    app: undefined,
    get: (name) => headers[String(name).toLowerCase()],
    ...overrides,
  };
};

/** 带 trust proxy 的 app 替身（值只用于真值判断，不做跳数解析） */
const appWithTrustProxy = (trustProxy) => ({
  get: (k) => (k === 'trust proxy' ? trustProxy : undefined),
});

describe('Top-3 ① 判据本体：isWhitelistExemptionTrustworthy 的四种组合', () => {
  test('未启用 trust proxy → 可信（req.ip 恒等于 socket 对端，请求头不参与判定）', () => {
    // 这条是既有行为的地基：绝大多数单测/本地开发都落在这一支。
    // 即使伪造 XFF 也无意义——express 不采信它。
    const req = makeReq({
      app: appWithTrustProxy(false),
      ip: '198.51.100.10',
      headers: { 'x-forwarded-for': '198.51.100.10' },
    });
    expect(isWhitelistExemptionTrustworthy(req)).toBe(true);
  });

  test('启用 trust proxy 但请求未带 XFF → 可信（req.ip 只能是 socket 对端）', () => {
    const req = makeReq({ app: appWithTrustProxy(1), ip: '198.51.100.10' });
    expect(isWhitelistExemptionTrustworthy(req)).toBe(true);
  });

  test('启用 trust proxy + 带 XFF + socket 对端是内网/回环 → 可信（经 nginx 的正常流量）', () => {
    // 生产 nginx 覆写 `X-Forwarded-For $remote_addr`，socket 对端是容器网络地址。
    // 这一支必须放行，否则"办公网 IP 加白后仍被限流/被 CSRF 拦"的可用性回退就回来了。
    for (const peer of ['::ffff:172.18.0.2', '172.18.0.2', '127.0.0.1', '::1']) {
      const req = makeReq({
        app: appWithTrustProxy(1),
        ip: '198.51.100.10',
        socket: { remoteAddress: peer },
        headers: { 'x-forwarded-for': '198.51.100.10' },
      });
      expect({ peer, ok: isWhitelistExemptionTrustworthy(req) }).toMatchObject({ peer, ok: true });
    }
  });

  test('启用 trust proxy + 带 XFF + socket 对端是公网 → 不可信（本次修复的核心）', () => {
    // 攻击形态：直连应用端口（绕过 nginx）并自报 `X-Forwarded-For: <白名单 IP>`。
    const req = makeReq({
      app: appWithTrustProxy(1),
      ip: '198.51.100.10',
      socket: { remoteAddress: '203.0.113.77' },
      headers: { 'x-forwarded-for': '198.51.100.10' },
    });
    expect(isWhitelistExemptionTrustworthy(req)).toBe(false);
  });

  test('前提自证：不可信判定不是因为"解析不出地址"而是因为"是公网"', () => {
    // 防空转：若 isPrivateOrLoopback 对所有输入都返回 false，上面那条也会绿。
    // 这里把同一函数在两段地址上的结论并排断言。
    const { isPrivateOrLoopback } = require('../../middleware/metricsAuth');
    expect(isPrivateOrLoopback('172.18.0.2')).toBe(true);
    expect(isPrivateOrLoopback('::ffff:10.0.0.5')).toBe(true);
    expect(isPrivateOrLoopback('203.0.113.77')).toBe(false);
  });
});

describe('Top-3 ② 发放侧：伪造 XFF 时标记不下发，但请求仍放行', () => {
  let IPBlacklist;

  beforeAll(async () => {
    IPBlacklist = require('../../models/IPBlacklist');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('白名单命中 + 公网直连伪造 XFF → 放行但**不挂** req.ipWhitelisted', async () => {
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(false);

    const req = makeReq({
      app: appWithTrustProxy(1),
      ip: '198.51.100.10', // 被伪造出来的"白名单 IP"
      socket: { remoteAddress: '203.0.113.77' }, // 真实来源：公网直连
      headers: { 'x-forwarded-for': '198.51.100.10' },
    });
    const res = { status: jest.fn(() => res), json: jest.fn() };
    const next = jest.fn();

    await checkIPBlacklist(req, res, next);

    expect(next).toHaveBeenCalled();
    // 关键：豁免标记必须缺席——它一旦被挂上，限流/CSRF/query 长度三处会同时放行
    expect(req.ipWhitelisted).toBeUndefined();
    // 且不得升级为拦截：白名单命中仍应放行（可用性不回退）
    expect(res.status).not.toHaveBeenCalled();
  });

  test('正对照：经内网代理的同一次白名单命中 → 标记照常下发（功能未被误伤）', async () => {
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(false);

    const req = makeReq({
      app: appWithTrustProxy(1),
      ip: '198.51.100.10',
      socket: { remoteAddress: '::ffff:172.18.0.2' }, // nginx/容器网络
      headers: { 'x-forwarded-for': '198.51.100.10' },
    });

    await checkIPBlacklist(req, { status: jest.fn(), json: jest.fn() }, jest.fn());

    expect(req.ipWhitelisted).toBe(true);
  });

  test('正对照：无 trust proxy 时白名单命中照常下发（既有单测走的正是这一支）', async () => {
    jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(true);
    jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true); // 双命中也放行

    const req = makeReq({ ip: '198.51.100.11' });

    await checkIPBlacklist(req, { status: jest.fn(), json: jest.fn() }, jest.fn());

    expect(req.ipWhitelisted).toBe(true);
  });
});

describe('Top-3 ③ 消费侧：标记缺席时两处豁免都必须恢复生效', () => {
  test('限流：skipIfWhitelisted 只认 `=== true`，伪造场景下不得跳过', () => {
    // 消费方读的是 req.ipWhitelisted。若将来有人把它改成"存在即跳过"
    // （`if (req.ipWhitelisted)`），undefined 仍为假、行为不变；但若改成读 req.ip
    // 自行判断白名单，就会绕过发放侧的门控——故这里把"读哪个字段"钉住。
    const src = require('fs')
      .readFileSync(
        require('path').join(__dirname, '..', '..', 'middleware', 'rateLimit.js'),
        'utf8'
      )
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .join('\n');
    expect(src).toMatch(/skipIfWhitelisted = \(req\) => req\.ipWhitelisted === true/);
    // 不得在限流器里另起一份白名单判据（两份判据迟早漂移，且新那份多半绕过门控）
    expect(src).not.toMatch(/isWhitelisted\s*\(/);
  });

  test('CSRF：标记缺席时跨站写请求必须被 403（豁免真的恢复生效）', () => {
    const { createOriginCheck } = require('../../middleware/originCheck');
    const middleware = createOriginCheck(['https://admin.example.com']);

    const mk = (ipWhitelisted) => ({
      method: 'POST',
      originalUrl: '/api/devices',
      ip: '203.0.113.77',
      headers: { origin: 'https://evil.example.net' },
      get: (n) => (n === 'origin' ? 'https://evil.example.net' : undefined),
      ...(ipWhitelisted ? { ipWhitelisted: true } : {}),
    });

    // 无标记：跨站来源被拒
    const denied = {
      statusCode: 200,
      status(c) {
        this.statusCode = c;
        return this;
      },
      json: jest.fn(),
    };
    middleware(mk(false), denied, jest.fn());
    expect(denied.statusCode).toBe(403);

    // 有标记（经可信边界发放）：白名单 IP 豁免来源校验
    const passed = {
      statusCode: 200,
      status(c) {
        this.statusCode = c;
        return this;
      },
      json: jest.fn(),
    };
    const next = jest.fn();
    middleware(mk(true), passed, next);
    expect(next).toHaveBeenCalled();
  });

  test('前提自证：本文件真的能看见发放侧的判据（否则第 ② 组是空转）', () => {
    // 直接断言导出面：security.js 若不再导出该判据，本文件会先在这里失败，
    // 而不是让第 ② 组以"标记为 undefined"的形式假绿。
    expect(typeof isWhitelistExemptionTrustworthy).toBe('function');
  });
});
