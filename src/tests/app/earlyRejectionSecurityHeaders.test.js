/**
 * 早期拒绝响应也必须带齐安全响应头（与"限流必须早"不矛盾）
 *
 * app.js 把 ipLimiter / generalLimiter 挂到 body 解析与协议合规闸门之前（前移的两条理由见
 * app.js 那段注释），但**整套安全头**（attachCspNonce → helmet → ensureHsts → permissionsPolicy）
 * 在 applyPreBodySecurity 里、也就是两个 limiter 的**后面**才挂载。于是：
 *   ① 429 与 IP 黑名单 403 这两类"全站最早"的拒绝响应，一个安全头都没有；
 *   ② helmet 的 hidePoweredBy 也在这条路径上失效 ⇒ 这些响应带出 `X-Powered-By: Express`，
 *      等于把"未认证的洪水打的是哪台服务器"这件事告诉攻击者（全站 200/4xx 都 hiding，
 *      唯独被限流的响应把指纹送出来）。
 * 修法只能是"纯写头的那段往前挪"（它不读 body、不碰数据库，不违背前移限流的两条理由），
 * 而不是把限流挪回后面——那会把批次里刚收口的审计链放大面重新打开。
 *
 * 阈值必须在 require 被测模块之前设好：config 与 limiter 都在模块加载期取值。
 * 对照用例（合规闸门的 4xx 与探针 200）是**故意留下的绿**：它们与 429 走同一份断言集合，
 * 若断言集合本身写错（要求了根本不会下发的头），红的就是三条而不是一条。
 */
const request = require('supertest');

const MAX_IP = 2;
const FLOOD = 6;

const SAVED_ENV = {};
['RATE_LIMIT_IP_MAX_REQUESTS', 'RATE_LIMIT_IP_WINDOW_MS', 'TRUST_PROXY_HOPS'].forEach((key) => {
  SAVED_ENV[key] = process.env[key];
});
process.env.RATE_LIMIT_IP_MAX_REQUESTS = String(MAX_IP);
process.env.RATE_LIMIT_IP_WINDOW_MS = '900000';
// 只为按用例分桶（limiter 是模块级单例，桶按 req.ip 分）
process.env.TRUST_PROXY_HOPS = '1';

// 显式清单，不从"对照响应"的头部键推导：推导会让对照一旦回归就两头都绿。
// 取值按 helmet 7 默认 + security.js 的显式配置 + permissionsPolicy/ensureHsts 手工下发的项。
const REQUIRED_SECURITY_HEADERS = [
  'content-security-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'referrer-policy',
  'x-content-type-options',
  'x-dns-prefetch-control',
  'x-download-options',
  'x-frame-options',
  'x-permitted-cross-domain-policies',
  'permissions-policy',
  'strict-transport-security',
];

/**
 * 三条用例共用同一份判据：头齐全 + 不漏 X-Powered-By。
 * @param {import('superagent').Response} res
 */
const expectHardenedResponse = (res) => {
  for (const name of REQUIRED_SECURITY_HEADERS) {
    expect(res.headers[name]).toBeDefined();
  }
  // 单独钉一条值：整份清单都是"存在性"断言时，把 helmet 配置改成下发空串也能全绿
  expect(res.headers['x-content-type-options']).toBe('nosniff');
  expect(res.headers['x-frame-options']).toBe('DENY');
  expect(res.headers['x-powered-by']).toBeUndefined();
};

describe('早期拒绝响应的安全头', () => {
  const mongoose = require('mongoose');

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    Object.entries(SAVED_ENV).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  // 对照 ①：合规闸门挂在整套安全头之后 ⇒ 它的 4xx 天生齐全。这条绿是给断言集合背书的。
  test('对照：协议合规闸门的 4xx 带齐安全头', async () => {
    const { createApp } = require('../../app');
    const app = createApp();

    const res = await request(app).trace('/api/devices').set('X-Forwarded-For', '10.77.0.1');
    expect(res.status).toBe(405);
    expect(res.body.errors).toMatchObject({ errorCode: 'HTTP_METHOD_UNSUPPORTED' });
    expectHardenedResponse(res);
  });

  // 对照 ②：探针走完整栈。同样不得带出 X-Powered-By。
  test('对照：/health 探针 200 带齐安全头且无 X-Powered-By', async () => {
    const { createApp } = require('../../app');
    const app = createApp();

    const res = await request(app).get('/health').set('X-Forwarded-For', '10.77.0.2');
    expect(res.status).toBe(200);
    expectHardenedResponse(res);
  });

  // 应用级不变量：`X-Powered-By` 的关闭挂在 app 设置上，而不是只靠 helmet 摘头。
  // 行为断言区分不了这两者（安全头栈前置后，两类早期拒绝都会被 helmet 摘掉），所以钉设置本身：
  // 将来有人把安全头栈往后挪，靠 helmet 的那份保障会跟着挪位置，靠 app 设置的不会。
  test('X-Powered-By 的关闭是 app 级设置（不依赖 helmet 的挂载位置）', async () => {
    const { createApp } = require('../../app');
    expect(createApp().get('x-powered-by')).toBeFalsy();
  });

  test('ipLimiter 的 429 同样必须带齐安全头（且不漏 X-Powered-By）', async () => {
    const { createApp } = require('../../app');
    const app = createApp();
    const ip = '10.77.0.3';

    let throttled;
    for (let i = 0; i < FLOOD; i++) {
      const res = await request(app).trace('/api/devices').set('X-Forwarded-For', ip);
      if (res.status === 429) throttled = res;
    }
    // 前提自证：确实撞到了 ipLimiter，否则下面只是在重复对照用例
    expect(throttled).toBeDefined();
    expect(throttled.body.message).toBe('IP 请求频率超限');
    expectHardenedResponse(throttled);
  });
});
