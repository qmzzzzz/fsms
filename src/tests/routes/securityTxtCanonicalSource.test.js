/**
 * security.txt 的 Canonical 只能来自配置，绝不来自请求
 *
 * 被修掉的形态是 `Canonical: ${req.protocol}://${req.get('host')}/...`。三个前提叠在
 * 一起才构成风险，本文件把三个前提都钉住，这样任何一环被改动都会显式暴露：
 *   1) 端点公开（app.js 里 wellKnownRoutes 挂在 `/`，PERMISSION-EXEMPT）；
 *   2) 响应可被共享缓存（`Cache-Control: public, max-age=86400`）；
 *   3) Host 头白名单是**可选**的——protocolCompliance 只在
 *      `allowedHosts.length > 0` 时才拦 `host_mismatch`，没配 ALLOWED_HOSTS 即 fail-open。
 * 于是"用一个自定义 Host 改写官方安全联络页里的规范地址"在没有 ALLOWED_HOSTS 的
 * 环境里零门槛，而 Canonical 正是漏洞提交者会去信任的字段（钓鱼目标），
 * 一次投毒还会被中间缓存固化 24 小时。
 *
 * 现在的取值优先级：SECURITY_TXT_CANONICAL → ALLOWED_HOSTS 首项 → 整行不输出。
 * 缺行是可接受的（RFC 9116 里 Canonical 为可选），输出一个来自请求的值不可接受。
 */

const express = require('express');
const request = require('supertest');

const router = require('../../routes/wellKnownRoutes');
const { buildSecurityTxt } = router;

const buildApp = () => {
  const app = express();
  app.use('/', router);
  return app;
};

const GET_KEYS = ['SECURITY_TXT_CANONICAL', 'ALLOWED_HOSTS'];
let snapshot;

beforeEach(() => {
  snapshot = GET_KEYS.map((k) => [k, process.env[k]]);
  for (const k of GET_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const [k, v] of snapshot) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

/** 直接从 HTTP 响应里取 Canonical 行；没有该行返回 null（不是空串——两者语义不同） */
const canonicalLine = async (path = '/.well-known/security.txt', host) => {
  let req = request(buildApp()).get(path);
  if (host) req = req.set('Host', host);
  const res = await req;
  expect(res.status).toBe(200);
  const line = (res.text.match(/^Canonical: (.*)$/m) || [null, null])[1];
  return { value: line, res };
};

describe('Canonical 的取值来源', () => {
  test('两个配置都没有 ⇒ 宁缺毋滥：不输出 Canonical 行，且绝不把 Host 写进响应', async () => {
    const { value, res } = await canonicalLine(undefined, 'evil.example');
    expect(value).toBeNull();
    expect(res.text).not.toMatch(/evil\.example/);
    // 直接喂一个"撒谎的 req"：HTTP 层能否覆盖 Host 与这条无关，
    // 它才是变异自检要打的点——把取值改回 req.get('host') 必须在这里变红。
    const lying = { protocol: 'http', get: () => 'evil.example' };
    expect(buildSecurityTxt(lying)).not.toMatch(/evil\.example/);
    expect(buildSecurityTxt(lying)).not.toMatch(/^Canonical:/m);
    // 其余必需字段不受影响（RFC 9116 的最低要求仍在）
    expect(res.text).toMatch(/^Contact: mailto:/m);
    expect(res.text).toMatch(/^Expires: /m);
  });

  test('ALLOWED_HOSTS 首项作为来源，攻击者 Host 头进不了响应', async () => {
    process.env.ALLOWED_HOSTS = 'api.example.com,api.example.com:443';
    const { value, res } = await canonicalLine(undefined, 'evil.example');
    expect(value).toBe('http://api.example.com/.well-known/security.txt');
    expect(res.text).not.toMatch(/evil\.example/);
    expect(res.text).not.toMatch(/:443/); // 首项，不做端口猜测
  });

  test('SECURITY_TXT_CANONICAL 优先于 ALLOWED_HOSTS，且原样输出（运维要的就是精确串）', async () => {
    process.env.SECURITY_TXT_CANONICAL = 'https://psirt.example.com/.well-known/security.txt';
    process.env.ALLOWED_HOSTS = 'api.example.com';
    const { value } = await canonicalLine(undefined, 'evil.example');
    expect(value).toBe('https://psirt.example.com/.well-known/security.txt');
  });

  test('空白串不算配置：显式写成空/纯空格要退到下一级，而不是输出 "Canonical: "', async () => {
    process.env.SECURITY_TXT_CANONICAL = '   ';
    expect(buildSecurityTxt({ protocol: 'http', get: () => 'evil.example' })).not.toMatch(
      /^Canonical: *$/m
    );
    process.env.ALLOWED_HOSTS = ' host-a.example , host-b.example ';
    const body = buildSecurityTxt({ protocol: 'https', get: () => 'evil.example' });
    expect(body).toContain('Canonical: https://host-a.example/.well-known/security.txt');
  });
});

describe('风险前提（改动任一环都必须显式暴露）', () => {
  test('端点无需认证即可达，且响应声明"可被共享缓存"——这正是不能反射 Host 的原因', async () => {
    const { res } = await canonicalLine();
    expect(res.headers['cache-control']).toMatch(/public/);
    expect(res.headers['cache-control']).toMatch(/max-age=86400/);
  });

  test('根路径过渡位置走同一条取值链（两个 URL 都公开、都可缓存）', async () => {
    process.env.ALLOWED_HOSTS = 'api.example.com';
    const a = await canonicalLine('/.well-known/security.txt', 'evil.example');
    const b = await canonicalLine('/security.txt', 'evil.example');
    expect(a.value).toBe(b.value);
    expect(b.res.text).not.toMatch(/evil\.example/);
  });

  test('protocolCompliance 的 Host 白名单在未配置时确实不生效（前提 3 的实证，非推测）', () => {
    // 这一条钉的是"上游兜底不可依赖"：如果哪天它改成无条件拒绝，
    // 上面"宁缺毋滥"那条仍然成立，但本用例的断言会变——那时要重新评估取值链。
    const { protocolCompliance } = require('../../middleware/protocolCompliance');
    const app = express();
    app.use(protocolCompliance({ maxContentLength: 1024 * 1024 }));
    app.get('/probe', (_req, res) => res.json({ host: _req.get('host') }));
    return request(app)
      .get('/probe')
      .set('Host', 'evil.example')
      .then((res) => {
        // 先自证探针有效：Host 覆盖必须真的到达应用，否则"未被拒绝"是空断言
        expect(res.body.host).toBe('evil.example');
        expect(res.status).toBe(200);
      });
  });
});
