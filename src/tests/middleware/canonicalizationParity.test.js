/**
 * 归一化平价（canonicalization parity）
 *
 * 一句话：同一个资源的两种合法写法（大小写不同的路径、百分号编码的键名）
 * 必须得到同一种处理。此前两处判据各按一种写法实现，导致：
 *   1) 审计白名单/分类按大小写敏感前缀比较，而 Express 路由大小写不敏感
 *      ⇒ GET /API/reports/export 真实导出全量数据却零留痕、category 退化 system；
 *   2) URL 打码按原始键名判断 ⇒ ?%74oken=<活令牌> 在访问日志/404 响应体里是明文，
 *      而同一请求的审计副本却是 ***；
 *   3) Transfer-Encoding 的值做 === 'chunked' 比较 ⇒ `Chunked` 免掉 Content-Type 声明要求；
 *   4) /readyz 未列入协议合规豁免 ⇒ 配了 ALLOWED_HOSTS 之后部署探针的 Host 恒被判非法。
 *
 * 每条都由"改一个大小写/一个转义"即可绕过来定义，因此用例都成对写：
 * 规范写法与变体写法必须得到完全相同的结果。
 */

const express = require('express');
const request = require('supertest');
const {
  auditPath,
  deriveCategory,
  deriveAction,
  deriveAuditMeta,
} = require('../../utils/auditMeta');
const { redactUrlQuery, matchesPathPrefix, matchesAnyPathPrefix } = require('../../utils/helpers');
const { protocolCompliance } = require('../../middleware/protocolCompliance');

const SECRET = 'eyJhbGciOiJIUzI1NiJ9.SUPERSECRET.sig';

describe('路径前缀判据与 Express 路由同尺', () => {
  test('matchesPathPrefix 对大小写不敏感，但不把 /apix 当成 /api 的子路径', () => {
    expect(matchesPathPrefix('/API/users', '/api/users')).toBe(true);
    expect(matchesPathPrefix('/Api/Reports/Export/x', '/api/reports/export')).toBe(true);
    expect(matchesPathPrefix('/api/users', '/API/USERS')).toBe(true); // 配置写错大小写也要生效
    expect(matchesPathPrefix('/apifoo', '/api')).toBe(false);
    expect(matchesPathPrefix('/api', '')).toBe(false);
    expect(matchesPathPrefix(undefined, '/api')).toBe(false);
  });

  test('matchesAnyPathPrefix 只认列表里的前缀', () => {
    const list = ['/health', '/api/users'];
    expect(matchesAnyPathPrefix(list, '/HEALTH')).toBe(true);
    expect(matchesAnyPathPrefix(list, '/API/USERS/1/roles')).toBe(true);
    expect(matchesAnyPathPrefix(list, '/api/roles')).toBe(false);
    expect(matchesAnyPathPrefix(undefined, '/x')).toBe(false);
  });

  test('category 与 action 对大小写变体给出同一结果，path 仍存原始证据', () => {
    expect(deriveCategory('/api/users')).toBe('user');
    expect(deriveCategory('/API/users')).toBe('user');
    expect(deriveCategory('/API/USERS/6a58f0/roles')).toBe('user');

    const lower = deriveAuditMeta({ originalUrl: '/api/reports/export?type=devices' });
    const upper = deriveAuditMeta({ originalUrl: '/API/REPORTS/EXPORT?type=devices' });
    expect(upper.category).toBe(lower.category);
    expect(upper.action).toBe(lower.action);
    // 落库路径保留客户端实际发送的形态（大写本身就是值得留痕的信号）
    expect(upper.path).toBe('/API/REPORTS/EXPORT');
    expect(deriveAction('GET', '/API/Users', 'user')).toBe(
      deriveAction('GET', '/api/users', 'user')
    );
  });
});

describe('审计中间件：大小写变体的敏感读取必须同等留痕', () => {
  const auditBuffer = require('../../services/auditBuffer');
  const { auditLog } = require('../../middleware/security');
  const spyPush = jest.spyOn(auditBuffer, 'push');
  const tick = () => new Promise((r) => setImmediate(r));

  const buildApp = () => {
    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.get('/api/users', (_req, res) => res.json({ ok: true }));
    app.get('/api/reports/export', (_req, res) => res.json({ ok: true }));
    return app;
  };

  beforeEach(() => spyPush.mockClear());

  const driven = (path) => {
    const hit = spyPush.mock.calls.map(([d]) => d).filter((d) => d && d.action);
    const matched = hit.filter((d) => d.path === path || d.path.toLowerCase() === path);
    return { count: matched.length, doc: matched[0] };
  };

  test.each([
    ['/api/users', '/API/users'],
    ['/api/reports/export', '/API/Reports/Export'],
  ])('%s 与 %s 的留痕数量/category/action 完全一致', async (canon, variant) => {
    const app = buildApp();

    await request(app).get(canon);
    await tick();
    const a = driven(canon);

    spyPush.mockClear();
    await request(app).get(variant);
    await tick();
    const b = driven(variant);

    // 先证"有留痕"，再证"两条一致"：只比 b===a 会在两边都为零时假绿
    expect({ canonCount: a.count, variantCount: b.count }).toEqual({
      canonCount: 1,
      variantCount: 1,
    });
    expect({
      canon: { path: a.doc.path, category: a.doc.category, action: a.doc.action },
      variant: { path: b.doc.path, category: b.doc.category, action: b.doc.action },
    }).toEqual({
      canon: { path: canon, category: a.doc.category, action: a.doc.action },
      variant: { path: variant, category: a.doc.category, action: a.doc.action },
    });
  });

  test('POST 变体路径不得将 category 退化为 system（按 category 过滤的查询会漏检）', async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/users', (_req, res) => res.json({ ok: true }));

    await request(app).post('/API/users').send({ a: 1 });
    await tick();
    const doc = spyPush.mock.calls.map(([d]) => d).find((d) => d && d.method === 'POST');
    expect(doc).toBeTruthy();
    expect({ category: doc.category, action: doc.action }).toEqual({
      category: 'user',
      action: 'user_create',
    });
  });
});

describe('URL 凭据打码：键名的百分号编码与大小写都不是豁免理由', () => {
  test.each([
    ['?token=A', '基线'],
    ['?%74oken=A', 't 编码'],
    ['?to%6Ben=A', 'k 编码'],
    ['?%54OKEN=A', 'T 编码 + 大写'],
    ['?accessToken=A', 'camelCase'],
    ['?current_password=A', 'snake_case'],
  ])('%s 的值必须被打码', (query) => {
    const out = redactUrlQuery(`/nope${query.replace('A', SECRET)}`);
    expect(out).not.toContain(SECRET);
    expect(out).toContain('***');
  });

  test('非凭据键保持原样（打码不得退化成"整串丢弃"）', () => {
    const out = redactUrlQuery('/api/users?page=2&sort=createdAt&token=x');
    expect(out).toBe('/api/users?page=2&sort=createdAt&token=***');
  });

  test('非法百分号序列不得让打码放弃判定', () => {
    // decodeURIComponent('%E0%A4%A') 会抛：回退原文后仍要走同一判据
    expect(redactUrlQuery('/x?%E0%A4%A=keep')).toBe('/x?%E0%A4%A=keep');
    expect(redactUrlQuery('/x?%74oken=abc')).toBe('/x?%74oken=***');
  });

  test('打码结果与审计侧脱敏对同一 URL 同尺', () => {
    const url = '/api/x?%74oken=abc&password=def';
    const { sanitizeAuditQuery } = require('../../models/auditLogSanitizer');
    const audited = JSON.stringify(sanitizeAuditQuery({ token: 'abc', password: 'def' }));
    expect(audited).not.toContain('abc');
    expect(audited).not.toContain('def');
    expect(redactUrlQuery(url)).not.toContain('abc');
    expect(redactUrlQuery(url)).not.toContain('def');
  });
});

describe('协议合规：头部值大小写与探针豁免', () => {
  // 这两条只测 Content-Type 声明要求，Host 白名单必须关掉：
  // supertest 发的 Host 是 127.0.0.1:随机端口，若开启校验会先被 HOST_HEADER_INVALID 拦掉，
  // 用例就变成"测到了另一条规则"。Host 规则本身由下面两组用例单独钉。
  const drive = async (req, options = {}) => {
    const app = express();
    app.use(protocolCompliance({ allowedHosts: [], ...options }));
    app.post('/api/thing', (_rq, res) => res.json({ ok: true }));
    app.get('/api/thing', (_rq, res) => res.json({ ok: true }));
    const res = await req(app);
    return { status: res.status, code: res.body?.errors?.errorCode };
  };

  /**
   * 直接驱动中间件而不是走 supertest：chunked-且-无-Content-Type 这个形态
   * 用 HTTP 客户端造不出来（superagent 必然带上 Content-Length 并自动补 Content-Type），
   * 只有按线上的字节形态喂 req 桩才能测到判据本身。
   */
  const runCompliance = (transferEncoding, withContentType) => {
    const mw = protocolCompliance({ allowedHosts: [] });
    const headers = {};
    if (transferEncoding !== undefined) headers['transfer-encoding'] = transferEncoding;
    if (withContentType) headers['content-type'] = 'application/json';
    const req = {
      method: 'POST',
      originalUrl: '/api/thing',
      headers,
      ip: '203.0.113.9',
      get: (name) => headers[String(name).toLowerCase()],
      app: { get: () => undefined },
    };
    const res = {
      statusCode: null,
      body: null,
      status(c) {
        this.statusCode = c;
        return this;
      },
      json(b) {
        this.body = b;
        return this;
      },
    };
    const next = jest.fn();
    mw(req, res, next);
    return { passed: next.mock.calls.length === 1, code: res.body?.errors?.errorCode };
  };

  test('Transfer-Encoding: Chunked（任意大小写/带列表/带空白）仍必须要求声明 Content-Type', () => {
    const expected = { passed: false, code: 'CONTENT_TYPE_MISSING' };
    expect(runCompliance('chunked', false)).toEqual(expected);
    expect(runCompliance('CHUNKED', false)).toEqual(expected);
    expect(runCompliance(' Chunked ', false)).toEqual(expected);
    expect(runCompliance('gzip, chunked', false)).toEqual(expected);
    // 反向：既无 chunked 也无 Content-Length ⇒ 不要求 Content-Type（别把无 body 请求拦死）
    expect(runCompliance(undefined, false)).toEqual({ passed: true, code: undefined });
  });

  test('声明了 Content-Type 的 chunked 请求照常放行（拦的是"未声明"，不是 chunked 本身）', () => {
    expect(runCompliance('chunked', true)).toEqual({ passed: true, code: undefined });
    expect(runCompliance('Chunked', true)).toEqual({ passed: true, code: undefined });
  });

  test('两个健康探针都不吃 Host 白名单（部署门禁以 127.0.0.1 探活）', async () => {
    const app = express();
    app.use(protocolCompliance({ allowedHosts: ['api.example.com'] }));
    app.get('/health', (_rq, res) => res.json({ ok: 'health' }));
    app.get('/readyz', (_rq, res) => res.json({ ok: 'ready' }));

    for (const probe of ['/health', '/readyz', '/HEALTH', '/ReadyZ']) {
      const res = await request(app).get(probe).set('Host', '127.0.0.1:3000');
      // 200 才算豁免生效：400/403 意味着探针被 Host 白名单打死（部署门禁恒红的成因）
      expect({ probe, status: res.status, code: res.body?.errors?.errorCode }).toEqual({
        probe,
        status: 200,
        code: undefined,
      });
    }
  });

  test('业务路径的 Host 校验不受豁免影响（豁免只给探针）', async () => {
    const denied = await drive(
      (app) => request(app).get('/api/thing').set('Host', 'evil.example'),
      { allowedHosts: ['api.example.com'] }
    );
    expect(denied.code).toBe('HOST_HEADER_INVALID');
  });

  test('auditPath 仍保留原始大小写（证据不被归一化抹掉）', () => {
    expect(auditPath({ originalUrl: '/API/Users?page=1' })).toBe('/API/Users');
  });
});
