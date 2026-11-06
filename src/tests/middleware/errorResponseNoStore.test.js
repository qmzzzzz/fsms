/**
 * 错误响应一律 Cache-Control: no-store（2026-11-01 参考研读 P0-1）
 *
 * 缺陷形态（修复前）：错误出口不设任何缓存头。401/403/429 这类鉴权与频控结论若被
 * 浏览器或反向代理按启发式缓存，下一个同 URL 的合法请求会命中缓存的失败结论——
 * 参考项目 Nu11Cyber 的 response.ts 对 error 出口统一 no-store，正是堵这一类。
 *
 * 三条出口统一口径：
 *   1. ApiResponse.error（codeError/unauthorized/forbidden/notFound/serverError 全部汇入）；
 *   2. errorHandler.respondApiError（errorHandler 里唯一的裸 res.status().json() 错误出口）；
 *   3. app.js 的 404 JSON 兜底（集成断言在文末，走真实 createApp）。
 *
 * 汇入点之外还有一批**绕过 ApiResponse 直接写响应**的裸出口（429 限流、403 来源校验），
 * 它们不在任何汇入点下游——P0-1 落地时因此整批漏掉（r21-b 审计 H-1/H-2：19 处 429 + 2 处 403）。
 * 下方「裸出口登记表」逐个核对，判据是「`.status(<code>)` 的接收者必须是 `setNoStore(res)`」：
 * 新增一处裸出口会当场变红，而不是靠人记得回来补；「负向自证」用例证明这道判据不是空转。
 *
 * 成功路径不受影响：本组用例同时验证 success 出口**不带** no-store，
 * 防止「顺手全站加头」把可缓存的公共发现端点（security.txt max-age=86400）一起打死。
 */

// 限流器在**模块加载期**读 env（rateLimit.js / swagger.js 顶层的 rateLimit({...})）：
// 必须在 require 之前把配额压到 1，否则驱动 429 出口要发几千次请求（静态面阈值 12000）。
const PREV_ENV = {
  rl: process.env.RATE_LIMIT_MAX_REQUESTS,
  docs: process.env.DOCS_RATE_LIMIT_MAX,
};
process.env.RATE_LIMIT_MAX_REQUESTS = '1';
process.env.DOCS_RATE_LIMIT_MAX = '1';

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');
const mongoose = require('mongoose');

const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/ApiError');
const errorHandler = require('../../middleware/errorHandler');

const ROOT = path.resolve(__dirname, '../../..');

/**
 * 出口登记表检查器：返回所有**没有** setNoStore 护着的出口（行号 + 原文）。
 * 两种合格形态，任一即可：
 *   ① 同一行接收者链上有 setNoStore(res)（本批 429/403 出口的写法）；
 *   ② 出口上方 3 行内出现过 setHeader('Cache-Control', 'no-store')（统一漏斗的写法，
 *      如 rateLimit.js 的 respond429）。
 * 只读本行与上文 3 行、不跨函数猜，所以「新增一处裸出口」必然被抓到。
 */
const NO_STORE_HEADER = /setHeader\('Cache-Control',\s*'no-store'\)/;
const unguardedExits = (source, statuses, window = 3) => {
  const lines = source.split('\n');
  const out = [];
  lines.forEach((line, i) => {
    statuses.forEach((code) => {
      const re = new RegExp('\\.status\\(' + code + '\\)', 'g');
      let m = re.exec(line);
      while (m) {
        const direct = /setNoStore\(res\)\s*$/.test(line.slice(0, m.index));
        const nearby = NO_STORE_HEADER.test(lines.slice(Math.max(0, i - window), i + 1).join('\n'));
        if (!direct && !nearby) out.push({ line: i + 1, code, text: line.trim() });
        m = re.exec(line);
      }
    });
  });
  return out;
};

const countSites = (source, code) =>
  (source.match(new RegExp('\\.status\\(' + code + '\\)', 'g')) || []).length;

/** sites = 出口总数：多了少了都红，防「新增一处裸出口无人登记」 */
const EXIT_REGISTRY = [
  {
    file: 'src/middleware/rateLimit.js',
    statuses: [429],
    sites: 1,
    // 2026-11-05 登录枚举收口（d13f431 对端桶）+ 攻击检测面接线新增两处 respond429 调用点
    funnel: { name: 'respond429', callSites: 17 },
  },
  { file: 'src/routes/wellKnownRoutes.js', statuses: [429], sites: 3 },
  { file: 'src/config/swagger.js', statuses: [429], sites: 1 },
  { file: 'src/middleware/originCheck.js', statuses: [403], sites: 2 },
];

describe('错误响应 Cache-Control: no-store（P0-1）', () => {
  const makeRes = () => {
    const res = {
      headers: {},
      statusCode: null,
      body: null,
      setHeader(name, value) {
        this.headers[name.toLowerCase()] = value;
        return this;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      },
    };
    return res;
  };

  test('ApiResponse.error 置 no-store（unauthorized/forbidden/notFound/serverError 同一汇入点）', () => {
    for (const call of [
      () => ApiResponse.error(makeRes(), 'x', 400),
      () => ApiResponse.unauthorized(makeRes()),
      () => ApiResponse.forbidden(makeRes()),
      () => ApiResponse.notFound(makeRes()),
      () => ApiResponse.serverError(makeRes()),
      () => ApiResponse.codeError(makeRes(), 'AUTH_TOKEN_MISSING'),
    ]) {
      const res = call();
      expect(res.headers['cache-control']).toBe('no-store');
    }
  });

  test('ApiResponse.success 不携带 no-store（可缓存端点不受牵连）', () => {
    const res = ApiResponse.success(makeRes(), { ok: 1 });
    expect(res.headers['cache-control']).toBeUndefined();
  });

  test('errorHandler 真实链路：ApiError 400 与未知错误 500 均置 no-store', async () => {
    const app = express();
    app.get('/api-err', (_req, _res, next) => next(new ApiError('业务失败', 400)));
    app.get('/unknown-err', (_req, _res, next) => next(new Error('boom')));
    app.use(errorHandler);

    const apiErr = await request(app).get('/api-err');
    expect(apiErr.status).toBe(400);
    expect(apiErr.headers['cache-control']).toBe('no-store');

    // 未知错误路径走 logUnhandledError → codeError(INTERNAL_ERROR)，同样必须 no-store；
    // 同时压制本用例的 error 日志噪音
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const unknown = await request(app).get('/unknown-err');
      expect(unknown.status).toBe(500);
      expect(unknown.headers['cache-control']).toBe('no-store');
    } finally {
      errSpy.mockRestore();
    }
  });

  describe('真实 app 的 404 JSON 兜底（app.js installStaticAndErrorHandling）', () => {
    let app;
    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      const { createApp } = require('../../app');
      app = createApp();
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test('未命中任何路由的 JSON 404 携带 no-store', async () => {
      const res = await request(app).get('/definitely-not-a-route-20261101');
      expect(res.status).toBe(404);
      expect(res.headers['cache-control']).toBe('no-store');
      // 响应体仍是 JSON 信封而非 SPA HTML（静态面未构建时直接落到 404 兜底）
      expect(res.body.success).toBe(false);
    });
  });
});

describe('裸出口登记表：绕过 ApiResponse 的 429/403（r21-b H-1/H-2）', () => {
  EXIT_REGISTRY.forEach((entry) => {
    test(`${entry.file}：.status(${entry.statuses.join('/')}) 出口共 ${entry.sites} 处且全部经 setNoStore`, () => {
      const source = fs.readFileSync(path.join(ROOT, entry.file), 'utf8');
      const problems = [];
      entry.statuses.forEach((code) => {
        // 出口总数先钉死：新增一处裸出口（或误删一处）都会让这条断言先红
        const total = countSites(source, code);
        if (total !== entry.sites) {
          problems.push(`.status(${code}) 出口数 ${total} ≠ 登记 ${entry.sites}`);
        }
        // 逐个核对：未加护的出口带行号与原文一起报出来
        unguardedExits(source, [code]).forEach((u) => {
          problems.push(`第 ${u.line} 行未置 no-store：${u.text}`);
        });
      });
      if (entry.funnel) {
        const calls = (source.match(new RegExp(entry.funnel.name + '\\(', 'g')) || []).length;
        if (calls !== entry.funnel.callSites) {
          problems.push(`${entry.funnel.name}( 调用点 ${calls} ≠ 登记 ${entry.funnel.callSites}`);
        }
      }
      expect(problems).toEqual([]);
    });
  });

  test('负向自证：判据抓得出未加护的出口，否则本组是空转', () => {
    const planted = '    res.status(429).json({ success: false });';
    const guarded = '    setNoStore(res).status(429).json({ success: false });';
    expect(unguardedExits(planted, [429])).toEqual([{ line: 1, code: 429, text: planted.trim() }]);
    expect(unguardedExits(guarded, [429])).toEqual([]);
    expect(countSites(guarded, 429)).toBe(1);
    // 漏斗形态：头在上方 3 行内算合格；同样一句挪到 6 行外就必须报出来
    const inWindow = [
      'const respond = (res) => {',
      "  res.setHeader('Cache-Control', 'no-store');",
      '  return res.status(429).json({});',
      '};',
    ].join('\n');
    expect(unguardedExits(inWindow, [429])).toEqual([]);
    const outOfWindow = [
      "res.setHeader('Cache-Control', 'no-store');",
      'a();',
      'b();',
      'c();',
      'd();',
      'res.status(429).json({});',
    ].join('\n');
    expect(unguardedExits(outOfWindow, [429]).length).toBe(1);
  });
});

describe('裸出口的真实链路（登记表的功能侧对照）', () => {
  test('originCheck 403（非白名单来源）带 no-store', async () => {
    const { createOriginCheck } = require('../../middleware/originCheck');
    const app = express();
    app.use(createOriginCheck(['https://ok.example.com']));
    app.post('/write', (_req, res) => res.status(200).json({ ok: true }));

    const denied = await request(app)
      .post('/write')
      .set('Origin', 'https://evil.example.com')
      .send({});
    expect(denied.status).toBe(403);
    expect(denied.headers['cache-control']).toBe('no-store');
  });

  test('security.txt 专属限流 429 带 no-store（wellKnownRoutes 第 1/3 处）', async () => {
    const router = require('../../routes/wellKnownRoutes');
    const app = express();
    app.use(router);
    let last = null;
    for (let i = 0; i < 40 && (!last || last.status !== 429); i += 1) {
      last = await request(app).get('/.well-known/security.txt');
    }
    expect(last.status).toBe(429);
    expect(last.headers['cache-control']).toBe('no-store');
  });

  test('CSP 上报专属限流 429 带 no-store（wellKnownRoutes 第 2/3 处）', async () => {
    const router = require('../../routes/wellKnownRoutes');
    const app = express();
    app.use(router);
    let last = null;
    for (let i = 0; i < 70 && (!last || last.status !== 429); i += 1) {
      last = await request(app)
        .post('/csp-report')
        .set('Content-Type', 'application/csp-report')
        .send({ 'csp-report': { 'blocked-uri': 'inline' } });
    }
    expect(last.status).toBe(429);
    expect(last.headers['cache-control']).toBe('no-store');
  });

  test('前端异常上报专属限流 429 带 no-store（wellKnownRoutes 第 3/3 处）', async () => {
    const router = require('../../routes/wellKnownRoutes');
    const app = express();
    app.use(router);
    let last = null;
    for (let i = 0; i < 40 && (!last || last.status !== 429); i += 1) {
      last = await request(app).post('/client-errors').send({ entries: [] });
    }
    expect(last.status).toBe(429);
    expect(last.headers['cache-control']).toBe('no-store');
  });

  test('docs 限流 429 带 no-store（config/swagger.js 的 docsLimiter）', async () => {
    const swagger = require('../../config/swagger');
    const app = express();
    app.use(swagger.docsLimiter);
    app.get('/api-docs', (_req, res) => res.status(200).end());

    const first = await request(app).get('/api-docs');
    const second = await request(app).get('/api-docs');
    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
    expect(second.headers['cache-control']).toBe('no-store');
  });

  test('generalLimiter 429 带 no-store（直接挂载，代表 rateLimit.js 的 15 处出口）', async () => {
    // 直接挂载而非 createApp：走 app 时 4xx 可能已被其他中间件加过头，
    // 那样这条用例就证明不了 rateLimit.js 的出口自己带 no-store。
    const { generalLimiter } = require('../../middleware/rateLimit');
    const app = express();
    app.use(generalLimiter);
    // 必须用写方法 + /api 前缀：GET 非 /api 路径属静态面，会被 skip 豁免（发多少都不计数）
    app.post('/api/probe', (_req, res) => res.status(200).end());

    const first = await request(app).post('/api/probe');
    const second = await request(app).post('/api/probe');
    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
    expect(second.headers['cache-control']).toBe('no-store');
  });
});

afterAll(() => {
  // env 是进程级的：本文件把两个配额压到 1，必须还原，否则同 worker 的后续测试文件
  // 会在自己的模块加载期读到被压低的配额（限流相关用例会成批假红）。
  if (PREV_ENV.rl === undefined) delete process.env.RATE_LIMIT_MAX_REQUESTS;
  else process.env.RATE_LIMIT_MAX_REQUESTS = PREV_ENV.rl;
  if (PREV_ENV.docs === undefined) delete process.env.DOCS_RATE_LIMIT_MAX;
  else process.env.DOCS_RATE_LIMIT_MAX = PREV_ENV.docs;
});
