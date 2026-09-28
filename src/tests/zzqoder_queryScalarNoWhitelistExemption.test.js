/**
 * query 标量守卫不得被 IP 白名单豁免
 *
 * `queryLimit.js` 文件头自己写着：Express 5 下 sanitizeMongo 与 hpp 对 req.query 的
 * 清洗均已失效，"query 侧的真正防线就是 queryScalarGuard，移除它则防线归零"。
 * 而它的第一行是 `if (req.ipWhitelisted === true) return next()`——
 * 于是这条"唯一防线"对**白名单来源整段归零**：`?building[$ne]=office` 这样的
 * Mongo 操作符对象会原样进入 req.query 并被 controller 赋给 mongoose 过滤条件。
 *
 * 豁免的本意是"可信来源不受限流约束"，那是频次/体量语义；
 * 而标量守卫约束的是**取值形态**，与来源是否可信无关。两者混用即成漏洞。
 *
 * 不复用 createApp()：本用例要精确控制 query parser 与 ipWhitelisted 的注入点，
 * 与仓库真实挂载形态（app.js `app.use('/api/', queryScalarGuard())` +
 * extended parser）逐项对齐即可，避免把被测面埋在整站装配里。
 */

const express = require('express');
const request = require('supertest');

const buildApp = () => {
  const { queryScalarGuard } = require('../middleware/queryLimit');
  const app = express();
  app.set('query parser', 'extended');
  // 模拟 ipBlocklist 中间件命中白名单后的写法（security.js 里就是 req.ipWhitelisted = true）
  app.use((req, _res, next) => {
    req.ipWhitelisted = true;
    next();
  });
  app.use('/api/', queryScalarGuard());
  // 终端 handler 把"实际到达 mongoose 的取值"回显出来，便于断言操作符是否穿透
  app.get('/api/things', (req, res) => {
    res.json({ echoed: req.query.building, type: typeof req.query.building });
  });
  return app;
};

describe('queryScalarGuard 对白名单来源同样强制标量', () => {
  let app;
  let originalWhitelist;

  beforeAll(() => {
    originalWhitelist = process.env.IP_WHITELIST;
    app = buildApp();
  });

  afterAll(() => {
    if (originalWhitelist === undefined) delete process.env.IP_WHITELIST;
    else process.env.IP_WHITELIST = originalWhitelist;
  });

  test('白名单来源提交对象型 query 取值 → 400，而不是让操作符对象穿透', async () => {
    const res = await request(app).get('/api/things?building[$ne]=office');

    // 修复前：200，且 echoed === {"$ne":"office"}（对象直达 mongoose 过滤条件）
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
    expect(res.body.errors.params).toContain('building');
  });

  test('白名单来源提交数组型 query 取值 → 同样 400', async () => {
    const res = await request(app).get('/api/things?building[]=a&building[]=b');
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
  });

  test('反向保护：正常标量查询不受影响（修复不得变成一律拒绝）', async () => {
    const ok = await request(app).get('/api/things?building=A%E6%A0%8B');
    expect(ok.status).toBe(200);
    expect(ok.body.echoed).toBe('A栋');
    expect(ok.body.type).toBe('string');
  });
});
