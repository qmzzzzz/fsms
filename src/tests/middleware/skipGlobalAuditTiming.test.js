/**
 * P0-5 修复锁定：res.locals.skipGlobalAudit 必须在**响应时刻**读取
 *
 * 缺陷（审计报告 §3.3 / §15 P0-5）：中间件原先在**请求入口**只检查一次该标志，
 * 而全部 11 处赋值点（securityController 8 / ipListController 2 / auditController 1）
 * 都在控制器内部、响应之前才赋值 → 入口检查永远早于赋值，标志 100% 失效，
 * 每个这类操作都被双写（控制器手写 1 条 + 全局中间件按路由再写 1 条）。
 *
 * 本文件锁定两件事：
 *  1. 时序语义：入口之后的赋值必须生效（不产生全局审计）；未赋值时必须产生
 *     恰好 1 条全局审计；响应之后才赋值不生效（读取点就在响应时刻）。
 *  2. 端到端：走真实 app + 真实控制器 POST /api/security/report，
 *     auditBuffer.push 不得再收到全局派生的 'security_report'。
 *
 * 另含 P1-33 的 queryScalarGuard 锁定（query 侧唯一真正生效的注入防线）。
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const auditBuffer = require('../../services/auditBuffer');
const { auditLog } = require('../../middleware/security');
const { queryScalarGuard } = require('../../middleware/queryLimit');

// auditBuffer.push 为模块对象上的可写属性（module.exports = { push, ... }），可被 spy
const spyPush = jest.spyOn(auditBuffer, 'push');

const tick = () => new Promise((resolve) => setImmediate(resolve));

/** 取本次改动 push 调用中命中指定 path 的记录 */
const pushedForPath = (fullPath) =>
  spyPush.mock.calls.map(([doc]) => doc).filter((doc) => doc && doc.path === fullPath);

// ============================================================
// 时序语义（中间件级：真实 Express 响应对象，非手工替身）
// ============================================================
describe('P0-5 skipGlobalAudit 时序：响应时刻读取', () => {
  beforeEach(() => {
    spyPush.mockClear();
  });

  const buildApp = (handler) => {
    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/probe', handler);
    return app;
  };

  test('中间件入口之后才置标志（控制器真实时序）→ 不产生全局审计', async () => {
    const app = buildApp((req, res) => {
      // 控制器在同一请求内、响应之前赋值——这正是原先永远晚于入口检查的时序
      res.locals.skipGlobalAudit = true;
      res.json({ success: true });
    });

    const res = await request(app).post('/api/probe').send({ a: 1 });
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toEqual([]);
  });

  test('未置标志 → 恰好产生 1 条全局审计（对照，防"一律跳过"式假修复）', async () => {
    const app = buildApp((req, res) => {
      res.json({ success: true });
    });

    const res = await request(app).post('/api/probe').send({ a: 1 });
    expect(res.status).toBe(200);
    await tick();

    const pushed = pushedForPath('/api/probe');
    expect(pushed).toHaveLength(1);
    expect(pushed[0].method).toBe('POST');
    expect(pushed[0].statusCode).toBe(200);
    expect(pushed[0].success).toBe(true);
  });

  test('置标志后走 res.write/res.end（流式）同样跳过（与 P0-6 包装共存）', async () => {
    const app = buildApp((req, res) => {
      res.locals.skipGlobalAudit = true;
      res.write('chunk');
      res.end();
    });

    const res = await request(app).post('/api/probe').send({ a: 1 });
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toEqual([]);
  });

  test('响应发出后才置标志 → 不追溯撤销已记录的审计（读取点即响应时刻）', async () => {
    const app = buildApp((req, res) => {
      res.json({ success: true });
      // 读取点已过：此赋值对本次请求不再有意义，属语义固化断言
      res.locals.skipGlobalAudit = true;
    });

    const res = await request(app).post('/api/probe').send({ a: 1 });
    expect(res.status).toBe(200);
    await tick();

    expect(pushedForPath('/api/probe')).toHaveLength(1);
  });
});

// ============================================================
// 端到端：真实 app + 真实控制器（POST /api/security/report）
// ============================================================
describe('P0-5 端到端：POST /api/security/report 不再双写', () => {
  let app;
  let User;
  let AuditLog;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');

    const user = await User.create({
      username: 'p05_reporter',
      email: 'p05_reporter@example.com',
      password: randomPassword(),
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: 'p05_reporter' });
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    spyPush.mockClear();
  });

  test('控制器已手写 suspicious_report → 全局派生的 security_report 不得入 buffer', async () => {
    const res = await request(app)
      .post('/api/security/report')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetType: 'system', reason: 'P0-5 时序回归验证' });

    expect(res.status).toBe(200);
    await tick();
    await tick();

    const pathHits = pushedForPath('/api/security/report');
    expect(pathHits).toEqual([]);
    expect(
      spyPush.mock.calls.map(([doc]) => doc && doc.action).filter((a) => a === 'security_report')
    ).toEqual([]);

    // 唯一留痕：控制器手写的 suspicious_report（category=security）仍在
    const recorded = await AuditLog.findOne({
      action: 'suspicious_report',
      username: 'p05_reporter',
    }).lean();
    expect(recorded).not.toBeNull();
    expect(recorded.category).toBe('security');
  });
});

// ============================================================
// P1-33 锁定：queryScalarGuard 是 query 侧唯一真正生效的防线
// ============================================================
describe('P1-33 锁定：queryScalarGuard 阻断 query 注入形态', () => {
  const buildGuardApp = () => {
    const app = express();
    // 与 src/app.js 同款设置：v5 默认 simple parser 不产出对象/数组，
    // 真实 app 显式设为 extended（ADR-007），此处必须一致才能复现攻击形态
    app.set('query parser', 'extended');
    app.use('/api/', queryScalarGuard());
    app.get('/api/probe', (req, res) => res.json({ query: req.query }));
    return app;
  };

  test.each([
    ['重复键被解析为数组', '/api/probe?status=a&status=b'],
    ['括号语法被解析为对象（$regex 操作符注入形态）', '/api/probe?search[$regex]=^a'],
    ['$ne 操作符注入形态', '/api/probe?status[$ne]=active'],
  ])('%s → 400 QUERY_PARAM_MUST_BE_SCALAR', async (_label, url) => {
    const res = await request(buildGuardApp()).get(url);
    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
  });

  test('标量 query 正常放行（防误伤，确认 400 来自类型收敛而非路径不存在）', async () => {
    const res = await request(buildGuardApp()).get('/api/probe?status=active&page=1');
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ status: 'active', page: '1' });
  });

  test('真实 app：两种注入形态同样返回 400（guard 确实挂载在 /api/ 上）', async () => {
    const { createApp } = require('../../app');
    const app = createApp();
    for (const url of ['/api/users?status=a&status=b', '/api/users?search[$regex]=^a']) {
      const res = await request(app).get(url);
      expect(res.status).toBe(400);
      expect(res.body.errors?.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
    }
  });

  test('事实锁定：sanitizeMongo/hpp 对 req.query 的原地清洗在 Express 5 下不生效', async () => {
    // 这条断言是上面两处注释（security.js / queryLimit.js）的事实依据：
    // req.query 是 getter，每次访问重新解析——原地清洗写的是被丢弃的临时对象
    const { sanitizeMongo, preventHPP } = require('../../middleware/security');
    const app = express();
    app.set('query parser', 'extended');
    app.use(sanitizeMongo);
    app.use(preventHPP);
    app.get('/api/probe', (req, res) => res.json({ query: req.query }));

    const res = await request(app).get('/api/probe?search[$regex]=^a&status=a&status=b');
    expect(res.status).toBe(200);
    expect(res.body.query.search).toEqual({ $regex: '^a' });
    expect(res.body.query.status).toEqual(['a', 'b']);
  });

  test('真实 app 挂载守卫：移除 queryScalarGuard 即防线归零（用真实 400 判定）', async () => {
    // 【本次改动改造：源码正则 → 真实行为】原用例匹配 app.js 源码里
    // `app.use('/api/', queryScalarGuard())` 这行文本——把挂载点放进永不执行的分支、
    // 或换成等价的运行时组装，源码文本仍在、断言照样绿。
    // 现直接对真实 app 发注入形态请求：若 guard 真的挂在 /api/ 上，
    // 必然返回 400 + QUERY_PARAM_MUST_BE_SCALAR；若挂载被移除，会落到
    // 401/404/200 等其它状态码，用例立即转红。
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    require('../../models/TokenBlacklist');
    const { createApp } = require('../../app');
    const app = createApp();

    const res = await request(app).get('/api/users?search[$regex]=^a');
    expect(res.status).toBe(400);
    expect(res.body.errors?.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
  });
});
