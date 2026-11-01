/**
 * Express 5 无 body 的归一（第 18 轮 audit-auth §4-1）
 *
 * 缺陷形状（下面第一条用例就是它的对照复现，故意不挂归一）：
 *   POST 不带 Content-Type ⇒ express.json() 不解析 ⇒ req.body === undefined（Express 4 恒为 {}）。
 *   于是路由里 `body('currentPassword').if((value, { req }) => !req.body.encCurrentPassword)`
 *   这类谓词抛 TypeError，而 express-validator 7.x 对**谓词抛错**的处置是把整条链当跳过：
 *   validationResult 里 0 条错误、错误中间件不触发。校验既已失效，请求直达控制器——
 *   控制器里 `const { currentPassword } = req.body` 对 undefined 解构 ⇒ TypeError ⇒ 500
 *   （本该是 400「请提供当前口令」）。畸形请求换来一个 500，既污染告警口径，
 *   也把"必填字段校验"整条变成摆设。
 *
 * 关键点：本文件挂的是**生产真实的校验链**（require 自 middleware/security/reauthCredentialRules）
 * 与**真实门面** applyPostBodySecurity，不是手搓复刻。所以它变红时一定是产品代码少了一次归一。
 */
const express = require('express');
const request = require('supertest');
const { validationResult } = require('express-validator');
const { applyPostBodySecurity } = require('../../middleware/security');
const { reauthCredentialValidation } = require('../../middleware/security/reauthCredentialRules');

/** 复刻 authRoutes 的 reauth 路由编排：真实校验链 → 「有错就 400」→ 控制器段 */
const reauthApp = ({ withPostBodySecurity }) => {
  const app = express();
  app.use(express.json());
  if (withPostBodySecurity) applyPostBodySecurity(app);
  app.post('/reauth', ...reauthCredentialValidation, (req, res, next) => {
    const errs = validationResult(req).array();
    if (errs.length) {
      return res.status(400).json({ kind: 'validation', errs: errs.map((e) => e.path) });
    }
    try {
      const { currentPassword } = req.body;
      if (!currentPassword) return res.status(400).json({ kind: 'missing' });
      return res.json({ kind: 'ok' });
    } catch (e) {
      return next(e);
    }
  });
  app.use((err, _req, res, _next) => res.status(500).json({ kind: 'crash', message: err.message }));
  return app;
};

describe('Express 5：无 body 的请求不得带着 undefined body 直达控制器（真实校验链）', () => {
  test('对照（故意不挂归一）：畸形请求以 500 收场——这条证明后面的绿不是恒真', async () => {
    const res = await request(reauthApp({ withPostBodySecurity: false }))
      .post('/reauth')
      .send();
    expect(res.status).toBe(500);
    expect(res.body.kind).toBe('crash');
    expect(String(res.body.message)).toMatch(/req\.body/);
  });

  test('挂了 applyPostBodySecurity ⇒ 同一个请求落到 400（判据缺失），不再是 500', async () => {
    const res = await request(reauthApp({ withPostBodySecurity: true }))
      .post('/reauth')
      .send();
    expect(res.status).toBe(400);
    expect(res.body.kind).toBe('missing');
  });

  test('正常请求不受影响：带 body 时校验链与控制器照常工作', async () => {
    const res = await request(reauthApp({ withPostBodySecurity: true }))
      .post('/reauth')
      .send({ currentPassword: 'a-long-enough-password' });
    // 真实链的 custom 校验（strict 模式/强度）可能给 400，但绝不能是 500，且当内容合法时是 200
    expect(res.status).not.toBe(500);
    if (res.status === 200) expect(res.body.kind).toBe('ok');
    else expect(res.body.kind).toBe('validation');
  });

  test('归一本身：无 body 时 req.body 是可解构的对象而不是 undefined', async () => {
    const app = express();
    app.use(express.json());
    applyPostBodySecurity(app);
    app.post('/echo', (req, res) => {
      const { username } = req.body; // 在 undefined 上解构会抛 TypeError
      res.json({ type: typeof req.body, username: username === undefined ? null : username });
    });
    const res = await request(app).post('/echo').send();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ type: 'object', username: null });
  });
});
