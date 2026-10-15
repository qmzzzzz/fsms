/**
 * X-XSS-Protection 显式置 0 —— 行为级验证（2026-10-15）
 *
 * ## 为什么需要这个文件
 *
 * `middleware/security.js` 的 helmet 配置写的是 `xssFilter: true`，而该选项的语义
 * **反直觉**（回源 node_modules/helmet/index.cjs，v7.2.0）：
 *   - `xXssProtection()` 恒 `res.setHeader("X-XSS-Protection", "0")`；
 *   - `getMiddlewareFunctionsFromOptions` 里 `case true: result.push(xXssProtection())`、
 *     `case false: break`（**不挂载该中间件**）。
 * ⇒ `true`（同时也是 helmet 的默认值）下发的正是 OWASP 建议的显式 `0`；
 *   `false` 是「完全不设这个头」，且 helmet **不告警**。
 *
 * 该头此前全仓零断言（`grep -ri 'x-xss-protection'` 在测试目录无命中）。后果是：
 * 把 `xssFilter` 误改为 `false` 不会有任何红灯——经 nginx 的流量仍被
 * `deployment/nginx.conf.example:111` 的 `add_header X-XSS-Protection "0"` 兜住，
 * 但**直连 app 端口**（容器网络内的其他服务、探针、任何绕过反代的调用）的响应
 * 会静默失去该头。本文件把「后端确实下发 0」这一事实钉住。
 *
 * ## 可证伪性（每条断言挡的是什么）
 *   - `xssFilter: false` ⇒ 头消失 ⇒ 前三条同时转红；
 *   - 改成 `1; mode=block` 或任何非 `'0'` 值 ⇒ 精确等值断言转红（防退回"启用旧 auditor"）；
 *   - 头只在成功路径下发 ⇒ 404 用例转红；
 *   - 重复下发（中间件被挂两次等）⇒「恰好一个头」用例转红。
 *
 * 断言必须**精确等值**而非 `toBeDefined()`：后者对 `1; mode=block` 同样为真，
 * 属于对目标回归无牙的空洞断言（本仓纪律：断言要挡得住它声称挡住的东西）。
 */

const express = require('express');
const http = require('http');
const helmet = require('helmet');
const request = require('supertest');

const {
  attachCspNonce,
  securityHeaders,
  applyResponseHardening,
} = require('../../middleware/security');

const XSS_HEADER = 'x-xss-protection';

/** 与 cspNonce.test.js 同构的最小 app：只挂被验证的那两个中间件 + 一个兜底路由 */
function buildApp() {
  const app = express();
  app.use(attachCspNonce);
  app.use(securityHeaders);
  app.use((req, res) => res.json({ ok: true }));
  return app;
}

describe('X-XSS-Protection 显式置 0', () => {
  test('普通路径下发且精确等于 "0"（不是 "1; mode=block"、也不是未设）', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    expect(res.headers[XSS_HEADER]).toBe('0');
  });

  test('错误路径（404）同样下发：头不只在成功响应上', async () => {
    // 刻意不挂兜底路由：Express 默认 404 处理器接管，验证该头与状态码无关
    const app = express();
    app.use(attachCspNonce);
    app.use(securityHeaders);
    const res = await request(app).get('/api/not-found').expect(404);
    expect(res.headers[XSS_HEADER]).toBe('0');
  });

  test('applyResponseHardening 真实挂载路径同样下发（与 src/app.js 的挂载方式一致）', async () => {
    const app = express();
    applyResponseHardening(app);
    app.use((req, res) => res.json({ ok: true }));
    const res = await request(app).get('/api/anything').expect(200);
    expect(res.headers[XSS_HEADER]).toBe('0');
  });

  /**
   * 用原生 http 取 rawHeaders 而非 supertest 的合并视图：
   * supertest/superagent 会把同名响应头合并成 `'0, 0'`，虽然等值断言同样会红，
   * 但"恰好一个"这件事要**直接计数**才说得清（本仓口径：结论要能自证形态）。
   */
  test('恰好下发一个 X-XSS-Protection（重复挂载会被抓出来）', async () => {
    const app = buildApp();
    const server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    try {
      const { port } = server.address();
      const rawHeaders = await new Promise((resolve, reject) => {
        http
          .get({ host: '127.0.0.1', port, path: '/api/anything' }, (res) => {
            res.resume();
            resolve(res.rawHeaders);
          })
          .on('error', reject);
      });
      const values = [];
      for (let i = 0; i < rawHeaders.length; i += 2) {
        if (rawHeaders[i].toLowerCase() === XSS_HEADER) values.push(rawHeaders[i + 1]);
      }
      expect(values).toEqual(['0']);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  /**
   * 判据有牙的自证：证明上面几条不是恒真。
   *
   * 这里直接钉住 helmet 的**反直觉语义**——`xssFilter: false` 时该头必须**消失**
   * （而不是变成某个"更弱的值"）。一旦上游改变这个语义（例如 false 改为下发 `'0'`），
   * 本用例先红，提示 `security.js` 那段注释与 nginx 的口径说明需要重新回源核对。
   */
  test('判据有牙：xssFilter 为 false 时该头确实消失（钉住 helmet 语义）', async () => {
    const app = express();
    app.use(helmet({ xssFilter: false }));
    app.use((req, res) => res.json({ ok: true }));
    const res = await request(app).get('/api/anything').expect(200);
    expect(res.headers[XSS_HEADER]).toBeUndefined();
  });
});
