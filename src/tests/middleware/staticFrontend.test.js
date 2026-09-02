/**
 * L-1 生产前端静态托管（src/middleware/staticFrontend.js）
 *
 * 覆盖：启用条件（auto/强制开关/开发跳过）、index 与 SPA history 回退、
 * 缓存策略（哈希资源长缓存 / index.html 与 sw.js 不缓存）、
 * .map 纵深拦截、保留前缀不被吞、非 HTML 请求落回 404。
 *
 * config.frontend 在 config/index.js 加载期求值，故每个用例用
 * jest.isolateModules 重新加载模块链，确保读到用例设置的 env。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

function makeFixtureDist() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dist-fixture-'));
  fs.mkdirSync(path.join(dir, 'assets'));
  fs.writeFileSync(
    path.join(dir, 'index.html'),
    '<!doctype html><html><body>SPA-INDEX-MARKER</body></html>'
  );
  fs.writeFileSync(path.join(dir, 'sw.js'), '// service worker');
  fs.writeFileSync(path.join(dir, 'assets', 'app-abc123.js'), 'console.log(1);');
  return dir;
}

function loadModule({ serve, distDir, nodeEnv = 'test' }) {
  const prev = {
    serve: process.env.SERVE_FRONTEND,
    dist: process.env.FRONTEND_DIST,
    env: process.env.NODE_ENV,
  };
  process.env.SERVE_FRONTEND = serve;
  process.env.FRONTEND_DIST = distDir;
  process.env.NODE_ENV = nodeEnv;

  let mod;
  let express;
  jest.isolateModules(() => {
    jest.resetModules();
    express = require('express');
    mod = require('../../middleware/staticFrontend');
  });

  // shouldServeFrontend 在挂载期读实时 env，还原必须发生在 buildApp 之后
  const restore = () => {
    process.env.SERVE_FRONTEND = prev.serve;
    process.env.FRONTEND_DIST = prev.dist;
    process.env.NODE_ENV = prev.env;
  };
  return { mod, express, restore };
}

function buildApp(mod, express, { mountFallback = true } = {}) {
  const app = express();
  app.get('/api/ping', (req, res) => res.json({ pong: true }));
  const mounted = mod.mountStaticFrontend(app, {});
  if (mountFallback) {
    app.use((req, res) => res.status(404).json({ success: false, message: 'nf' }));
  }
  return { app, mounted };
}

describe('staticFrontend 启用条件', () => {
  test('serve=false 强制关闭（即使产物存在）', () => {
    const dist = makeFixtureDist();
    const { mod, express, restore } = loadModule({ serve: 'false', distDir: dist });
    const { mounted } = buildApp(mod, express);
    restore();
    expect(mounted).toBe(false);
  });

  test('auto 模式 development 下跳过（Vite 工作流不受影响）', () => {
    const dist = makeFixtureDist();
    const { mod, express, restore } = loadModule({
      serve: 'auto',
      distDir: dist,
      nodeEnv: 'development',
    });
    const { mounted } = buildApp(mod, express);
    restore();
    expect(mounted).toBe(false);
  });

  test('auto 模式 test 环境下同样跳过（避免吞掉 404 类断言）', () => {
    const dist = makeFixtureDist();
    const { mod, express, restore } = loadModule({ serve: 'auto', distDir: dist, nodeEnv: 'test' });
    const { mounted } = buildApp(mod, express);
    restore();
    expect(mounted).toBe(false);
  });

  test('auto 模式无产物时不启用', () => {
    const { mod, express, restore } = loadModule({
      serve: 'auto',
      distDir: path.join(os.tmpdir(), 'no-such-dist'),
    });
    const { mounted } = buildApp(mod, express);
    restore();
    expect(mounted).toBe(false);
  });

  test('auto 模式非开发环境且产物存在时启用', () => {
    const dist = makeFixtureDist();
    const { mod, express, restore } = loadModule({
      serve: 'auto',
      distDir: dist,
      nodeEnv: 'production',
    });
    const { mounted } = buildApp(mod, express);
    restore();
    expect(mounted).toBe(true);
  });
});

describe('staticFrontend 请求行为', () => {
  let dist;
  let app;

  beforeAll(() => {
    dist = makeFixtureDist();
    const { mod, express, restore } = loadModule({ serve: 'true', distDir: dist });
    ({ app } = buildApp(mod, express));
    restore();
  });

  test('GET / 返回 index.html 且不缓存', async () => {
    const res = await request(app).get('/').expect(200);
    expect(res.text).toContain('SPA-INDEX-MARKER');
    expect(res.headers['cache-control']).toBe('no-cache');
  });

  test('SPA history 回退：深链（接受 HTML 的 GET）返回 index', async () => {
    const res = await request(app)
      .get('/devices/detail?id=1')
      .set('Accept', 'text/html')
      .expect(200);
    expect(res.text).toContain('SPA-INDEX-MARKER');
  });

  test('带内容哈希的资源走强缓存（1 年 + immutable）', async () => {
    const res = await request(app).get('/assets/app-abc123.js').expect(200);
    expect(res.headers['cache-control']).toMatch(/max-age=31536000/);
    expect(res.headers['cache-control']).toMatch(/immutable/);
  });

  test('sw.js 不缓存（发版即时生效）', async () => {
    const res = await request(app).get('/sw.js').expect(200);
    expect(res.headers['cache-control']).toBe('no-cache');
  });

  test('.map 请求被纵深拦截为 404（源码映射绝不下发）', async () => {
    fs.writeFileSync(path.join(dist, 'assets', 'leak.js.map'), '{"version":3}');
    const res = await request(app).get('/assets/leak.js.map').expect(404);
    expect(res.body.success).toBe(false);
  });

  test('保留前缀 /api 不被静态层吞掉', async () => {
    const res = await request(app).get('/api/ping').expect(200);
    expect(res.body).toEqual({ pong: true });
  });

  test('不接受 HTML 的 GET 落回 404（静态文件以外的路径不当 SPA 处理）', async () => {
    const res = await request(app)
      .get('/no-such-file')
      .set('Accept', 'application/json')
      .expect(404);
    expect(res.body.success).toBe(false);
  });

  test('POST 未命中路由落回 404（仅 GET/HEAD 走 history 回退）', async () => {
    await request(app).post('/some-page').expect(404);
  });
});
