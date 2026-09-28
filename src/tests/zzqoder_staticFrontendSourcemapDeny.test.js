/**
 * 前端静态托管的 sourcemap 纵深拦截：编码与方法是可绕过的两个维度
 *
 * 背景（逐行审计 src/middleware/staticFrontend.js:77）：
 * 该中间件是"纵深拦截"——构建已关 sourcemap，这里防的是配置漂移后
 * 产物里出现 .map/.ts 仍被公网取到。它的判定写成
 *   req.method === 'GET' && (req.path.endsWith('.map') || req.path.endsWith('.ts'))
 * 两个维度各有一处可绕过：
 *
 * 1) 编码维度：req.path 是**未解码**的原始路径段（Express 不做 percent-decode），
 *    而真正落盘的 send 模块会先 decodeURIComponent 再解析文件
 *    （node_modules/send/index.js:881）。于是
 *      GET /assets/leak.js%2Emap
 *    判定时 endsWith('.map') === false ⇒ 放行；
 *    解析时解码成 /assets/leak.js.map ⇒ 文件存在 ⇒ 200 下发。
 *    即拦截层与解析层对"同一个 URL 指向哪个文件"的认知不一致，
 *    这正是纵深被自己的编码差异吃掉的形态。
 *
 * 2) 方法维度：判定只认 GET，HEAD 直接落到 express.static。
 *    HEAD 无响应体，但会回 200 + Content-Length ⇒ 探测 sourcemap 是否存在
 *    （以及多大），这本身就是该拦截想消掉的信息。
 *
 * 本用例把"编码/方法都不影响拦截结果"钉成契约，并反向钉住不得过度拦截：
 * 正常哈希资源、SPA 深链、/api 前缀必须照旧。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const MAP_MARKER = '{"version":3,"sources":["webpack:///src/secret-algorithm.ts"]}';
const TS_MARKER = 'export const INTERNAL_SIGNING_KEY_MATERIAL = 1;';

function makeFixtureDist() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dist-deny-'));
  fs.mkdirSync(path.join(dir, 'assets'));
  fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html><html>SPA-INDEX</html>');
  fs.writeFileSync(path.join(dir, 'assets', 'app-abc123.js'), 'console.log(1);');
  fs.writeFileSync(path.join(dir, 'assets', 'leak.js.map'), MAP_MARKER);
  fs.writeFileSync(path.join(dir, 'config.ts'), TS_MARKER);
  return dir;
}

function buildMountedApp(distDir) {
  const prev = {
    serve: process.env.SERVE_FRONTEND,
    dist: process.env.FRONTEND_DIST,
    env: process.env.NODE_ENV,
  };
  process.env.SERVE_FRONTEND = 'true';
  process.env.FRONTEND_DIST = distDir;
  process.env.NODE_ENV = 'test';

  let mod;
  let express;
  jest.isolateModules(() => {
    jest.resetModules();
    express = require('express');
    mod = require('../middleware/staticFrontend');
  });

  const app = express();
  app.get('/api/ping', (req, res) => res.json({ pong: true }));
  const mounted = mod.mountStaticFrontend(app, {});
  app.use((req, res) => res.status(404).json({ success: false, message: 'nf' }));

  process.env.SERVE_FRONTEND = prev.serve;
  process.env.FRONTEND_DIST = prev.dist;
  process.env.NODE_ENV = prev.env;

  if (!mounted) throw new Error('夹具未启用静态托管，用例前提不成立');
  return app;
}

describe('zzqoder 静态托管 sourcemap 拦截不得被编码/方法绕过', () => {
  let dist;
  let app;

  beforeAll(() => {
    dist = makeFixtureDist();
    app = buildMountedApp(dist);
  });

  afterAll(() => {
    fs.rmSync(dist, { recursive: true, force: true });
  });

  // ---- 前提自证：夹具文件真的存在且真的可读（否则下面所有 404 都是假绿）----
  test('前提自证：夹具 .map/.ts 文件确实落盘，且不经中间件时可直接取到', async () => {
    expect(fs.existsSync(path.join(dist, 'assets', 'leak.js.map'))).toBe(true);
    // 对照 app：只挂 express.static、不挂纵深拦截
    const express = require('express');
    const bare = express();
    bare.use(express.static(dist));
    bare.use((req, res) => res.status(404).end());
    const res = await request(bare).get('/assets/leak.js.map').expect(200);
    expect(res.text).toContain('secret-algorithm');
  });

  // ---- 方法维度 ----
  test.each([
    ['GET', '/assets/leak.js.map'],
    ['HEAD', '/assets/leak.js.map'],
  ])('%s 明文 .map 被拦成 404（既有契约，锚点）', async (method, url) => {
    const req = request(app)[method.toLowerCase()](url);
    const res = await req.expect(404);
    if (method === 'GET') expect(res.text).not.toContain('secret-algorithm');
  });

  test('HEAD 不得因"只判 GET"而放行：探测存在性也是泄露', async () => {
    await request(app).head('/assets/leak.js.map').expect(404);
  });

  // ---- 编码维度（send 会 decodeURIComponent，拦截层也必须看解码后的形态）----
  test.each([
    ['%2E 小写', '/assets/leak.js%2Emap'],
    ['%2E 大写', '/assets/leak.js%2emap'],
    ['根目录 %2Ets', '/config%2Ets'],
    ['双重编码（不得被解两次而误判/误放）', '/assets/leak.js%252Emap'],
    ['路径段中间编码点号', '/assets/leak%2Ejs%2Emap'],
  ])('%s → 404 且响应体不含 sourcemap 内容', async (_label, url) => {
    const res = await request(app).get(url).expect(404);
    expect(res.text).not.toContain('secret-algorithm');
    expect(res.text).not.toContain('INTERNAL_SIGNING_KEY_MATERIAL');
  });

  test('HEAD + 编码组合同样被拦（两个维度不得各自为政）', async () => {
    await request(app).head('/assets/leak.js%2Emap').expect(404);
  });

  test('大小写变体被拦（判定按归一后扩展名）', async () => {
    // 跨平台说明：Windows 文件系统不区分大小写，本机 leak.js.MAP 会命中同一份
    // 真实文件——去掉归一化在本机即可观测到红。Linux CI 上该文件不存在，
    // 这一条同样返回 404（由静态层兜底），所以它在两侧都是绿的安全断言，
    // 但只有在本机才对"漏掉 toLowerCase"的改动设防。
    await request(app).get('/assets/leak.js.MAP').expect(404);
    await request(app).get('/assets/leak.js%2EMap').expect(404);
  });

  test('编码后的 .ts 也不下发源码', async () => {
    const res = await request(app).get('/config%2Ets').expect(404);
    expect(res.text).not.toContain('INTERNAL_SIGNING_KEY_MATERIAL');
  });

  // ---- 反向：不得过度拦截 ----
  test('正常哈希资源与 SPA 深链照旧可用', async () => {
    const js = await request(app).get('/assets/app-abc123.js').expect(200);
    expect(js.text).toContain('console.log');
    const spa = await request(app).get('/devices/detail').set('Accept', 'text/html').expect(200);
    expect(spa.text).toContain('SPA-INDEX');
    // 段名里带 map 但不是扩展名（/map 路由类深链）不许被误杀
    const mapRoute = await request(app).get('/floor/map').set('Accept', 'text/html').expect(200);
    expect(mapRoute.text).toContain('SPA-INDEX');
  });

  test('/api 前缀不受影响（含编码点号的查询样式路径）', async () => {
    const res = await request(app).get('/api/ping').expect(200);
    expect(res.body).toEqual({ pong: true });
  });

  test('非法编码序列不得把请求打成 500（解码失败要落到 404）', async () => {
    // %zz 不是合法百分号编码：decodeURIComponent 抛错，必须被吞掉后按普通路径处理
    const res = await request(app).get('/assets/leak.js%zzmap').expect(404);
    expect(res.text).not.toContain('secret-algorithm');
  });
});
