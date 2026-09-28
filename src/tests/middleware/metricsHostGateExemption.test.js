/**
 * `/metrics` 只豁免 Host 一项协议合规校验
 *
 * 断链本体（不是理论推演，是 shipped 配置两侧的字节）：
 *   · deployment/observability/prometheus.yml 的 job `xf-app` 直连容器服务名抓
 *     `app:3000` ⇒ 发出的 Host 就是 `app:3000`；
 *   · docker-compose.yml:41 强制 `ALLOWED_HOSTS=${ALLOWED_HOSTS:?...}`，且填的是对外域名。
 * 两侧永不相交 ⇒ 每一次抓取都被 protocolCompliance 判 400 HOST_HEADER_INVALID
 * ⇒ `up{job="xf-app"} == 0` 恒成立：BackendDown 永久告警（告警疲劳淹掉真告警），
 * 而所有基于指标的告警（错误率/审计链/登录突增）根本没有数据进时序库、永不触发。
 * 同一条件下 /health、/readyz 一直 200（走探针豁免，五项校验整体跳过）——这个不对称是线索。
 *
 * 本文件要钉住的是"豁免必须有多窄"，因此每条正向用例都配一条反向对照：
 *  1. 只豁免 Host：方法白名单、头部卫生、Content-Length 上限在 /metrics 上照常生效
 *     （顺带证伪"把 /metrics 并进探针豁免清单"这种更省事的改法——那会连两处限流器一起绕开）；
 *  2. 精确等值不是前缀：/metrics/foo、/metrics/../api/devices 这类"以 /metrics 开头"的
 *     形态不得逃掉 Host 闸门；
 *  3. 与路由同尺：换大小写不得改变 Host 的处理结果（判据大小写无关，路由器也大小写无关）；
 *  4. 真实应用侧的部署契约：用 prometheus.yml 解析出来的 Host 打到真实 createApp()，
 *     拿到的是 Prometheus 文本而不是 400。
 *
 * 用例里的路径清单是手写的，不从 HOST_GATE_EXEMPT_PATHS / PROBE_PATHS 推导——
 * 从被测清单推导出来的用例，被测清单少一条就跟着少一条断言，闸门等于没装。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');
const { protocolCompliance } = require('../../middleware/protocolCompliance');
const { PROBE_PATHS } = require('../../constants/probePaths');

const ROOT = path.join(__dirname, '..', '..', '..');

/** 生产 compose 里 ALLOWED_HOSTS 的代表值（对外域名，绝不含容器服务名） */
const ALLOWED_HOST = 'fsms.example.com';

/**
 * 抓取方实际发出的 Host —— 从 shipped 配置解析，不手抄。
 *
 * 手抄成 'app:3000' 会让本文件在 prometheus.yml 改了采集目标后继续绿灯，
 * 而那正是它要防的那类漂移。解析锚点失效时抛错而不是静默兜底。
 */
function readScrapeContract() {
  const text = fs.readFileSync(
    path.join(ROOT, 'deployment', 'observability', 'prometheus.yml'),
    'utf8'
  );
  // 只取 xf-app 那个 job：alertmanager 的 targets 与业务端点无关
  const job = text.split(/^\s*-\s+job_name:\s*/m).find((block) => block.startsWith('xf-app'));
  if (!job) throw new Error('prometheus.yml 里找不到 job_name: xf-app（解析锚点已失效）');

  const pathMatch = /metrics_path:\s*(\S+)/.exec(job);
  const targetsMatch = /targets:\s*\[([^\]]*)\]/.exec(job);
  if (!pathMatch || !targetsMatch) {
    throw new Error('xf-app job 缺少 metrics_path 或 inline targets（解析锚点已失效）');
  }
  const targets = targetsMatch[1]
    .split(',')
    .map((t) => t.trim().replace(/^['"]|['"]$/g, ''))
    .filter(Boolean);
  if (targets.length !== 1) {
    throw new Error(`xf-app 目标数应为 1，实测 ${targets.length}：${targets.join('|')}`);
  }
  return { metricsPath: pathMatch[1], host: targets[0] };
}

const SCRAPE = readScrapeContract();

/** 最小应用：只挂被测中间件 + 若干打桩路由，把语义与全栈噪声分离 */
function buildApp(options = {}) {
  const app = express();
  app.use(protocolCompliance({ allowedHosts: [ALLOWED_HOST], ...options }));
  app.get('/metrics', (_rq, res) => res.type('text/plain').send('stub_metric 1\n'));
  app.post('/metrics', (_rq, res) => res.type('text/plain').send('stub_metric 1\n'));
  app.get('/api/devices', (_rq, res) => res.json({ ok: 'devices' }));
  app.get('/api-docs', (_rq, res) => res.json({ ok: 'docs' }));
  app.get('/', (_rq, res) => res.json({ ok: 'root' }));
  return app;
}

const probe = async (app, { method = 'get', url, host }) => {
  const req = request(app)[method](url);
  if (host !== undefined) req.set('Host', host);
  const res = await req;
  return { status: res.status, code: res.body && res.body.errors && res.body.errors.errorCode };
};

describe('/metrics 的 Host 豁免：语义边界', () => {
  test('解析锚点自证：抓的是 /metrics、Host 不是对外域名那种形态', () => {
    expect(SCRAPE.metricsPath).toBe('/metrics');
    expect(SCRAPE.host).toBe('app:3000');
    // 前提：这个 Host 确实不在白名单里（否则正向用例测的是"闸门本来就放行"）
    expect(SCRAPE.host).not.toBe(ALLOWED_HOST);
  });

  test('抓取方的 Host 打 /metrics 必须命中业务处理，而不是被 Host 闸门打死', async () => {
    const res = await probe(buildApp(), { url: '/metrics', host: SCRAPE.host });
    expect(res).toEqual({ status: 200, code: undefined });
  });

  test('反向对照：同一非法 Host 打其他路径仍 400（闸门是武装的，没被整体关掉）', async () => {
    const app = buildApp();
    for (const url of ['/api/devices', '/api-docs', '/']) {
      const res = await probe(app, { url, host: SCRAPE.host });
      expect({ url, ...res }).toEqual({ url, status: 400, code: 'HOST_HEADER_INVALID' });
    }
    // 白名单内的 Host 打同几条路径必须放行，否则上面的 400 是"任何 Host 都 400"造成的假绿
    for (const url of ['/api/devices', '/api-docs', '/']) {
      expect({ url, ...(await probe(app, { url, host: ALLOWED_HOST })) }).toEqual({
        url,
        status: 200,
        code: undefined,
      });
    }
  });

  test('豁免是精确等值而不是前缀：以 /metrics 开头的其他形态照旧 400', async () => {
    const app = buildApp();
    for (const url of ['/metrics/foo', '/metricsx', '/metrics/../api/devices']) {
      const res = await probe(app, { url, host: SCRAPE.host });
      expect({ url, ...res }).toEqual({ url, status: 400, code: 'HOST_HEADER_INVALID' });
    }
  });

  test('豁免不吞方法白名单：TRACE /metrics 被方法拒绝而不是被 Host 拒绝', async () => {
    // 405（HTTP_METHOD_UNSUPPORTED）而非 400/404：证明请求确实走进了本中间件的后续检查，
    // "把 /metrics 并进探针豁免清单"那种整块豁免的改法会在这里红（它跳过全部五项）
    const res = await probe(buildApp(), { method: 'trace', url: '/metrics', host: SCRAPE.host });
    expect(res).toEqual({ status: 405, code: 'HTTP_METHOD_UNSUPPORTED' });
  });

  test('豁免不吞头部卫生：/metrics 上的超长头部值仍被拒', async () => {
    const app = express();
    app.use(protocolCompliance({ allowedHosts: [ALLOWED_HOST], maxHeaderValueLength: 32 }));
    app.get('/metrics', (_rq, res) => res.type('text/plain').send('stub_metric 1\n'));
    const res = await request(app)
      .get('/metrics')
      .set('Host', SCRAPE.host)
      .set('x-probe', 'a'.repeat(40));
    expect(res.body.errors.errorCode).toBe('HEADER_VALUE_TOO_LONG');
    expect(res.status).toBe(431);
  });

  test('豁免不吞 Content-Length 上限：POST /metrics 超限仍被拒', async () => {
    // 显式给 body：Content-Length 必须真实存在，否则测的是"没有 body 的请求"
    const res = await request(buildApp({ maxContentLength: 8 }))
      .post('/metrics')
      .set('Host', SCRAPE.host)
      .send({ probe: '0123456789' });
    expect(res.body.errors.errorCode).toBe('PAYLOAD_TOO_LARGE');
  });

  test('未配置 ALLOWED_HOSTS 时行为分毫未动（闸门本就未武装，豁免不是它生效的前提）', async () => {
    const app = buildApp({ allowedHosts: [] });
    // /metrics/foo 没有打桩路由：闸门关掉后它落到路由层的 404，
    // 与闸门武装时的 400 形成对照（同一条形态在两侧各测一次）
    const expected = { '/metrics': 200, '/api/devices': 200, '/metrics/foo': 404 };
    for (const [url, status] of Object.entries(expected)) {
      expect({ url, ...(await probe(app, { url, host: SCRAPE.host })) }).toEqual({
        url,
        status,
        code: undefined,
      });
    }
  });

  test('与路由同尺：换个大小写不得改变 Host 的处理结果', async () => {
    const app = buildApp();
    // Express 默认大小写不敏感 ⇒ /METRICS 也会命中 /metrics 的处理；
    // 豁免若做成大小写敏感，就会留一个"换个大小写就吃 Host 闸门"的不对称面
    for (const url of ['/metrics', '/METRICS', '/Metrics']) {
      const bogus = await probe(app, { url, host: SCRAPE.host });
      const allowed = await probe(app, { url, host: ALLOWED_HOST });
      expect({ url, ...bogus }).toEqual({ url, ...allowed });
    }
    // 反向对照：非豁免路径上，Host 合法与非法必须给出不同结果，
    // 否则上面的"结果相同"是闸门整体失效造成的假绿
    const differing = await Promise.all([
      probe(app, { url: '/api/devices', host: SCRAPE.host }),
      probe(app, { url: '/api/devices', host: ALLOWED_HOST }),
    ]);
    expect(differing[0]).toEqual({ status: 400, code: 'HOST_HEADER_INVALID' });
    expect(differing[1].status).toBe(200);
  });

  test('/metrics 绝不在探针豁免清单里（那是两处限流器共用的豁免面）', () => {
    // 行为侧已由上面三条"不吞其他校验"的用例钉住；这里钉的是限流器那一侧：
    // PROBE_PATHS 同时被 protocolCompliance 与全站限流器用作 skip，
    // 把 /metrics 并进去等于给出一个不限流的运行情报端点
    expect(PROBE_PATHS.some((p) => String(p).toLowerCase() === '/metrics')).toBe(false);
  });
});

describe('真实应用 + shipped 监控配置：部署链必须真的能抓起来', () => {
  const SAVED = {};
  let app;

  beforeAll(async () => {
    ['ALLOWED_HOSTS', 'METRICS_TOKEN', 'TRUST_PROXY_HOPS'].forEach((k) => {
      SAVED[k] = process.env[k];
    });
    process.env.ALLOWED_HOSTS = ALLOWED_HOST;
    delete process.env.METRICS_TOKEN;
    process.env.TRUST_PROXY_HOPS = '1';
    // Host 闸门每次拒绝都写一条链上审计；不连库的话这些写入会各自挂满
    // 10s 缓冲超时（本文件曾因此慢 30s 并让 worker 强制退出）
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // createApp 内部读 env，必须在设置之后 require
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    Object.entries(SAVED).forEach(([k, v]) => {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    });
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('以 prometheus.yml 的 target 作为 Host 抓真实 /metrics：拿到 Prometheus 文本', async () => {
    const res = await request(app).get(SCRAPE.metricsPath).set('Host', SCRAPE.host);
    expect(res.status).toBe(200);
    expect(res.text).toContain('# HELP http_requests_total');
  });

  test('同一 Host 打真实业务路径仍 400（豁免没有泄漏到全局）', async () => {
    const res = await request(app).get('/api/devices').set('Host', SCRAPE.host);
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('HOST_HEADER_INVALID');
  });

  test('Host 头在 /metrics 响应里没有输出面（豁免安全性的前提）', async () => {
    // 前提若哪天不成立（有人把 Host 写进指标标签/文本注释），Host 头注入就重新有了
    // 落点，本条先用红把改动挡住，逼改动方回头重估豁免
    const res = await request(app).get('/metrics').set('Host', SCRAPE.host);
    expect(res.status).toBe(200);
    expect(res.text).not.toContain(SCRAPE.host);
    expect(res.text).not.toContain(ALLOWED_HOST);
  });
});
