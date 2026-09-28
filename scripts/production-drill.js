/**
 * 生产模式启动演练（零依赖）：验证 NODE_ENV=production 的完整启动链路
 *
 * 覆盖两件事：
 *   A. 弱密钥拒绝：生产模式下弱/缺密钥必须被 validateConfig 拦截（process.exit(1)）。
 *      在 Worker 线程中执行——worker 内的 exit 只终止 worker，不影响演练主进程。
 *      worker 以 eval 模式运行，require 相对 process.cwd()（npm script 下为项目根）。
 *   B. 强配置完整启动：随机强密钥 + 内存 MongoDB（URI 为 127.0.0.1，不含
 *      'localhost' 字面量，符合生产校验），验证健康/就绪/指标/文档关闭/
 *      登录/安全响应头/Cookie 属性/登出吊销全链路 + Host 闸门反向对照。
 *
 * 用法：npm run test:prod-drill
 * 注意：index.js 为 require 即启动，环境变量必须先于 require 设置；
 * 临时内存库随进程退出消亡。
 */

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const { Worker } = require('worker_threads');

const PORT = process.env.DRILL_PORT || 3666;
const BASE = 'http://127.0.0.1:' + PORT;
const ROOT = path.resolve(__dirname, '..');
// 运行期组装（无凭据字面量）：大小写+数字+特殊符+随机段
const PASSWORD = 'Prd' + String.fromCharCode(33) + crypto.randomBytes(6).toString('hex') + 'Bb2';

let passed = 0;
let failed = 0;
const failures = [];
const ranSteps = [];

/**
 * 门禁自证（关键步骤必须真的被执行过）。
 *
 * 为什么需要：`step()` 只在 fn 被调用时才计数，所以「步骤块消失」既不进 passed
 * 也不进 failed——一处提前的 return、一次误删、一个 `if (false)` 包裹，都会让演练
 * 以更少的步数**照样全绿退出 0**。而 CI 的步骤名写着「生产模式演练 9 步」，
 * 那之前只是注释。本仓已在 ci.yml 为浏览器旅程加过同型防线
 * （"Assert no skipped journeys"，起因是 E2E 曾可全量跳过而 CI 全绿），这里补齐另两个门禁。
 *
 * 比对用关键子串而不是全名：改文案不会误伤，删步骤一定会红。
 */
const REQUIRED_STEP_MARKERS = [
  '弱密钥',
  '/health',
  '/readyz',
  'HSTS',
  '/api-docs',
  '/metrics',
  '/api/auth/login',
  '/api/auth/me',
  '/api/auth/logout',
  'Host 闸门',
];

/**
 * 库级 error 侦测：库自己 console.error、但不参与断言的"绿着报错"永远没人看见。
 *
 * 起因（2026-09-19 实测）：生产必须配 REDIS_URL（config/validate.js 强制），
 * 而 rateLimit.makeSharedStore 返回的手写包装 store 原先既不申报 localKeys 也不申报
 * prefix ⇒ express-rate-limit 的 singleCount 校验把 11 个 limiter 全塌进同一个
 * "Object" 桶、比较值退化成裸 IP ⇒ 凡是同时穿过 ipLimiter 与 generalLimiter 的
 * /api/ 请求都打一段 error 级 ERR_ERL_DOUBLE_COUNT 堆栈。
 * 可证伪性已验证：本门禁的正则对**修复前留存的演练日志**命中 3 行（会判红），
 * 对修复后的日志命中 0 行（判绿）。
 *
 * 只覆盖 B 阶段：A 阶段子进程的 error 日志是**被测行为本身**，不得算脏。
 * 扩展点：要纳入其它库签名时改 LIBRARY_ERROR_RE 即可（当前只钉 ERR_ERL_*）。
 */
const LIBRARY_ERROR_RE = /ERR_ERL_[A-Z_]+/;
const libraryErrors = [];
let realConsoleError = null;

function installLibraryErrorGuard() {
  realConsoleError = console.error;
  console.error = (...args) => {
    const text = args
      .map((a) => (a instanceof Error ? `${a.name}: ${a.message}` : String(a)))
      .join(' ');
    if (LIBRARY_ERROR_RE.test(text)) libraryErrors.push(text.split('\n')[0]);
    realConsoleError.apply(console, args);
  };
}

/** 收口：B 阶段侦测到的库级 error 计入失败；成功也留痕，让门禁在 CI 日志里可见 */
function assertLibraryErrorClean() {
  if (realConsoleError) console.error = realConsoleError;
  if (libraryErrors.length === 0) {
    console.log('  ok stderr 洁净：B 阶段无库级 error（ERR_ERL_*）');
    return true;
  }
  failed++;
  failures.push('stderr 洁净（库级 error）');
  console.error(
    `  FAIL stderr 洁净：B 阶段出现 ${libraryErrors.length} 条库级 error，` +
      `首个：${libraryErrors[0]}`
  );
  return false;
}

function step(name, fn) {
  ranSteps.push(name);
  return fn()
    .then(() => {
      passed++;
      console.log('  ok ' + name);
    })
    .catch((err) => {
      failed++;
      failures.push(name);
      console.error('  FAIL ' + name + ': ' + err.message);
    });
}

/** 收口：关键步骤有缺失时把整体判为失败（返回 false 便于将来被别处复用） */
function selfCheckRequiredSteps(label) {
  const missing = REQUIRED_STEP_MARKERS.filter((m) => !ranSteps.some((n) => n.includes(m)));
  if (missing.length === 0) {
    // 成功也要留痕：一条"自证通过"的日志，否则这道门禁在 CI 日志里完全不可见
    console.log(
      `  ok 门禁自证：${REQUIRED_STEP_MARKERS.length} 项关键步骤全部执行（实际 ${ranSteps.length} 步）`
    );
    return true;
  }
  failed++;
  failures.push('门禁自证：关键步骤未执行');
  console.error(`  FAIL 门禁自证：缺失 ${missing.length} 项关键步骤：${missing.join(' | ')}`);
  console.error(`[${label}] 实际执行 ${ranSteps.length} 步：${ranSteps.join(' / ')}`);
  return false;
}

function req(method, urlPath, { token, body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      BASE + urlPath,
      {
        method,
        // 调用方的 headers 合并在最后：Node 会按连接地址自动生成 Host，只有显式传入
        // 才改得写（B9 的反向对照必须发出「抓取 Host ≠ 对外白名单 Host」的形态）
        headers: Object.assign(
          {},
          payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {},
          token ? { Authorization: 'Bearer ' + token } : {},
          headers || {}
        ),
        timeout: 10000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ status: res.statusCode, body: JSON.parse(text), headers: res.headers, text });
          } catch (_) {
            resolve({ status: res.statusCode, body: text, headers: res.headers, text });
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('请求超时 ' + urlPath)));
    if (payload) req.write(payload);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await req('GET', '/health');
      if (r.status === 200) return;
    } catch (_) {
      /* 未就绪 */
    }
    await sleep(300);
  }
  throw new Error(`服务器 ${Math.round(timeoutMs / 1000)} 秒内未就绪`);
}

/** A 阶段：Worker 内以弱密钥调 validateConfig，期望 process.exit(1) */
function runNegativePhase() {
  return new Promise((resolve, reject) => {
    // 弱密钥固定长度 8（低于 32 下限），运行期生成，非真实凭据
    const workerCode = [
      "process.env.NODE_ENV = 'production';",
      "process.env.JWT_SECRET = 'x'.repeat(8);",
      "process.env.JWT_REFRESH_SECRET = 'x'.repeat(8);",
      "process.env.AES_SECRET_KEY = 'x'.repeat(8);",
      "process.env.HMAC_SECRET = 'x'.repeat(8);",
      "const { validateConfig } = require('./src/config/validate.js');",
      'validateConfig();',
      "console.log('NEGATIVE-PHASE-NOT-REJECTED');",
      'process.exit(0);',
    ].join('\n');
    const worker = new Worker(workerCode, { eval: true });
    let errText = '';
    worker.stderr.on('data', (c) => {
      errText += c.toString('utf8');
    });
    worker.stdout.on('data', (c) => {
      errText += c.toString('utf8');
    });
    worker.on('exit', (code) => resolve({ code, errText }));
    worker.on('error', reject);
  });
}

/**
 * B9 的三格判据（Host 闸门反向对照），拆出来单放：`main` 已过 `max-lines-per-function` 上限。
 *
 * 演练把 ALLOWED_HOSTS 填成自己的探测地址，所以 B1–B8 全绿并不证明闸门武装着——
 * 整条 Host 校验被摘掉、或豁免清单失控放宽，演练都看不出来。这里显式复现生产的真实
 * 错配形态：Prometheus 按容器服务名抓 `app:3000`
 * （deployment/observability/prometheus.yml 的 targets），而 compose 只允许填对外域名。
 * 两侧永不相交时，被豁免的 /metrics 必须仍然 200（否则监控链路恒红、按 up 判定的
 * BackendDown 永久告警），未被豁免的路径必须 400（否则豁免变成了"全都免"）。
 */
async function assertHostGateArmed() {
  const FOREIGN_HOST = 'app:3000';
  const scraped = await req('GET', '/metrics', { headers: { Host: FOREIGN_HOST } });
  // 要的是**样本行**而不是指标名：注册即输出 `# HELP http_requests_total`，
  // 所以只搜名字时"采集中间件被摘掉 / series 全被上限丢弃"这类空 exposition 也是绿的，
  // 而那恰好是本条要防的监控链路失效形态。取一个前面步骤真的打过的路由。
  const hasSample = /http_requests_total\{[^}]*route="\/api\/auth/.test(scraped.text);
  if (scraped.status !== 200 || !hasSample) {
    throw new Error(
      `Host=${FOREIGN_HOST} 的抓取未拿到已采到的请求样本（status=${scraped.status}）：` +
        '生产 ALLOWED_HOSTS 只填对外域名时监控链路恒红'
    );
  }
  const blocked = await req('GET', '/api/auth/me', { headers: { Host: FOREIGN_HOST } });
  // 判据要的是 400 而不是 401：401 说明请求穿过了 Host 闸门、死在认证，即闸门没武装
  const code = blocked.body && blocked.body.errors && blocked.body.errors.errorCode;
  if (blocked.status !== 400 || code !== 'HOST_HEADER_INVALID') {
    throw new Error(
      `Host=${FOREIGN_HOST} 的 /api 请求未判 HOST_HEADER_INVALID 400，` +
        `实得 ${blocked.status} ${JSON.stringify(blocked.body).slice(0, 120)}`
    );
  }
  // 第三格：豁免只免 Host 这一项。把 /metrics 并进 skipPaths（= 免掉整条协议校验，
  // 同时还是两处限流器的 skip 清单）时上面两格都是绿的，只有方法白名单还能分辨：
  // TRACE 在 skipPaths 下会一路走到路由不匹配（404），闸门正常时是 405。
  const trace = await req('TRACE', '/metrics');
  const traceCode = trace.body && trace.body.errors && trace.body.errors.errorCode;
  if (trace.status !== 405 || traceCode !== 'HTTP_METHOD_UNSUPPORTED') {
    throw new Error(
      'TRACE /metrics 实得 ' +
        trace.status +
        ' ' +
        String(traceCode) +
        '（期望 405 HTTP_METHOD_UNSUPPORTED）：/metrics 逃过了方法白名单，' +
        '说明它被并进了 skipPaths 而不是只免 Host 一项'
    );
  }
}

async function main() {
  const { MongoMemoryServer } = require('mongodb-memory-server');
  console.log('[DRILL] A 阶段：弱密钥拒绝（Worker 隔离）…');
  const neg = await runNegativePhase();
  await step('A. 弱密钥被生产校验拒绝（exit 1 + 明确错误信息）', async () => {
    if (neg.code !== 1) {
      throw new Error(
        '期望 exit 1，实得 ' +
          neg.code +
          (neg.errText.includes('NEGATIVE-PHASE-NOT-REJECTED') ? '（弱密钥未被拦截！）' : '')
      );
    }
    if (!neg.errText.includes('JWT_SECRET')) {
      throw new Error('错误信息未包含 JWT_SECRET 说明，实际输出截断：' + neg.errText.slice(0, 200));
    }
  });

  console.log('[DRILL] B 阶段：强配置完整启动（NODE_ENV=production）…');
  const mongoMem = await MongoMemoryServer.create();
  process.env.NODE_ENV = 'production';
  process.env.PORT = String(PORT);
  process.env.MONGODB_URI = mongoMem.getUri('fire_safety_prod_drill');
  // 4×强随机密钥（96 字符 hex，远超 32 下限）
  process.env.JWT_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.AES_SECRET_KEY = crypto.randomBytes(48).toString('hex');
  process.env.HMAC_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
  process.env.CORS_ORIGIN = BASE;
  process.env.TRUST_PROXY_HOPS = '1';
  // 消除 G6 告警噪声：演练声明 Host 白名单（无前置反代场景的本机域名）
  process.env.ALLOWED_HOSTS = '127.0.0.1:' + PORT;
  process.env.ALLOW_PUBLIC_REGISTRATION = 'false';
  // 演练声明 REDIS_URL：通过格式校验；运行时无真实 Redis 时内部降级为内存态
  process.env.REDIS_URL = 'redis://127.0.0.1:6379';
  process.env.AUDIT_WAL_PATH = path.join(ROOT, 'logs', 'prod-drill-audit.wal');
  process.env.LOG_LEVEL = 'warn';

  // require 即启动：生产配置强校验通过后进入监听
  require('../src/index.js');
  console.log('[DRILL] 等待就绪…');
  await waitForServer(30000);

  // 库级 error 侦测（判据与来龙去脉见上方 installLibraryErrorGuard 的注释）。
  // 只覆盖 B 阶段：A 阶段子进程的 error 日志是被测行为本身。
  installLibraryErrorGuard();

  let healthHeaders = null;
  await step('B1. GET /health 200（存活探针）', async () => {
    const r = await req('GET', '/health');
    healthHeaders = r.headers;
    if (r.status !== 200 || r.body.status !== 'ok') throw new Error('status=' + r.status);
  });

  await step('B2. GET /readyz 200（Mongo ping）', async () => {
    const r = await req('GET', '/readyz');
    if (r.status !== 200 || r.body.checks.mongo !== 'ok') throw new Error(JSON.stringify(r.body));
  });

  await step('B3. HSTS 响应头下发（ensureHsts 兜底）', async () => {
    const h = healthHeaders && healthHeaders['strict-transport-security'];
    if (!h || !h.includes('max-age=31536000')) throw new Error('HSTS 头缺失：' + h);
  });

  await step('B4. GET /api-docs 404（生产默认关闭文档）', async () => {
    const r = await req('GET', '/api-docs');
    if (r.status !== 404) throw new Error('生产环境文档未关闭，status=' + r.status);
  });

  await step('B5. GET /metrics 200（回环 metricsAuth 放行）', async () => {
    const r = await req('GET', '/metrics');
    if (r.status !== 200 || !r.text.includes('http_requests_total'))
      throw new Error('status=' + r.status);
  });

  let token = null;
  await step(
    'B6. POST /api/auth/login（admin + 初始密码；Cookie 带 Secure/HttpOnly）',
    async () => {
      const r = await req('POST', '/api/auth/login', {
        body: { username: 'admin', password: PASSWORD },
      });
      if (r.status !== 200 || !r.body.data.token) {
        throw new Error('status=' + r.status + ' ' + JSON.stringify(r.body).slice(0, 120));
      }
      token = r.body.data.token;
      const cookie = (r.headers['set-cookie'] || []).join('; ');
      if (!cookie.includes('HttpOnly'))
        throw new Error('Cookie 缺 HttpOnly：' + cookie.slice(0, 120));
      if (!/Secure/i.test(cookie))
        throw new Error('生产模式 Cookie 缺 Secure：' + cookie.slice(0, 120));
    }
  );

  await step('B7. GET /api/auth/me 200（会话有效）', async () => {
    const r = await req('GET', '/api/auth/me', { token });
    if (r.status !== 200 || !r.body.data.user) throw new Error('status=' + r.status);
  });

  await step('B8. POST /api/auth/logout 200 且旧令牌失效（me → 401）', async () => {
    const out = await req('POST', '/api/auth/logout', { token, body: {} });
    if (out.status !== 200) throw new Error('logout status=' + out.status);
    const me = await req('GET', '/api/auth/me', { token });
    if (me.status !== 401) throw new Error('旧令牌未吊销，me status=' + me.status);
  });

  await step(
    'B9. Host 闸门反向对照：抓取 Host 下 /metrics 放行、/api 仍拦、只免 Host 一项',
    assertHostGateArmed
  );

  assertLibraryErrorClean();

  selfCheckRequiredSteps('DRILL');
  console.log('[DRILL] 结果：' + passed + ' 通过, ' + failed + ' 失败');
  if (failed > 0) {
    console.error('[DRILL] 失败步骤：' + failures.join(' / '));
    process.exitCode = 1;
  }
}

main()
  .catch((err) => {
    console.error('[DRILL] 执行失败: ' + err.message);
    process.exitCode = 1;
  })
  .finally(() => {
    console.log('[DRILL] 演练结束（内存库随进程退出）');
    process.exit(process.exitCode || 0);
  });
