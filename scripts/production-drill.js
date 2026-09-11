/**
 * 生产模式启动演练（零依赖）：验证 NODE_ENV=production 的完整启动链路
 *
 * 覆盖两件事：
 *   A. 弱密钥拒绝：生产模式下弱/缺密钥必须被 validateConfig 拦截（process.exit(1)）。
 *      在 Worker 线程中执行——worker 内的 exit 只终止 worker，不影响演练主进程。
 *      worker 以 eval 模式运行，require 相对 process.cwd()（npm script 下为项目根）。
 *   B. 强配置完整启动：随机强密钥 + 内存 MongoDB（URI 为 127.0.0.1，不含
 *      'localhost' 字面量，符合生产校验），验证健康/就绪/指标/文档关闭/
 *      登录/安全响应头/Cookie 属性/登出吊销全链路。
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

function step(name, fn) {
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

function req(method, urlPath, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      BASE + urlPath,
      {
        method,
        headers: Object.assign(
          {},
          payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {},
          token ? { Authorization: 'Bearer ' + token } : {}
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
  throw new Error('服务器 30 秒内未就绪');
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
