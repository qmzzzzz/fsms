/**
 * E2E 冒烟测试（零依赖）：在进程内启动完整服务器，全链路 HTTP 走查
 *
 * 与 supertest 集成测试的区别：走的是 index.js 的**完整启动序列**——
 * dotenv → 配置强校验 → 密钥注入 → initData 播种 → HTTP 监听 →
 * WebSocket/调度器/审计缓冲启动 → 真实端口上的 HTTP 请求往返。
 * supertest 套件测不到的接线问题（初始化崩溃、挂载遗漏）在这一层兜住。
 *
 * 用法：npm run test:e2e
 * 数据隔离：mongodb-memory-server 起临时库，冒烟数据不触碰开发库。
 *
 * 注意：index.js 为 require 即启动（无条件 startServer），因此本脚本
 * 必须在 require 之前完成全部环境变量设置；退出用 process.exit
 * （临时内存库随进程消亡，无需优雅关闭）。
 */

const http = require('http');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.E2E_PORT || 3555;
const BASE = 'http://127.0.0.1:' + PORT;
// 运行期组装（无凭据字面量）：大小写+数字+特殊符+随机段
const PASSWORD = 'E2e' + String.fromCharCode(33) + crypto.randomBytes(6).toString('hex') + 'Aa1';

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

function req(method, urlPath, { token, body, raw } = {}) {
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
          if (raw) return resolve({ status: res.statusCode, text, headers: res.headers });
          try {
            resolve({ status: res.statusCode, body: JSON.parse(text) });
          } catch (_) {
            resolve({ status: res.statusCode, body: text });
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

/** 轮询等待服务器可服务（启动含 initData 播种，可能需要数秒） */
async function waitForServer(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await req('GET', '/health');
      if (res.status === 200) return;
    } catch (_) {
      /* 尚未就绪 */
    }
    await sleep(300);
  }
  throw new Error('服务器 30 秒内未就绪');
}

async function main() {
  // ===== 1. 环境设置（必须先于 require index.js）=====
  const { MongoMemoryServer } = require('mongodb-memory-server');
  console.log('[E2E] 启动临时 MongoDB（内存）…');
  const mongoMem = await MongoMemoryServer.create();
  process.env.NODE_ENV = 'development';
  process.env.PORT = String(PORT);
  process.env.MONGODB_URI = mongoMem.getUri('fire_safety_e2e');
  process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(32).toString('hex');
  process.env.AES_SECRET_KEY = crypto.randomBytes(32).toString('hex');
  process.env.HMAC_SECRET = crypto.randomBytes(16).toString('hex');
  process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
  process.env.ALLOW_PUBLIC_REGISTRATION = 'true';
  process.env.CORS_ORIGIN = BASE;
  process.env.ENABLE_API_DOCS = 'false';
  process.env.AUDIT_WAL_PATH = path.join(__dirname, '..', 'logs', 'e2e-audit.wal');
  process.env.LOG_LEVEL = 'error';

  // ===== 2. 进程内启动完整服务器 =====
  console.log('[E2E] 启动服务器（进程内，端口 ' + PORT + '）…');
  require('../src/index.js');

  console.log('[E2E] 等待就绪…');
  await waitForServer(30000);

  let token = null;

  // ===== 3. 基础探针 =====
  await step('GET /health 存活探针', async () => {
    const r = await req('GET', '/health');
    if (r.status !== 200 || r.body.status !== 'ok') throw new Error('status=' + r.status);
  });

  await step('GET /readyz 就绪探针（Mongo ping）', async () => {
    const r = await req('GET', '/readyz');
    if (r.status !== 200 || r.body.checks.mongo !== 'ok') throw new Error(JSON.stringify(r.body));
  });

  await step('GET /metrics Prometheus 文本', async () => {
    const r = await req('GET', '/metrics', { raw: true });
    if (r.status !== 200 || !r.text.includes('http_requests_total'))
      throw new Error('status=' + r.status);
  });

  // ===== 4. 认证闭环 =====
  await step('GET /api/auth/login-public-key 下发公钥', async () => {
    const r = await req('GET', '/api/auth/login-public-key');
    if (r.status !== 200 || !r.body.data.publicKey.includes('PUBLIC KEY'))
      throw new Error('status=' + r.status);
  });

  await step('POST /api/auth/login（admin + 初始密码）', async () => {
    const r = await req('POST', '/api/auth/login', {
      body: { username: 'admin', password: PASSWORD },
    });
    if (r.status !== 200 || !r.body.data.token)
      throw new Error('status=' + r.status + ' ' + JSON.stringify(r.body).slice(0, 120));
    token = r.body.data.token;
  });

  await step('GET /api/auth/me 会话有效', async () => {
    const r = await req('GET', '/api/auth/me', { token });
    // getMe 返回 { user: {...}, permissions, menus } 嵌套形状
    if (r.status !== 200 || r.body.data.user.username !== 'admin')
      throw new Error('status=' + r.status);
  });

  await step('GET /api/auth/sessions 设备级会话列表', async () => {
    const r = await req('GET', '/api/auth/sessions', { token });
    if (r.status !== 200) throw new Error('status=' + r.status);
  });

  await step('GET /api/metrics 面板 JSON（超管权限）', async () => {
    const r = await req('GET', '/api/metrics', { token });
    if (r.status !== 200) throw new Error('status=' + r.status);
    const snap = r.body.data;
    if (!snap.summary || !Array.isArray(snap.routes)) throw new Error('snapshot 结构异常');
    if (snap.summary.totalRequests < 1) throw new Error('请求计数未累积');
  });

  // ===== 5. 业务闭环 =====
  let deviceId = null;
  await step('POST /api/devices 创建设备', async () => {
    const r = await req('POST', '/api/devices', {
      token,
      body: {
        deviceCode: 'E2E-SMOKE-001',
        deviceName: '冒烟设备',
        deviceType: 'hydrant',
        installDate: new Date().toISOString(),
        location: { building: 'E2E栋' },
      },
    });
    if (r.status !== 201)
      throw new Error('status=' + r.status + ' ' + JSON.stringify(r.body).slice(0, 120));
    deviceId = r.body.data._id || r.body.data.id;
  });

  await step('PUT /api/devices/{id}/status 状态迁移', async () => {
    const r = await req('PUT', '/api/devices/' + deviceId + '/status', {
      token,
      body: { status: 'maintenance' },
    });
    if (r.status !== 200) throw new Error('status=' + r.status);
  });

  await step('GET /api/reports/dashboard 报表聚合', async () => {
    const r = await req('GET', '/api/reports/dashboard', { token });
    if (r.status !== 200) throw new Error('status=' + r.status);
    if (!r.body.data.devices) throw new Error('缺 devices 维度');
  });

  await step('DELETE /api/devices/{id} 删除设备', async () => {
    const r = await req('DELETE', '/api/devices/' + deviceId, { token });
    if (![200, 204].includes(r.status)) throw new Error('status=' + r.status);
  });

  await step('POST /api/auth/logout 登出吊销', async () => {
    const r = await req('POST', '/api/auth/logout', { token, body: {} });
    if (r.status !== 200) throw new Error('status=' + r.status);
  });

  await step('登出后旧令牌失效（/api/auth/me 返回 401）', async () => {
    const r = await req('GET', '/api/auth/me', { token });
    if (r.status !== 401) throw new Error('status=' + r.status + '（令牌未被吊销！）');
  });

  console.log('[E2E] 结果：' + passed + ' 通过, ' + failed + ' 失败');
  if (failed > 0) {
    console.error('[E2E] 失败步骤：' + failures.join(' / '));
    process.exitCode = 1;
  }
}

main()
  .catch((err) => {
    console.error('[E2E] 冒烟执行失败: ' + err.message);
    process.exitCode = 1;
  })
  .finally(() => {
    // 临时内存库随进程消亡；显式退出避免 mongoose/定时器句柄悬挂
    console.log('[E2E] 冒烟结束');
    process.exit(process.exitCode || 0);
  });
