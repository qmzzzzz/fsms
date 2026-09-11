/**
 * E-1 压测基线（零依赖）：本地自测版
 *
 * 覆盖四相：
 *   B. GET /health        —— 纯事件循环基线（/api 外，无限流）
 *   C. GET /metrics       —— 全中间件链（metricsAuth 回环放行）
 *   E. GET /api/devices   —— 已认证业务端点；跑到用户级配额（admin 500/15min）
 *                            触发 429 为预期结果，验证限流生效并测得突发吞吐
 *   D. POST /api/auth/login（错误口令 ×12，专用一次性用户）——
 *                            验证暴力破解防护链：401 → IP 自动封禁 403
 *                            （放最后：封禁会波及同 IP 后续全部请求）
 *
 * 口径说明：单进程自测——客户端与服务端共享事件循环，测得 QPS 为该机器的
 * 下界；正式压测（k6/wrk + 独立压测机）仍按 E-1 待办在部署环境执行。
 *
 * 用法：npm run test:load   （基线 JSON 落 logs/load-baseline.json）
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.LOAD_PORT || 3777;
const BASE = 'http://127.0.0.1:' + PORT;
const PASSWORD = 'Ld' + String.fromCharCode(33) + crypto.randomBytes(6).toString('hex') + 'Cc3';

let passed = 0;
let failed = 0;
const failures = [];
const baseline = { timestamp: new Date().toISOString(), node: process.version, phases: {} };

function step(name, fn) {
  return fn()
    .then((extra) => {
      passed++;
      console.log('  ok ' + name + (extra || ''));
    })
    .catch((err) => {
      failed++;
      failures.push(name);
      console.error('  FAIL ' + name + ': ' + err.message);
    });
}

/** keepAlive 客户端 + 计时请求 */
const agent = new http.Agent({ keepAlive: true, maxSockets: 256 });
function req(method, urlPath, { token, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const started = process.hrtime.bigint();
    const r = http.request(
      BASE + urlPath,
      {
        method,
        agent,
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
          const ms = Number(process.hrtime.bigint() - started) / 1e6;
          const text = Buffer.concat(chunks).toString('utf8');
          let bodyParsed = text;
          try {
            bodyParsed = JSON.parse(text);
          } catch (_) {
            /* 保留原文 */
          }
          resolve({ status: res.statusCode, body: bodyParsed, ms, headers: res.headers });
        });
      }
    );
    r.on('error', reject);
    r.on('timeout', () => r.destroy(new Error('请求超时 ' + urlPath)));
    if (payload) r.write(payload);
    r.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

/** 并发压测引擎：N worker 各自串行循环，直到 deadline / maxRequests / 命中 stopStatus */
async function hammer({
  name,
  path: urlPath,
  method = 'GET',
  token,
  body,
  concurrency,
  durationMs,
  maxRequests = Infinity,
  stopOnStatus = null,
}) {
  const latencies = [];
  const byStatus = {};
  let total = 0;
  let stopped = false;
  const deadline = Date.now() + durationMs;

  const worker = async () => {
    while (!stopped && Date.now() < deadline && total < maxRequests) {
      try {
        const r = await req(method, urlPath, { token, body });
        total += 1;
        latencies.push(r.ms);
        byStatus[r.status] = (byStatus[r.status] || 0) + 1;
        if (stopOnStatus && r.status === stopOnStatus) {
          stopped = true;
          break;
        }
      } catch (_) {
        byStatus.error = (byStatus.error || 0) + 1;
      }
    }
  };

  const started = Date.now();
  await Promise.all(Array.from({ length: concurrency }, worker));
  const elapsedSec = (Date.now() - started) / 1000;

  latencies.sort((a, b) => a - b);
  const result = {
    total,
    elapsedSec: Number(elapsedSec.toFixed(2)),
    qps: Number((total / elapsedSec).toFixed(1)),
    p50: Number(percentile(latencies, 50).toFixed(2)),
    p90: Number(percentile(latencies, 90).toFixed(2)),
    p95: Number(percentile(latencies, 95).toFixed(2)),
    p99: Number(percentile(latencies, 99).toFixed(2)),
    max: latencies.length ? Number(latencies[latencies.length - 1].toFixed(2)) : 0,
    byStatus,
  };
  baseline.phases[name] = result;
  return result;
}

const fmt = (r) =>
  '  ' +
  r.total +
  ' req / ' +
  r.elapsedSec +
  's  QPS=' +
  r.qps +
  '  P50=' +
  r.p50 +
  'ms  P95=' +
  r.p95 +
  'ms  P99=' +
  r.p99 +
  'ms  status=' +
  JSON.stringify(r.byStatus);

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

async function main() {
  const { MongoMemoryServer } = require('mongodb-memory-server');
  console.log('[LOAD] 启动临时 MongoDB 与服务器（进程内，端口 ' + PORT + '）…');
  const mongoMem = await MongoMemoryServer.create();
  process.env.NODE_ENV = 'test';
  process.env.PORT = String(PORT);
  process.env.MONGODB_URI = mongoMem.getUri('fire_safety_load');
  process.env.JWT_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.AES_SECRET_KEY = crypto.randomBytes(48).toString('hex');
  process.env.HMAC_SECRET = crypto.randomBytes(48).toString('hex');
  process.env.ADMIN_INITIAL_PASSWORD = PASSWORD;
  process.env.CORS_ORIGIN = BASE;
  // 抬高 IP/全局配额，让 E 相的 429 精确来自【用户级配额】（admin 硬编码 500/15min）
  process.env.RATE_LIMIT_MAX_REQUESTS = '1000000';
  process.env.RATE_LIMIT_IP_MAX_REQUESTS = '1000000';
  process.env.AUDIT_WAL_PATH = path.join(__dirname, '..', 'logs', 'load-audit.wal');
  process.env.LOG_LEVEL = 'error';

  require('../src/index.js');
  await waitForServer(30000);

  // 预热：20 次 /health（JIT/keepAlive 连接池）
  await Promise.all(Array.from({ length: 20 }, () => req('GET', '/health')));

  console.log('[LOAD] B 相：/health 基线（C=50, 8s）…');
  const health = await hammer({
    name: 'health',
    path: '/health',
    concurrency: 50,
    durationMs: 8000,
  });
  console.log(fmt(health));

  console.log('[LOAD] C 相：/metrics 全中间件链（C=50, 8s）…');
  const metrics = await hammer({
    name: 'metrics',
    path: '/metrics',
    concurrency: 50,
    durationMs: 8000,
  });
  console.log(fmt(metrics));

  console.log('[LOAD] 登录取 token + 创建暴力破解靶用户（须在 E 相耗尽配额前完成）…');
  let token = null;
  await step('登录（admin）', async () => {
    const r = await req('POST', '/api/auth/login', {
      body: { username: 'admin', password: PASSWORD },
    });
    if (r.status !== 200 || !r.body.data.token) throw new Error('status=' + r.status);
    token = r.body.data.token;
  });

  // 专用一次性用户（保护 admin 不被锁定）；密码满足强度策略（14 字符混合）。
  // 必须在 E 相之前创建——E 相会耗尽 admin 的用户级配额（500/15min），
  // 之后 POST /api/users 会 429。
  const bfPassword = 'Bf' + String.fromCharCode(33) + crypto.randomBytes(6).toString('hex') + 'Dd4';
  await step('D0. 创建暴力破解靶用户', async () => {
    const r = await req('POST', '/api/users', {
      token,
      body: { username: 'loadbf', email: 'loadbf@example.com', password: bfPassword },
    });
    if (![200, 201].includes(r.status))
      throw new Error('status=' + r.status + ' ' + JSON.stringify(r.body).slice(0, 120));
  });

  console.log('[LOAD] E 相：已认证 /api/devices（C=20，跑到用户级配额触发 429 或 20s）…');
  const devices = await hammer({
    name: 'devices-authed',
    path: '/api/devices?limit=20&page=1',
    token,
    concurrency: 20,
    durationMs: 20000,
    stopOnStatus: 429,
  });
  console.log(fmt(devices));

  await step('E. 用户级限流生效（配额内 2xx 突发 + 429 触发）', async () => {
    const ok2xx = Object.entries(devices.byStatus)
      .filter(([s]) => s.startsWith('2'))
      .reduce((a, [, n]) => a + n, 0);
    if (!(devices.byStatus['429'] > 0))
      throw new Error('未观察到 429（用户配额未触发？2xx=' + ok2xx + '）');
    if (ok2xx < 100) throw new Error('配额内成功请求过少：' + ok2xx);
    baseline.phases['devices-authed'].quotaFinding =
      'admin 用户级配额 500/15min 触发 429，配额内突发 ' + ok2xx + ' 请求';
  });

  console.log('[LOAD] D 相：暴力破解防护链（专用用户错误口令 ×12，串行）…');
  const bfResults = [];
  let sawBan = false;
  for (let i = 0; i < 12; i++) {
    const r = await req('POST', '/api/auth/login', {
      body: { username: 'loadbf', password: 'Wrong!' + i + 'x' },
    });
    bfResults.push(r.status);
    if (r.status === 403) {
      sawBan = true;
      break;
    }
  }
  await step('D. 暴力破解链：≥5 次 401 后 IP 自动封禁 403', async () => {
    const count401 = bfResults.filter((s) => s === 401).length;
    if (count401 < 5) throw new Error('401 次数不足 5：' + JSON.stringify(bfResults));
    if (!sawBan) throw new Error('未观察到 IP 自动封禁 403：' + JSON.stringify(bfResults));
    baseline.phases['brute-force-chain'] = {
      sequence: bfResults,
      finding: '5 次失败阈值触发 IP 自动封禁（先于登录限流器 10 次阈值生效）',
    };
  });

  // 封禁后的连带验证（最后做，不影响前面各相）
  await step('D+. 封禁后同 IP 业务请求一并 403（黑名单全局生效）', async () => {
    const r = await req('GET', '/api/devices?limit=5', { token });
    if (r.status !== 403)
      throw new Error('期望 403，实得 ' + r.status + '（自动封禁未覆盖业务端点？）');
  });

  console.log('\n[LOAD] 结果：' + passed + ' 通过, ' + failed + ' 失败');
  console.log('[LOAD] 基线摘要：');
  console.log('  health  : ' + health.qps + ' QPS  P95=' + health.p95 + 'ms');
  console.log('  metrics : ' + metrics.qps + ' QPS  P95=' + metrics.p95 + 'ms');
  console.log(
    '  devices : ' + devices.qps + ' QPS  P95=' + devices.p95 + 'ms（突发至用户配额触发）'
  );
  if (failed > 0) {
    console.error('[LOAD] 失败步骤：' + failures.join(' / '));
    process.exitCode = 1;
  }

  try {
    const outPath = path.join(__dirname, '..', 'logs', 'load-baseline.json');
    fs.writeFileSync(outPath, JSON.stringify(baseline, null, 2));
    console.log('[LOAD] 基线已写入 ' + outPath);
  } catch (_) {
    /* 基线落盘失败不影响结论 */
  }
}

main()
  .catch((err) => {
    console.error('[LOAD] 执行失败: ' + err.message);
    process.exitCode = 1;
  })
  .finally(() => {
    console.log('[LOAD] 压测结束（内存库随进程退出）');
    process.exit(process.exitCode || 0);
  });
