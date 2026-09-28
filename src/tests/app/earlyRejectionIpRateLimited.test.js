/**
 * IP 级限流同样必须早于协议合规闸门（与 earlyRejectionRateLimited.test.js 成对）
 *
 * app.js 把 ipLimiter 与 generalLimiter 一起挂到 body 解析之前，两者键都是 req.ip 但
 * store 前缀不同（rl:ip: / rl:general:）⇒ 配额各自独立。只钉其中一个，另一个的位置就
 * 无人设防（实测：把 ipLimiter 单独挪回 express.json 之后，另一份用例照样全绿）。
 *
 * 本文件把 IP 配额压到 3、通用配额放宽，于是 429 的成因唯一归到 ipLimiter：
 *   ① 前 MAX 条过合规闸门（4xx），其后全部 429；
 *   ② 429 响应体是 ipLimiter 自己的文案（区分"谁先把住了门"，防止退化成巧合绿）；
 *   ③ 协议违规审计落库条数恰为 MAX（期望值来自响应侧，见 awaitViolations 注释）。
 * 阈值必须在 require 被测模块之前设好：config 与 limiter 都在模块加载期取值。
 *
 * 扩面（同一个文件、各自独立的 IP 桶）：ipLimiter 现在挂在**全站**而不是 `/api/`
 * 前缀上，于是它必须同时满足两件事——非 `/api` 表面吃到它的 429（否则放大面仍在），
 * 而 `/health` 探针**绝不**吃它的 429（否则容器与部署门禁以 127.0.0.1 高频探测，
 * 对完全健康的新版本恒红并自动回滚）。两件事各一条用例，都用新的合成 IP，
 * 避免继承第一条用例已打满的配额（limiter 是模块级单例，桶按 req.ip 分）。
 */
const request = require('supertest');

const MAX_IP = 3;
const FLOOD = 10;
const VIOLATION_ACTION = 'malformed_request_blocked';

const SAVED_ENV = {};
[
  'RATE_LIMIT_MAX_REQUESTS',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_IP_MAX_REQUESTS',
  'RATE_LIMIT_IP_WINDOW_MS',
  'TRUST_PROXY_HOPS',
].forEach((key) => {
  SAVED_ENV[key] = process.env[key];
});
process.env.RATE_LIMIT_IP_MAX_REQUESTS = String(MAX_IP);
process.env.RATE_LIMIT_IP_WINDOW_MS = '900000';
// 通用配额刻意放宽：见文件头 ② 的归因要求
process.env.RATE_LIMIT_MAX_REQUESTS = '100000';
process.env.RATE_LIMIT_WINDOW_MS = '900000';
// 只为给扩面用例分桶：采信 XFF 后 req.ip 取合成地址，本用例不参与任何安全判定
process.env.TRUST_PROXY_HOPS = '1';

// 每个测试文件都有一份全新空库（setup.js 给库名追加文件级后缀），所以这里按 path 取数
// 不会被别的套件污染；省略 path = 全局计数只在"本文件第一条用例"成立，扩面用例必须按 path
// 取数，否则继承前一条用例的落库结果，判据退化成"总数凑上就行"。
const countViolations = (path) =>
  require('../../models/AuditLog').countDocuments(
    path === undefined
      ? { action: VIOLATION_ACTION }
      : { action: VIOLATION_ACTION, path: String(path).split('?')[0] }
  );

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// 宽限期必须明显大于一次落库往返：并行门禁下写库会排队（实测单跑恒绿、全量跑读到 1 而不是 3）
const FLUSH_GRACE_MS = 3000;
const AWAIT_TIMEOUT_MS = 8000; // 加上宽限期仍远小于 jest 的 testTimeout(30s)

/**
 * 期望值来自响应侧（谁被合规闸门放过），而不是"轮询到数字不再变"。
 *
 * 原先的稳定性轮询（每 150ms 采样，两次相等就返回）三个方向都会错：
 *  - 正向欠数：写库慢于头两次采样时，把"还没落库"当成"已经静默"⇒ 数到 1 而不是 3
 *    （全量并行跑实测；单文件跑恒绿，因为写库不排队）；
 *  - 反向假绿：`探针不产生链上写入` 这类 0 值判据，头两次采样恰好都是 0 就直接返回，
 *    之后才落库的那条（也就是防线真的漏了的那条）永远看不见；
 *  - 正向超额：数到 N 就收，看不见第 N+1 条——而"多一条"正是闸门放漏了一个请求的形态。
 * 三个方向都得靠时间换确定性：先等期望值到齐，再等满宽限期复查「没有更多」，取最终值交回断言。
 * 注入一条延后落库的记录即可把三错各自显形（自检记录见 deliverables/复核台账）。
 */
const awaitViolations = async (path, expected) => {
  const deadline = Date.now() + AWAIT_TIMEOUT_MS;
  for (;;) {
    const n = await countViolations(path);
    if (n >= expected || Date.now() > deadline) break;
    await sleep(150);
  }
  await sleep(FLUSH_GRACE_MS);
  return countViolations(path); // 超时也照常取数：宁可红，不"返回当前值让它过"
};

// 每条用例一个独立合成 IP：limiter 是模块级单例，桶按 req.ip 分（见文件头）
const flood = async (app, method, path, ip) => {
  const responses = [];
  for (let i = 0; i < FLOOD; i++) {
    responses.push(await request(app)[method](path).set('X-Forwarded-For', ip));
  }
  return responses;
};

describe('早期拒绝与限流的顺序（IP 维度）', () => {
  const mongoose = require('mongoose');

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    Object.entries(SAVED_ENV).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  // 一条用例：limiter 在模块加载期创建，同文件二次 createApp() 会复用已打满的配额
  test('IP 配额被早期拒绝耗尽后，后续违规请求不再产生链上写入', async () => {
    const { createApp } = require('../../app');
    const app = createApp();

    const responses = [];
    for (let i = 0; i < FLOOD; i++) {
      responses.push(await request(app).trace('/api/devices'));
    }
    const statuses = responses.map((r) => r.status);
    const throttled = statuses.filter((s) => s === 429).length;
    const blockedByCompliance = statuses.filter((s) => s >= 400 && s < 500 && s !== 429).length;

    expect(throttled).toBe(FLOOD - MAX_IP);
    expect(statuses.slice(MAX_IP)).toEqual(new Array(FLOOD - MAX_IP).fill(429));
    // ② 429 出自 ipLimiter（通用限流文案是另一句），否则本用例没钉住 IP 维度
    expect(responses[FLOOD - 1].body.message).toBe('IP 请求频率超限');
    expect(blockedByCompliance).toBe(MAX_IP);
    expect(responses[0].body.errors).toMatchObject({ errorCode: 'HTTP_METHOD_UNSUPPORTED' });
    expect(await awaitViolations(undefined, MAX_IP)).toBe(MAX_IP);
  });

  // 扩面 ①：ipLimiter 挂在 /api/ 前缀上时，未认证的 `TRACE /csp-report` 既不消耗配额也不被拒，
  // 每条十余字节的请求必定放大成一次链上写入 ⇒ 前 MAX 条 405、其后 429 才算修好。
  test('非 /api 表面的协议违规洪水同样撞 ipLimiter 的 429', async () => {
    const { createApp } = require('../../app');
    const app = createApp();
    const ip = '10.88.0.1';

    const responses = await flood(app, 'trace', '/csp-report', ip);
    const statuses = responses.map((r) => r.status);

    expect(statuses.slice(0, MAX_IP)).toEqual(new Array(MAX_IP).fill(405));
    expect(statuses.slice(MAX_IP)).toEqual(new Array(FLOOD - MAX_IP).fill(429));
    // 429 出自 ipLimiter（generalLimiter 文案不同）⇒ 本用例钉的是 IP 维度而非通用维度
    expect(responses[FLOOD - 1].body.message).toBe('IP 请求频率超限');
    // 未过闸的 7 条零写入：按 path 取数，避免读到你上面那条用例的 3 条
    expect(await awaitViolations('/csp-report', MAX_IP)).toBe(MAX_IP);
  });

  // 扩面 ②：容器/部署门禁以 127.0.0.1 高频探测 /health 与 /readyz，配额打满后对完全健康的
  // 新版本恒红并自动回滚 ⇒ 清单里**每个**探针都必须豁免 IP 配额（与
  // earlyRejectionRateLimitedAllSurfaces 的通用维度用例成对，两边各钉一个 limiter）。
  // 探针清单写死在这里而不是 require constants/probePaths：从被测清单推导用例集合，
  // "漏登记一个探针"就会同时少一条用例，那个改动就永远测不出来。
  test.each([
    ['/health', '10.88.0.2'],
    ['/readyz', '10.88.0.3'],
  ])('%s：IP 配额打满后探针仍然探针自己的状态码', async (probe, ip) => {
    const { createApp } = require('../../app');
    const app = createApp();

    const responses = await flood(app, 'get', probe, ip);
    const statuses = responses.map((r) => r.status);

    expect(statuses).toEqual(new Array(FLOOD).fill(200));
    expect(statuses).not.toContain(429);
    // 前提自证：这个 IP 的配额确实会被打满（同一地址换成非探针表面就会出 429），
    // 否则上面的 200 只是"限流根本没生效"的假绿
    const control = await flood(app, 'trace', '/api-docs', ip);
    expect(control.map((r) => r.status)).toContain(429);
    expect(await awaitViolations(probe, 0)).toBe(0);
  });
});
