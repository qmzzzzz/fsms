/**
 * 早期拒绝类审计写入必须受限流约束（app.js 挂载顺序的行为化判据）
 *
 * 缺陷形态：protocolCompliance 这类"body 解析之前"的闸门，每次拒绝都会写一条走哈希链的
 * 审计记录（recordViolation → AuditLog.record → create → pre('save') → withChainLock
 * 全局串行）。而 IP 级与通用限流器原先挂在它们**之后**：未认证的一个 `TRACE /api/x`
 * （十余字节）既不消耗配额、又必定产生一次链上写入 ⇒ 小请求放大成审计洪水；
 * 链锁排队超时的后果不是变慢，而是**合法审计降级为无 hash 的 legacy 行**
 * （utils/auditChain.js 的 P3-19 注释自证）。
 *
 * 判据：把通用配额压到 3，连发 10 条 TRACE。
 *   ① 出现 FLOOD-MAX 次 429（限流跑在合规闸门之前）；
 *   ② 协议违规审计**落库**条数恰为 MAX（未过闸的请求零写入 ⇒ 洪水被掐断）；
 *   ③ 前提自证：这条写入通道确实落库过（否则 ② 是恒真的空集），
 *      且过闸请求拿到的是协议违规码而不是别的 4xx。
 * 把两个 limiter 一起挪回 express.json 之后，①② 同时转红；只挪其中一个时，被挪走的那个
 * 由成对用例 earlyRejectionIpRateLimited.test.js 抓到（各钉一个配额，见那里的文件头）。
 *
 * 限流阈值在 config 模块加载期从 env 取值，故本文件在 require 任何被测模块**之前**
 * 就设好 env（Jest 为每个测试文件单开模块注册表，无需 resetModules；实测用
 * resetModules 会把 mongoose 拆成两代，create 阶段报 `MongooseArray is not a function`）。
 */
const request = require('supertest');

const MAX_GENERAL = 3;
const FLOOD = 10;
const VIOLATION_ACTION = 'malformed_request_blocked';

// —— 必须早于 require('../../app')：config 在加载期读这些值 ——
const SAVED_ENV = {};
[
  'RATE_LIMIT_MAX_REQUESTS',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_IP_MAX_REQUESTS',
  'RATE_LIMIT_IP_WINDOW_MS',
].forEach((key) => {
  SAVED_ENV[key] = process.env[key];
});
process.env.RATE_LIMIT_MAX_REQUESTS = String(MAX_GENERAL);
process.env.RATE_LIMIT_WINDOW_MS = '900000';
// IP 限流刻意放宽：本用例钉的是"通用限流是否早于合规闸门"。两个限流器的相对顺序
// 同为修复内容，但 429 的触发者必须唯一，否则归因不成立。
process.env.RATE_LIMIT_IP_MAX_REQUESTS = '100000';
process.env.RATE_LIMIT_IP_WINDOW_MS = '900000';

const countViolations = () =>
  require('../../models/AuditLog').countDocuments({ action: VIOLATION_ACTION });

// 等异步落库**静默**后再取数：recordViolation 用 setImmediate 投递，create 还要过全局链锁。
// 只"等到达到预期值"会造成单向假绿——把限流挪回原位时 10 条写入里前 3 条先到，
// 计数立刻满足 `=== 3`，而后到的 7 条永远漏判。故判据必须等"两次连续读数相同"。
const settleCount = async (timeoutMs = 8000) => {
  const deadline = Date.now() + timeoutMs;
  let prev = await countViolations();
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    const now = await countViolations();
    if (now === prev) return now;
    prev = now;
    if (Date.now() > deadline) return now;
  }
};

describe('早期拒绝与限流的顺序', () => {
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

  // 判据全部收在一条用例里：两个 limiter 是在 middleware/rateLimit.js 的**模块加载期**
  // 创建的（不是 createApp 内），同一文件里再 createApp() 会复用同一份配额 ⇒ 拆成两条
  // 用例时第二条必然继承第一条打满的配额（实测：首条请求即 429）。
  test('协议违规洪水先撞 429，链上审计不再逐条放大', async () => {
    const { createApp } = require('../../app');
    const app = createApp();

    const responses = [];
    for (let i = 0; i < FLOOD; i++) {
      responses.push(await request(app).trace('/api/devices'));
    }
    const statuses = responses.map((r) => r.status);
    const throttled = statuses.filter((s) => s === 429).length;
    const blockedByCompliance = statuses.filter((s) => s >= 400 && s < 500 && s !== 429).length;

    // ① 前 MAX 条撞协议合规闸门、其后全部 429 ⇒ 限流确实早于闸门，且 429 归因唯一
    //（IP 限流已放宽到 10 万次，不可能是它先触发）
    expect(throttled).toBe(FLOOD - MAX_GENERAL);
    expect(statuses.slice(MAX_GENERAL)).toEqual(new Array(FLOOD - MAX_GENERAL).fill(429));
    // 429 出自 generalLimiter 自己的 handler（ipLimiter 文案不同）⇒ 本用例钉的是通用配额
    expect(responses[FLOOD - 1].body.message).toBe('请求过于频繁，请稍后再试');
    // ② 过闸的请求由合规闸门原样拒绝：拒绝语义没被"限流提前"改掉
    expect(blockedByCompliance).toBe(MAX_GENERAL);
    // codeError 把 errorCode 放进 ApiResponse.error 的 errors 参数（body 顶层没有该键）
    expect(responses[0].body.errors).toMatchObject({ errorCode: 'HTTP_METHOD_UNSUPPORTED' });
    // ③ 前提自证：只有过了限流闸的违规请求才产生链上写入，且这条通道真的落库
    //（否则 ② 可能是恒真的空集）
    expect(await settleCount()).toBe(MAX_GENERAL);
  });
});
