/**
 * 全站表面的早期拒绝必须都有限流闸门（姊妹文件 earlyRejectionRateLimited.test.js 的扩面）
 *
 * 缺陷形态：两个资源型限流器挂在 **`/api/` 前缀**上（`app.use('/api/', ipLimiter)`），
 * 而 `applyPreBodySecurity(app)` 是**无前缀、全站生效**的。于是 `/`、`/csp-report`、
 * `/api-docs` 这些对外表面上，未认证者的每一个 `TRACE` 都会写一条走哈希链的审计记录，
 * 却**一条 429 都不吃**——更早那次"把限流器提到 body 解析之前"的修复只覆盖了 `/api/` 前缀，
 * 洪水面原样保留在其余路径。
 * 后果不是负载而是覆盖率：链锁全局串行，排队超时的既定结局是合法审计降级为
 * 无 hash 的 legacy 行（`utils/auditChain.js` 的 P3-19 注释自证）。
 *
 * 判据（每个表面各自独立配额，见下面 X-Forwarded-For 的用法）：
 *   ① 前 MAX 条撞协议合规闸门（405 + HTTP_METHOD_UNSUPPORTED，拒绝语义没被限流提前改掉）；
 *   ② 其后全部 429，且 429 归因唯一（IP 配额刻意放宽到 10 万次，不可能是它先触发）；
 *   ③ 该表面的链上审计**恰好** MAX 条（按 path 归因，未过闸的请求零写入）；
 *   ④ `/health` 反向对照：探针必须**既不 429、也不写审计**——缺了 skip 的全站挂载
 *      会先把容器/部署门禁打成红并自动回滚，这条就是把那个部署事故钉在测试里。
 *   ⑤ 探针豁免的**判据本体**也要设防：豁免只属于"探活请求"（精确路径 + GET/HEAD），
 *      不属于"以 /health 开头的任意流量"。同一探针路径上的 TRACE 必须与普通表面同构
 *      （405 × MAX → 429，链上写入恰好 MAX 条），GET 探针必须仍然一条 429 都不吃。
 *
 * 每表面必须用不同 IP：两个 limiter 在 `middleware/rateLimit.js` 的**模块加载期**创建，
 * 同一文件里所有请求共用同一份配额；不隔离 IP 的话第一条洪水就会把后面三个表面全打成
 * 429，②③ 变成恒真。`TRUST_PROXY_HOPS=1` 让 Express 采信 XFF（本用例只用来分桶，
 * 不参与任何安全判定）。
 */
const request = require('supertest');

const MAX_GENERAL = 3;
const FLOOD = 10;
const VIOLATION_ACTION = 'malformed_request_blocked';
/** 除 /api/ 前缀外的对外表面：本文件存在的理由就是这三格此前一条限流都没有 */
const SURFACES = ['/api/devices', '/', '/csp-report', '/api-docs'];
/** 探针路径：GET 探活必须豁免（限流与闸门两侧），非探针方法打到它则按普通表面对待 */
const PROBE = '/health';
/**
 * 刻意**不**从 constants/probePaths 取：从被测清单本身推导用例集合，删掉一项就等于
 * 删掉一条用例 ⇒ "漏登记探针"这个改动天然无法被测出。
 * 写死在这里，清单少一个探针就红一条。
 */
const PROBES = ['/health', '/readyz'];

// —— 必须早于 require('../../app')：config 与 limiter 都在加载期取值 ——
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
process.env.RATE_LIMIT_MAX_REQUESTS = String(MAX_GENERAL);
process.env.RATE_LIMIT_WINDOW_MS = '900000';
process.env.RATE_LIMIT_IP_MAX_REQUESTS = '100000';
process.env.RATE_LIMIT_IP_WINDOW_MS = '900000';
process.env.TRUST_PROXY_HOPS = '1';

const countViolationsFor = (path) =>
  require('../../models/AuditLog').countDocuments({ action: VIOLATION_ACTION, path });

// 等该 path 的异步落库**静默**后再取数：recordViolation 用 setImmediate 投递，create 还要过全局链锁。
// 只"等到达到预期值"会单向假绿——先到的 MAX 条就让计数满足，后到的漏判永远看不见。
//
// 计数一律取「本条用例自己的增量」，不取绝对值：审计集合是全仓共享的，而同一批
// (action, path) 会被本文件**多条**用例写入（GET 探针用例期望 0 条、TRACE 探针用例期望 MAX 条），
// 绝对计数等于把前置状态写成一条有序用例——`--randomize` 下三个 seed 各自复现过 1 红
// （见台账 §91.9 / F-112 / F-185 同一类）。增量不削弱设防：探针真的开始写审计时 before≠after 立刻红。
const settleCount = async (path, timeoutMs = 8000) => {
  const deadline = Date.now() + timeoutMs;
  let prev = await countViolationsFor(path);
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    const now = await countViolationsFor(path);
    if (now === prev) return now;
    prev = now;
    if (Date.now() > deadline) return now;
  }
};

describe('限流挂载范围覆盖全部对外表面', () => {
  const mongoose = require('mongoose');
  let app;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    await mongoose.disconnect();
    Object.entries(SAVED_ENV).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  test.each(SURFACES)('%s：协议违规洪水先撞 429，链上写入被掐到 MAX 条', async (path) => {
    const ip = `10.7${SURFACES.indexOf(path)}.0.1`;
    const baseline = await settleCount(path);
    const responses = [];
    for (let i = 0; i < FLOOD; i++) {
      responses.push(await request(app).trace(path).set('X-Forwarded-For', ip));
    }
    const statuses = responses.map((r) => r.status);

    // ② 前 MAX 条过闸、其后全部 429
    expect(statuses.slice(MAX_GENERAL)).toEqual(new Array(FLOOD - MAX_GENERAL).fill(429));
    expect(statuses.slice(0, MAX_GENERAL)).toEqual(new Array(MAX_GENERAL).fill(405));
    // 429 出自 generalLimiter 自己的 handler（ipLimiter 文案不同）⇒ 钉的是通用配额
    expect(responses[FLOOD - 1].body.message).toBe('请求过于频繁，请稍后再试');
    // ① 拒绝语义没被"限流提前"改掉
    expect(responses[0].body.errors).toMatchObject({ errorCode: 'HTTP_METHOD_UNSUPPORTED' });
    // ③ 只有过闸的 MAX 条产生链上写入，且这条写入通道确实落库过（否则 ③ 是恒真的空集）
    expect(await settleCount(path)).toBe(baseline + MAX_GENERAL);
  });

  test(`${PROBE}：探针不被限流吃掉，也不产生审计写入`, async () => {
    const ip = '10.79.0.1';
    const baseline = await settleCount(PROBE);
    const responses = [];
    for (let i = 0; i < FLOOD; i++) {
      responses.push(await request(app).get(PROBE).set('X-Forwarded-For', ip));
    }
    // 容器/部署门禁以 127.0.0.1 高频探测：全站挂载后若漏了 skip，这里必红，
    // 且红法恰好是"对完全健康的新版本恒红并自动回滚"
    expect(responses.map((r) => r.status)).toEqual(new Array(FLOOD).fill(200));
    expect(await settleCount(PROBE)).toBe(baseline);
  });

  // ④ 的第二个齿：清单里**每一个**探针都要过这两道，且必须钉住"闸门与限流器读同一份
  // 判据"。判据本体是 constants/probePaths 的 `isProbeRequest(method, path)`，两处消费方
  // 各自 import 同一个函数——所以这里要设防的是"某一侧改回自带一份清单/改成前缀匹配"：
  //   · GET 探针：漏登记或被改成前缀语义都不影响这一发，但漏登记会立刻让 429 出现
  //     （限流侧 skip 失效）⇒ 用 GET 洪水钉限流侧；
  //   · 探针路径上的普通请求（TRACE）：闸门侧若把它当探针整体免检，得到的是 404 且
  //     零链上写入；收口后它必须先撞协议合规闸（405 × MAX）再吃 429 ⇒ 用 TRACE 钉闸门侧
  //     与"豁免只看 GET/HEAD"这条方法维度。
  test.each(PROBES.map((probe, i) => [probe, `10.9${i}.0.2`]))(
    '%s：GET 探针仍然整体豁免（部署门禁恒红的反向对照）',
    async (probe, ip) => {
      const baseline = await settleCount(probe);
      const responses = [];
      for (let i = 0; i < FLOOD; i++) {
        responses.push(await request(app).get(probe).set('X-Forwarded-For', ip));
      }
      const statuses = responses.map((r) => r.status);
      expect(statuses).toEqual(new Array(FLOOD).fill(200));
      expect(statuses).not.toContain(429);
      expect(await settleCount(probe)).toBe(baseline);
    }
  );

  test.each(PROBES.map((probe, i) => [probe, `10.9${i}.0.3`]))(
    '%s：非探针方法按普通表面对待（豁免不含子树与方法维度）',
    async (probe, ip) => {
      const baseline = await settleCount(probe);
      const responses = [];
      for (let i = 0; i < FLOOD; i++) {
        responses.push(await request(app).trace(probe).set('X-Forwarded-For', ip));
      }
      const statuses = responses.map((r) => r.status);
      // 前 MAX 条由闸门亲自拒绝（拒绝语义没被限流提前改掉），其后全部 429——
      // 404 + 零写入才是缺陷形态（= 闸门把整条 /health 当成探针放了过去）
      expect(statuses.slice(0, MAX_GENERAL)).toEqual(new Array(MAX_GENERAL).fill(405));
      expect(statuses.slice(MAX_GENERAL)).toEqual(new Array(FLOOD - MAX_GENERAL).fill(429));
      expect(responses[FLOOD - 1].body.message).toBe('请求过于频繁，请稍后再试');
      expect(await settleCount(probe)).toBe(baseline + MAX_GENERAL);
    }
  );
});
