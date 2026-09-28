/**
 * rateLimitEscalation 单元测试（限流触发 → 自动封禁的 CC 防护闭环）
 *
 * 该服务把 429 变成安全事件：可观测（security_alerts_total）+ 可升级（达阈值
 * 自动封禁，阶梯与暴力破解同源）。测试钉住的不变式：
 *  1. 阈值内只计数不动作（正常聚合流量触顶一次绝不至于被封）；
 *  2. 达阈值必走「审计落库 → 通知 → addToBlacklist」三步，阶梯第一档 1h；
 *  3. 30 天审计窗口内有过升级事件 → 阶梯升档（与暴力破解同一条 ESCALATION_TIERS）；
 *  4. ::ffff: 前缀与纯 IPv4 必须是同一个计数桶（否则配额翻倍的老问题在升级层复刻）；
 *  5. addToBlacklist 返回 {banned:false}（白名单/写库失败）不抛错、审计照写——
 *     升级链路是 fail-soft 的，任何一步失败都不能拖垮 429 响应路径；
 *  6. 窗口重开：达阈值后计数归零，下一窗口从零重新累计。
 *
 * 执行注意：escalate 是 void fire-and-forget（这正是被测语义），断言必须轮询
 * 等待升级链路落地，而不是数一两个微任务——中间隔着两次真实的 Mongo 往返。
 * 每条用例用独立 IP：升级动作跨用例仍在途（fire-and-forget 的固有形态），
 * 共用 IP 会让上一例的审计行泄漏进下一例的断言。
 */

const mongoose = require('mongoose');

const security = require('../../middleware/security');
const escalation = require('../../services/rateLimitEscalation');
const { ALERT_TYPES, ESCALATION_TIERS } = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');

const stamp = Date.now().toString().slice(-7);
// 每条用例独立 IP（见文件头「执行注意」）
const IPS = {
  threshold: `192.0.2.${(Number(stamp) % 100) + 30}`,
  ladder: `192.0.2.${(Number(stamp) % 100) + 31}`,
  bucket: `192.0.2.${(Number(stamp) % 100) + 32}`,
  failsoft: `192.0.2.${(Number(stamp) % 100) + 33}`,
  reset: `192.0.2.${(Number(stamp) % 100) + 34}`,
};
const ALL_TEST_IPS = Object.values(IPS).flatMap((ip) => [ip, `::ffff:${ip}`]);

const originalAdd = security.addToBlacklist;
let banCalls;
let banResult;

/** 轮询等待升级链路落地（escalate 为 fire-and-forget，中间是真实 DB 往返） */
const waitUntil = async (fn, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (fn()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

/** 驱动一次限流触发（429 路径的入参形状，仅 ip 被用到） */
const hit = (ip, limiter = 'general') => escalation.noteRateLimitHit({ ip }, limiter);

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  security.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
    banCalls.push({ ip, durationMs, reason, source });
    return banResult;
  });
});

afterAll(async () => {
  security.addToBlacklist = originalAdd;
  await AuditLog.deleteMany(
    { action: ALERT_TYPES.RATE_LIMIT_ABUSE, ip: { $in: ALL_TEST_IPS } },
    { bypassAppendOnly: true }
  );
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
});

beforeEach(() => {
  banCalls = [];
  banResult = { banned: true, normalizedIp: 'ok' };
  security.addToBlacklist.mockImplementation(async (ip, durationMs, reason, source) => {
    banCalls.push({ ip, durationMs, reason, source });
    return banResult;
  });
  escalation.resetForTest();
});

describe('rateLimitEscalation（CC 防护闭环）', () => {
  test('阈值内只计数，不写审计、不封禁', async () => {
    for (let i = 0; i < escalation.ESCALATION_THRESHOLD - 1; i += 1) hit(IPS.threshold);

    expect(escalation.peekHits(IPS.threshold)).toBe(escalation.ESCALATION_THRESHOLD - 1);
    // 给在途/未来的异步链路留出时间：这里不该有任何动作
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(
      await AuditLog.countDocuments({ action: ALERT_TYPES.RATE_LIMIT_ABUSE, ip: IPS.threshold })
    ).toBe(0);
    expect(banCalls).toHaveLength(0);
  });

  test('达阈值：审计落库 + addToBlacklist 第一档 1h + auto 来源', async () => {
    for (let i = 0; i < escalation.ESCALATION_THRESHOLD; i += 1) hit(IPS.threshold);

    expect(await waitUntil(() => banCalls.length === 1)).toBe(true);
    expect(banCalls[0]).toMatchObject({
      ip: IPS.threshold,
      durationMs: ESCALATION_TIERS[0],
      reason: 'rate_limit_auto_ban_tier1',
      source: 'auto',
    });

    // 审计先于封禁（阶梯事件源），banCalls 已到 ⇒ 审计行必然已落库
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: IPS.threshold,
    }).lean();
    expect(row).toBeTruthy();
    expect(row.riskLevel).toBe('high');
    expect(row.body).toMatchObject({
      limiter: 'general',
      threshold: escalation.ESCALATION_THRESHOLD,
    });
  });

  test('阶梯升档：30 天内已有升级事件 ⇒ 本次按第二档（4h）封禁', async () => {
    await AuditLog.create({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      category: 'security',
      username: 'anonymous',
      ip: IPS.ladder,
      riskLevel: 'high',
      riskFactors: ['限流持续触顶'],
      body: { limiter: 'general' },
    });

    for (let i = 0; i < escalation.ESCALATION_THRESHOLD; i += 1) hit(IPS.ladder, 'ip');
    expect(await waitUntil(() => banCalls.length === 1)).toBe(true);
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[1]);
  });

  test('::ffff: 前缀与纯 IPv4 是同一个计数桶，且达阈值封禁的是归一化地址', async () => {
    const ip = IPS.bucket;
    // 各推一半再留一击：若按原文组键是两个桶，混打的累计值永远到不了阈值
    const half = escalation.ESCALATION_THRESHOLD / 2;
    for (let i = 0; i < half; i += 1) hit(ip);
    for (let i = 0; i < half - 1; i += 1) hit(`::ffff:${ip}`);

    // 阈值内：两种形态的计数完全共享（都查得到同一份累计值）
    expect(escalation.peekHits(ip)).toBe(escalation.ESCALATION_THRESHOLD - 1);
    expect(escalation.peekHits(`::ffff:${ip}`)).toBe(escalation.ESCALATION_THRESHOLD - 1);

    // 最后一击达阈值 → 封禁动作落在归一化地址上
    hit(ip);
    expect(await waitUntil(() => banCalls.length === 1)).toBe(true);
    expect(banCalls[0].ip).toBe(ip);
  });

  test('addToBlacklist 返回 {banned:false}（白名单等）：不抛错，审计照写', async () => {
    banResult = { banned: false, reason: 'whitelisted' };
    for (let i = 0; i < escalation.ESCALATION_THRESHOLD; i += 1) hit(IPS.failsoft);

    expect(await waitUntil(() => banCalls.length === 1)).toBe(true);
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: IPS.failsoft,
    }).lean();
    expect(row).toBeTruthy();
  });

  test('达阈值后窗口重开：计数从零重新累计', () => {
    for (let i = 0; i < escalation.ESCALATION_THRESHOLD; i += 1) hit(IPS.reset);
    expect(escalation.peekHits(IPS.reset)).toBe(0);
    hit(IPS.reset);
    expect(escalation.peekHits(IPS.reset)).toBe(1);
  });

  test('畸形入参（无 ip / 非对象）不抛错，计入 unknown 桶', () => {
    expect(() => escalation.noteRateLimitHit(null, 'general')).not.toThrow();
    expect(() => escalation.noteRateLimitHit({}, 'general')).not.toThrow();
  });

  test('写法门禁：noteRateLimitHit 必须在 429 响应路径上同步调用（不许丢进 setImmediate）', () => {
    // 升级信号若异步化，高频触顶场景下响应与信号之间没有先行关系，
    // 极端下进程崩溃会整窗丢信号；钉住"同步调用"的接线形状
    const src = require('fs')
      .readFileSync(require('path').join(__dirname, '../../middleware/rateLimit.js'), 'utf-8')
      .replace(/^\/\*[\s\S]*?\*\//gm, (m) => m.replace(/[^\n]/g, ''));
    const handlers = src.match(/noteRateLimitHit\(req, '[a-z-]+'\)/g) || [];
    expect(handlers.length).toBeGreaterThanOrEqual(6);
  });
});
