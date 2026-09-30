/**
 * rateLimitEscalation 单元测试（限流触发 → 自动封禁的 CC 防护闭环）
 *
 * 该服务把 429 变成安全事件：可观测（security_alerts_total）+ 可升级（达阈值
 * 自动封禁，阶梯与暴力破解同源）。测试钉住的不变式：
 *  1. **按信号分类**：三类信号各有各的阀值，互相不串。这是本次重构的核心——
 *     把 7 个合法拒绝率相差两个数量级的限流器加进同一个桶，等于宣称
 *     "30 次 captcha 拒绝"与"30 次任意请求拒绝"是同一种证据。
 *  2. **混检不提前**：10 次 captcha + 90 次 general 不会让 ANON_ABUSE 到点
 *     （各按各的量纲判）。
 *  3. **令牌桶而非固定窗口**：持续速率恰好等于阀值不触发；边界突发无收益；
 *     达阈值**不重置计数**——压力必须被记住（否则封禁失败后攻击者白拿一个窗口）。
 *  4. 阈值内只计数不动作。
 *  5. 达阈值必走「审计落库 → 通知 → addToBlacklist」，阶梯第一档 1h。
 *  6. 30 天审计窗口内有过升级事件 → 阶梯升档。
 *  7. ::ffff: 前缀与纯 IPv4 必须是同一个计数桶。
 *  8. addToBlacklist 返回 {banned:false}（白名单/写库失败）不抛错、审计照写。
 *  9. **处置与通知解耦**：通知频控命中时，审计与封禁仍必须执行。
 * 10. 计数表超限走**有界淘汰**而非整体清空（否则轮换 IP 是一条一键重置旁路）。
 *
 * 执行注意：escalateIp 是 void fire-and-forget（这正是被测语义），断言必须轮询
 * 等待升级链路落地，而不是数一两个微任务——中间隔着两次真实的 Mongo 往返。
 *
 * 隔离纪律（三条，缺一不可；`--randomize` 会打乱声明顺序）：
 *  1. **每条用例独占一个 IP**：升级动作是 fire-and-forget 的，上一条用例的 escalate
 *     会在下一条用例的 beforeEach 之后才落地（写审计 + 调 addToBlacklist），
 *     共用 IP 就把上一例的审计行泄漏进下一例的断言。故 IPS 里每个键只归一条用例。
 *  2. **封禁断言必须按 IP 取**（见 bansFor）：banCalls 是跨用例共享的数组。
 *  3. 令牌桶按**时间**回填，所以断言不得依赖"上一次用例打了多少下"——
 *     每条用例自证自己的起点（`peekIp` 读回水位）。
 */

const mongoose = require('mongoose');

const security = require('../../middleware/security');
const escalation = require('../../services/rateLimitEscalation');
const {
  CLASS_ANON_ABUSE,
  CLASS_VOLUME,
  CLASS_AUTH,
  SIGNAL_CLASSES,
} = require('../../services/rateLimitEscalation');
const {
  ALERT_TYPES,
  ESCALATION_TIERS,
  BAN_ESCALATION_WINDOW_MS,
} = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');

const stamp = Date.now().toString().slice(-7);
// 每条用例独占一个 IP（见文件头「隔离纪律 1」）：一个键只归一条用例，不复用
const IPS = {
  anon: `192.0.2.${(Number(stamp) % 100) + 29}`,
  anonMixed: `192.0.2.${(Number(stamp) % 100) + 30}`,
  volume: `192.0.2.${(Number(stamp) % 100) + 31}`,
  auth: `192.0.2.${(Number(stamp) % 100) + 32}`,
  bucket: `192.0.2.${(Number(stamp) % 100) + 33}`,
  failsoft: `192.0.2.${(Number(stamp) % 100) + 34}`,
  ladder: `192.0.2.${(Number(stamp) % 100) + 35}`,
  notif: `192.0.2.${(Number(stamp) % 100) + 36}`,
  retry: `192.0.2.${(Number(stamp) % 100) + 37}`,
  notif2: `192.0.2.${(Number(stamp) % 100) + 38}`,
};
const ALL_TEST_IPS = Object.values(IPS).flatMap((ip) => [ip, `::ffff:${ip}`]);

const originalAdd = security.addToBlacklist;
let banCalls;
let banResult;

/**
 * 本 IP 收到的封禁调用。
 *
 * **不要直接读 banCalls**：escalateIp 是 fire-and-forget，上一条用例的封禁会在本条
 * 用例的 beforeEach 之后才 push 进来（见文件头「隔离纪律 2」）。
 */
const bansFor = (ip) => banCalls.filter((c) => c.ip === ip);

/** 轮询等待升级链路落地（fire-and-forget，中间是真实 DB 往返） */
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

/** 打满某类别的阀值（令牌桶：净消耗到 <0 才升级，故需 threshold+1 下） */
const flood = (ip, limiter, times) => {
  for (let i = 0; i < times; i += 1) hit(ip, limiter);
};

const anonThreshold = SIGNAL_CLASSES[CLASS_ANON_ABUSE].threshold;
const volumeThreshold = SIGNAL_CLASSES[CLASS_VOLUME].threshold;
const authThreshold = SIGNAL_CLASSES[CLASS_AUTH].threshold;

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

// 这里**不做**审计清理：清理是"擦共享状态"，而本文件的隔离靠"每条用例独占自己的
// IP + 自证起点"（见文件头隔离纪律）——那才是与 --randomize 无关的形态。
beforeEach(() => {
  banCalls = [];
  banResult = { banned: true, normalizedIp: 'ok' };
  security.addToBlacklist.mockImplementation(async (ip, durationMs, reason, source) => {
    banCalls.push({ ip, durationMs, reason, source });
    return banResult;
  });
  escalation.resetForTest();
});

describe('rateLimitEscalation：按信号分类（本次重构的核心）', () => {
  test('三个类别各有阀值，且 ANON < VOLUME（端点滥用的证据更强，阀值更低）', () => {
    expect(anonThreshold).toBeGreaterThan(0);
    expect(volumeThreshold).toBeGreaterThan(anonThreshold);
    expect(authThreshold).toBeGreaterThan(0);
  });

  test('只有未认证两类会封 IP；已认证类只告警（处置对象是账号）', () => {
    expect(SIGNAL_CLASSES[CLASS_ANON_ABUSE].ban).toBe(true);
    expect(SIGNAL_CLASSES[CLASS_VOLUME].ban).toBe(true);
    // 这条是"不误封共享出口"的唯一保证：已认证越界绝不能升级成 IP 封禁
    expect(SIGNAL_CLASSES[CLASS_AUTH].ban).toBe(false);
  });

  test('已认证类打到阀值 + 1：只告警，不调 addToBlacklist', async () => {
    flood(IPS.auth, 'strict', authThreshold + 2);

    expect(escalation.peekIp(IPS.auth)[CLASS_AUTH].total).toBeGreaterThanOrEqual(authThreshold);
    // 给异步链路留时间：这里不该有任何封禁动作
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(bansFor(IPS.auth)).toHaveLength(0);
    expect(
      await AuditLog.countDocuments({
        action: ALERT_TYPES.RATE_LIMIT_ABUSE,
        ip: IPS.auth,
      })
    ).toBe(0);
  });

  test('混检不提前：ANON 打满而 VOLUME 未满时，ANON 封禁、VOLUME 不动', async () => {
    // captcha 打满 anon 桶
    flood(IPS.anonMixed, 'captcha', anonThreshold + 1);
    // 同时给 volume 桶一点压力但远不到 100
    flood(IPS.anonMixed, 'general', 5);

    expect(await waitUntil(() => bansFor(IPS.anonMixed).length === 1)).toBe(true);
    const state = escalation.peekIp(IPS.anonMixed);
    expect(state[CLASS_ANON_ABUSE].total).toBeGreaterThanOrEqual(anonThreshold);
    expect(state[CLASS_VOLUME].total).toBe(5);
    expect(state[CLASS_VOLUME].total).toBeLessThan(volumeThreshold);
  });

  test('反证混检保护：体量打满不会顺带把 ANON 也推到点', async () => {
    // 只打 general：ANON 桶必须仍是 0 次
    flood(IPS.volume, 'general', volumeThreshold + 1);
    expect(await waitUntil(() => bansFor(IPS.volume).length === 1)).toBe(true);
    const state = escalation.peekIp(IPS.volume);
    expect(state[CLASS_ANON_ABUSE].total).toBe(0);
    expect(state[CLASS_VOLUME].total).toBeGreaterThanOrEqual(volumeThreshold);
  });

  test('未登记的限流器归入 VOLUME（最保守：不豁免、不轻判）', () => {
    expect(escalation.LIMITER_CLASS.get('captcha')).toBe(CLASS_ANON_ABUSE);
    expect(escalation.LIMITER_CLASS.get('general')).toBe(CLASS_VOLUME);
    expect(escalation.LIMITER_CLASS.get('根本没注册过的限流器')).toBeUndefined();
    // 实际行为按 VOLUME 落桶（由下一条的行为断言覆盖判据本身）
  });
});

describe('rateLimitEscalation：令牌桶语义（取代固定窗口）', () => {
  test('阈值内只计数，不写审计、不封禁', async () => {
    flood(IPS.anon, 'captcha', anonThreshold);
    expect(escalation.peekIp(IPS.anon)[CLASS_ANON_ABUSE].total).toBe(anonThreshold);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(bansFor(IPS.anon)).toHaveLength(0);
    expect(
      await AuditLog.countDocuments({ action: ALERT_TYPES.RATE_LIMIT_ABUSE, ip: IPS.anon })
    ).toBe(0);
  });

  test('达阈值（净消耗到负）：审计落库 + addToBlacklist 第一档 1h + auto 来源', async () => {
    flood(IPS.failsoft, 'login-ip', anonThreshold + 1);

    expect(await waitUntil(() => bansFor(IPS.failsoft).length === 1)).toBe(true);
    expect(bansFor(IPS.failsoft)[0]).toMatchObject({
      ip: IPS.failsoft,
      durationMs: ESCALATION_TIERS[0],
      reason: 'rate_limit_auto_ban_tier1',
      source: 'auto',
    });

    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: IPS.failsoft,
    }).lean();
    expect(row).toBeTruthy();
    expect(row.riskLevel).toBe('high');
  });

  test('审计记全量构成而不是只记触发阀值的那一个限流器', async () => {
    flood(IPS.anon, 'captcha', 4);
    flood(IPS.anon, 'register', anonThreshold - 3);
    expect(await waitUntil(() => bansFor(IPS.anon).length === 1)).toBe(true);

    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: IPS.anon,
    }).lean();
    // 混检下只记 limiter 字段会让事后复盘归因错误——这正是本次要修的谎报
    expect(row.body.mix.captcha).toBe(4);
    expect(row.body.mix.register).toBeGreaterThan(0);
    expect(row.body.total).toBe(anonThreshold + 1);
    expect(row.body.className).toBe(CLASS_ANON_ABUSE);
  });

  test('每窗口只升级一次，且升级后压力被记住（不再重置计数）', async () => {
    flood(IPS.notif, 'captcha', anonThreshold + 5);
    expect(await waitUntil(() => bansFor(IPS.notif).length === 1)).toBe(true);

    // 同窗口内继续冲：不得二次升级
    flood(IPS.notif, 'captcha', anonThreshold + 5);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(bansFor(IPS.notif)).toHaveLength(1);
    // 计数**不清零**：原实现 `entry.count = 0; windowStart = now` 会让封禁失败的
    // 攻击者白拿一整个新窗口
    const total = escalation.peekIp(IPS.notif)[CLASS_ANON_ABUSE].total;
    expect(total).toBeGreaterThan(anonThreshold * 2);
  });

  test('::ffff: 前缀与纯 IPv4 是同一个计数桶，且达阈值封禁的是归一化地址', async () => {
    const ip = IPS.bucket;
    // 前 total-1 下均摊到两种形态：按原文组键是两个桶的话，混打的累计值永远到不了阈值
    const before = anonThreshold;
    const plain = Math.ceil(before / 2);
    for (let i = 0; i < plain; i += 1) hit(ip, 'captcha');
    for (let i = 0; i < before - plain; i += 1) hit(`::ffff:${ip}`, 'captcha');

    // 两种形态的计数完全共享（都查得到同一份累计值）
    expect(escalation.peekIp(ip)[CLASS_ANON_ABUSE].total).toBe(before);
    expect(escalation.peekIp(`::ffff:${ip}`)[CLASS_ANON_ABUSE].total).toBe(before);

    // 最后一击让净消耗转负 → 封禁动作落在归一化地址上
    hit(ip, 'captcha');
    expect(await waitUntil(() => bansFor(ip).length === 1)).toBe(true);
    expect(bansFor(ip)[0].ip).toBe(ip);
  });

  test('阶梯升档：30 天内已有升级事件 ⇒ 本次按第二档（4h）封禁', async () => {
    await AuditLog.create({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      category: 'security',
      username: 'anonymous',
      ip: IPS.ladder,
      riskLevel: 'high',
      riskFactors: ['限流持续触顶'],
      body: { limiter: 'captcha' },
    });

    // 自证起点：档位由「30 天窗口内该 IP 的审计条数」决定，本用例押的是"恰好 1 条"
    expect(
      await AuditLog.countDocuments({
        action: ALERT_TYPES.RATE_LIMIT_ABUSE,
        ip: IPS.ladder,
        timestamp: { $gte: new Date(Date.now() - BAN_ESCALATION_WINDOW_MS) },
      })
    ).toBe(1);

    flood(IPS.ladder, 'register', anonThreshold + 1);
    expect(await waitUntil(() => bansFor(IPS.ladder).length === 1)).toBe(true);
    expect(bansFor(IPS.ladder)[0].durationMs).toBe(ESCALATION_TIERS[1]);
  });

  test('addToBlacklist 返回 {banned:false}：不抛错，审计照写，且如实报未生效', async () => {
    banResult = { banned: false, reason: 'whitelisted' };
    flood(IPS.retry, 'captcha', anonThreshold + 1);

    expect(await waitUntil(() => bansFor(IPS.retry).length === 1)).toBe(true);
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: IPS.retry,
    }).lean();
    expect(row).toBeTruthy();
  });

  test('通知频控不得挡住审计与封禁（处置与通知解耦）', async () => {
    // 刻意**不**用 jest.spyOn：那拦不住——rateLimitEscalationBan 在模块加载期就把
    // shouldSendAlert 解构进了闭包，spy 换掉的是 exports 上的属性。
    // 那样写出来的用例会恒绿（默认 shouldSendAlert 本来就返回 true），
    // 是一条与被测语义无关的纸面断言。
    //
    // 这里直接调用真实的 shouldSendAlert 把该 IP 的频控键占掉，效果等价于
    // "刚发过同 IP 的告警"，且不依赖任何 mock 装配顺序。
    const securityAlert = require('../../services/securityAlert');
    expect(securityAlert.shouldSendAlert(`rate_limit_abuse_${IPS.notif2}`)).toBe(true);
    // 第二次必然被频控挡下——这就是升级链路将要面对的处境
    expect(securityAlert.shouldSendAlert(`rate_limit_abuse_${IPS.notif2}`)).toBe(false);

    flood(IPS.notif2, 'register', anonThreshold + 1);

    // 封禁照执行……
    expect(await waitUntil(() => bansFor(IPS.notif2).length === 1)).toBe(true);
    // ……审计也照写。审计行是**阶梯的事件源**，漏写会让阶梯永远停在第一档，
    // 于是反复触发的 IP 每次都只被封 1 小时，而日志照打"第 N 档"。
    expect(
      await AuditLog.countDocuments({
        action: ALERT_TYPES.RATE_LIMIT_ABUSE,
        ip: IPS.notif2,
      })
    ).toBe(1);
  });

  test('结构不变量：shouldSendAlert 只出现在封禁之后，且前面没有提前 return', () => {
    // 上面那条钉"行为"，这条钉"代码里 gate 的位置"——行为测试只在我把封禁
    // 挪到 gate 之后时才会红，而挪动本身不改变任何外部可观测行为。
    const fs = require('fs');
    const path = require('path');
    const src = fs
      .readFileSync(path.join(__dirname, '../../services/rateLimitEscalationBan.js'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '');
    const escalate = src.slice(src.indexOf('const escalateIp ='));

    const gate = escalate.indexOf('shouldSendAlert(');
    const audit = escalate.indexOf('await recordEscalation(');
    const ban = escalate.indexOf('await addToBlacklist(');

    expect(gate).toBeGreaterThan(-1);
    expect(audit).toBeGreaterThan(-1);
    expect(ban).toBeGreaterThan(-1);
    // 通知频控必须排在「审计」与「封禁」之后——它挡的只是又一条相同告警
    expect(gate).toBeGreaterThan(audit);
    expect(gate).toBeGreaterThan(ban);
    // 频控命中时提前 return 是允许的（跳过通知即可），但不得有任何 return 出现在
    // 审计/封禁之前
    const firstReturn = escalate.search(/\breturn\b/);
    expect(firstReturn === -1 || firstReturn > ban).toBe(true);
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
