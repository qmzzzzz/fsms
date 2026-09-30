/**
 * 处置与通知解耦：频控不得挡住审计与封禁（securityAlert 侧）
 *
 * 【本次修的两处缺陷，与 rateLimitEscalationBan.js 是同一条纪律】
 *
 * 缺陷 A —— `checkBruteForce`（2026-09-30）：
 *   两行 `shouldSendAlert` 挡在 priorBans 统计 / 审计 / 封禁**之前**，任一命中即 return。
 *   后果不是少一条通知：
 *     - 封禁**失败**（白名单命中 / 黑名单写库故障）时，5 分钟内的重试被吞掉——
 *       而"封禁没生效"恰恰是最需要重试的场合；
 *     - 审计行是**阶梯的事件源**（IPBanEvents.countPrior 数的就是它），跳过审计 ⇒
 *       阶梯永远停在第一档 ⇒ 反复触发的 IP 每次都只被封 1 小时，而日志照打「第 N 次」。
 *
 * 缺陷 B —— `checkPermissionAbuse`：
 *   本检测器**只告警、不封任何东西**（另两个检测器都有封禁动作）。攻击者只要拿到一份
 *   有效凭据，把权限探测压到每 5 分钟 < 20 次，就能永久试探权限边界——每次都不达阈值
 *   ⇒ 无告警、无审计、无遏制。修复：达阈值时对来源 IP 走同一条渐进式封禁阶梯。
 *
 * 【为什么这些用例必须"先占掉频控键"】
 * 直接 `jest.spyOn(securityAlert, 'shouldSendAlert')` 是**无效**的：securityAlert.js
 * 内部调用的是同模块闭包里的 `shouldSendAlert`，spy 换掉的是 exports 上的属性。
 * 照 rateLimitEscalation.test.js 的先例——直接调真实的 `shouldSendAlert` 把该 IP
 * 的频控键占掉，效果等价于"刚发过同 IP 的告警"，且不依赖任何 mock 装配顺序。
 *
 * 【为什么用例之间要各用各的 IP / username】
 * `alertRateLimit` 是**模块级 Map**（进程内），5 分钟窗口。共用键会让第二条用例被
 * 真正存在的频控闸挡下——表现为"没封禁也没审计"的假绿，而杀掉的却是错误的东西。
 * 基准时间也逐条错开（`FIXED_BASE + i` 天），避免 `Date.now` 落在同一窗口。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

jest.mock('../../services/securityAlertDelivery', () => ({
  sendNotification: jest.fn().mockResolvedValue(undefined),
  isWebhookTargetAllowed: jest.fn(() => true),
}));

const security = require('../../middleware/security');
const securityAlert = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');
const IPBlacklist = require('../../models/IPBlacklist');
const User = require('../../models/User');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const { ALERT_TYPES, THRESHOLDS, ESCALATION_TIERS, IPBanEvents } = securityAlert;
const stamp = Date.now().toString().slice(-7);

const originalAdd = security.addToBlacklist;
let banCalls = [];
let banResult = { banned: true, normalizedIp: null };

const purge = (filter) => AuditLog.deleteMany(filter, { bypassAppendOnly: true });

/** 塞够阈值条数的登录失败审计（checkBruteForce 的事件源） */
const seedFailures = async (username, ip, count = THRESHOLDS.bruteForceAttempts) => {
  const rows = [];
  for (let i = 0; i < count; i += 1) {
    rows.push({
      action: 'login_failed',
      category: 'auth',
      username,
      ip,
      success: false,
      riskLevel: 'low',
      timestamp: new Date(),
    });
  }
  await AuditLog.insertMany(rows);
};

/** 把某 IP 的暴力破解阶梯起点钉死为 0，并自证清空成功 */
const startChainAtZero = async (ip) => {
  await purge({ action: ALERT_TYPES.BRUTE_FORCE, ip: { $in: [ip, `::ffff:${ip}`] } });
  await purge({ action: ALERT_TYPES.PERMISSION_ABUSE, ip: { $in: [ip, `::ffff:${ip}`] } });
  expect(await IPBanEvents.countPrior(ip)).toBe(0);
};

const IPS = {
  decouple: '203.0.113.181',
  retryAfterFail: '203.0.113.182',
  ladder: '203.0.113.183',
  abuse: '203.0.113.184',
  abuseLadder: '203.0.113.185',
  abuseNoIp: '203.0.113.186',
};

describe('处置与通知解耦：频控不得挡住审计与封禁', () => {
  let abuseUser;
  let abuseUser2;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/TokenBlacklist');
    abuseUser = await User.create({
      username: `zzpd${stamp}`,
      email: `zzpd${stamp}@example.com`,
      password: randomPassword(),
      roles: [],
    });
    abuseUser2 = await User.create({
      username: `zzpd2${stamp}`,
      email: `zzpd2${stamp}@example.com`,
      password: randomPassword(),
      roles: [],
    });
  });

  afterAll(async () => {
    security.addToBlacklist = originalAdd;
    const ips = Object.values(IPS);
    await purge({
      $or: [
        { ip: { $in: [...ips, ...ips.map((i) => `::ffff:${i}`)] } },
        { username: new RegExp(`^zz(pd|bfdec)${stamp}`) },
        { userId: { $in: [abuseUser?._id, abuseUser2?._id].filter(Boolean) } },
      ],
    });
    await User.deleteMany({ username: new RegExp(`^zzpd2?${stamp}`) }).catch(() => {});
    await IPBlacklist.deleteMany({ ip: { $in: ips } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });

  beforeEach(() => {
    banCalls = [];
    banResult = { banned: true, normalizedIp: null };
    security.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
      banCalls.push({ ip, durationMs, reason, source });
      return banResult;
    });
  });

  // ============================ 缺陷 A：checkBruteForce ============================

  test('频控命中时审计照写、封禁照做（拒绝的是重复通知，不是处置）', async () => {
    const ip = IPS.decouple;
    const username = `zzbfdec_${stamp}`;
    await startChainAtZero(ip);

    // 用真实 shouldSendAlert 把两个维度的频控键都占掉：等价于"刚发过同一账号/同一 IP 的告警"
    expect(securityAlert.shouldSendAlert(`brute_force_user_${username}`)).toBe(true);
    expect(securityAlert.shouldSendAlert(`brute_force_ip_${ip}`)).toBe(true);
    expect(securityAlert.shouldSendAlert(`brute_force_user_${username}`)).toBe(false);
    expect(securityAlert.shouldSendAlert(`brute_force_ip_${ip}`)).toBe(false);

    await seedFailures(username, ip);
    await securityAlert.checkBruteForce(username, ip);

    // 修复前：频控命中 ⇒ 直接 return ⇒ 一条审计都没有、封禁一次都不做
    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].ip).toBe(ip);
    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.BRUTE_FORCE, ip })).toBe(1);
  }, 20000);

  test('封禁失败后的重试不被频控吞掉，且阶梯照常推进（第 2 次触发 ⇒ 第 2 档）', async () => {
    const ip = IPS.retryAfterFail;
    await startChainAtZero(ip);
    // 两次触发**共用同一个 username 与 IP**：频控有两个键（`brute_force_user_<名>` 与
    // `brute_force_ip_<IP>`），修复前的闸是 `!user && !ip ⇒ return`——只要有一个键放行
    // 就继续。若第二次换 username，user 键是新的 ⇒ 旧形态下仍会放行 ⇒ 用例漏杀变异
    //（实测：变异 A 下这条不红）。共用键才能让两次都落在"两个键都命中"的状态上。
    const username = `zzbfdec_retry_${stamp}`;

    // 第一次触发：封禁"未生效"（模拟白名单命中 / 写库失败）
    banResult = { banned: false, reason: 'persist_failed' };
    await seedFailures(username, ip);
    await securityAlert.checkBruteForce(username, ip);
    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);
    // 审计必须落库——它就是阶梯的事件源
    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.BRUTE_FORCE, ip })).toBe(1);

    // 第二次触发（同一账号 + 同一 IP，5 分钟频控窗口内）：修复前会被频控闸整个吞掉
    banCalls.length = 0;
    banResult = { banned: true, normalizedIp: ip };
    await seedFailures(username, ip);
    await securityAlert.checkBruteForce(username, ip);

    // 修复前：两个键都命中 ⇒ return ⇒ banCalls 为 0（重试被吞，阶梯永远停在第一档）
    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[1]);
    expect(banCalls[0].reason).toBe('brute_force_auto_ban_tier2');
    await expect(IPBanEvents.countPrior(ip)).resolves.toBe(2);
  }, 20000);

  // ============================ 缺陷 B：checkPermissionAbuse ============================

  test('权限滥用达阈值 ⇒ 必须真的封 IP（修复前只告警、不封任何东西）', async () => {
    const ip = IPS.abuse;
    await startChainAtZero(ip);
    // 只桩**第一次** countDocuments（即 403 计数那次），后续走真实实现。
    // 不能用 mockResolvedValue 整体替换：那样 IPBanEvents.countPermissionAbusePrior
    // （拿阶梯档位）也会恒返回阈值 ⇒ 每次触发都算成第 4 档，用例测的是"恒 20"而非阶梯。
    const real = AuditLog.countDocuments.bind(AuditLog);
    const countSpy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockImplementationOnce(async () => THRESHOLDS.permissionFailures)
      .mockImplementation((...args) => real(...args));

    try {
      await securityAlert.checkPermissionAbuse(abuseUser._id, ip);
    } finally {
      countSpy.mockRestore();
    }

    // 修复前：banCalls 恒为空——这就是"有效凭据持有者把探测压到 <20 次/5 分钟即可无限试探"
    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].ip).toBe(ip);
    expect(banCalls[0].source).toBe('auto');
    expect(banCalls[0].reason).toBe('permission_abuse_auto_ban_tier1');
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);
    // 审计也照写（且 action 是独立的 permission_abuse，与暴力破解分账）
    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.PERMISSION_ABUSE, ip })).toBe(1);
  }, 20000);

  test('权限滥用阶梯：同一 IP 第二次触发升到第 2 档（独立事件源，与暴力破解分账）', async () => {
    const ip = IPS.abuseLadder;
    await startChainAtZero(ip);
    // 每次触发含两次 countDocuments：① 403 计数 ② 阶梯统计。
    // 只桩 ①（$or 形态），②走真实实现 ⇒ 档位才能真的随历史增长而升。
    const real = AuditLog.countDocuments.bind(AuditLog);
    const countSpy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockImplementation((filter, ...rest) =>
        filter && filter.$or
          ? Promise.resolve(THRESHOLDS.permissionFailures)
          : real(filter, ...rest)
      );

    try {
      await securityAlert.checkPermissionAbuse(abuseUser._id, ip);
      expect(banCalls).toHaveLength(1);
      expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);

      banCalls.length = 0;
      await securityAlert.checkPermissionAbuse(abuseUser2._id, ip);
      expect(banCalls).toHaveLength(1);
      expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[1]);
      expect(banCalls[0].reason).toBe('permission_abuse_auto_ban_tier2');
    } finally {
      countSpy.mockRestore();
    }
    // 事件源确实是 permission_abuse（不是 brute_force_login）
    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.PERMISSION_ABUSE, ip })).toBe(2);
    await expect(IPBanEvents.countPrior(ip)).resolves.toBe(0);
  }, 20000);

  test('无 IP 上下文 ⇒ 只告警不封禁（不得把 undefined 当 IP 封）', async () => {
    const countSpy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockResolvedValue(THRESHOLDS.permissionFailures);
    try {
      await securityAlert.checkPermissionAbuse(abuseUser._id, undefined);
    } finally {
      countSpy.mockRestore();
    }
    // 调用点 rbac.js 总会带 req.ip，但直调路径下必须 fail-soft：
    // 不封 "undefined"，审计照写（username 有了就写）
    expect(banCalls).toHaveLength(0);
    expect(await AuditLog.countDocuments({ action: ALERT_TYPES.PERMISSION_ABUSE })).toBeGreaterThan(
      0
    );
  }, 20000);
});

// ============================ 写法门禁：闸的位置 ============================
// 行为用例只在"把封禁挪到 gate 之后"时才红；而闸的位置本身不改变外部可观测行为。
// 照 rateLimitEscalation.test.js 的先例补一条文本闸，钉住"闸必须在审计与封禁之后"。

describe('写法门禁：shouldSendAlert 必须排在审计与封禁之后', () => {
  const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');

  test('checkBruteForce：首个 shouldSendAlert 晚于 AuditLog.create 与 addToBlacklist', () => {
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', '..', 'services', 'securityAlert.js'), 'utf8')
    );
    const from = src.indexOf('const checkBruteForce =');
    expect(from).toBeGreaterThan(-1);
    const body = src.slice(from, src.indexOf('\nconst checkBulkExport', from));

    const gate = body.indexOf('shouldSendAlert(');
    const audit = body.indexOf('await AuditLog.create(');
    const ban = body.indexOf('await addToBlacklist(');
    expect(gate).toBeGreaterThan(-1);
    expect(audit).toBeGreaterThan(-1);
    expect(ban).toBeGreaterThan(-1);
    expect(gate).toBeGreaterThan(audit);
    expect(gate).toBeGreaterThan(ban);
    // 闸**之前**不得有任何 return：那正是"频控把审计与封禁一起关在门外"的形状。
    // 允许 R-H2 的那个 `if (ipFailures < 阈值) return;`——它排在审计之后、封禁之前，
    // 是既有的正确设计（账号维度达标不封 IP，防 NAT 无辜陪绑），与本闸无关。
    const beforeAudit = body.slice(0, audit);
    expect(beforeAudit.search(/\breturn\b/)).toBe(-1);
  });

  test('checkPermissionAbuse 的处置侧：首个 shouldSendAlert 晚于审计与封禁', () => {
    const src = stripComments(
      fs.readFileSync(
        path.join(__dirname, '..', '..', 'services', 'securityAlertPermissionAbuse.js'),
        'utf8'
      )
    );
    const from = src.indexOf('const recordAndContain =');
    expect(from).toBeGreaterThan(-1);
    const body = src.slice(from);

    const gate = body.indexOf('shouldSendAlert(');
    const audit = body.indexOf('await AuditLog.create(');
    const ban = body.indexOf('await addToBlacklist(');
    expect(gate).toBeGreaterThan(-1);
    expect(audit).toBeGreaterThan(-1);
    expect(ban).toBeGreaterThan(-1);
    expect(gate).toBeGreaterThan(audit);
    expect(gate).toBeGreaterThan(ban);
  });
});
