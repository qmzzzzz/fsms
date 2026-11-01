/**
 * 暴力破解自动封禁的判据回归
 *
 * 第一层（R-H2）：封禁只在 **IP 维度自己刷满** 时执行。`max(userFailures, ipFailures)`
 * 达标只说明"有攻击"，分布式撞单账号时当前 IP 可能只贡献 1 次失败——封它是 NAT 陪绑。
 *
 * 第二层（#21，2026-10-21）：IP 维度刷满也不再无条件封禁——
 *  - 单账号失败（distinct < 2）交给账户锁定 + loginUserLimiter，IP 只告警；
 *  - 近 7 天有 ≥3 个不同账号成功登录的共享出口，首次触发只告警（一次宽限）；
 *  - 跳过封禁的告警行写 body.ipBanApplied:false，且**不得**抬升后续封禁档位。
 *
 * 第三层（#22）：账户维度计数与 User.findByUsername 同口径（大小写不敏感），
 * 否则轮换大小写即可让同一账户永远到不了阈值。
 */

const mongoose = require('mongoose');

const ipBlacklistStore = require('../../middleware/security/ipBlacklistStore');
const {
  checkBruteForce,
  ALERT_TYPES,
  THRESHOLDS,
  ESCALATION_TIERS,
} = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');

const stamp = Date.now().toString().slice(-7);
const ipFor = (offset) => `198.51.100.${(Number(stamp) % 40) + offset}`;
// 攻击者使用的多个源 IP（各自低于 IP 维度阈值）
const ATTACK_IP_1 = ipFor(100);
const ATTACK_IP_2 = ipFor(101);
// 撞库进行中，受害者本人的真实来源 IP（仅 1 次失败——他自己输错了密码）
const VICTIM_IP = ipFor(102);
const SINGLE_ACCOUNT_IP = ipFor(103);
const LADDER_IP = ipFor(104);
const SHARED_EGRESS_IP = ipFor(105);
const CASE_IP = ipFor(106);
const USER = `zzrh2_${stamp}`;
const USER_B = `${USER}_b`;
const USER_C = `${USER}_c`;
const USER_D = `${USER}_d`;
const USER_E = `${USER}_e`;
const USER_F = `${USER}_f`;
const USER_G = `${USER}_g`;
const CASE_USER = `zzcase_${stamp}`;
const CASE_VARIANTS = [CASE_USER, CASE_USER.toLowerCase(), CASE_USER.toUpperCase()];
// B-F-2 变体测试的专属账户（变体清洗后都落在本名上，afterAll 按本名清理）
const BLAST_USER = `zzblast_${stamp}`;
const SEEDED_USERS = [
  USER,
  USER_B,
  USER_C,
  USER_D,
  USER_E,
  USER_F,
  USER_G,
  BLAST_USER,
  ...CASE_VARIANTS,
];

const originalAdd = ipBlacklistStore.addToBlacklist;
let banCalls;

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  ipBlacklistStore.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
    banCalls.push({ ip, durationMs, reason, source });
    return { banned: true, normalizedIp: ip };
  });
});

afterAll(async () => {
  ipBlacklistStore.addToBlacklist = originalAdd;
  // 清理本套件种下的全部行（失败记录 + 成功登录 + 告警），避免污染共享测试库的
  // ip 维度计数（distinctAccounts/sharedEgress 都按 ip 查询，跨套件泄漏会改变判据）
  await AuditLog.deleteMany({ username: { $in: SEEDED_USERS } }, { bypassAppendOnly: true });
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
});

beforeEach(() => {
  banCalls = [];
});

/** 塞一条登录失败审计（checkBruteForce 的事件源） */
const seedFailure = (username, ip) =>
  AuditLog.create({
    action: 'login_failed',
    category: 'auth',
    username,
    ip,
    success: false,
    riskLevel: 'low',
    timestamp: new Date(),
  });

/** 塞一条成功登录审计（共享出口信号的来源） */
const seedSuccess = (username, ip) =>
  AuditLog.create({
    action: 'login_success',
    category: 'auth',
    username,
    ip,
    success: true,
    riskLevel: 'low',
    timestamp: new Date(),
  });

const seedFailures = async (pairs) => {
  for (const [username, ip] of pairs) await seedFailure(username, ip);
};

describe('checkBruteForce 封禁判据（R-H2：只看 IP 维度）', () => {
  test('账号维度达标而 IP 维度未达标：不封禁当前 IP，但告警审计照写', async () => {
    // 多个攻击 IP 各自少量尝试同一账号：ip=1 < 阈值 5；user=5 达到阈值
    for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
      await seedFailure(USER, i % 2 === 0 ? ATTACK_IP_1 : ATTACK_IP_2);
    }
    // 受害者本人（另一个 IP）此时登录失败 1 次，驱动本次检测
    await seedFailure(USER, VICTIM_IP);
    await checkBruteForce(USER, VICTIM_IP);

    // 核心断言：无辜的受害者 IP 没有被封
    expect(banCalls).toHaveLength(0);

    // 但攻击信号本身必须可见：告警审计落库（风险因素含双维度计数）
    const alert = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      username: USER,
      ip: VICTIM_IP,
    }).lean();
    expect(alert).toBeTruthy();
    // IP 维度未达标 → 即使多账号信号成立也不封，且行上明确标注未执行
    expect(alert.body.ipBanApplied).toBe(false);
  });

  test('IP 维度达标且跨账号：封禁照常执行（修复不削弱既有防线）', async () => {
    // 两个不同账号各贡献一部分失败：这是 password spraying 的确定性信号
    await seedFailures([
      [USER_B, ATTACK_IP_1],
      [USER_D, ATTACK_IP_1],
      [USER_B, ATTACK_IP_1],
      [USER_D, ATTACK_IP_1],
      [USER_B, ATTACK_IP_1],
    ]);
    await checkBruteForce(USER_B, ATTACK_IP_1);

    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].ip).toBe(ATTACK_IP_1);
    expect(banCalls[0].source).toBe('auto');
  });
});

describe('checkBruteForce 多账号与共享出口判据（#21）', () => {
  test('单账号刷满 5 次：只告警不封 IP，审计标注 skipped_single_account', async () => {
    for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
      await seedFailure(USER_E, SINGLE_ACCOUNT_IP);
    }
    await checkBruteForce(USER_E, SINGLE_ACCOUNT_IP);

    expect(banCalls).toHaveLength(0);
    const alert = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      username: USER_E,
      ip: SINGLE_ACCOUNT_IP,
    }).lean();
    expect(alert).toBeTruthy();
    expect(alert.body).toMatchObject({
      ipAttempts: THRESHOLDS.bruteForceAttempts,
      distinctAccounts: 1,
      ipBanApplied: false,
      ipBanOutcome: 'skipped_single_account',
    });
    expect(alert.riskFactors).toContain('ip_ban_skipped_single_account');
  });

  test('共享出口首次触发只告警；第二次触发恢复封禁（宽限只有一次）', async () => {
    // 该 IP 近 7 天有 3 个不同账号成功登录 → 判定为 NAT/办公出口
    await seedSuccess(USER, SHARED_EGRESS_IP);
    await seedSuccess(USER_B, SHARED_EGRESS_IP);
    await seedSuccess(USER_C, SHARED_EGRESS_IP);
    // 首次跨账号失败：2 个账号共 5 次
    await seedFailures([
      [USER_D, SHARED_EGRESS_IP],
      [USER_E, SHARED_EGRESS_IP],
      [USER_D, SHARED_EGRESS_IP],
      [USER_E, SHARED_EGRESS_IP],
      [USER_D, SHARED_EGRESS_IP],
    ]);
    await checkBruteForce(USER_D, SHARED_EGRESS_IP);

    expect(banCalls).toHaveLength(0);
    const first = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: SHARED_EGRESS_IP,
    }).lean();
    expect(first.body).toMatchObject({
      sharedEgressAccounts: 3,
      ipBanApplied: false,
      ipBanOutcome: 'skipped_shared_egress',
    });

    // 第二次跨账号失败（另外两个账号）：宽限已用完，必须真的封
    await seedFailures([
      [USER_F, SHARED_EGRESS_IP],
      [USER_G, SHARED_EGRESS_IP],
      [USER_F, SHARED_EGRESS_IP],
      [USER_G, SHARED_EGRESS_IP],
      [USER_F, SHARED_EGRESS_IP],
    ]);
    await checkBruteForce(USER_F, SHARED_EGRESS_IP);

    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].ip).toBe(SHARED_EGRESS_IP);
    // 首次只告警未封 → 不抬档，仍是第一档
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);
  });
});

describe('checkBruteForce 账户维度计数口径（#22）', () => {
  test('同一账户的大小写变体合并计数（与 User.findByUsername 同口径）', async () => {
    // 轮换大小写共 5 次：若按原文分桶，userAttempts 只有 1–2，永远到不了阈值
    await seedFailure(CASE_USER, CASE_IP);
    await seedFailure(CASE_USER.toLowerCase(), CASE_IP);
    await seedFailure(CASE_USER.toUpperCase(), CASE_IP);
    await seedFailure(CASE_USER, CASE_IP);
    await seedFailure(CASE_USER.toLowerCase(), CASE_IP);

    await checkBruteForce(CASE_USER.toUpperCase(), CASE_IP);

    const alert = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: CASE_IP,
    }).lean();
    expect(alert).toBeTruthy();
    expect(alert.body.userAttempts).toBe(THRESHOLDS.bruteForceAttempts);
  });

  test('带空白/控制字符的变体用户名不绕过账户维度计数（2026-11-02 B-F-2）', async () => {
    // 写入侧 set 钩子把变体清洗成本名落库（stripControlChars→空格 + trim），
    // 而 Mongoose 对 filter 不应用 setter：修复前查询用**原文键**恒查 0 行，
    // 每个变体各占一个空桶，账户维度阈值永远攒不满（与轮换大小写同型的绕过）。
    // 修复后查询键走同一把 cleanAuditUsername，与落库行同键。
    await seedFailure(` ${BLAST_USER}\u0001`, CASE_IP);
    await seedFailure(`${BLAST_USER} `, CASE_IP);
    await seedFailure(`\t${BLAST_USER}\n`, CASE_IP);
    await seedFailure(` ${BLAST_USER} `, CASE_IP);
    await seedFailure(BLAST_USER, CASE_IP);

    // 用最脏的变体发问：必须能数到全部 5 条（含它自己变体清洗后的那份）
    await checkBruteForce(` ${BLAST_USER}\u0001`, CASE_IP);

    const alert = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: CASE_IP,
    }).lean();
    expect(alert).toBeTruthy();
    expect(alert.body.userAttempts).toBe(THRESHOLDS.bruteForceAttempts);
  });
});

describe('checkBruteForce 阶梯事件源（R-H2 续）', () => {
  test('IP 维度未达标的告警行不得抬升后续封禁档位', async () => {
    // 场景：受害 IP 在分布式撞库期间被写过一条 ipFailures=1 的告警行（上一例
    // 同款形态），之后有人用同一 IP 真实刷满 5 次失败——若 countPrior 把那行
    // 也算"封禁事件"，本次会直接跳到第二档（4h），无辜 IP 陪绑被放大。
    const victimUser = USER_C;
    // 模拟历史遗留：一条 ip 维度未达标的告警行（body.ipAttempts=1）
    await AuditLog.create({
      action: ALERT_TYPES.BRUTE_FORCE,
      category: 'auth',
      username: victimUser,
      ip: LADDER_IP,
      riskLevel: 'critical',
      riskFactors: [`登录失败次数超标 (账户:${THRESHOLDS.bruteForceAttempts}, IP:1)`],
      body: { userAttempts: THRESHOLDS.bruteForceAttempts, ipAttempts: 1, window: '5 分钟' },
      timestamp: new Date(),
    });

    // 该 IP 现在跨两个账号真实刷满 5 次 → 本次是它第一次"够格"的封禁事件
    await seedFailures([
      [victimUser, LADDER_IP],
      [USER_G, LADDER_IP],
      [victimUser, LADDER_IP],
      [USER_G, LADDER_IP],
      [victimUser, LADDER_IP],
    ]);
    await checkBruteForce(victimUser, LADDER_IP);

    expect(banCalls).toHaveLength(1);
    // 没被历史告警行抬档：仍是第一档 1h
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);
  });
});
