/**
 * R-H2 回归：暴力破解自动封禁的判据必须只看 IP 维度
 *
 * 缺陷（总账 R-H2）：checkBruteForce 以 `max(userFailures, ipFailures)` 达标即进入
 * 封禁分支，而封禁对象是**当前请求的 IP**——分布式撞单账号（多 IP 各自少量尝试
 * 同一账号）会让账号维度达标，此时把"可能只贡献了 1 次失败的当前 IP"封 1 小时，
 * NAT 出口后的无辜用户陪绑（受害者本人换个网络登录一次即被封）。
 * 修复后：告警/审计照发（双维度都是真实攻击信号），封禁只在 `ipFailures` 达标时执行。
 */

const mongoose = require('mongoose');

const security = require('../../middleware/security');
const {
  checkBruteForce,
  ALERT_TYPES,
  THRESHOLDS,
  ESCALATION_TIERS,
} = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');

const stamp = Date.now().toString().slice(-7);
// 攻击者使用的多个源 IP（各自低于 IP 维度阈值）
const ATTACK_IP_1 = `198.51.100.${(Number(stamp) % 100) + 40}`;
const ATTACK_IP_2 = `198.51.100.${(Number(stamp) % 100) + 41}`;
// 撞库进行中，受害者本人的真实来源 IP（仅 1 次失败——他自己输错了密码）
const VICTIM_IP = `203.0.113.${(Number(stamp) % 200) + 30}`;
const USER = `zzrh2_${stamp}`;

const originalAdd = security.addToBlacklist;
let banCalls;

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  security.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
    banCalls.push({ ip, durationMs, reason, source });
    return { banned: true, normalizedIp: ip };
  });
});

afterAll(async () => {
  security.addToBlacklist = originalAdd;
  // 第二例的账号名是 `${USER}_b`（IP 维度对照臂），精确等值清不到会泄漏
  // 5+1 条审计行污染共享测试库（ip=ATTACK_IP_1 的行会干扰后续阶梯用例）
  await AuditLog.deleteMany(
    {
      username: { $in: [USER, `${USER}_b`, `${USER}_c`] },
      action: { $in: ['login_failed', ALERT_TYPES.BRUTE_FORCE] },
    },
    { bypassAppendOnly: true }
  );
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
  });

  test('IP 维度达标：封禁照常执行（修复不削弱既有防线）', async () => {
    for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
      await seedFailure(`${USER}_b`, ATTACK_IP_1);
    }
    await checkBruteForce(`${USER}_b`, ATTACK_IP_1);

    expect(banCalls).toHaveLength(1);
    expect(banCalls[0].ip).toBe(ATTACK_IP_1);
    expect(banCalls[0].source).toBe('auto');
  });

  test('阶梯事件源只认「该 IP 自己刷满」的行：IP 维度未达标的告警行不得抬升后续封禁档位', async () => {
    // 场景：受害 IP 在分布式撞库期间被写过一条 ipFailures=1 的告警行（上一例
    // 同款形态），之后有人用同一 IP 真实刷满 5 次失败——若 countPrior 把那行
    // 也算"封禁事件"，本次会直接跳到第二档（4h），无辜 IP 陪绑被放大。
    const ip = `203.0.113.${(Number(stamp) % 200) + 40}`;
    const victimUser = `${USER}_c`;
    // 模拟历史遗留：一条 ip 维度未达标的告警行（body.ipAttempts=1）
    await AuditLog.create({
      action: ALERT_TYPES.BRUTE_FORCE,
      category: 'auth',
      username: victimUser,
      ip,
      riskLevel: 'critical',
      riskFactors: [`登录失败次数超标 (账户:${THRESHOLDS.bruteForceAttempts}, IP:1)`],
      body: { userAttempts: THRESHOLDS.bruteForceAttempts, ipAttempts: 1, window: '5 分钟' },
      timestamp: new Date(),
    });

    // 该 IP 现在真实刷满 5 次 → 本次是它第一次"够格"的封禁事件
    for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
      await seedFailure(victimUser, ip);
    }
    await checkBruteForce(victimUser, ip);

    expect(banCalls).toHaveLength(1);
    // 没被历史告警行抬档：仍是第一档 1h
    expect(banCalls[0].durationMs).toBe(ESCALATION_TIERS[0]);
  });
});
