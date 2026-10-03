/**
 * 惩罚目标裁定（utils/ipUtils.resolvePunishableIp）接线门禁
 *
 * finding（2026-10-01）：classifyIpAttribution 造好了却零消费方——三条封禁链路
 * （限流升级 noteRateLimitHit / 暴力破解 checkBruteForce / 权限滥用
 * checkPermissionAbuse→recordAndContain）都拿未分类的 req.ip 当打击对象：
 *   - PUBLIC_PEER_HEADER（对端公网却自带 XFF）的 reportedIp 完全由请求方写：
 *     同网段容器写 X-Forwarded-For: <受害者IP> 即可定点踢任意地址下线，
 *     且攻击者换个伪造值就换一个新计数桶、永不被封；
 *   - TRUSTED_PROXY「可用但不可区分」必须留痕（ipUtils 函数注释的义务条款）。
 *
 * 三个层次（与 piiEncryption.test.js 的 A/B 分层同一经验——语义对而没接线
 * 是这类修复最常见的落地失败形态）：
 *   A. 裁定真值表（纯函数，四类逐个钉）；
 *   B. 限流升级链路端到端：伪造值轮换 + 同一对端 ⇒ 桶在对端攒满、封的也是对端；
 *   C. 暴力破解 / 权限滥用链路端到端：封禁目标与审计留痕逐条核对。
 */
'use strict';

const mongoose = require('mongoose');

const { resolvePunishableIp, IP_ATTRIBUTION_KINDS } = require('../../utils/ipUtils');
const security = require('../../middleware/security');
const escalation = require('../../services/rateLimitEscalation');
const {
  checkBruteForce,
  checkPermissionAbuse,
  ALERT_TYPES,
  ESCALATION_TIERS,
  THRESHOLDS,
  IPBanEvents,
} = require('../../services/securityAlert');
const AuditLog = require('../../models/AuditLog');
const User = require('../../models/User');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = Date.now().toString().slice(-7);
// TEST-NET 地址段（192.0.2.0/24 不属 RFC1918 ⇒ isPrivateOrLoopback=false ⇒ 公网语义）
const PEER_IP = `192.0.2.${(Number(stamp) % 100) + 70}`;
const FORGED_A = `192.0.2.${(Number(stamp) % 100) + 71}`;
const FORGED_B = `192.0.2.${(Number(stamp) % 100) + 72}`;
const TRUSTED_REPORTED = `192.0.2.${(Number(stamp) % 100) + 73}`;
const DIRECT_IP = `192.0.2.${(Number(stamp) % 100) + 74}`;
const BF_REPORTED = `192.0.2.${(Number(stamp) % 100) + 75}`;
const BF_PEER = `192.0.2.${(Number(stamp) % 100) + 76}`;
const ABUSE_PEER = `192.0.2.${(Number(stamp) % 100) + 77}`;
const ABUSE_FORGED = `192.0.2.${(Number(stamp) % 100) + 78}`;
const TEST_IPS = [
  PEER_IP,
  FORGED_A,
  FORGED_B,
  TRUSTED_REPORTED,
  DIRECT_IP,
  BF_REPORTED,
  BF_PEER,
  ABUSE_PEER,
  ABUSE_FORGED,
];

const originalAdd = security.addToBlacklist;
let captured;

const waitUntil = async (fn, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (fn()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

const purgeAudit = (filter) => AuditLog.deleteMany(filter, { bypassAppendOnly: true });

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  security.addToBlacklist = jest.fn(async (ip, durationMs, reason, source) => {
    captured.push({ ip, durationMs, reason, source });
    return { banned: true, normalizedIp: ip };
  });
});

afterAll(async () => {
  security.addToBlacklist = originalAdd;
  await purgeAudit({
    $or: [{ ip: { $in: TEST_IPS } }, { username: /^zzattr/ }],
  });
  await User.deleteMany({ username: /^zzattrab_/ }, { bypassAppendOnly: true });
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
});

beforeEach(() => {
  captured = [];
  escalation.resetForTest();
});

// ============ A. 裁定真值表（纯函数，四类逐个钉） ============

describe('resolvePunishableIp 真值表', () => {
  test('PUBLIC_PEER_HEADER：punishIp = socketPeer（伪造的 XFF 值绝不成为打击对象）', () => {
    const r = resolvePunishableIp({ ip: FORGED_A, socket: { remoteAddress: PEER_IP } });
    expect(r.kind).toBe(IP_ATTRIBUTION_KINDS.PUBLIC_PEER_HEADER);
    expect(r.punishIp).toBe(PEER_IP);
    expect(r.punishIp).not.toBe(FORGED_A);
  });

  test('TRUSTED_PROXY：punishIp = reportedIp（经可信代理按跳数取位的真实客户）', () => {
    const r = resolvePunishableIp({ ip: TRUSTED_REPORTED, socket: { remoteAddress: '10.0.0.7' } });
    expect(r.kind).toBe(IP_ATTRIBUTION_KINDS.TRUSTED_PROXY);
    expect(r.punishIp).toBe(TRUSTED_REPORTED);
  });

  test('DIRECT：punishIp = reportedIp（对端即身份，TCP 源不可伪造）', () => {
    const r = resolvePunishableIp({ ip: DIRECT_IP, socket: { remoteAddress: DIRECT_IP } });
    expect(r.kind).toBe(IP_ATTRIBUTION_KINDS.DIRECT);
    expect(r.punishIp).toBe(DIRECT_IP);
  });

  test('UNVERIFIABLE：无 socket 信息按 req.ip 既有口径（替身 req/夹具语义不变）', () => {
    expect(resolvePunishableIp({ ip: DIRECT_IP }).punishIp).toBe(DIRECT_IP);
    // 无 ip 的两种形态统一落 null（调用方 normalizeIP(null)||'unknown' 口径不变）
    expect(resolvePunishableIp({}).punishIp).toBeNull();
    // req 缺省不抛错（部分调用方 ctx.req 未传）——分类器不能成为新的抛错点
    expect(resolvePunishableIp(undefined).punishIp).toBeNull();
    expect(() => resolvePunishableIp(null)).not.toThrow();
  });
});

// ============ B. 限流升级链路端到端 ============

describe('限流升级 × 惩罚目标裁定', () => {
  test('伪造值轮换 + 同一对端：桶在对端攒满，封的也是对端，受害者 IP 全程不进桶', async () => {
    // 攻击面复现：攻击者每次请求换一个伪造的 XFF（FORGED_A/FORGED_B 轮换），
    // socket 对端不变。修复前 = 两个伪造桶各攒一半永远够不着阈值；修复后 = 对端一桶攒满。
    const anonThreshold = 10; // SIGNAL_CLASSES.ANON_ABUSE.threshold（下同，见断言）
    for (let i = 0; i < anonThreshold + 1; i += 1) {
      escalation.noteRateLimitHit(
        {
          ip: i % 2 === 0 ? FORGED_A : FORGED_B,
          socket: { remoteAddress: PEER_IP },
        },
        'captcha'
      );
    }
    expect(await waitUntil(() => captured.filter((c) => c.ip === PEER_IP).length === 1)).toBe(true);
    // 受害者/伪造值都不是打击对象
    expect(captured.filter((c) => c.ip === FORGED_A || c.ip === FORGED_B)).toHaveLength(0);
    // 审计留痕：这次的封禁依据是哪一类来源，事后必须可查
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.RATE_LIMIT_ABUSE,
      ip: PEER_IP,
    }).lean();
    expect(row.riskFactors).toContain('ip_attribution_public_peer_header');
  }, 20000);
});

// ============ C. 暴力破解 / 权限滥用链路端到端 ============

describe('checkBruteForce / checkPermissionAbuse × 惩罚目标裁定', () => {
  test('暴力破解：attribution=PUBLIC_PEER_HEADER ⇒ 封 socket 对端 + 审计留痕', async () => {
    await purgeAudit({ action: ALERT_TYPES.BRUTE_FORCE, ip: BF_PEER });
    expect(await IPBanEvents.countPrior(BF_PEER)).toBe(0);
    // IP 维度失败数攒到阈值（R-H2 判据走 ipFailures）
    const rows = [];
    for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
      rows.push({
        action: 'login_failed',
        category: 'auth',
        username: `zzattrbf_${stamp}`,
        ip: BF_REPORTED, // 审计行记的是伪造值（真实库内形态）
        success: false,
        riskLevel: 'low',
        timestamp: new Date(),
      });
    }
    await AuditLog.insertMany(rows);
    await checkBruteForce(`zzattrbf_${stamp}`, BF_REPORTED, {
      kind: IP_ATTRIBUTION_KINDS.PUBLIC_PEER_HEADER,
      punishIp: BF_PEER,
      socketPeer: BF_PEER,
    });
    expect(await waitUntil(() => captured.filter((c) => c.ip === BF_PEER).length >= 1)).toBe(true);
    expect(captured[0].durationMs).toBe(ESCALATION_TIERS[0]);
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: BF_PEER,
    }).lean();
    expect(row.riskFactors).toContain('ip_attribution_public_peer_header');
  }, 20000);

  test('权限滥用：rbac 链路的裁定入参 ⇒ 遏制封禁落在 socket 对端而非伪造 XFF', async () => {
    const abuser = await User.create({
      username: `zzattrab_${stamp}`,
      email: `zzattrab_${stamp}@example.invalid`,
      password: randomPassword(),
      roles: [],
    });
    const rows = [];
    for (let i = 0; i < THRESHOLDS.permissionFailures; i += 1) {
      rows.push({
        action: 'read_resource',
        category: 'system',
        userId: abuser._id,
        username: abuser.username,
        ip: ABUSE_FORGED, // 审计中间件落库的是请求方可写的 XFF 值
        statusCode: 403,
        success: false,
        riskLevel: 'low',
        timestamp: new Date(),
      });
    }
    await AuditLog.insertMany(rows);
    await checkPermissionAbuse(
      String(abuser._id),
      resolvePunishableIp({ ip: ABUSE_FORGED, socket: { remoteAddress: ABUSE_PEER } })
    );
    expect(await waitUntil(() => captured.filter((c) => c.ip === ABUSE_PEER).length >= 1)).toBe(
      true
    );
    expect(captured.filter((c) => c.ip === ABUSE_FORGED)).toHaveLength(0);
    const row = await AuditLog.findOne({
      action: ALERT_TYPES.PERMISSION_ABUSE,
      ip: ABUSE_PEER,
    }).lean();
    expect(row.riskFactors).toContain('ip_attribution_public_peer_header');
  }, 20000);

  test('TRUSTED_PROXY / DIRECT 回归：仍打 reportedIp，留痕只对非 DIRECT 类别存在', async () => {
    await purgeAudit({ action: ALERT_TYPES.BRUTE_FORCE, ip: { $in: [TRUSTED_REPORTED] } });
    await purgeAudit({ action: ALERT_TYPES.BRUTE_FORCE, ip: { $in: [DIRECT_IP] } });
    // R-H2：IP 维度失败数各自攒到阈值（两条链各自播种，互不借计数）
    for (const [ip, user] of [
      [TRUSTED_REPORTED, `zzattrtp_${stamp}`],
      [DIRECT_IP, `zzattrdir_${stamp}`],
    ]) {
      const rows = [];
      for (let i = 0; i < THRESHOLDS.bruteForceAttempts; i += 1) {
        rows.push({
          action: 'login_failed',
          category: 'auth',
          username: user,
          ip,
          success: false,
          riskLevel: 'low',
          timestamp: new Date(),
        });
      }
      await AuditLog.insertMany(rows);
    }
    // TRUSTED_PROXY：打 reportedIp + 留痕
    await checkBruteForce(`zzattrtp_${stamp}`, TRUSTED_REPORTED, {
      kind: IP_ATTRIBUTION_KINDS.TRUSTED_PROXY,
      punishIp: TRUSTED_REPORTED,
      socketPeer: '127.0.0.1',
    });
    expect(await waitUntil(() => captured.some((c) => c.ip === TRUSTED_REPORTED))).toBe(true);
    const trusted = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: TRUSTED_REPORTED,
    }).lean();
    expect(trusted.riskFactors).toContain('ip_attribution_trusted_proxy');
    // DIRECT：打 reportedIp，不带 ip_attribution 标记（默认事实不必刷存在）
    await checkBruteForce(`zzattrdir_${stamp}`, DIRECT_IP, {
      kind: IP_ATTRIBUTION_KINDS.DIRECT,
      punishIp: DIRECT_IP,
      socketPeer: DIRECT_IP,
    });
    expect(await waitUntil(() => captured.some((c) => c.ip === DIRECT_IP))).toBe(true);
    const direct = await AuditLog.findOne({
      action: ALERT_TYPES.BRUTE_FORCE,
      ip: DIRECT_IP,
    }).lean();
    expect(direct.riskFactors.some((f) => String(f).startsWith('ip_attribution_'))).toBe(false);
  }, 30000);
});
