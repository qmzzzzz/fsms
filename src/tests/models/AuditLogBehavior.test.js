const mongoose = require('mongoose');

describe('AuditLog behavior guards', () => {
  let AuditLog;
  const stamp = `alb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      AuditLog._setAppendOnlyEnforced(false);
      await AuditLog.deleteMany({ username: stamp }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('getUserActivity filters by category and omits protected fields', async () => {
    const userId = new mongoose.Types.ObjectId();
    await AuditLog.create({
      action: 'auth_login',
      category: 'auth',
      userId,
      username: stamp,
      body: { password: 'secret' },
      hmac: 'must-not-leak',
    });
    await AuditLog.create({
      action: 'device_update',
      category: 'device',
      userId,
      username: stamp,
    });

    const logs = await AuditLog.getUserActivity(userId, { category: 'auth', limit: 10 });
    expect(logs).toHaveLength(1);
    expect(logs[0].category).toBe('auth');
    expect(logs[0].body).toBeUndefined();
    expect(logs[0].hmac).toBeUndefined();
  });

  test('preserves a caller-provided hash and derives its HMAC and version', async () => {
    const doc = await AuditLog.create({
      action: 'audit_imported',
      category: 'system',
      username: stamp,
      hash: 'imported-chain-hash',
    });
    // 【断言收紧】原断言只有 toBeTruthy()×2，标题承诺的「保留调用方提供的 hash」从未被断言：
    // 变异验证——把 auditLogHooks 的 `if (this.hash)` 短路分支改成 `if (false)`
    // （调用方 hash 会被重算覆盖），旧写法 SURVIVED（同目录 45 个相关用例全绿）。
    // 实测：hash 原样保留、prevHash 保持 null 不被改写、hashVersion 落为 CURRENT_PAYLOAD_VERSION、
    // hmac 为 64 位十六进制（= SHA-256 输出长度）。
    expect(doc.hash).toBe('imported-chain-hash');
    expect(doc.prevHash).toBeNull();
    const { CURRENT_PAYLOAD_VERSION } = require('../../utils/auditChain');
    expect(doc.hashVersion).toBe(CURRENT_PAYLOAD_VERSION);
    expect(String(doc.hmac)).toMatch(/^[0-9a-f]{64}$/);
  });

  test('blocks save-side modification of an append-only audit record', async () => {
    const doc = await AuditLog.create({
      action: 'append_only_original',
      category: 'system',
      username: stamp,
    });
    doc.action = 'append_only_tampered';
    await expect(doc.save()).rejects.toThrow('append-only');
  });

  /**
   * F-B43（2026-10-01 第 5 轮，中间件逐行审计复核后落实）：ip 是**被索引**
   * （`{ip:1, timestamp:-1}`）、且完全由请求方决定的字符串。
   *
   * trust proxy 打开时 req.ip 取自 X-Forwarded-For 的可信段，express 不校验其形态
   * （Node 的头部上限 ~16KB，够写到索引上限的数倍）。本仓对同类风险已有定论：
   * `method` 用 `set: auditMethodOrUndefined` 把「一维取值」降级为「少一维」，
   * 注释写明「宁可少一维，不可丢一行——丢一行是不可逆的取证缺口」；
   * `auditMeta` 把 path/action 截到 512/96。ip 是第三条同型通道，此前无人管。
   *
   * 危害定性与实测见下面那条「前提：非唯一索引不因超长 ip 拒写」——超长值今天
   * 不会丢审计，本条钉的是**界**本身（无界的请求方可控存储 + 索引形态漂移后
   * 就会变成丢审计）。
   */
  test('ip 有界：超长 XFF 派生值被截断落库，而不是让整条审计写入失败', async () => {
    const junk = `203.0.113.7${'x'.repeat(4000)}`;
    const doc = await AuditLog.record({
      action: 'security_ip_probe',
      category: 'security',
      username: stamp,
      ip: junk,
    });

    // 修复前这一条转红在长度断言上（实测 stored.ip.length = 4011），写入本身是成功的
    expect(doc).not.toBeNull();
    const stored = await AuditLog.findById(doc._id).select('ip');
    expect(stored).not.toBeNull();
    expect(stored.ip.length).toBeLessThanOrEqual(64);
    // 截断必须保留前缀：仍能定位到来源地址的可辨识部分
    expect(stored.ip.startsWith('203.0.113.7')).toBe(true);
  });

  test('ip 归一不改变合法值，也不把缺失值写成空串（空串会命中全体无 ip 的记录）', async () => {
    const kept = await AuditLog.create({
      action: 'security_ip_probe',
      category: 'security',
      username: stamp,
      ip: '203.0.113.8',
    });
    expect(kept.ip).toBe('203.0.113.8');

    const absent = await AuditLog.create({
      action: 'security_ip_probe',
      category: 'security',
      username: stamp,
    });
    // 与 method 的 `|| undefined` 同口径：降级成"不记这一维"，而不是记一个
    // 能被 `{ip: ''}` 查到的哨兵空串。
    expect(absent.ip).toBeUndefined();
  });

  // 前提自证（决定下面两条的定性）：本仓 MongoDB 的**非唯一**索引不因超长键拒写——
  // 绕过 mongoose setter 直连 driver 插入 4011 字符的 ip 仍然成功。
  // 所以审计报告里「超长 ip ⇒ 整条审计被索引键上限挤掉 ⇒ 可定向抹掉自己的安全记录」
  // 这一推断**不成立**（该报告定级为高，实测降级为补界而非救丢）。
  // 补界仍然要做，理由换成站得住的两条：
  //  1) ip 当时是请求方可控文本里没被剪的一位（path/action 由 auditMeta 截到 512/96，
  //     method 由 schema 的 set 降级；userAgent 在同一族里随后补界，见下面两条）。
  //     无界的请求方可控存储本身即问题（文档体积、列表渲染）。
  //  2) 该索引一旦改成 unique（或新增 unique 索引），超长键立刻变成**静默丢审计**，
  //     而 record() 吞错只计 audit_write_failed——正是 method 注释里
  //     「宁可少一维，不可丢一行」要防的形态。补在 schema 单点上，不等它变成事故。
  test('前提：非唯一索引不因超长 ip 拒写（据此把修复定性为补界而非救丢）', async () => {
    await AuditLog.collection.createIndex({ ip: 1, timestamp: -1 });
    const junk = `203.0.113.7${'x'.repeat(4000)}`;
    await AuditLog.collection.insertOne({
      action: 'probe',
      category: 'security',
      username: stamp,
      timestamp: new Date(),
      ip: junk,
    });
    // 按本用例专用的 action 取值筛选：同文件前两条用同一个 username 写过正常形态的记录，
    // 只按 username findOne 会命中它们，那条"超长仍落库"的断言就会假红/假绿漂移。
    const stored = await AuditLog.collection.findOne({ username: stamp, action: 'probe' });
    expect(stored.ip.length).toBeGreaterThan(1024);
    await AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: true });
  });

  test('ip 里的控制字符被中和（日志/终端渲染不得被审计字段二次注入）', async () => {
    const C = String.fromCharCode(10, 13, 0); // LF / CR / NUL
    const doc = await AuditLog.record({
      action: 'security_ip_probe',
      category: 'security',
      username: stamp,
      ip: `203.0.113.9${C}FAKE LOG LINE${C}${'y'.repeat(300)}`,
    });
    expect(doc).not.toBeNull();
    const after = await AuditLog.findById(doc._id).select('ip');
    expect(after.ip).not.toMatch(new RegExp(`[${C}]`));
    expect(after.ip.length).toBeLessThanOrEqual(64);
  });

  /**
   * userAgent 与 ip 出自同一个闸工厂（第 6 轮）。这里刻意走 `AuditLog.record()`
   * ——也就是全仓 21 个「传裸 `req.get('user-agent')`」写入点的真实路径——
   * 因为补界的价值恰恰在于：**不清洗的旧写入点无需改动就被治了**，
   * 而不是要求每个人记得在调用点先 stripControlChars（ip 的注释记过同型漏洗：
   * middleware/protocolCompliance.js:23-27）。
   */
  test('userAgent 有界：未清洗写入点交来 16KB 裸 UA，落库仍 ≤512 且保留可辨识前缀', async () => {
    const junk = `Mozilla/5.0 (Windows NT 10.0; Win64; x64)${'a'.repeat(16000)}`;
    const doc = await AuditLog.record({
      action: 'security_ua_probe',
      category: 'security',
      username: stamp,
      userAgent: junk,
    });
    expect(doc).not.toBeNull();

    const { AUDIT_USER_AGENT_MAX_LENGTH } = require('../../constants/audit');
    const stored = await AuditLog.findById(doc._id).select('userAgent');
    expect(stored).not.toBeNull();
    expect(stored.userAgent.length).toBeLessThanOrEqual(AUDIT_USER_AGENT_MAX_LENGTH);
    // 截断保留前缀：仍能认出是哪类客户端（这正是取证要看的那一维）
    expect(stored.userAgent.startsWith('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe(true);
    // 内存形态 == 落库形态（record 返回的是铸造后的文档）
    expect(doc.userAgent).toBe(stored.userAgent);
  });

  test('userAgent 归一：合法值原样、控制字符中和、缺失不写成空串', async () => {
    const { AUDIT_USER_AGENT_MAX_LENGTH } = require('../../constants/audit');
    const real =
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
    const kept = await AuditLog.create({
      action: 'security_ua_probe',
      category: 'security',
      username: stamp,
      userAgent: real,
    });
    expect(kept.userAgent).toBe(real);
    // 前提：真实浏览器 UA 远未触界（否则"合法值一个都不被改写"这条声明就不成立）
    expect(real.length).toBeLessThan(AUDIT_USER_AGENT_MAX_LENGTH);

    const C = String.fromCharCode(10, 13, 0);
    const injected = await AuditLog.record({
      action: 'security_ua_probe',
      category: 'security',
      username: stamp,
      userAgent: `curl/8.4.0${C}INFO: audit line forged${C}${'z'.repeat(600)}`,
    });
    const after = await AuditLog.findById(injected._id).select('userAgent');
    expect(after.userAgent).not.toMatch(new RegExp(`[${C}]`));
    expect(after.userAgent.length).toBeLessThanOrEqual(AUDIT_USER_AGENT_MAX_LENGTH);

    const absent = await AuditLog.create({
      action: 'security_ua_probe',
      category: 'security',
      username: stamp,
    });
    expect(absent.userAgent).toBeUndefined();
  });
});
