/**
 * 业务数据保留期声明 + 用户匿名化（A2，2026-10-16）
 *
 * 需求对应：数据保护 → 全生命周期（**销毁段**）。该段此前完全空白：
 * 有 TTL 的只有 AuditLog / IPBlacklist / TokenBlacklist / UserSession，
 * 而 User / FireDevice / FireAlarm / Inspection 的 `expireAfterSeconds` 零命中，
 * 且用户删除是**硬删除**（`findByIdAndDelete`）——审计链上指向该用户的引用随之悬空。
 *
 * 本轮交付的是**骨架**（口径待业务方给）：
 *   ① 保留期：可查的单一事实来源 + 与 constants/retention.js 同源的严格解析/钳制/告警，
 *      但**默认不启用**（`declaredDays` 全为 null ⇒ 不建 TTL）。本文件钉住
 *      "口径未定 ⇒ 不许建索引"这条 fail-closed 判据，以及"不许静默定数字"的形态；
 *   ② 删除权：`anonymizeById` 的抹除/保留清单与幂等性。
 *
 * 可证伪点：解析判据全部用 `90x` / `1e3` / `''` 这类**parseInt 会静默放过**的输入，
 * 若实现退回 parseInt，第 6、7 条立刻红。
 */

const mongoose = require('mongoose');

describe('业务数据保留期声明（A2）', () => {
  const {
    BUSINESS_RETENTION_POLICY,
    getBusinessRetentionPolicy,
    resolveBusinessRetention,
    assertBusinessRetentionEnforceable,
    describeBusinessRetention,
    describeAllBusinessRetention,
  } = require('../../constants/businessRetention');
  const { MIN_RETENTION_DAYS, MAX_RETENTION_DAYS } = require('../../constants/retention');

  const ENV_KEYS = BUSINESS_RETENTION_POLICY.map((p) => p.envKey);
  const clearEnv = () => ENV_KEYS.forEach((k) => delete process.env[k]);
  beforeEach(clearEnv);
  afterEach(clearEnv);

  test('受管业务集合清单：四个"无 TTL"的集合都被登记，且新增集合必须显式登记', () => {
    expect(BUSINESS_RETENTION_POLICY.map((p) => p.modelName).sort()).toEqual([
      'FireAlarm',
      'FireDevice',
      'Inspection',
      'User',
    ]);
    // 未登记即抛：静默返回 undefined 会让调用方拿着空对象继续走
    expect(() => getBusinessRetentionPolicy('NotARegisteredModel')).toThrow(/未登记保留期策略/);
    // 前提自证：合规区间来自 constants/retention.js（不另抄一份）
    expect(MIN_RETENTION_DAYS).toBe(90);
    expect(MAX_RETENTION_DAYS).toBe(3650);
  });

  test('默认（无环境变量）：不启用 TTL——业务口径未定时不得替业务定数字', () => {
    for (const p of BUSINESS_RETENTION_POLICY) {
      const r = resolveBusinessRetention(p.modelName);
      expect({ m: p.modelName, enabled: r.enabled, eff: r.effectiveDays }).toEqual({
        m: p.modelName,
        enabled: false,
        eff: null,
      });
      expect(r.wasAdjusted).toBe(false);
    }
  });

  test('fail-closed：口径未配置时建 TTL 索引必须抛错（而不是默默按 null 建）', () => {
    expect(() => assertBusinessRetentionEnforceable('FireAlarm')).toThrow(/未配置/);
    expect(() => assertBusinessRetentionEnforceable('FireAlarm')).toThrow(/业务\/合规口径/);
  });

  test('配置合法值：原样生效，wasAdjusted 为 false', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '365';
    const r = resolveBusinessRetention('FireAlarm');
    expect({ enabled: r.enabled, eff: r.effectiveDays, adj: r.wasAdjusted }).toEqual({
      enabled: true,
      eff: 365,
      adj: false,
    });
    expect(assertBusinessRetentionEnforceable('FireAlarm')).toBe(365);
    expect(describeBusinessRetention('FireAlarm')).toContain('原样生效');
  });

  test('越界值被钳制到合规区间，且 wasAdjusted 为 true（配置意图与实际必须一致）', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '1';
    let r = resolveBusinessRetention('FireAlarm');
    expect({ eff: r.effectiveDays, adj: r.wasAdjusted }).toEqual({ eff: 90, adj: true });

    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '99999';
    r = resolveBusinessRetention('FireAlarm');
    expect({ eff: r.effectiveDays, adj: r.wasAdjusted }).toEqual({ eff: 3650, adj: true });
    expect(describeBusinessRetention('FireAlarm')).toContain('超出允许区间');
  });

  test('严格解析：`90x` 不得被当成 90（parseInt 会，Number 不会）⇒ 未启用且说明"无法解析"', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '90x';
    const r = resolveBusinessRetention('FireAlarm');
    expect(r.enabled).toBe(false);
    expect(r.wasAdjusted).toBe(true); // 配了值却没生效 ⇒ 必须显形
    expect(describeBusinessRetention('FireAlarm')).toContain('无法解析');
    expect(() => assertBusinessRetentionEnforceable('FireAlarm')).toThrow();
  });

  test('`1e3` 同样按严格解析处理（不落成 1 天，也不静默当 1000）', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '1e3';
    const r = resolveBusinessRetention('FireAlarm');
    // Number('1e3') === 1000 ⇒ 合法且在区间内（这里要的是"明确"而不是"猜"）
    expect(r.enabled).toBe(true);
    expect(r.effectiveDays).toBe(1000);
    expect(r.wasAdjusted).toBe(false);
  });

  test('空串按"未配置"处理（不落成 0 天）', () => {
    process.env.BUSINESS_RETENTION_DAYS_FIRE_ALARM = '';
    const r = resolveBusinessRetention('FireAlarm');
    expect(r.enabled).toBe(false);
    expect(describeBusinessRetention('FireAlarm')).toContain('未配置');
  });

  test('全集合说明逐条给出，且未启用时明写"数据永久保留"（不得以一句"就绪"盖过去）', () => {
    const lines = describeAllBusinessRetention();
    expect(lines).toHaveLength(BUSINESS_RETENTION_POLICY.length);
    for (const line of lines) expect(line).toContain('数据永久保留');
  });

  test('接线闸：合规检查脚本真的把这条判据接进了检查表', () => {
    const fs = require('fs');
    const path = require('path');
    const readScript = (rel) =>
      fs.readFileSync(path.resolve(__dirname, '../../../scripts', rel), 'utf8');
    const src = readScript('compliance-check.js');
    expect(src).toContain('function checkBusinessRetention()');
    expect(src).toMatch(/const COMPLIANCE_CHECKS = \[\s*checkRetention,\s*checkBusinessRetention,/);
    // 判据取自声明模块，而不是在脚本里另抄一份。2026-10-16（A8）判据本体搬到
    // complianceVerdicts.js（compliance-check.js 触到 max-lines 体积棘轮预算，
    // 而 check* 的**声明**必须留在原文件供 complianceGate 的 C 用例对账）⇒
    // 接线变成两跳，两跳都要断：compliance-check → verdicts → constants。
    expect(src).toContain("require('./complianceVerdicts')");
    const verdicts = readScript('complianceVerdicts.js');
    expect(verdicts).toContain("require('../src/constants/businessRetention')");
    // 反向自证：判据不在 compliance-check.js 里就地实现（否则上面两跳可以同时是死代码）
    expect(src).not.toContain("require('../src/constants/businessRetention')");
  });
});

describe('用户匿名化：删除权流程的落点（A2）', () => {
  let User;
  let FireAlarm;
  let userService;
  const stamp = `anon${String(Date.now()).slice(-8)}`;
  const OLD_EMAIL = `anon-${stamp}@example.com`;
  const OLD_PHONE = '13800138123';
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ User, FireAlarm } = require('../../models'));
    userService = require('../../services/userService');

    const user = await User.create({
      username: `anon_${stamp}`,
      email: OLD_EMAIL,
      password: `P@ssw0rd-${stamp}`,
      realName: '张三',
      phone: OLD_PHONE,
      avatar: '/avatars/x.png',
      status: 'active',
      roles: [],
    });
    userId = user._id;

    // 一条"处理中"的报警挂在该用户名下：匿名化后必须被退回待指派池
    await FireAlarm.create({
      alarmType: 'smoke',
      description: `${stamp} 匿名化级联用例`,
      reporter: { name: '上报人' },
      handler: userId,
      status: 'processing',
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^anon_${stamp}$`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('抹除可识别信息、保留 userId/username：审计链上的引用不悬空', async () => {
    const before = await User.findById(userId).select('+password');
    const oldHash = before.password;
    const oldTokenVersion = before.tokenVersion;

    await userService.anonymizeById(userId, { reason: 'unit_test' });

    const after = await User.findById(userId).select('+password');
    // 抹除项
    expect(after.realName).toBe('已注销用户');
    expect(after.phone).toBe('');
    expect(after.avatar).toBe('');
    expect(after.email).toMatch(/^deleted\+/);
    expect(after.email).toContain(String(userId)); // 占位唯一 ⇒ 第二个注销用户不会撞 E11000
    expect(after.email).not.toBe(OLD_EMAIL);
    // 保留项（统计口径与审计引用都靠它们）
    expect(String(after._id)).toBe(String(userId));
    expect(after.username).toBe(`anon_${stamp}`);
    // 账户不可再用：停用 + 令牌版本自增 + 口令改写
    expect(after.status).toBe('inactive');
    expect(after.tokenVersion).toBe(oldTokenVersion + 1);
    expect(after.password).not.toBe(oldHash);
    // phoneKey 必须同步清空（写侧钩子的职责，走 save 才会触发）
    const raw = await mongoose.connection.collection('users').findOne({ _id: userId });
    expect(raw.phoneKey).toBe('');
  });

  test('幂等：重复匿名化不改写任何东西（tokenVersion 不自增）', async () => {
    const before = await User.findById(userId);
    await userService.anonymizeById(userId, { reason: 'unit_test_again' });
    const after = await User.findById(userId);
    expect(after.email).toBe(before.email);
    expect(after.tokenVersion).toBe(before.tokenVersion);
  });

  test('级联：进行中的指派被退回待指派池（与删号同一口径）', async () => {
    const alarm = await FireAlarm.findOne({ description: new RegExp(stamp) });
    expect(alarm.status).toBe('pending');
    expect(alarm.handler).toBeNull();
    // 留痕：processLog 里必须记下"处理人账户已删除，工单退回待指派池"
    const entry = alarm.processLog.find((l) => l.action === 'handler_released');
    expect(entry).toBeDefined();
  });

  test('用户不存在时返回 null（不抛，调用方可安全重放）', async () => {
    const res = await userService.anonymizeById(new mongoose.Types.ObjectId());
    expect(res).toBeNull();
  });
});
