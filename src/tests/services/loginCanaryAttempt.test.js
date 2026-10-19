/**
 * 端到端：幽灵名探测在登录主流程（authService.loginUser）被完整处置。
 *
 * 与 canaryWatch.test.js 的分工：那边测检测器自身的契约（mock 掉周围），
 * 这里测**接线**——login 的「用户名不存在」分支确实调用了检测器，且：
 *  - 审计行真的落进 auditlogs 集合（action/等级/IP）；
 *  - 网络告警经 securityAlert.dispatchNotification 发出（spy 拦截）；
 *  - 对外 outcome 仍是 INVALID_CREDENTIALS（幽灵检测不得改变拒绝口径）；
 *  - 非名单名不误报；同一哨兵重复探测审计逐条、告警只一次。
 *
 * 每个测试用不同来源 IP：checkBruteForce 按 IP 维度计数（5 次/5 分钟），
 * 共用 IP 会让第 5 个用例把暴力破解告警混进来污染 dispatch 断言。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('登录幽灵名（canary）端到端：审计 + 告警 + 对外口径不变', () => {
  let AuditLog;
  let securityAlert;
  let authService;
  const stamp = `lca${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  let dispatchSpy;

  const ctx = (ip) => ({
    ip,
    userAgent: 'test-agent',
    fingerprint: 'fp-test',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'test-agent' }, ip, connection: {} },
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    require('../../models/User');
    require('../../models/TokenBlacklist');
    AuditLog = require('../../models/AuditLog');
    securityAlert = require('../../services/securityAlert');
    authService = require('../../services/authService');
  });

  afterAll(async () => {
    const coll = mongoose.connection.collection('auditlogs');
    await coll.deleteMany({ action: 'canary_username_attempt' }).catch(() => {});
    await coll.deleteMany({ username: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
  });

  afterEach(() => {
    dispatchSpy.mockRestore();
  });

  const canaryDispatches = () =>
    dispatchSpy.mock.calls.filter((c) => c[0] === 'canary_username_attempt');

  test('不存在的哨兵名：审计落库 + 告警一次，对外仍是 INVALID_CREDENTIALS', async () => {
    const result = await authService.loginUser(
      { username: 'guest', password: PASSWORD },
      ctx('10.20.0.1')
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');

    const row = await AuditLog.findOne({
      action: 'canary_username_attempt',
      username: 'guest',
    }).lean();
    expect(row).toBeTruthy();
    expect(row.category).toBe('auth');
    expect(row.riskLevel).toBe('critical');
    expect(row.ip).toBe('10.20.0.1');

    const calls = canaryDispatches();
    expect(calls).toHaveLength(1);
    expect(calls[0][2]).toContain('guest');
  });

  test('大小写不敏感：DEMO 命中；审计保留原样输入，canary 键是归一化名', async () => {
    await authService.loginUser({ username: 'DEMO', password: PASSWORD }, ctx('10.20.0.2'));
    const row = await AuditLog.findOne({
      action: 'canary_username_attempt',
      username: 'DEMO',
    }).lean();
    expect(row).toBeTruthy();
    expect(row.body.canary).toBe('demo');
  });

  test('非名单名的普通不存在用户名：无 canary 审计、无告警（不误报）', async () => {
    await authService.loginUser(
      { username: `${stamp}plain`, password: PASSWORD },
      ctx('10.20.0.3')
    );
    expect(
      await AuditLog.countDocuments({
        action: 'canary_username_attempt',
        username: `${stamp}plain`,
      })
    ).toBe(0);
    expect(canaryDispatches()).toHaveLength(0);
  });

  test('同日重复探测同一哨兵：审计逐条（2 条）、告警仍只一次', async () => {
    await authService.loginUser({ username: 'postgres', password: PASSWORD }, ctx('10.20.0.4'));
    await authService.loginUser({ username: 'postgres', password: PASSWORD }, ctx('10.20.0.5'));
    expect(
      await AuditLog.countDocuments({
        action: 'canary_username_attempt',
        username: 'postgres',
      })
    ).toBe(2);
    expect(canaryDispatches()).toHaveLength(1);
  });
});
