/**
 * ip_range_denied 分支补测（覆盖率缺口：login.js 记录块的 fire-and-forget catch 臂）
 *
 * 该分支的主路径由 loginTimingParity 覆盖（比较次数平价），但 AuditLog.record(...)
 * 挂的 .catch(() => {}) 降级臂从未被走到——审计库抖动时该臂吞掉 rejection 防
 * unhandledRejection。本套件两条腿：正常落库（waitFor 到行）+ record 拒绝
 * （outcome 不变、rejection 被吞）。
 */
const mongoose = require('mongoose');

// 与 loginTimingParity 同口径：authService 在模块加载期解构这些导出，
// 必须在 require 之前整模块换成桩（jest.mock 提升到所有 require 之上）。
jest.mock('../services/securityAlert', () => ({
  checkBruteForce: jest.fn().mockResolvedValue(undefined),
  checkUnusualTime: jest.fn().mockResolvedValue(false),
}));
jest.mock('../services/loginChallenge', () => ({
  isChallengeRequired: jest.fn().mockResolvedValue(false),
  recordCaptchaRejected: jest.fn().mockResolvedValue(undefined),
  CAPTCHA_TRIGGERS: { SWITCH: 'captcha_switch', CHALLENGE: 'challenge_required' },
}));

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const { waitFor } = require('./helpers/waitFor');

const stamp = `ipdn${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

describe('ip_range_denied 分支的审计落库与降级臂', () => {
  let User;
  let Role;
  let authService;
  let AuditLog;
  const created = [];

  const ctx = (overrides = {}) => ({
    ip: '203.0.113.77',
    userAgent: 'test-agent',
    fingerprint: 'fp-ipdn',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'test-agent' }, ip: '203.0.113.77', connection: {} },
    ...overrides,
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    AuditLog = require('../models/AuditLog');
    authService = require('../services/authService');
    if (!(await Role.findOne({ code: 'GUEST' }))) {
      await Role.create({ name: '访客', code: 'GUEST', level: 1 });
    }
  });

  afterAll(async () => {
    if (created.length) {
      await User.deleteMany({ _id: { $in: created } }).catch(() => {});
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('受限 IP 持正确口令 ⇒ 统一 401 口径，且 ip_range_denied 审计行落库', async () => {
    const u = await User.create({
      username: `${stamp}a`,
      email: `${stamp}a@example.com`,
      password: PASSWORD,
      allowedIPs: '10.0.0.0/8',
    });
    created.push(u._id);

    const out = await authService.loginUser(
      { username: u.username, password: PASSWORD },
      ctx()
    );
    expect(out.outcome).toBe('INVALID_CREDENTIALS');

    await waitFor(
      async () => {
        const row = await AuditLog.findOne({
          action: 'ip_range_denied',
          username: u.username,
        }).lean();
        return Boolean(row);
      },
      { label: 'ip_range_denied 审计落库' }
    );
  });

  test('record 拒绝被 catch 臂吞掉：outcome 不变、无未处理 rejection', async () => {
    const u = await User.create({
      username: `${stamp}b`,
      email: `${stamp}b@example.com`,
      password: PASSWORD,
      allowedIPs: '10.0.0.0/8',
    });
    created.push(u._id);

    const rejectSpy = jest.spyOn(AuditLog, 'record').mockRejectedValueOnce(
      new Error('audit db down')
    );
    const out = await authService.loginUser(
      { username: u.username, password: PASSWORD },
      ctx({ ip: '203.0.113.78' })
    );
    expect(rejectSpy).toHaveBeenCalled();
    expect(out.outcome).toBe('INVALID_CREDENTIALS');
    // fire-and-forget 的 rejection 在微任务队列里被吞：多让几个 tick 落地，
    // 若未被吞这里会以 unhandledRejection 形式炸掉本进程（jest 会判红）
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    rejectSpy.mockRestore();
  });
});
