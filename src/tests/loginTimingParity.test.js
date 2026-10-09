/**
 * 登录拒绝路径的口令比较次数必须一致（账号存在性 / 锁定态时序预言机）
 *
 * 缺陷（中危）：`assertAccountUsable`（src/services/authService.js:330）的两条拒绝分支
 * （status inactive|locked、lockUntil 未到期）**既没跑 consumeDummyPasswordTime，
 * 也没走 checkBruteForce**；而「用户不存在」（src/services/authService.js:240，
 * 其 checkBruteForce 在 src/services/authService.js:245）与「IP 不在允许范围」
 * （src/services/authService.js:400，其 checkBruteForce 在
 * src/services/authService.js:427）两条都跑了。bcrypt 是纯 JS cost-12（百毫秒级），于是
 * **存在的已禁用/已锁定账号比不存在的用户名快约一次 compare 的时间** ⇒
 * 不需要正确口令就能区分「这个用户名存在且被禁了」，
 * 把 P2-11 / M-5 / P2-10 辛苦做的时序拉平从另一个方向漏掉。
 *
 * 结论：缺陷成立（读码即见分支缺失）。修法不采用"量耗时"，
 * 而是**数口令比较次数**：墙钟差在共机上必然假红，比较次数是确定的、可证伪的等价判据。
 *
 * 断言的是"与不存在的用户名同价"这个不变量，而不是硬编码 1：
 * 将来若某条路径合理地改成两次比较，它会立刻红并要求写清理由，而不是无声漂移。
 */
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// authService 在**模块加载期**就解构了 securityAlert 的导出，
// 所以必须在 require 之前把该模块整体换成 spy（jest.mock 会被提升到所有 require 之上）。
jest.mock('../services/securityAlert', () => ({
  checkBruteForce: jest.fn().mockResolvedValue(undefined),
  checkUnusualTime: jest.fn().mockResolvedValue(false),
}));

const { checkBruteForce } = require('../services/securityAlert');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

const stamp = `zztp${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

describe('登录各拒绝路径的口令比较次数一致', () => {
  let User;
  let Role;
  let authService;
  const created = [];

  let realCompare;
  let compares = 0;

  const countCompares = async (fn) => {
    compares = 0;
    const out = await fn();
    return { calls: compares, out };
  };

  const ctx = (overrides = {}) => ({
    ip: '127.0.0.1',
    userAgent: 'test-agent',
    fingerprint: 'fp-test',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
    ...overrides,
  });

  const makeUser = async (suffix, extra = {}) => {
    const u = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    created.push(u._id);
    return u;
  };

  const login = (username, password = PASSWORD, ctxOverrides) =>
    countCompares(() => authService.loginUser({ username, password }, ctx(ctxOverrides)));

  /** 「不存在的用户名」比较次数——所有分支的对照基线 */
  let baseline;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    require('../models/TokenBlacklist');
    require('../models/AuditLog');
    if (!(await Role.findOne({ code: 'GUEST' }))) {
      await Role.create({ name: '访客', code: 'GUEST', level: 1 });
    }
    authService = require('../services/authService');

    realCompare = bcrypt.compare;
    bcrypt.compare = (...args) => {
      compares += 1;
      return realCompare(...args);
    };

    // 基线在 beforeAll 里量一次，**不能**靠"某条用例先跑"来填全局变量：
    // 本仓有双 seed 随机顺序门禁，跨用例传状态会偶发假红。
    const probe = await login(`${stamp}nosuch`);
    baseline = probe.calls;
  });

  afterAll(async () => {
    if (realCompare) bcrypt.compare = realCompare;
    await User.deleteMany({ _id: { $in: created } }).catch(() => {});
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ username: new RegExp(stamp) })
      .catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    checkBruteForce.mockClear();
  });

  test('探针有效：口令比较计数确实抓得到 bcrypt.compare（否则下面全是假绿）', async () => {
    const { calls } = await login(`${stamp}nosuch`);
    expect(calls).toBeGreaterThan(0);
  });

  test('基线自身可信：不存在的用户名 = N 次比较，且计入暴力破解检测', async () => {
    const { calls, out } = await login(`${stamp}nosuch`);
    expect(out.outcome).toBe('INVALID_CREDENTIALS');
    expect(calls).toBeGreaterThanOrEqual(1);
    expect(calls).toBe(baseline);
    expect(checkBruteForce).toHaveBeenCalledTimes(1);
  });

  test('status=inactive 与不存在的用户名同价（时序预言机已闭合）', async () => {
    const u = await makeUser('ina', { status: 'inactive' });
    const { calls, out } = await login(u.username);
    expect(out.outcome).toBe('INVALID_CREDENTIALS');
    expect(calls).toBe(baseline);
  });

  test('status=locked 同价', async () => {
    const u = await makeUser('lck', { status: 'locked' });
    const { calls } = await login(u.username);
    expect(calls).toBe(baseline);
  });

  test('lockUntil 未到期同价', async () => {
    const u = await makeUser('tmp', { lockUntil: new Date(Date.now() + 600000) });
    const { calls } = await login(u.username);
    expect(calls).toBe(baseline);
  });

  test('IP 不在允许范围同价（这条原本就做了拉平，作为回归锚）', async () => {
    const u = await makeUser('ip', { allowedIPs: '10.0.0.0/8' });
    const { calls } = await login(u.username, PASSWORD, { ip: '192.168.5.5' });
    expect(calls).toBe(baseline);
  });

  test('存在的正常账号 + 错误口令同价（拉平不得只覆盖禁用分支）', async () => {
    const u = await makeUser('act');
    const { calls } = await login(u.username, `${PASSWORD}wrong`);
    expect(calls).toBe(baseline);
  });

  test('禁用/锁定分支同样进入暴力破解检测（探测被禁账号不再是免检路径）', async () => {
    const u = await makeUser('bf', { status: 'inactive' });
    await login(u.username);
    expect(checkBruteForce).toHaveBeenCalledTimes(1);

    const locked = await makeUser('bf2', { lockUntil: new Date(Date.now() + 600000) });
    await login(locked.username);
    expect(checkBruteForce).toHaveBeenCalledTimes(2);
  });

  test('对外口径不变：所有路径仍是同一个 INVALID_CREDENTIALS（修时序不得顺手差异化）', async () => {
    const u = await makeUser('shape', { status: 'inactive' });
    const outcomes = await Promise.all([
      login(`${stamp}nosuch`).then((r) => r.out.outcome),
      login(u.username).then((r) => r.out.outcome),
      login(u.username, `${PASSWORD}wrong`).then((r) => r.out.outcome),
    ]);
    expect(new Set(outcomes)).toEqual(new Set(['INVALID_CREDENTIALS']));
  });
});
