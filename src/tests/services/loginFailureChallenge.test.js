/**
 * 失败触发的人机挑战闸门（登录防爆破收口）
 *
 * 被测对象：services/loginChallenge.isChallengeRequired 与 authService 登录前置层的闸门。
 * 守护的不变式：
 *   A. 同一用户名连续失败达阈值后，登录必须先过人机验证——即使验证码静态开关是关的；
 *      被闸门拦下的尝试**不推进失败计数**，于是"凭连续失败把已知账户传入 10 分钟锁定"
 *      这条可用性 DoS 路径不再通：无验证码的一方推不到 MAX_FAILED_LOGINS（锁阈值不可达）。
 *   B. 判据与"账户是否存在"无关：不存在的用户名与存在的用户名拿到同一个对外错误码。
 *   C. 判据读不到时 fail-closed（要求挑战），而不是静默放行。
 *   D. 粘滞（2026-11-04 渗透测试后补）：失败计数窗滑走后，闸门拦下的痕迹
 *      （login_captcha_rejected 审计行）在更长的粘滞窗内仍要求挑战——否则攻击者按
 *      「3 次猜测 + 等窗口」可持续枚举；成功登录即清零（账户主人过一次人机验证即可恢复）。
 * 可证伪性：闸门改成"只在静态开关开启时生效" ⇒ A 组红；判据改成读 User.failedLoginCount
 * ⇒ B 组红（不存在的用户名永远不触发）；catch 改成 return false ⇒ C 组红；
 * 粘滞判据删掉或改成读失败行 ⇒ D 组红（出窗后 401 口令校验恢复，枚举节奏复活）。
 * 统计口径：判据数的是 AuditLog 里的 login_failed/auth_failed（与 securityAlert.checkBruteForce
 * 同一批动作），所以用例可以直接播种审计行来表达"连续失败"，不必跑满十次 bcrypt。
 */

const mongoose = require('mongoose');

jest.mock('../../services/securityAlert', () => ({
  checkBruteForce: jest.fn().mockResolvedValue(undefined),
  checkUnusualTime: jest.fn().mockResolvedValue(false),
}));
jest.mock('../../services/captchaService', () => ({ verify: jest.fn() }));

const { verify: verifyCaptcha } = require('../../services/captchaService');
const {
  isChallengeRequired,
  CHALLENGE_AFTER_FAILURES,
  CHALLENGE_WINDOW_MS,
  CHALLENGE_STICKY_WINDOW_MS,
} = require('../../services/loginChallenge');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();
const TAG = `lc${Date.now().toString(36)}`;

const ctx = {
  ip: '127.0.0.1',
  userAgent: 'test-agent',
  fingerprint: 'fp-challenge',
  method: 'POST',
  path: '/api/auth/login',
  req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
};

describe('失败触发的人机挑战闸门', () => {
  let User;
  let AuditLog;
  let authService;
  const ids = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    require('../../models/Role');
    AuditLog = require('../../models/AuditLog');
    authService = require('../../services/authService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      if (ids.length) await User.deleteMany({ _id: { $in: ids } });
      await mongoose.connection
        .collection('auditlogs')
        .deleteMany({ username: new RegExp(TAG) })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    verifyCaptcha.mockReset();
    verifyCaptcha.mockResolvedValue(false);
  });

  const makeUser = async (suffix) => {
    const user = await User.create({
      username: `${TAG}${suffix}`,
      email: `${TAG}${suffix}@example.com`,
      password: PASSWORD,
    });
    ids.push(user._id);
    return user;
  };

  /** 直接播种失败审计行（判据的输入口径），避免为了凑阈值反复跑 bcrypt */
  const seedFailures = async (username, count, timestamp) => {
    for (let i = 0; i < count; i += 1) {
      await AuditLog.create({
        action: 'login_failed',
        category: 'auth',
        username,
        ip: '127.0.0.1',
        success: false,
        riskLevel: 'medium',
        ...(timestamp ? { timestamp } : {}),
      });
    }
  };

  /** 直接播种闸门拦下的痕迹行（粘滞判据的输入口径），形态与 recordCaptchaRejected 落库一致 */
  const seedGateBlocked = async (username, count = 1, timestamp) => {
    for (let i = 0; i < count; i += 1) {
      await AuditLog.create({
        action: 'login_captcha_rejected',
        category: 'auth',
        username,
        ip: '127.0.0.1',
        success: false,
        riskLevel: 'medium',
        reason: 'challenge_required',
        ...(timestamp ? { timestamp } : {}),
      });
    }
  };

  const readBack = (id) => User.findById(id).select('+failedLoginCount +lockUntil');

  const login = (username, password) => authService.loginUser({ username, password }, ctx);

  test('A：阈值内是统一 401，越阈后要验证码，且闸门拦下的尝试不推进失败计数', async () => {
    const user = await makeUser('a');
    for (let i = 1; i <= CHALLENGE_AFTER_FAILURES; i += 1) {
      const r = await login(user.username, `${PASSWORD}wrong`);
      expect(r.outcome).toBe('INVALID_CREDENTIALS');
    }
    let after = await readBack(user._id);
    expect(after.failedLoginCount).toBe(CHALLENGE_AFTER_FAILURES);
    expect(after.lockUntil).toBeFalsy();

    const gated = await login(user.username, `${PASSWORD}wrong`);
    expect(gated.outcome).toBe('CAPTCHA_INVALID');
    after = await readBack(user._id);
    // 计数停在阈值：无验证码的一方推不到 MAX_FAILED_LOGINS ⇒ 锁窗口不可被廉价触发
    expect(after.failedLoginCount).toBe(CHALLENGE_AFTER_FAILURES);
    expect(after.lockUntil).toBeFalsy();
  });

  test('A：携带有效验证码时闸门放行，真实失败照常计数', async () => {
    const user = await makeUser('b');
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);
    verifyCaptcha.mockResolvedValue(true);

    const r = await login(user.username, `${PASSWORD}wrong`);
    expect(verifyCaptcha).toHaveBeenCalledTimes(1);
    expect(r.outcome).toBe('INVALID_CREDENTIALS');
    const after = await readBack(user._id);
    expect(after.failedLoginCount).toBe(1);
  });

  test('连续失败的起点是最近一次成功登录：成功之后再错一次不再要验证码', async () => {
    const username = `${TAG}streak`;
    await seedFailures(username, CHALLENGE_AFTER_FAILURES);
    expect(await isChallengeRequired(username)).toBe(true);

    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      username,
      ip: '127.0.0.1',
      success: true,
      riskLevel: 'low',
    });
    expect(await isChallengeRequired(username)).toBe(false);

    await seedFailures(username, CHALLENGE_AFTER_FAILURES);
    expect(await isChallengeRequired(username)).toBe(true);
  });

  test('B：不存在的用户名与存在的用户名同一对外口径（无存在性预言机）', async () => {
    const ghost = `${TAG}ghost`;
    const user = await makeUser('c');
    await seedFailures(ghost, CHALLENGE_AFTER_FAILURES);
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);

    const [ghostResult, userResult] = await Promise.all([
      login(ghost, `${PASSWORD}wrong`),
      login(user.username, `${PASSWORD}wrong`),
    ]);
    expect(ghostResult.outcome).toBe('CAPTCHA_INVALID');
    expect(userResult.outcome).toBe(ghostResult.outcome);
  });

  test('B：窗口外的失败不计入（连续失败只在判据窗口内累计）', async () => {
    const username = `${TAG}old`;
    const stale = new Date(Date.now() - 60 * 60 * 1000);
    await seedFailures(username, CHALLENGE_AFTER_FAILURES + 2, stale);
    expect(await isChallengeRequired(username)).toBe(false);
  });

  test('C：判据读不到时 fail-closed（要求挑战，而不是静默放行）', async () => {
    const user = await makeUser('d');
    // 故障注入按真实 Query 的形状返回"可链式、await 时 reject"的对象：
    // 直接 mockRejectedValue 会让 .collation 先抛 TypeError，且那个没人接的
    // rejected Promise 会被 Jest 记成 unhandled rejection（见同族用例的注记）。
    const rejected = Promise.reject(new Error('db transient down'));
    rejected.catch(() => {});
    const spy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockImplementation(() => ({ collation: () => rejected }));
    try {
      const r = await login(user.username, PASSWORD);
      expect(r.outcome).toBe('CAPTCHA_INVALID');
    } finally {
      spy.mockRestore();
    }
  });

  test('D：粘滞——失败行滑出计数窗后，闸门拦下的痕迹仍要求挑战；成功登录清零', async () => {
    const username = `${TAG}sticky`;
    // 失败行整体落在计数窗（15 分钟）之外：单看失败判据不触发——这正是被观测到的衰减形态
    const outsideWindow = new Date(Date.now() - (CHALLENGE_WINDOW_MS + 60 * 1000));
    await seedFailures(username, CHALLENGE_AFTER_FAILURES, outsideWindow);
    expect(await isChallengeRequired(username)).toBe(false);

    // 闸门拦下过一次（攻击者无验证码继续试）⇒ 粘滞生效，口令校验不再恢复
    await seedGateBlocked(username, 1);
    expect(await isChallengeRequired(username)).toBe(true);

    // 成功登录即清零：账户主人过一次人机验证后回到常规判据（粘滞不跟踪到下一次登录之后）
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      username,
      ip: '127.0.0.1',
      success: true,
      riskLevel: 'low',
    });
    expect(await isChallengeRequired(username)).toBe(false);

    // 清零后再被拦 → 重新粘滞（粘滞以"最近一次成功登录"为清零点，不是一次性烙印）
    await seedGateBlocked(username, 1);
    expect(await isChallengeRequired(username)).toBe(true);
  });

  test('D：粘滞窗外的拦下行不触发（静默满窗后回到失败计数判据）', async () => {
    const username = `${TAG}stickyold`;
    const stale = new Date(Date.now() - (CHALLENGE_STICKY_WINDOW_MS + 60 * 1000));
    await seedGateBlocked(username, 3, stale);
    expect(await isChallengeRequired(username)).toBe(false);
  });

  test('D：粘滞不清算成功登录之后的账——成功点之后的失败行仍按原判据计数', async () => {
    // 成功登录落在粘滞窗与计数窗之内：粘滞判据以成功点为清零点，
    // 成功后的新失败仍由原失败判据负责（两条判据互不替代）
    const username = `${TAG}stickyfresh`;
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      username,
      ip: '127.0.0.1',
      success: true,
      riskLevel: 'low',
      timestamp: new Date(Date.now() - 2 * 60 * 1000),
    });
    await seedFailures(username, CHALLENGE_AFTER_FAILURES - 1);
    expect(await isChallengeRequired(username)).toBe(false);
  });
});
