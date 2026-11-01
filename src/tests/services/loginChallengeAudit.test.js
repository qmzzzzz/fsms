/**
 * 审计二-3「失败尝试是否留痕」——裁决取 B（落库留痕）：前置人机层拦下的登录尝试
 *
 * 被测对象：`services/loginChallenge.recordCaptchaRejected` 与
 * `authService.resolveLoginPassword` 的验证码拒绝分支。
 *
 * 原缺口（ADR-015「后果与局限」末条自述）：闸门拦下的尝试**零留痕**——被拦下的人机验证
 * 失败既没有 `login_failed` 行、也不写任何别的东西，于是「谁在反复撞这道闸、撞的是哪个用户名、
 * 来自哪个 IP」在审计库里答不上来；而这条路径恰恰是自动化爆破被拦住的地方（最该看见的地方）。
 *
 * 守护的不变式：
 *   A. 被拦下的尝试必须留一条**可查询**的审计行（action=login_captcha_rejected，带
 *      username/ip/userAgent/fingerprint/reason），且 reason 能分辨拦下它的是哪一层
 *      （静态开关 / 失败触发的挑战）。
 *   B. 这条行**不推进任何失败计数**：既不在 `loginChallenge.FAILURE_ACTIONS` 里，也不进
 *      `securityAlert.checkBruteForce` 的统计（那里同样只数 login_failed/auth_failed）。
 *      否则「被拦下」自我维持：被拦得越多、闸门越不可能关；且闸门拒绝会被误报成口令爆破。
 *   C. 留痕不改变对外口径：仍是 400 CAPTCHA_INVALID；不存在的用户名与存在的用户名写同一形态的行
 *      （无存在性预言机）。
 *   D. 审计写失败不阻断拒绝（400 照旧）且不静默：走 `onAuditWriteFailure`。
 *
 * 可证伪性（逐条反向对照，任一实现退化必有一条转红）：
 *   · 删掉调用 ⇒ ① 读不回那条行；
 *   · 动作名换成 'login_failed' ⇒ ② B 组红（计数被推进、闸门自我维持）；
 *   · recordCaptchaRejected 的 catch 换成 `.catch(() => {})` ⇒ ④ 红（无 audit_write_failed{high}）；
 *   · 去掉 username 形态闸 ⇒ ⑤ 组红（畸形请求也产噪声行）。
 */

const mongoose = require('mongoose');

jest.mock('../../services/securityAlert', () => ({
  checkBruteForce: jest.fn().mockResolvedValue(undefined),
  checkUnusualTime: jest.fn().mockResolvedValue(false),
}));
jest.mock('../../services/captchaService', () => ({ verify: jest.fn() }));

const { verify: verifyCaptcha } = require('../../services/captchaService');
const { checkBruteForce } = require('../../services/securityAlert');
const {
  isChallengeRequired,
  recordCaptchaRejected,
  CHALLENGE_AFTER_FAILURES,
  CAPTCHA_REJECTED_ACTION,
  CAPTCHA_TRIGGERS,
  FAILURE_ACTIONS,
} = require('../../services/loginChallenge');
const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
const metrics = require('../../utils/metrics');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();
const TAG = `lcr${Date.now().toString(36)}`;

const ctx = {
  ip: '127.0.0.1',
  userAgent: 'test-agent',
  fingerprint: 'fp-captcha-trail',
  method: 'POST',
  path: '/api/auth/login',
  req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
};

describe('闸门拦下的登录尝试落库留痕（审计二-3 取 B）', () => {
  let User;
  let AuditLog;
  let SystemConfig;
  let authService;
  const ids = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    ({ SystemConfig } = require('../../models'));
    require('../../models/Role');
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
    checkBruteForce.mockClear();
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

  /** 直接播种失败审计行（判据的输入口径），不必为了凑阈值反复跑 bcrypt */
  const seedFailures = async (username, count) => {
    for (let i = 0; i < count; i += 1) {
      await AuditLog.create({
        action: 'login_failed',
        category: 'auth',
        username,
        ip: ctx.ip,
        success: false,
        riskLevel: 'medium',
      });
    }
  };

  const login = (username, password) => authService.loginUser({ username, password }, ctx);
  const rowsOf = (username) => AuditLog.find({ action: CAPTCHA_REJECTED_ACTION, username }).lean();
  /** 判据口径的原始计数（FAILURE_ACTIONS 全集，不是只看 login_failed） */
  const failureRows = (username) =>
    AuditLog.countDocuments({ username, action: { $in: FAILURE_ACTIONS } });
  const readBack = (id) => User.findById(id).select('+failedLoginCount +lockUntil');

  test('登记面：动作在白名单内、且不在任何失败计数清单里', () => {
    expect(AUDIT_LOG_ACTIONS).toContain(CAPTCHA_REJECTED_ACTION);
    expect(FAILURE_ACTIONS).not.toContain(CAPTCHA_REJECTED_ACTION);
    // 反向对照：白名单里确实还留着被计数的动作（否则上面那条恒真）
    expect(AUDIT_LOG_ACTIONS).toContain('login_failed');
    expect(FAILURE_ACTIONS).toContain('login_failed');
  });

  test('① 挑战闸门拦下：写一条 reason=challenge_required 的行，且失败计数停在阈值', async () => {
    const user = await makeUser('gate');
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);
    expect(await isChallengeRequired(user.username)).toBe(true);

    const result = await login(user.username, PASSWORD);
    expect(result.outcome).toBe('CAPTCHA_INVALID');

    const rows = await rowsOf(user.username);
    expect(rows).toHaveLength(1);
    const [row] = rows;
    expect(row.category).toBe('auth');
    expect(row.success).toBe(false);
    expect(row.riskLevel).toBe('medium');
    expect(row.ip).toBe(ctx.ip);
    expect(row.userAgent).toBe(ctx.userAgent);
    expect(row.fingerprint).toBe(ctx.fingerprint);
    expect(row.reason).toBe(CAPTCHA_TRIGGERS.CHALLENGE);
    expect(row.riskFactors).toEqual(['captcha_absent']);

    // B：拦下的尝试不推进任何失败计数（判据口径的全部动作）、不触发暴力破解检测
    expect(await failureRows(user.username)).toBe(CHALLENGE_AFTER_FAILURES);
    const after = await readBack(user._id);
    // 本例的失败行是播种的，User.failedLoginCount 本就为 0 ⇒ 拦下后仍必须是 0（一次都没推进）
    expect(after.failedLoginCount || 0).toBe(0);
    expect(after.lockUntil).toBeFalsy();
    expect(checkBruteForce).not.toHaveBeenCalled();
  });

  test('② 静态验证码开关拦下：reason=captcha_switch，并区分「没带验证码」与「带错」', async () => {
    const user = await makeUser('switch');
    const spy = jest.spyOn(SystemConfig, 'captchaSwitch').mockResolvedValue(true);
    try {
      expect((await login(user.username, PASSWORD)).outcome).toBe('CAPTCHA_INVALID');
      expect(
        (
          await authService.loginUser(
            { username: user.username, password: PASSWORD, captchaId: 'cid', captchaText: 'abc' },
            ctx
          )
        ).outcome
      ).toBe('CAPTCHA_INVALID');
    } finally {
      spy.mockRestore();
    }

    const rows = await rowsOf(user.username);
    expect(rows).toHaveLength(2);
    rows.forEach((row) => expect(row.reason).toBe(CAPTCHA_TRIGGERS.SWITCH));
    expect(rows.map((r) => r.riskFactors.join()).sort()).toEqual([
      'captcha_absent',
      'captcha_mismatch',
    ]);
    // 开关常开的部署同样不推进计数（否则正常用户连点两次验证码就被计入爆破）
    expect(await failureRows(user.username)).toBe(0);
    expect(checkBruteForce).not.toHaveBeenCalled();
  });

  test('③ 不存在的用户名同样留痕、同一对外口径（无存在性预言机）', async () => {
    const ghost = `${TAG}ghost`;
    const user = await makeUser('real');
    await seedFailures(ghost, CHALLENGE_AFTER_FAILURES);
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);

    const [ghostResult, userResult] = await Promise.all([
      login(ghost, PASSWORD),
      login(user.username, PASSWORD),
    ]);
    expect(ghostResult.outcome).toBe('CAPTCHA_INVALID');
    expect(userResult.outcome).toBe(ghostResult.outcome);

    const ghostRows = await rowsOf(ghost);
    expect(ghostRows).toHaveLength(1);
    expect(ghostRows[0].reason).toBe(CAPTCHA_TRIGGERS.CHALLENGE);
    expect(ghostRows[0].username).toBe(ghost);
  });

  test('④ 审计写失败：仍拒绝（400 口径不变）且按 high 档记账，不静默', async () => {
    const user = await makeUser('auditdown');
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);

    const createSpy = jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('mongo down'));
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert');
    try {
      const result = await login(user.username, PASSWORD);
      expect(result.outcome).toBe('CAPTCHA_INVALID');
      const alerts = alertSpy.mock.calls.filter((c) => c[0] === 'audit_write_failed');
      expect(alerts.length).toBeGreaterThan(0);
      expect(alerts.some((c) => c[1] === 'high')).toBe(true);
    } finally {
      createSpy.mockRestore();
      alertSpy.mockRestore();
    }
  });

  test('⑤ 畸形 username：不产噪声行、不抛（审计必填项不靠 ValidationError 兜底）', async () => {
    const probeIp = '203.0.113.77';
    const base = {
      ip: probeIp,
      userAgent: 'ua',
      fingerprint: 'fp',
      trigger: CAPTCHA_TRIGGERS.CHALLENGE,
    };
    const nullCount = await AuditLog.countDocuments({
      action: CAPTCHA_REJECTED_ACTION,
      ip: probeIp,
    });
    await expect(recordCaptchaRejected({ ...base, username: '' })).resolves.toBeNull();
    await expect(recordCaptchaRejected({ ...base, username: '   ' })).resolves.toBeNull();
    await expect(recordCaptchaRejected({ ...base, username: undefined })).resolves.toBeNull();
    await expect(
      recordCaptchaRejected({ ...base, username: { toString: () => 'x' } })
    ).resolves.toBeNull();
    expect(await AuditLog.countDocuments({ action: CAPTCHA_REJECTED_ACTION, ip: probeIp })).toBe(
      nullCount
    );
    // reason 是导出件的入参、schema 侧无清洗 ⇒ 只允许闭集里的值，其余一律归一成 unspecified
    await recordCaptchaRejected({
      ...base,
      username: `${TAG}inject`,
      trigger: 'attacker\u0000text',
    });
    const injected = await AuditLog.collection.findOne({
      action: CAPTCHA_REJECTED_ACTION,
      username: `${TAG}inject`,
    });
    expect(injected.reason).toBe('unspecified');
    // 对照：形态合法的用户名确实写得进去（证明上面不是"什么都不写"的假绿）
    await recordCaptchaRejected({ ...base, username: `${TAG}ok` });
    expect(await AuditLog.countDocuments({ action: CAPTCHA_REJECTED_ACTION, ip: probeIp })).toBe(
      nullCount + 2
    );
  });

  test('⑥ 请求方可控文本仍走 schema 单点闸（新写入点不自己发明清洗口径）', async () => {
    const username = `${TAG}raw`;
    await recordCaptchaRejected({
      username,
      ip: `9.9.9.9${'a'.repeat(200)}`,
      userAgent: `bad\nua${'x'.repeat(600)}`,
      fingerprint: null,
      trigger: CAPTCHA_TRIGGERS.SWITCH,
      captchaSubmitted: true,
    });
    const row = await AuditLog.collection.findOne({ action: CAPTCHA_REJECTED_ACTION, username });
    expect(row).not.toBeNull();
    expect(row.userAgent).not.toMatch(/[\n\r]/);
    expect(row.userAgent.length).toBeLessThanOrEqual(512);
    expect(row.ip.length).toBeLessThanOrEqual(64);
    expect(row.fingerprint).toBeNull();
  });
  test('⑦ 模型层同步抛（未就绪/CastError）：不外溢成 500，仍按 high 记账', async () => {
    const user = await makeUser('syncthrow');
    await seedFailures(user.username, CHALLENGE_AFTER_FAILURES);
    const createSpy = jest.spyOn(AuditLog, 'create').mockImplementation(() => {
      throw new Error('schema not ready');
    });
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert');
    try {
      const direct = await recordCaptchaRejected({
        username: `${TAG}sync`,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        trigger: CAPTCHA_TRIGGERS.SWITCH,
      });
      expect(direct).toBeNull();
      // 登录路径同样不得因此改口径：仍是 400，不是 500
      expect((await login(user.username, PASSWORD)).outcome).toBe('CAPTCHA_INVALID');
      const alerts = alertSpy.mock.calls.filter(
        (c) => c[0] === 'audit_write_failed' && c[1] === 'high'
      );
      expect(alerts.length).toBeGreaterThanOrEqual(2);
    } finally {
      createSpy.mockRestore();
      alertSpy.mockRestore();
    }
  });
});
