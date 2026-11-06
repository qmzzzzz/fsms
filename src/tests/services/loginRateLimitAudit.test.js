/**
 * 429 也要算「失败尝试」——限流拦下的登录尝试留痕并推进挑战闸。
 *
 * 原缺口：限流器在中间件层就返回 429，请求根本进不到 loginUser，于是被挡下的
 * 尝试既不落审计行、也不推进挑战判据。攻击者只需要把速度调到“刚好不锁账户”，
 * 就能用限流额度无成本地试口令，而防护看不到任何痕迹。
 *
 * 守护的不变式（任一退化必有一条转红）：
 *   A. 留痕形态可查：action=login_rate_limited，带 username/ip/userAgent/reason，
 *      reason 只能取闭集（login-ip / login-user / login-peer）；
 *   B. 同键去重（默认 60s）：否则每个 429 一行，攻击流量等于把审计库打爆；
 *   C. 记账户维度的尝试同样留痕（键按 username，不按 IP）；
 *   D. 审计写失败不抛、不影响 429 响应；
 *   E. 进 FAILURE_ACTIONS（推进挑战闸），但不进 lockUntil 计数（见 failureAndMfa）。
 */
const mongoose = require('mongoose');

const {
  recordLimitedAttempt,
  resetForTest,
  DEDUPE_TTL_MS,
} = require('../../services/loginRateLimitAudit');
const { FAILURE_ACTIONS, CAPTCHA_REJECTED_ACTION } = require('../../services/loginChallenge');

const TAG = `lrla${Date.now().toString(36)}`;

const fakeReq = (username, ip = '203.0.113.7') => ({
  body: username === undefined ? {} : { username },
  ip,
  socket: { remoteAddress: ip },
  connection: { remoteAddress: ip },
  app: { get: () => false }, // trust proxy 关：客户端身份取 socket 对端，不看 XFF
  get: (name) => (name === 'user-agent' ? 'ua-lrla' : undefined),
});

const { tick } = require('../helpers/pollTick');

const waitFor = async (fn, timeoutMs = 3000) => {
  const start = Date.now();
  for (;;) {
    const got = await fn();
    if (got) return got;
    if (Date.now() - start > timeoutMs) return null;
    await tick(25);
  }
};

describe('登录限流命中的记账（429 计入失败尝试）', () => {
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection
        .collection('auditlogs')
        .deleteMany({ username: new RegExp(TAG) })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    resetForTest();
    jest.restoreAllMocks();
  });

  test('A 留痕形态：action / reason / riskFactors / 级别', async () => {
    const username = `${TAG}-a`;
    expect(recordLimitedAttempt(fakeReq(username), 'login-ip')).toBe(true);
    const row = await waitFor(() => AuditLog.findOne({ username }).lean());
    expect(row).toBeTruthy();
    expect(row.action).toBe('login_rate_limited');
    expect(row.reason).toBe('login-ip');
    expect(row.riskLevel).toBe('medium');
    expect(row.success).toBe(false);
    expect(row.riskFactors).toContain('rate_limit_attempt');
  });

  test('B 同键去重：窗口内第二次不再写库', async () => {
    const username = `${TAG}-b`;
    expect(recordLimitedAttempt(fakeReq(username), 'login-user')).toBe(true);
    expect(recordLimitedAttempt(fakeReq(username), 'login-user')).toBe(false);
    await waitFor(() => AuditLog.findOne({ username }).lean());
    expect(await AuditLog.countDocuments({ username })).toBe(1);
  });

  test('C 换用户名是新键（账户维度不靠 IP 区分）', async () => {
    expect(recordLimitedAttempt(fakeReq(`${TAG}-c1`), 'login-user')).toBe(true);
    expect(recordLimitedAttempt(fakeReq(`${TAG}-c2`), 'login-user')).toBe(true);
    await waitFor(() => AuditLog.findOne({ username: `${TAG}-c2` }).lean());
    expect(await AuditLog.countDocuments({ username: `${TAG}-c1` })).toBe(1);
    expect(await AuditLog.countDocuments({ username: `${TAG}-c2` })).toBe(1);
  });

  test('A2 对端维度桶（login-peer）同样落闭集 reason', async () => {
    const username = `${TAG}-peer`;
    expect(recordLimitedAttempt(fakeReq(username), 'login-peer')).toBe(true);
    const row = await waitFor(() => AuditLog.findOne({ username }).lean());
    expect(row.reason).toBe('login-peer');
  });

  test('B2 去重窗口过期后同键重新记账', async () => {
    const username = `${TAG}-b2`;
    const base = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(base);
    expect(recordLimitedAttempt(fakeReq(username), 'login-ip')).toBe(true);
    expect(recordLimitedAttempt(fakeReq(username), 'login-ip')).toBe(false);
    spy.mockReturnValue(base + DEDUPE_TTL_MS + 1);
    expect(recordLimitedAttempt(fakeReq(username), 'login-ip')).toBe(true);
    spy.mockRestore();
    await waitFor(() => AuditLog.findOne({ username }).lean());
  });

  test('D 审计写失败不抛、不阻断 429', async () => {
    const username = `${TAG}-d`;
    jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('audit down'));
    expect(() => recordLimitedAttempt(fakeReq(username), 'login-ip')).not.toThrow();
    // 等的是 fire-and-forget 链的拒绝落定（create 已 mock，无真实 I/O）：
    // setImmediate 让步宏任务即可确定性结算，不需要也不允许固定 80ms 睡眠。
    await new Promise((resolve) => setImmediate(resolve));
    expect(await AuditLog.countDocuments({ username })).toBe(0);
  });

  test('E 进挑战判据但不自身触发挑战（口径分账）', () => {
    expect(FAILURE_ACTIONS).toContain('login_rate_limited');
    expect(FAILURE_ACTIONS).not.toContain('login_rate_limited_rejected');
    expect(CAPTCHA_REJECTED_ACTION).toBe('login_captcha_rejected');
    expect(FAILURE_ACTIONS).not.toContain(CAPTCHA_REJECTED_ACTION);
  });
});
