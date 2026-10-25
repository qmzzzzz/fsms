/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：认证链路的**关键审计**是否真的"先落库、后发令牌"，以及
 *   `/api/auth/login`、`/api/auth/refresh` 从全局审计排除后是否仍有替代留痕。
 *
 * 缺陷形状（修复前实测，审计报告 P2 两项）：
 *   1) 登录成功审计 `AuditLog.recordLogin(...).catch(...)` **不 await**，
 *      令牌紧接着就返回。进程在写库完成前重启 ⇒ "谁登录成功过"永久缺失，
 *      而客户端已拿到可用令牌。更糟的是**不对称**：登录失败审计是 await 的
 *      （login_failed 是爆破检测的唯一数据源），于是取证链只缺成功那一半。
 *   2) `/api/auth/refresh` 在全局审计中间件里被排除（`excludePaths`），
 *      而排除理由写的是"刷新走 recordRefreshAudit"——当时并不存在这个函数。
 *      轮换/重放/强制吊销因此零审计，只剩 logger.warn。
 *
 * 守护的不变式：
 *   A. 登录成功的审计 promise 未 settle 时，`loginUser` 不得 resolve（不得发令牌）；
 *   B. 刷新成功的审计 promise 未 settle 时，`refreshSession` 不得 resolve；
 *   C. 刷新成功写 `auth_refresh`（success=true, riskLevel=low）；
 *   D. 重放写 `auth_refresh_failed`（success=false, riskLevel=high,
 *      riskFactors 含 refresh_token_replay, reason=REPLAYED）。
 *
 * 可证伪性（每条都对着一个单点变异）：
 *   - 把 `await awaitAuditWrite(...)` 改回 `void ... .catch(...)`（fire-and-forget）
 *     ⇒ A / B 转红（promise 立刻 resolve）；
 *   - 删掉 `recordRefreshAudit` 调用 ⇒ C / D 转红（查不到审计文档）；
 *   - 把重放的 riskLevel 从 high 降为 medium ⇒ D 转红；
 *   - 只 await 不写（把 create 换成 no-op）⇒ C / D 转红。
 *   A/B 的"未 settle"断言前面都先等一个**正对照**（spy 已被调用），否则
 *   "还没走到审计点"会被误判成"await 生效"（假绿）。
 * ──────────────────────────────────────────────────────────────────────────
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { waitFor, flushEventLoop } = require('../helpers/waitFor');

describe('认证关键审计：先落库后发令牌 + 刷新链路替代留痕', () => {
  let User;
  let AuditLog;
  let TokenBlacklist;
  let authService;
  let sessionService;

  const stamp = `raf${Date.now().toString(36)}`;
  const PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    TokenBlacklist = require('../../models/TokenBlacklist');
    const Role = require('../../models/Role');
    const exists = await Role.findOne({ code: 'GUEST' });
    if (!exists) {
      await Role.create({ name: '访客', code: 'GUEST', level: 1 });
    }
    authService = require('../../services/authService');
    sessionService = require('../../services/sessionService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await AuditLog.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const makeUser = (suffix) =>
    User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
    });

  const defaultCtx = (overrides = {}) => ({
    ip: '127.0.0.1',
    userAgent: 'jest-agent',
    fingerprint: 'fp-jest',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'jest-agent' }, ip: '127.0.0.1', connection: {} },
    ...overrides,
  });

  /** 造一条带真实设备会话的 refresh 令牌（无 sid 的串会被直接拒绝，走不到审计点） */
  const makeRefreshToken = async (user, sid) => {
    await sessionService.createSession({
      userId: user._id,
      req: { ip: '127.0.0.1', get: () => 'jest-agent' },
      sid,
    });
    return jwt.sign(
      {
        userId: String(user._id),
        type: 'refresh',
        tokenVersion: user.tokenVersion ?? 0,
        jti: crypto.randomUUID(),
        sid,
      },
      require('../../config').jwt.refreshSecret,
      { expiresIn: '7d' }
    );
  };

  // ===== A. 登录成功：审计未 settle ⇒ 不得返回令牌 =====

  test('A. 登录成功审计未落库前 loginUser 不得 resolve（fire-and-forget 会立刻 resolve）', async () => {
    const user = await makeUser('login1');
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const spy = jest.spyOn(AuditLog, 'recordLogin').mockImplementation(() => gate);

    let settled = false;
    const pending = authService
      .loginUser({ username: user.username, password: PASSWORD }, defaultCtx())
      .then((result) => {
        settled = true;
        return result;
      });

    // 正对照：必须**确实走到**了那次审计调用，否则"未 settle"毫无意义
    expect(await waitFor(() => spy.mock.calls.length === 1, { label: '登录审计已发起' })).toBe(
      true
    );
    // 再给足若干轮事件循环：fire-and-forget 下此刻早已 resolve
    await flushEventLoop(8);
    expect(settled).toBe(false);

    release();
    const result = await pending;
    expect(result.outcome).toBe('OK');
    expect(result.token).toBeTruthy();
  });

  // ===== B/C. 刷新成功：先落库后返回，且留痕 auth_refresh =====

  test('B. 刷新成功审计未落库前 refreshSession 不得 resolve', async () => {
    const user = await makeUser('refresh1');
    const token = await makeRefreshToken(user, crypto.randomUUID());

    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const spy = jest.spyOn(AuditLog, 'create').mockImplementation(() => gate);

    let settled = false;
    const pending = authService.refreshSession(token, defaultCtx()).then((result) => {
      settled = true;
      return result;
    });

    expect(await waitFor(() => spy.mock.calls.length === 1, { label: '刷新审计已发起' })).toBe(
      true
    );
    await flushEventLoop(8);
    expect(settled).toBe(false);

    release();
    const result = await pending;
    expect(result.outcome).toBe('OK');
    expect(result.token).toBeTruthy();
  });

  test('C. 刷新成功留下 auth_refresh（success=true / riskLevel=low / 带 sessionId）', async () => {
    const user = await makeUser('refresh2');
    const sid = crypto.randomUUID();
    const token = await makeRefreshToken(user, sid);

    const result = await authService.refreshSession(token, defaultCtx());
    expect(result.outcome).toBe('OK');

    const doc = await AuditLog.findOne({ username: user.username, action: 'auth_refresh' }).lean();
    expect(doc).toBeTruthy();
    expect(doc.success).toBe(true);
    expect(doc.riskLevel).toBe('low');
    expect(doc.sessionId).toBe(sid);
  });

  // ===== D. 重放：必须留痕为高危失败事件 =====

  test('D. 重放留下 auth_refresh_failed（success=false / high / refresh_token_replay / REPLAYED）', async () => {
    const user = await makeUser('replay1');
    const token = await makeRefreshToken(user, crypto.randomUUID());

    // 首次刷新消费掉旧串
    const first = await authService.refreshSession(token, defaultCtx());
    expect(first.outcome).toBe('OK');

    // 10 秒宽限窗口内的二次使用是 CONCURRENT（并发轮换），要拨到窗口外才是真重放
    await TokenBlacklist.updateOne(
      { tokenHash: crypto.createHash('sha256').update(token).digest('hex') },
      { $set: { createdAt: new Date(Date.now() - 60_000) } }
    );

    const second = await authService.refreshSession(token, defaultCtx());
    expect(second.outcome).toBe('REPLAYED');

    const doc = await AuditLog.findOne({
      username: user.username,
      action: 'auth_refresh_failed',
    }).lean();
    expect(doc).toBeTruthy();
    expect(doc.success).toBe(false);
    expect(doc.riskLevel).toBe('high');
    expect(doc.reason).toBe('REPLAYED');
    expect(doc.riskFactors).toContain('refresh_token_replay');
  });
});
