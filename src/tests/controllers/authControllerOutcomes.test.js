/**
 * authController 编排层 outcome 矩阵测试（单元测试，不依赖数据库）
 *
 * 背景：authController 分支覆盖率 64%（全仓最低），未覆盖分支几乎全部是
 * 「service 返回 outcome → switch 映射到 HTTP 响应」的编排分支。
 * 这些分支此前只在部分集成测试中被顺带触达（happy path），
 * 错误映射从未逐一验证过。
 *
 * 策略：mock 全部 service 依赖，直接调用控制器函数，
 * 让每个 outcome 分支都被真实执行并断言状态码/响应体/副作用（cookie、审计）。
 * 与 authCookies.test.js（supertest 集成）正交互补，不重复造数据库数据。
 *
 * 覆盖：
 * - register 5 个 outcome + 校验失败 + 成功下发 cookie（201）
 * - login 7 个 outcome + 成功
 * - refreshToken 10 个 outcome + service 抛异常兜底 401 + 成功轮换 cookie
 * - changePassword 8 个 outcome（含 REVOKE_FAILED 的 503 + 审计落库）
 * - updateProfile 5 个 outcome + 成功
 * - logout revokeFailed fail-closed（不清 cookie）/ 成功（清 cookie + 会话收敛）
 * - getMe 用户消失 / 成功聚合
 * - getSessionStatus 双令牌三态
 * - listSessions / revokeSession（自踢拦截、404 不区分存在性）/ revokeOtherSessions
 * - getCaptcha 服务不可用 / getCaptchaStatus DB 故障降级
 */

jest.mock('express-validator', () => ({
  validationResult: (req) => ({
    isEmpty: () => !req._invalid,
    array: () => req._errors || [{ msg: 'mock validation error' }],
  }),
}));

jest.mock('../../services/authService');
jest.mock('../../services/captchaService');
jest.mock('../../services/sessionService');
jest.mock('../../services/tokenService', () => ({
  isAccessTokenValid: jest.fn(),
  isRefreshTokenValid: jest.fn(),
}));
jest.mock('../../utils/permissionHelper', () => ({
  getUserPermissions: jest.fn(),
  getMenuTree: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  recordSensitiveAction: jest.fn(() => Promise.resolve()),
  record: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../utils/loginCipher', () => ({
  getPublicKeyInfo: jest.fn(() => ({ keyId: 'k1', publicKey: 'PUB' })),
}));
jest.mock('../../utils/fingerprint', () => ({
  computeFingerprint: jest.fn(() => 'fp-mock'),
}));
jest.mock('../../models', () => ({
  SystemConfig: {
    isLoginCaptchaEnabled: jest.fn(),
    isRegisterCaptchaEnabled: jest.fn(),
  },
}));
jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(async () => ({ type: 'all' })),
  checkPermission: jest.fn(() => (req, res, next) => next()),
  checkRole: jest.fn(() => (req, res, next) => next()),
}));

const authService = require('../../services/authService');
const captchaService = require('../../services/captchaService');
const sessionService = require('../../services/sessionService');
const tokenService = require('../../services/tokenService');
const permissionHelper = require('../../utils/permissionHelper');
const AuditLog = require('../../models/AuditLog');
const { SystemConfig } = require('../../models');

const controller = require('../../controllers/authController');

/** 构造可链式记录 status/json 的 res mock（ApiResponse 走 res.status(c).json(b)） */
const makeRes = () => {
  const res = {};
  res.statusCode = 200;
  res.status = jest.fn((c) => {
    res.statusCode = c;
    return res;
  });
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  res.cookie = jest.fn();
  res.clearCookie = jest.fn();
  res.headersSent = false;
  return res;
};

const makeReq = (over = {}) => ({
  body: {},
  params: {},
  query: {},
  ip: '127.0.0.1',
  method: 'POST',
  path: '/api/auth/unit',
  originalUrl: '/api/auth/unit',
  headers: {},
  get: jest.fn(() => 'jest-agent'),
  user: { userId: 'u-1', username: 'alice', sid: 'sid-cur' },
  ...over,
});

/**
 * 执行控制器并捕获内部错误：asyncHandler 以 .catch(next) 兜底，
 * 不传 next 时控制器异常会变成 unhandled rejection 被吞掉，
 * 表现为「res.body 为 undefined」而看不到真实错误。显式传 next 使错误显形。
 */
const invoke = async (fn, req, res) => {
  const next = jest.fn((e) => {
    if (e) {
      throw e;
    }
  });
  await fn(req, res, next);
  // asyncHandler 包了一层 Promise.resolve().then(fn)，res.json 的执行比
  // 控制器函数体返回晚一轮微任务：await 后必须再 flush 一次微任务队列，
  // 否则 res.body 尚未写入（本文件调试 1 小时的教训，勿删）
  await new Promise((resolve) => setImmediate(resolve));
  return res;
};

beforeEach(() => {
  jest.clearAllMocks();
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
describe('register outcome 矩阵', () => {
  test.each([
    ['CAPTCHA_INVALID', 400],
    ['ENC_INVALID', 400],
    ['WEAK', 400],
    ['DUPLICATE', 400],
  ])('outcome=%s 映射为 %i 且不下发 cookie', async (outcome, expectedStatus) => {
    authService.registerUser.mockResolvedValue({ outcome, message: 'x' });
    const res = makeRes();
    await invoke(controller.register, makeReq(), res);
    expect(res.status).toHaveBeenCalledWith(expectedStatus);
    expect(res.cookie).not.toHaveBeenCalled();
  });

  test('DUPLICATE 返回模糊文案，防用户名/邮箱枚举', async () => {
    authService.registerUser.mockResolvedValue({ outcome: 'DUPLICATE' });
    const res = makeRes();
    await invoke(controller.register, makeReq(), res);
    expect(res.body.message).toBe('注册信息无效或已被使用');
    expect(res.body.message).not.toContain('邮箱');
  });

  test('成功：201 + 下发两个 httpOnly cookie', async () => {
    authService.registerUser.mockResolvedValue({
      outcome: 'OK',
      token: 't1',
      refreshToken: 'r1',
      userId: 'u9',
      username: 'bob',
      email: 'b@x.io',
    });
    const res = makeRes();
    await invoke(controller.register, makeReq(), res);
    expect(res.statusCode).toBe(201);
    expect(res.cookie).toHaveBeenCalledTimes(2);
    expect(res.body.data.userId).toBe('u9');
  });

  test('校验失败：400 且不触达 service', async () => {
    const req = makeReq({ _invalid: true });
    const res = makeRes();
    await invoke(controller.register, req, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(authService.registerUser).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
describe('login outcome 矩阵', () => {
  test.each([
    ['CAPTCHA_INVALID', 400],
    ['ENC_INVALID', 400],
    ['INVALID_CREDENTIALS', 401],
    ['MFA_ATTEMPTS_EXCEEDED', 429],
    ['MFA_CODE_INVALID', 401],
  ])('outcome=%s 走 codeError/error 且不下发 cookie', async (outcome, expectedStatus) => {
    authService.loginUser.mockResolvedValue({ outcome });
    const res = makeRes();
    await invoke(controller.login, makeReq(), res);
    expect(res.statusCode).toBe(expectedStatus);
    expect(res.cookie).not.toHaveBeenCalled();
  });

  test('MFA_REQUIRED 返回 200 + mfaRequired 标记（非错误）', async () => {
    authService.loginUser.mockResolvedValue({ outcome: 'MFA_REQUIRED' });
    const res = makeRes();
    await invoke(controller.login, makeReq(), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.data.mfaRequired).toBe(true);
    expect(res.cookie).not.toHaveBeenCalled();
  });

  test('成功：下发 cookie 并回传 token/refreshToken/expires/user', async () => {
    authService.loginUser.mockResolvedValue({
      outcome: 'OK',
      token: 't1',
      refreshToken: 'r1',
      user: { username: 'alice' },
    });
    const res = makeRes();
    await invoke(controller.login, makeReq(), res);
    expect(res.cookie).toHaveBeenCalledTimes(2);
    expect(res.body.data.token).toBe('t1');
    expect(res.body.data.expires).toBeDefined();
  });

  test('登录上下文携带 ip/userAgent/fingerprint（风控依赖）', async () => {
    authService.loginUser.mockResolvedValue({ outcome: 'OK', token: 't', refreshToken: 'r' });
    await invoke(controller.login, makeReq(), makeRes());
    const ctx = authService.loginUser.mock.calls[0][1];
    expect(ctx.ip).toBe('127.0.0.1');
    expect(ctx.fingerprint).toBe('fp-mock');
    expect(ctx.method).toBe('POST');
  });
});

// ---------------------------------------------------------------------------
// refreshToken
// ---------------------------------------------------------------------------
describe('refreshToken outcome 矩阵', () => {
  test.each([
    ['MISSING', 400, '缺少刷新令牌'],
    ['INVALID', 401, '无效的刷新令牌'],
    ['IP_DENIED', 401, '刷新令牌已失效，请重新登录'],
    ['REPLAYED', 401, '刷新令牌已失效，请重新登录'],
    ['PASSWORD_CHANGED', 401, '密码已修改，请重新登录'],
    ['VERSION_MISMATCH', 401, '会话已失效，请重新登录'],
    ['SESSION_REVOKED', 401, '该设备的登录已被终止，请重新登录'],
    ['EXPIRED', 401, '刷新令牌已过期，请重新登录'],
    ['BLACKLIST_UNAVAILABLE', 503, '安全服务暂不可用，请稍后重试'],
    ['SESSION_UNAVAILABLE', 503, '安全服务暂不可用，请稍后重试'],
    ['REVOKE_UNAVAILABLE', 503, '安全服务暂不可用，请稍后重试'],
  ])('outcome=%s → %i', async (outcome, expectedStatus, expectedMessage) => {
    authService.refreshSession.mockResolvedValue({ outcome });
    const res = makeRes();
    await invoke(controller.refreshToken, makeReq(), res);
    expect(res.statusCode).toBe(expectedStatus);
    expect(res.cookie).not.toHaveBeenCalled();
    if (expectedMessage) expect(res.body.message).toBe(expectedMessage);
  });

  test('service 抛未预期异常（含 DB 故障）：401 且不泄露内部错误', async () => {
    authService.refreshSession.mockRejectedValue(new Error('ECONNREFUSED mongo:27017'));
    const res = makeRes();
    await invoke(controller.refreshToken, makeReq(), res);
    expect(res.statusCode).toBe(401);
    expect(res.body.message).toBe('无效的刷新令牌');
    expect(JSON.stringify(res.body)).not.toContain('ECONNREFUSED');
  });

  test('成功：cookie 轮换 + 响应体保留 tokens 字段（兼容契约）', async () => {
    authService.refreshSession.mockResolvedValue({
      outcome: 'OK',
      token: 't2',
      refreshToken: 'r2',
    });
    const res = makeRes();
    await invoke(controller.refreshToken, makeReq({ body: { refreshToken: 'r-old' } }), res);
    expect(res.cookie).toHaveBeenCalledTimes(2);
    expect(res.body.data.refreshToken).toBe('r2');
  });

  test('请求体缺 refreshToken 时回退读 refresh_token cookie', async () => {
    authService.refreshSession.mockResolvedValue({ outcome: 'OK', token: 't', refreshToken: 'r' });
    const req = makeReq({
      headers: { cookie: 'refresh_token=cookie-r; access_token=a' },
    });
    await invoke(controller.refreshToken, req, makeRes());
    expect(authService.refreshSession).toHaveBeenCalledWith('cookie-r', expect.anything());
  });
});

// ---------------------------------------------------------------------------
// changePassword
// ---------------------------------------------------------------------------
describe('changePassword outcome 矩阵', () => {
  test.each([
    ['ENC_INVALID', 400],
    ['MISSING', 400],
    ['WEAK', 400],
    ['USER_NOT_FOUND', 401],
    ['CURRENT_WRONG', 400],
    ['SAME_PASSWORD', 400],
  ])('outcome=%s → %i', async (outcome, expectedStatus) => {
    authService.changeUserPassword.mockResolvedValue({ outcome, message: 'm' });
    const res = makeRes();
    await invoke(controller.changePassword, makeReq(), res);
    expect(res.status).toHaveBeenCalledWith(expectedStatus);
    expect(AuditLog.recordSensitiveAction).not.toHaveBeenCalled();
  });

  test('REVOKE_FAILED：密码已改但吊销失败 → 503 且如实落审计（fail-safe 口径）', async () => {
    authService.changeUserPassword.mockResolvedValue({
      outcome: 'REVOKE_FAILED',
      username: 'alice',
    });
    const res = makeRes();
    await invoke(controller.changePassword, makeReq(), res);
    expect(res.statusCode).toBe(503);
    expect(res.body.message).toContain('会话吊销服务暂不可用');
    // 审计以 503 状态如实记录，而非伪装成功
    expect(AuditLog.recordSensitiveAction).toHaveBeenCalledWith(
      'u-1',
      'alice',
      'change_password',
      'auth',
      expect.anything(),
      expect.objectContaining({ statusCode: 503 })
    );
  });

  test('成功：审计落库（fire-and-forget）+ 200', async () => {
    authService.changeUserPassword.mockResolvedValue({ outcome: 'OK', username: 'alice' });
    const res = makeRes();
    await invoke(controller.changePassword, makeReq(), res);
    expect(res.statusCode).toBe(200);
    expect(AuditLog.recordSensitiveAction).toHaveBeenCalledWith(
      'u-1',
      'alice',
      'change_password',
      'auth',
      expect.anything(),
      expect.anything()
    );
  });
});

// ---------------------------------------------------------------------------
// updateProfile
// ---------------------------------------------------------------------------
describe('updateProfile outcome 矩阵', () => {
  test.each([
    ['NOT_FOUND', 404],
    ['INVALID_PHONE', 400],
    ['INVALID_EMAIL', 400],
    ['EMAIL_TAKEN', 400],
    ['INVALID_AVATAR', 400],
  ])('outcome=%s → %i', async (outcome, expectedStatus) => {
    authService.updateUserProfile.mockResolvedValue({ outcome });
    const res = makeRes();
    await invoke(controller.updateProfile, makeReq(), res);
    expect(res.status).toHaveBeenCalledWith(expectedStatus);
  });

  test('成功返回 profile', async () => {
    authService.updateUserProfile.mockResolvedValue({
      outcome: 'OK',
      profile: { realName: 'Alice' },
    });
    const res = makeRes();
    await invoke(controller.updateProfile, makeReq(), res);
    expect(res.body.data.realName).toBe('Alice');
  });
});

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------
describe('logout fail-closed 与会话收敛', () => {
  test('revokeFailed=true：503 且不清 cookie（保留重试能力，防 fail-open）', async () => {
    authService.revokeTokensOnLogout.mockResolvedValue({ revokeFailed: true });
    const res = makeRes();
    await invoke(controller.logout, makeReq(), res);
    expect(res.statusCode).toBe(503);
    expect(res.body.data?.code || res.body.message).toBeDefined();
    expect(res.clearCookie).not.toHaveBeenCalled();
  });

  test('成功：清两个 cookie + 按 sid 收敛会话', async () => {
    authService.revokeTokensOnLogout.mockResolvedValue({ revokeFailed: false });
    const res = makeRes();
    await invoke(controller.logout, makeReq(), res);
    expect(res.clearCookie).toHaveBeenCalledTimes(2);
    expect(sessionService.revokeSessionSafe).toHaveBeenCalledWith(
      expect.objectContaining({ sid: 'sid-cur', userId: 'u-1', reason: 'logout' })
    );
  });

  test('令牌无 sid（旧令牌）时跳过会话收敛，不报错', async () => {
    authService.revokeTokensOnLogout.mockResolvedValue({ revokeFailed: false });
    const res = makeRes();
    await invoke(controller.logout, makeReq({ user: { userId: 'u-1', username: 'a', sid: null } }), res);
    expect(res.statusCode).toBe(200);
    expect(sessionService.revokeSessionSafe).not.toHaveBeenCalled();
  });

  test('token 来源优先 Bearer 头，回退 access_token cookie', async () => {
    authService.revokeTokensOnLogout.mockResolvedValue({ revokeFailed: false });
    await invoke(controller.logout, makeReq({ headers: { authorization: 'Bearer hdr-token' } }), makeRes());
    expect(authService.revokeTokensOnLogout).toHaveBeenCalledWith(
      expect.objectContaining({ accessToken: 'hdr-token' })
    );

    authService.revokeTokensOnLogout.mockClear();
    await invoke(controller.logout, makeReq({ headers: { cookie: 'access_token=ck-token' } }), makeRes());
    expect(authService.revokeTokensOnLogout).toHaveBeenCalledWith(
      expect.objectContaining({ accessToken: 'ck-token' })
    );
  });
});

// ---------------------------------------------------------------------------
// getMe / getSessionStatus
// ---------------------------------------------------------------------------
describe('getMe 与 getSessionStatus', () => {
  test('getMe：用户权限信息缺失（已删除）→ AUTH_USER_NOT_FOUND', async () => {
    permissionHelper.getUserPermissions.mockImplementation(async () => null);
    const res = makeRes();
    await invoke(controller.getMe, makeReq(), res);
    expect(res.body.data?.code || res.body.message).toBeDefined();
    expect(res.statusCode).toBe(404);
  });

  test('getMe：成功聚合 permissions/menus/dataScope', async () => {
    permissionHelper.getUserPermissions.mockImplementation(async () => ({
      user: { username: 'alice' },
      permissions: ['device:read'],
      menuPermissions: [],
      buttonPermissions: [{ code: 'device:create' }],
      apiPermissions: [],
    }));
    permissionHelper.getMenuTree.mockImplementation(async () => [{ key: 'devices' }]);
    const res = makeRes();
    await invoke(controller.getMe, makeReq(), res);
    expect(res.body.data.buttons).toEqual(['device:create']);
    expect(res.body.data.dataScope).toEqual({ type: 'all' });
  });

  test('getSessionStatus：access 有效 → authenticated=true（不查 refresh）', async () => {
    tokenService.isAccessTokenValid.mockResolvedValue(true);
    const res = makeRes();
    await invoke(controller.getSessionStatus, makeReq({ headers: { cookie: 'access_token=a; refresh_token=r' } }), res);
    expect(res.body.data.authenticated).toBe(true);
    expect(tokenService.isRefreshTokenValid).not.toHaveBeenCalled();
  });

  test('getSessionStatus：access 失效但 refresh 有效 → 仍视为已登录', async () => {
    tokenService.isAccessTokenValid.mockResolvedValue(false);
    tokenService.isRefreshTokenValid.mockResolvedValue(true);
    const res = makeRes();
    await invoke(controller.getSessionStatus, makeReq({ headers: { cookie: 'access_token=a; refresh_token=r' } }), res);
    expect(res.body.data.authenticated).toBe(true);
  });

  test('getSessionStatus：双令牌均无效 → authenticated=false 且恒 200（不触发前端刷新连锁）', async () => {
    tokenService.isAccessTokenValid.mockResolvedValue(false);
    tokenService.isRefreshTokenValid.mockResolvedValue(false);
    const res = makeRes();
    await invoke(controller.getSessionStatus, makeReq(), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.data.authenticated).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// captcha / captchaStatus
// ---------------------------------------------------------------------------
describe('captcha 与 captchaStatus', () => {
  test('getCaptcha：服务不可用返回 CAPTCHA_SERVICE_UNAVAILABLE', async () => {
    captchaService.generate.mockResolvedValue(null);
    const res = makeRes();
    await invoke(controller.getCaptcha, makeReq(), res);
    expect(res.statusCode).toBe(503);
  });

  test('getCaptchaStatus：DB 故障降级到静态配置而非 500', async () => {
    SystemConfig.isLoginCaptchaEnabled.mockRejectedValue(new Error('db down'));
    SystemConfig.isRegisterCaptchaEnabled.mockRejectedValue(new Error('db down'));
    const res = makeRes();
    await invoke(controller.getCaptchaStatus, makeReq(), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.data.loginCaptchaEnabled).toBeDefined();
  });

  test('getCaptchaStatus：正常路径返回库内开关', async () => {
    SystemConfig.isLoginCaptchaEnabled.mockResolvedValue(true);
    SystemConfig.isRegisterCaptchaEnabled.mockResolvedValue(false);
    const res = makeRes();
    await invoke(controller.getCaptchaStatus, makeReq(), res);
    expect(res.body.data).toEqual({
      loginCaptchaEnabled: true,
      registerCaptchaEnabled: false,
    });
  });
});

// ---------------------------------------------------------------------------
// 会话管理三接口
// ---------------------------------------------------------------------------
describe('listSessions / revokeSession / revokeOtherSessions', () => {
  test('listSessions：total 与 currentSidPresent 派生正确', async () => {
    sessionService.listSessions.mockResolvedValue([{ sid: 's1' }, { sid: 's2' }]);
    const res = makeRes();
    await invoke(controller.listSessions, makeReq(), res);
    expect(res.body.data.total).toBe(2);
    expect(res.body.data.currentSidPresent).toBe(true);
  });

  test('listSessions：旧令牌无 sid 时 currentSidPresent=false', async () => {
    sessionService.listSessions.mockResolvedValue([]);
    const res = makeRes();
    await invoke(controller.listSessions, makeReq({ user: { userId: 'u-1', username: 'a', sid: null } }), res);
    expect(res.body.data.currentSidPresent).toBe(false);
  });

  test('revokeSession：踢自己 → 400 引导走登出', async () => {
    const res = makeRes();
    await invoke(controller.revokeSession, makeReq({ params: { sid: 'sid-cur' } }), res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(sessionService.revokeSession).not.toHaveBeenCalled();
  });

  test('revokeSession：不存在或不属于本人 → 统一 404（不泄露 sid 存在性）', async () => {
    sessionService.revokeSession.mockResolvedValue(false);
    const res = makeRes();
    await invoke(controller.revokeSession, makeReq({ params: { sid: 'sid-ghost' } }), res);
    expect(res.statusCode).toBe(404);
    expect(res.body.message).toBe('会话不存在或已失效');
  });

  test('revokeSession：成功落审计', async () => {
    sessionService.revokeSession.mockResolvedValue(true);
    const res = makeRes();
    await invoke(controller.revokeSession, makeReq({ params: { sid: 'sid-other' } }), res);
    expect(res.statusCode).toBe(200);
    expect(sessionService.revokeSession).toHaveBeenCalledWith(
      expect.objectContaining({ sid: 'sid-other', userId: 'u-1', reason: 'user_revoked' })
    );
    expect(AuditLog.recordSensitiveAction).toHaveBeenCalled();
  });

  test('revokeOtherSessions：返回吊销计数（当前设备除外）', async () => {
    sessionService.revokeOtherSessions.mockResolvedValue(3);
    const res = makeRes();
    await invoke(controller.revokeOtherSessions, makeReq(), res);
    expect(res.body.data.revokedCount).toBe(3);
    expect(sessionService.revokeOtherSessions).toHaveBeenCalledWith(
      expect.objectContaining({ exceptSid: 'sid-cur' })
    );
  });
});
