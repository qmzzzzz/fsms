/**
 * authService/login.js 残余分支与函数覆盖率（2026-10-20，审计 P2-1）
 *
 * 此前 jest.config.js 对该文件只要求 functions 47%、branches 81%。缺口集中在两类：
 *   1. 真实业务分支：验证码不通过、密文解密失败、MFA 未通过、IP 范围放行、
 *      过期 lockUntil 重置计数；
 *   2. 各拒绝路径上的 `.catch(() => {})` 兜底回调——正常库况下永不被执行，
 *      于是「DB 瞬断时统一 401 是否会退化成 500」这条防线本身没有测试证据。
 * 本文件用模块桩把两条路径都走一遍，目标是把 functions 拉到 ≥90（实测 100）。
 *
 * 用桩而非真库：这些分支需要让审计写入/暴力破解检测/哨兵随机 reject，
 * 真库无法稳定制造；且该文件的核心契约是「依赖失败不改变外部 outcome」，
 * 用桩表达最直接。真库下的完整登录链路由 authServiceLoginRefreshGuards 等覆盖。
 */

jest.mock('../../models/User', () => ({
  findByUsername: jest.fn(),
  findByIdAndUpdate: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  recordLogin: jest.fn(),
  record: jest.fn(),
}));
jest.mock('../../models', () => ({
  SystemConfig: { captchaSwitch: jest.fn() },
}));
jest.mock('../../services/securityAlert', () => ({ checkBruteForce: jest.fn() }));
jest.mock('../../services/canaryWatch', () => ({ recordGhostAttempt: jest.fn() }));
jest.mock('../../services/captchaService', () => ({ verify: jest.fn() }));
jest.mock('../../utils/loginCipher', () => ({ decryptLoginCredential: jest.fn() }));
jest.mock('../../services/authService/failureAndMfa', () => ({
  verifyMfaChallenge: jest.fn(),
  MAX_FAILED_LOGINS: 10,
  LOCK_DURATION_MS: 10 * 60 * 1000,
  resolveFailedLoginCount: jest.fn((updated) =>
    typeof updated?.failedLoginCount === 'number' ? updated.failedLoginCount : 10
  ),
}));
jest.mock('../../services/authService/session', () => ({ issueLoginSession: jest.fn() }));

const User = require('../../models/User');
const AuditLog = require('../../models/AuditLog');
const { SystemConfig } = require('../../models');
const securityAlert = require('../../services/securityAlert');
const canaryWatch = require('../../services/canaryWatch');
const captchaService = require('../../services/captchaService');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const failureAndMfa = require('../../services/authService/failureAndMfa');
const session = require('../../services/authService/session');
const { loginUser } = require('../../services/authService/login');

const CTX = {
  ip: '127.0.0.1',
  userAgent: 'jest',
  method: 'POST',
  path: '/api/auth/login',
  fingerprint: 'fp-residual',
  req: { ip: '127.0.0.1' },
};

const makeUser = (overrides = {}) => ({
  _id: '65f0000000000000000000aa',
  username: 'alice',
  status: 'active',
  comparePassword: jest.fn().mockResolvedValue(true),
  ...overrides,
});

let currentUser;

beforeEach(() => {
  jest.clearAllMocks();
  currentUser = null;
  User.findByUsername.mockImplementation(() => ({
    select: jest.fn().mockResolvedValue(currentUser),
  }));
  SystemConfig.captchaSwitch.mockResolvedValue(false);
  captchaService.verify.mockResolvedValue(true);
  AuditLog.recordLogin.mockResolvedValue({});
  AuditLog.record.mockResolvedValue({});
  securityAlert.checkBruteForce.mockResolvedValue({});
  canaryWatch.recordGhostAttempt.mockResolvedValue({});
  session.issueLoginSession.mockResolvedValue({ outcome: 'OK', token: 'token' });
  failureAndMfa.verifyMfaChallenge.mockResolvedValue({ outcome: 'OK' });
});

describe('登录前置：验证码与口令解析', () => {
  test('验证码开启且校验失败：直接返回 CAPTCHA_INVALID，不查用户', async () => {
    SystemConfig.captchaSwitch.mockResolvedValue(true);
    captchaService.verify.mockResolvedValue(false);

    const result = await loginUser({ username: 'alice', password: 'x', captchaId: 'c1' }, CTX);

    expect(result).toEqual({ outcome: 'CAPTCHA_INVALID' });
    expect(User.findByUsername).not.toHaveBeenCalled();
    expect(AuditLog.recordLogin).not.toHaveBeenCalled();
  });

  test('用户不存在 + 非字符串/空口令：哑 compare 兜底不抛，仍返回统一 401', async () => {
    SystemConfig.captchaSwitch.mockResolvedValue(true);
    securityAlert.checkBruteForce.mockRejectedValue(new Error('db down'));
    canaryWatch.recordGhostAttempt.mockRejectedValue(new Error('watch down'));
    AuditLog.recordLogin.mockRejectedValue(new Error('audit down'));

    await expect(loginUser({ username: 'ghost', password: 12345 }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    await expect(loginUser({ username: 'ghost', password: null }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(captchaService.verify).toHaveBeenCalled();
  });

  test('密文解密失败：解密/审计/爆破检测三重失败仍返回 ENC_INVALID', async () => {
    decryptLoginCredential.mockRejectedValue(
      Object.assign(new Error('bad cipher'), { code: 'LOGIN_CIPHER_BAD' })
    );
    securityAlert.checkBruteForce.mockRejectedValue(new Error('db down'));
    AuditLog.recordLogin.mockRejectedValue(new Error('audit down'));

    const result = await loginUser({ username: 'alice', encPassword: 'cipher' }, CTX);

    expect(result).toEqual({ outcome: 'ENC_INVALID' });
    expect(AuditLog.recordLogin).toHaveBeenCalledWith(null, 'alice', CTX.ip, false, CTX.userAgent, {
      reason: 'credential_decrypt_failed:LOGIN_CIPHER_BAD',
    });
    expect(User.findByUsername).not.toHaveBeenCalled();
  });
});

describe('账户可用性：兜底失败不改变 401 口径', () => {
  test('账户状态非 active：checkBruteForce 拒绝被吞，仍返回 INVALID_CREDENTIALS', async () => {
    currentUser = makeUser({ status: 'inactive' });
    securityAlert.checkBruteForce.mockRejectedValue(new Error('db down'));

    await expect(loginUser({ username: 'alice', password: 'x' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(currentUser.comparePassword).not.toHaveBeenCalled();
    expect(securityAlert.checkBruteForce).toHaveBeenCalled();
  });

  test('临时锁定中：checkBruteForce 拒绝被吞，仍返回 INVALID_CREDENTIALS', async () => {
    currentUser = makeUser({ lockUntil: new Date(Date.now() + 60_000) });
    securityAlert.checkBruteForce.mockRejectedValue(new Error('db down'));

    await expect(loginUser({ username: 'alice', password: 'x' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(currentUser.comparePassword).not.toHaveBeenCalled();
  });

  test('IP 不在允许范围：审计写入失败被吞，仍返回 INVALID_CREDENTIALS', async () => {
    currentUser = makeUser({ allowedIPs: '10.0.0.0/8' });
    AuditLog.record.mockRejectedValue(new Error('audit down'));

    await expect(loginUser({ username: 'alice', password: 'x' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(AuditLog.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'ip_range_denied', riskFactors: ['ip_range_violation'] })
    );
  });

  test('IP 在允许范围且 lockUntil 已过期：口令错误按新一轮从 1 计', async () => {
    currentUser = makeUser({
      allowedIPs: '127.0.0.0/8',
      lockUntil: new Date(Date.now() - 1_000),
      comparePassword: jest.fn().mockResolvedValue(false),
    });
    User.findByIdAndUpdate.mockResolvedValue({ failedLoginCount: 1 });

    await expect(loginUser({ username: 'alice', password: 'wrong' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    // 能走到 comparePassword 即证明 IP 允许分支放行（否则在上一步就 401）
    expect(currentUser.comparePassword).toHaveBeenCalledWith('wrong');
    expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
      currentUser._id,
      { $set: { failedLoginCount: 1, lockUntil: null } },
      { new: true }
    );
  });
});

describe('口令失败计数与锁定', () => {
  test('密码错误达到阈值：锁定写入与审计均失败时仍返回 401，且尝试写 lockUntil', async () => {
    currentUser = makeUser({ comparePassword: jest.fn().mockResolvedValue(false) });
    User.findByIdAndUpdate.mockResolvedValueOnce({ failedLoginCount: 10 });
    User.findByIdAndUpdate.mockResolvedValue({});
    AuditLog.record.mockRejectedValue(new Error('audit down'));
    securityAlert.checkBruteForce.mockRejectedValue(new Error('db down'));

    await expect(loginUser({ username: 'alice', password: 'wrong' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(User.findByIdAndUpdate).toHaveBeenNthCalledWith(
      1,
      currentUser._id,
      { $inc: { failedLoginCount: 1 } },
      { new: true }
    );
    expect(User.findByIdAndUpdate).toHaveBeenNthCalledWith(2, currentUser._id, {
      lockUntil: expect.any(Date),
    });
    expect(AuditLog.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'account_temp_locked',
        riskFactors: ['excessive_failed_logins'],
      })
    );
  });

  test('失败计数写入失败按 fail-closed 处理：视为已达阈值并尝试锁定', async () => {
    currentUser = makeUser({ comparePassword: jest.fn().mockResolvedValue(false) });
    User.findByIdAndUpdate
      .mockRejectedValueOnce(new Error('counter write down'))
      .mockResolvedValueOnce({});

    await expect(loginUser({ username: 'alice', password: 'wrong' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(User.findByIdAndUpdate).toHaveBeenNthCalledWith(2, currentUser._id, {
      lockUntil: expect.any(Date),
    });
  });

  test('锁定写入失败：审计如实记录防线未生效，而非宣称已锁定', async () => {
    currentUser = makeUser({ comparePassword: jest.fn().mockResolvedValue(false) });
    User.findByIdAndUpdate
      .mockResolvedValueOnce({ failedLoginCount: 10 })
      .mockRejectedValueOnce(new Error('lock write down'));

    await expect(loginUser({ username: 'alice', password: 'wrong' }, CTX)).resolves.toEqual({
      outcome: 'INVALID_CREDENTIALS',
    });
    expect(AuditLog.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'account_temp_locked',
        reason: expect.stringContaining('锁定未能写入数据库'),
      })
    );
  });
});

describe('MFA 二期', () => {
  test('验证码未通过：透传 MFA 结果且不签发会话', async () => {
    currentUser = makeUser({ mfaEnabled: true });
    failureAndMfa.verifyMfaChallenge.mockResolvedValue({ outcome: 'MFA_CODE_INVALID' });

    await expect(
      loginUser({ username: 'alice', password: 'x', mfaCode: '000000' }, CTX)
    ).resolves.toEqual({ outcome: 'MFA_CODE_INVALID' });
    expect(session.issueLoginSession).not.toHaveBeenCalled();
  });

  test('未开启 MFA：口令正确后直接签发，不再调用 MFA 校验', async () => {
    currentUser = makeUser();

    await expect(loginUser({ username: 'alice', password: 'x' }, CTX)).resolves.toEqual({
      outcome: 'OK',
      token: 'token',
    });
    expect(failureAndMfa.verifyMfaChallenge).not.toHaveBeenCalled();
    expect(session.issueLoginSession).toHaveBeenCalled();
  });

  test('验证码通过：继续签发会话', async () => {
    currentUser = makeUser({ mfaEnabled: true });
    failureAndMfa.verifyMfaChallenge.mockResolvedValue({ outcome: 'OK' });

    await expect(
      loginUser({ username: 'alice', password: 'x', mfaCode: '123456' }, CTX)
    ).resolves.toEqual({ outcome: 'OK', token: 'token' });
    expect(failureAndMfa.verifyMfaChallenge).toHaveBeenCalledWith(
      currentUser,
      expect.objectContaining({ mfaCodeRaw: '123456', username: 'alice' })
    );
    expect(session.issueLoginSession).toHaveBeenCalledWith(currentUser, CTX, 'alice');
  });
});
