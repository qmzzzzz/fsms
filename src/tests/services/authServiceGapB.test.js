/**
 * authService 覆盖率补全 B：loginUser 分支 + refreshSession 分支 + registerUser 分支
 *
 * 目标行（2026-09-01 实测未覆盖）：
 *   registerUser: 92, 95, 106-107
 *   loginUser: 188, 241-246, 251-259, 320, 323-327, 365-379, 411, 423, 426-429,
 *              458, 461-464, 482-483, 498, 509, 535-537, 599
 *   refreshSession: 655, 661, 676-679, 712-713, 745-746, 749-750
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('authService gap B', () => {
  let User;
  let Role;
  let authService;
  let sessionService;
  const stamp = `gb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const createdUsers = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    require('../../models/TokenBlacklist');
    require('../../models/AuditLog');

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
      await mongoose.connection.close();
    }
  });

  const makeUser = async (suffix, extra = {}) => {
    const user = await User.create({
      username: `${stamp}${suffix}`,
      email: `${stamp}${suffix}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    createdUsers.push(user._id);
    return user;
  };

  const defaultCtx = (overrides = {}) => ({
    ip: '127.0.0.1',
    userAgent: 'test-agent',
    fingerprint: 'fp-test',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
    ...overrides,
  });

  // ==================== registerUser ====================
  describe('registerUser', () => {
    test('CAPTCHA_INVALID - 验证码校验失败', async () => {
      const captchaService = require('../../services/captchaService');
      const SysConfig = require('../../models').SystemConfig;
      const capSpy = jest.spyOn(captchaService, 'verify').mockResolvedValueOnce(false);
      const cfgSpy = jest.spyOn(SysConfig, 'isRegisterCaptchaEnabled').mockResolvedValueOnce(true);
      const result = await authService.registerUser({
        username: `${stamp}cap1`,
        email: `${stamp}cap1@example.com`,
        password: PASSWORD,
        captchaId: 'fake-id',
        captchaText: 'wrong',
      });
      expect(result.outcome).toBe('CAPTCHA_INVALID');
      capSpy.mockRestore();
      cfgSpy.mockRestore();
    });

    test('ENC_INVALID - 注册时 encPassword 解密失败', async () => {
      const badEnc = Buffer.from(JSON.stringify({ v: 1, x: 'bad', y: 'bad', c: 'bad' })).toString(
        'base64'
      );
      const result = await authService.registerUser({
        username: `${stamp}enc1`,
        email: `${stamp}enc1@example.com`,
        encPassword: badEnc,
      });
      expect(result.outcome).toBe('ENC_INVALID');
    });

    test('OK - 正常注册（captcha disabled by config fallback or DB）', async () => {
      // SystemConfig.isRegisterCaptchaEnabled may throw in fresh DB → falls back to config
      // which defaults to true. We mock captcha verify to pass.
      const captchaService = require('../../services/captchaService');
      const spy = jest.spyOn(captchaService, 'verify').mockResolvedValueOnce(true);
      const result = await authService.registerUser({
        username: `${stamp}ok1`,
        email: `${stamp}ok1@example.com`,
        password: PASSWORD,
        captchaId: 'any',
        captchaText: 'any',
      });
      expect(result.outcome).toBe('OK');
      expect(result.userId).toBeTruthy();
      spy.mockRestore();
    });
  });

  // ==================== loginUser ====================
  describe('loginUser', () => {
    test('INVALID_CREDENTIALS - 账户 inactive 状态', async () => {
      const user = await makeUser('inact', { status: 'inactive' });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
    });

    test('INVALID_CREDENTIALS - 账户 locked 状态', async () => {
      const user = await makeUser('locked', { status: 'locked' });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
    });

    test('INVALID_CREDENTIALS - 账户临时锁定中（lockUntil > now）', async () => {
      const user = await makeUser('tmplock', {
        lockUntil: new Date(Date.now() + 600000),
      });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
    });

    test('INVALID_CREDENTIALS - 密码错误触发 failedLoginCount 递增', async () => {
      const user = await makeUser('pwfail');
      const result = await authService.loginUser(
        { username: user.username, password: 'WrongPass!99zz' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      const updated = await User.findById(user._id).select('failedLoginCount');
      expect(updated.failedLoginCount).toBeGreaterThanOrEqual(1);
    });

    test('INVALID_CREDENTIALS - 连续失败 ≥10 次触发临时锁定', async () => {
      const user = await makeUser('maxfail', { failedLoginCount: 9 });
      const result = await authService.loginUser(
        { username: user.username, password: 'WrongPass!99zz' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      const updated = await User.findById(user._id).select('failedLoginCount lockUntil');
      expect(updated.failedLoginCount).toBeGreaterThanOrEqual(10);
      expect(updated.lockUntil).toBeTruthy();
      expect(updated.lockUntil.getTime()).toBeGreaterThan(Date.now());
    });

    test('MFA_REQUIRED - MFA 已开启但未提供 mfaCode', async () => {
      const user = await makeUser('mfareq', { mfaEnabled: true });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_REQUIRED');
    });

    test('MFA_ATTEMPTS_EXCEEDED - MFA 通道锁定中', async () => {
      const user = await makeUser('mfalock', {
        mfaEnabled: true,
        mfaLockUntil: new Date(Date.now() + 600000),
      });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '123456' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_ATTEMPTS_EXCEEDED');
    });

    test('MFA_CODE_INVALID - TOTP 验证码错误', async () => {
      const user = await makeUser('mfabad', { mfaEnabled: true });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '000000' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
    });

    test('MFA_CODE_INVALID - 恢复码格式无效', async () => {
      const user = await makeUser('rcfmt', { mfaEnabled: true });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: 'INVALID!' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
    });

    test('MFA_CODE_INVALID - 恢复码不匹配', async () => {
      const user = await makeUser('rcnomatch', {
        mfaEnabled: true,
        mfaRecoveryCodes: ['some-other-hash'],
      });
      // Use a valid format recovery code that doesn't match
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: 'AAAA-BBBB' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
    });

    // NOTE: unusual time branch (lines 535-537) depends on time-of-day and
    // checkUnusualTime is destructured at load → cannot spy. Skipped intentionally.

    test('OK - sessionService.createSession 失败时降级为无 sid 令牌', async () => {
      const user = await makeUser('sessfail');
      const spy = jest
        .spyOn(sessionService, 'createSession')
        .mockRejectedValueOnce(new Error('session db down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('OK');
      expect(result.token).toBeTruthy();
      spy.mockRestore();
    });

    test('captcha fallback - SystemConfig.isLoginCaptchaEnabled 抛错时降级到 config', async () => {
      // This tests line 188: when SystemConfig throws, falls back to config.loginCaptchaEnabled
      // In test env config.loginCaptchaEnabled is false (LOGIN_CAPTCHA_ENABLED not set to 'true')
      // So captcha should be skipped and login proceeds normally
      const SysConfig = require('../../models').SystemConfig;
      const spy = jest
        .spyOn(SysConfig, 'isLoginCaptchaEnabled')
        .mockRejectedValueOnce(new Error('db error'));
      const user = await makeUser('capfall');
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('OK');
      spy.mockRestore();
    });
  });

  // ==================== refreshSession ====================
  describe('refreshSession', () => {
    // Must resolve lazily: dotenv loads .env only when config is first required (in beforeAll),
    // but describe-scope code runs during file parse before that.
    const getRefreshSecret = () => require('../../config').jwt.refreshSecret;

    test('MISSING - refreshToken 为空', async () => {
      const result = await authService.refreshSession(null, defaultCtx());
      expect(result.outcome).toBe('MISSING');
    });

    test('EXPIRED - refresh token 已过期', async () => {
      const token = jwt.sign(
        { userId: 'x', type: 'refresh', tokenVersion: 0 },
        getRefreshSecret(),
        { expiresIn: '-1s' }
      );
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('EXPIRED');
    });

    test('INVALID - type 不是 refresh', async () => {
      const token = jwt.sign({ userId: 'x', type: 'access', tokenVersion: 0 }, getRefreshSecret(), {
        expiresIn: '1h',
      });
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('INVALID');
    });

    test('INVALID - 签名错误', async () => {
      const token = jwt.sign({ userId: 'x', type: 'refresh', tokenVersion: 0 }, 'wrong-secret', {
        expiresIn: '1h',
      });
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('INVALID');
    });

    test('INVALID - 用户不存在或状态非 active', async () => {
      const ghostId = new mongoose.Types.ObjectId();
      const token = jwt.sign(
        { userId: String(ghostId), type: 'refresh', tokenVersion: 0 },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('INVALID');
    });

    test('IP_DENIED - refresh 时 IP 不在 allowedIPs 范围', async () => {
      const user = await makeUser('rfip', { allowedIPs: '10.99.99.99' });
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
        },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      const result = await authService.refreshSession(token, defaultCtx({ ip: '192.168.1.1' }));
      expect(result.outcome).toBe('IP_DENIED');
    });

    test('BLACKLIST_UNAVAILABLE - consumeToken 抛错', async () => {
      const user = await makeUser('rfblk');
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
        },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      // consumeToken is destructured in authService; spy on underlying model op
      const TokenBlacklist = require('../../models/TokenBlacklist');
      const spy = jest
        .spyOn(TokenBlacklist, 'create')
        .mockRejectedValueOnce(new Error('blacklist down'));
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('BLACKLIST_UNAVAILABLE');
      spy.mockRestore();
    });

    test('SESSION_UNAVAILABLE - validateSession 抛错', async () => {
      const user = await makeUser('rfsess');
      const sid = crypto.randomUUID();
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
          sid,
        },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      const spy = jest
        .spyOn(sessionService, 'validateSession')
        .mockRejectedValueOnce(new Error('session service down'));
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('SESSION_UNAVAILABLE');
      spy.mockRestore();
    });

    test('SESSION_REVOKED - 会话已被吊销', async () => {
      const user = await makeUser('rfrev');
      const sid = crypto.randomUUID();
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
          sid,
        },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      const spy = jest
        .spyOn(sessionService, 'validateSession')
        .mockResolvedValueOnce({ usable: false });
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('SESSION_REVOKED');
      spy.mockRestore();
    });

    test('PASSWORD_CHANGED - 改密后旧 refresh token 被拒绝', async () => {
      const user = await makeUser('rfpwd');
      // Issue token with iat 1 hour ago but long expiry so it doesn't expire during test
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
          iat: Math.floor(Date.now() / 1000) - 3600,
        },
        getRefreshSecret(),
        { expiresIn: '7d' }
      );
      // Set passwordChangedAt to now (after the token was issued)
      await User.findByIdAndUpdate(user._id, { passwordChangedAt: new Date() });
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('PASSWORD_CHANGED');
    });

    test('VERSION_MISMATCH - tokenVersion 不匹配', async () => {
      const user = await makeUser('rfver');
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: 999,
        },
        getRefreshSecret(),
        { expiresIn: '1h' }
      );
      const result = await authService.refreshSession(token, defaultCtx());
      expect(result.outcome).toBe('VERSION_MISMATCH');
    });
  });
});
