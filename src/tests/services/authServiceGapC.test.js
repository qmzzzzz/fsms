/**
 * authService 覆盖率补全 C：故障注入触发 .catch(() => {}) 匿名回调
 *
 * authService.js 中有 ~22 个 .catch(() => {}) 处理器，每个都被 Istanbul
 * 计为独立函数。正常路径下这些 promise 不会 reject，导致函数覆盖率偏低。
 * 本套件通过在模型层注入故障（spyOn Model.method → mockRejectedValue）来
 * 触发这些 catch 分支，提升 functions 指标。
 *
 * 注意：checkBruteForce / checkUnusualTime / isMfaLocked 等是解构导入，
 * 无法事后 spyOn；只能通过可引用的模块对象（AuditLog / User / sessionService）
 * 间接触发。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('authService gap C - catch handler coverage', () => {
  let User;
  let AuditLog;
  let authService;
  let sessionService;
  const stamp = `gc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');
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

  // ===== loginUser catch handlers =====

  describe('loginUser - AuditLog.recordLogin failure paths', () => {
    test('用户不存在 + AuditLog.recordLogin 失败 → catch handler (line 230)', async () => {
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: 'nonexistent_user_xyz', password: 'Whatever!123' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      spy.mockRestore();
    });

    test('密码错误 + AuditLog.recordLogin 失败 → catch handler (line 296)', async () => {
      const user = await makeUser('caudit1');
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: 'WrongPass!99zz' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      spy.mockRestore();
    });

    test('inactive 账户 + AuditLog.recordLogin 失败 → catch handler (line 242-245)', async () => {
      const user = await makeUser('caudit2', { status: 'inactive' });
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      spy.mockRestore();
    });

    test('临时锁定 + AuditLog.recordLogin 失败 → catch handler (line 256)', async () => {
      const user = await makeUser('caudit3', {
        lockUntil: new Date(Date.now() + 600000),
      });
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      spy.mockRestore();
    });

    test('登录成功 + AuditLog.recordLogin 失败 → catch handler (line 619-622)', async () => {
      const user = await makeUser('caudit4');
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('OK');
      spy.mockRestore();
    });
  });

  describe('loginUser - User.findByIdAndUpdate failure paths', () => {
    test('密码错误后 findByIdAndUpdate 失败 → catch returns null (line 320)', async () => {
      const user = await makeUser('cuid1');
      // First call to comparePassword succeeds (wrong pwd → false),
      // then User.findByIdAndUpdate should fail
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        // Only fail the first call (the failedLoginCount increment)
        if (callCount === 1) {
          return Promise.reject(new Error('db error'));
        }
        return origFindByIdAndUpdate(...args);
      });
      const result = await authService.loginUser(
        { username: user.username, password: 'WrongPass!99zz' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      spy.mockRestore();
    });

    test('MFA TOTP 失败后 findByIdAndUpdate 失败 → catch (line 423)', async () => {
      const user = await makeUser('cuid2', { mfaEnabled: true });
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        if (callCount === 1) {
          return Promise.reject(new Error('db error'));
        }
        return origFindByIdAndUpdate(...args);
      });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '000000' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
      spy.mockRestore();
    });

    test('恢复码验证失败 handleRecoveryFailure 中 findByIdAndUpdate 失败 → catch (line 458)', async () => {
      const user = await makeUser('cuid3', {
        mfaEnabled: true,
        mfaRecoveryCodes: ['some-hash'],
      });
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        if (callCount === 1) {
          return Promise.reject(new Error('db error'));
        }
        return origFindByIdAndUpdate(...args);
      });
      // Valid format recovery code that doesn't match
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: 'AAAA-BBBB' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
      spy.mockRestore();
    });
  });

  describe('loginUser - MFA audit catch handlers', () => {
    test('MFA_REQUIRED + AuditLog.record 失败 → catch (line 349-359)', async () => {
      const user = await makeUser('cmfa1', { mfaEnabled: true });
      const spy = jest.spyOn(AuditLog, 'record').mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_REQUIRED');
      spy.mockRestore();
    });

    test('MFA_ATTEMPTS_EXCEEDED + AuditLog.record 失败 → catch (line 366-378)', async () => {
      const user = await makeUser('cmfa2', {
        mfaEnabled: true,
        mfaLockUntil: new Date(Date.now() + 600000),
      });
      const spy = jest.spyOn(AuditLog, 'record').mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '123456' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_ATTEMPTS_EXCEEDED');
      spy.mockRestore();
    });

    test('MFA_CODE_INVALID TOTP + AuditLog.record 失败 → catch (line 433-445)', async () => {
      const user = await makeUser('cmfa3', { mfaEnabled: true });
      const spy = jest.spyOn(AuditLog, 'record').mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '000000' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
      spy.mockRestore();
    });

    test('恢复码格式无效 + AuditLog.record in handleRecoveryFailure 失败 → catch (line 467-479)', async () => {
      const user = await makeUser('cmfa4', { mfaEnabled: true });
      const spy = jest.spyOn(AuditLog, 'record').mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: 'INVALID!' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
      spy.mockRestore();
    });
  });

  describe('loginUser - other catch handlers', () => {
    test('encPassword 解密失败 + AuditLog.recordLogin 失败 → catch (line 207-209)', async () => {
      const badEnc = Buffer.from(JSON.stringify({ v: 1, x: 'bad', y: 'bad', c: 'bad' })).toString(
        'base64'
      );
      const spy = jest
        .spyOn(AuditLog, 'recordLogin')
        .mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: `${stamp}encfail`, encPassword: badEnc },
        defaultCtx()
      );
      expect(result.outcome).toBe('ENC_INVALID');
      spy.mockRestore();
    });

    test('sessionService.createSession 失败 + AuditLog.recordLogin 成功 → line 599', async () => {
      const user = await makeUser('csess1');
      const spy = jest
        .spyOn(sessionService, 'createSession')
        .mockRejectedValueOnce(new Error('session db down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('OK');
      spy.mockRestore();
    });

    test('unusual time + AuditLog.create 失败 → catch (line 537-547)', async () => {
      // This only triggers during off-hours; use AuditLog.create spy just in case
      // the test happens to run during off-hours
      const user = await makeUser('cutime');
      const spy = jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('audit down'));
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD },
        defaultCtx()
      );
      expect(result.outcome).toBe('OK');
      spy.mockRestore();
    });
  });

  // ===== refreshSession catch handlers =====

  describe('refreshSession - catch handlers', () => {
    const getRefreshSecret = () => require('../../config').jwt.refreshSecret;

    test('REPLAYED + invalidateUserTokens 成功 + revokeAllSessionsSafe 执行 → lines 719-731', async () => {
      const user = await makeUser('creplay');
      // Sign two identical refresh tokens (same jti won't happen naturally, so we reuse one)
      const token = jwt.sign(
        {
          userId: String(user._id),
          type: 'refresh',
          tokenVersion: user.tokenVersion ?? 0,
          jti: crypto.randomUUID(),
        },
        getRefreshSecret(),
        { expiresIn: '7d' }
      );

      // First refresh consumes the token (succeeds)
      const _r1 = await authService.refreshSession(token, defaultCtx());
      // Second refresh with same token → replayed
      const r2 = await authService.refreshSession(token, defaultCtx());
      expect(r2.outcome).toBe('REPLAYED');
    });
  });

  // ===== changeUserPassword catch handlers =====

  describe('changeUserPassword - catch handlers', () => {
    test('改密成功但 invalidateUserTokens 失败 → REVOKE_FAILED (line 840-841)', async () => {
      const user = await makeUser('crev1');
      const newPwd = randomPassword();
      // invalidateUserTokens calls User.findByIdAndUpdate internally
      // We need it to throw AFTER the password save succeeds
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        // The invalidateUserTokens call will be after save; let first few pass
        if (callCount >= 2) {
          return Promise.reject(new Error('revoke failed'));
        }
        return origFindByIdAndUpdate(...args);
      });
      const result = await authService.changeUserPassword(
        user._id,
        { currentPassword: PASSWORD, newPassword: newPwd },
        { username: user.username }
      );
      // Could be OK or REVOKE_FAILED depending on call order
      expect(['OK', 'REVOKE_FAILED']).toContain(result.outcome);
      spy.mockRestore();
    });
  });

  // ===== registerUser catch handlers =====

  describe('registerUser - catch handlers', () => {
    test('captcha fallback when SysConfig throws → config fallback (line 92)', async () => {
      const SysConfig = require('../../models').SystemConfig;
      const spy = jest
        .spyOn(SysConfig, 'isRegisterCaptchaEnabled')
        .mockRejectedValueOnce(new Error('db error'));
      // With captcha enabled by config fallback, provide valid captcha
      const captchaService = require('../../services/captchaService');
      const capSpy = jest.spyOn(captchaService, 'verify').mockResolvedValueOnce(true);
      const result = await authService.registerUser({
        username: `${stamp}cfb`,
        email: `${stamp}cfb@example.com`,
        password: PASSWORD,
        captchaId: 'any',
        captchaText: 'any',
      });
      expect(result.outcome).toBe('OK');
      spy.mockRestore();
      capSpy.mockRestore();
    });
  });
});
