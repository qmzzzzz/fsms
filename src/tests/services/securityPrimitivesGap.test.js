/**
 * mfaService / tokenService 安全原语分支补齐（覆盖率棘轮）
 *
 * mfaService 缺口：pepper 缺失降级路径（26/35）、锁定窗口三态（60-63）、
 * 失败计数 DB 故障降级（74）、达阈值触发锁定 + 审计（77-85）。
 * tokenService 缺口：isAccessTokenValid 吞错分支（71）、
 * isRefreshTokenValid 的用户态/版本校验主体（84-88）。
 */

const crypto = require('crypto');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('mfaService / tokenService 安全原语分支补齐', () => {
  let User;
  let AuditLog;
  let mfaService;
  let tokenService;
  const PASSWORD = randomPassword();
  const stamp = `sp${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  const makeUser = async (name, extra = {}) => {
    const user = await User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    return user;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    mfaService = require('../../services/mfaService');
    tokenService = require('../../services/tokenService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await AuditLog.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('mfaService.isMfaLocked 锁定窗口三态', () => {
    test('无锁定记录 → false', async () => {
      const u = await makeUser('nolock');
      await expect(mfaService.isMfaLocked(u._id)).resolves.toBe(false);
    });

    test('锁定期内 → true', async () => {
      const u = await makeUser('locking', { mfaLockUntil: new Date(Date.now() + 60000) });
      await expect(mfaService.isMfaLocked(u._id)).resolves.toBe(true);
    });

    test('锁定已过期 → false 且惰性清零失败计数', async () => {
      const u = await makeUser('expired', {
        mfaLockUntil: new Date(Date.now() - 1000),
        mfaFailCount: 5,
      });
      await expect(mfaService.isMfaLocked(u._id)).resolves.toBe(false);
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(0);
      expect(after.mfaLockUntil).toBeNull();
    });
  });

  describe('mfaService.recordMfaFailure 防爆破', () => {
    test('未达阈值不锁定；达阈值锁定 10 分钟并落审计', async () => {
      const u = await makeUser('brute');
      const userDoc = await User.findById(u._id);

      for (let i = 0; i < mfaService.MFA_MAX_FAILS - 1; i++) {
        await mfaService.recordMfaFailure(userDoc);
      }
      let after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(mfaService.MFA_MAX_FAILS - 1);
      expect(after.mfaLockUntil).toBeFalsy();

      await mfaService.recordMfaFailure(userDoc);
      after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(mfaService.MFA_MAX_FAILS);
      expect(after.mfaLockUntil).toBeTruthy();
      expect(after.mfaLockUntil.getTime()).toBeGreaterThan(Date.now());

      // 审计为 fire-and-forget，轮询等待落库
      let audit = null;
      for (let i = 0; i < 20 && !audit; i++) {
        audit = await AuditLog.findOne({
          action: 'mfa_attempt_locked',
          username: userDoc.username,
        });
        if (!audit) await new Promise((r) => setTimeout(r, 100));
      }
      expect(audit).toBeTruthy();
      expect(audit.riskFactors).toContain('mfa_bruteforce');
    });

    test('失败计数 DB 故障时降级（计数按 1 处理）且不抛错、不锁定', async () => {
      const u = await makeUser('dbfail');
      const userDoc = await User.findById(u._id);
      // recordMfaFailure 会在返回值上链式调用 .select()：裸 reject Promise 会
      // 触发 TypeError 而非业务降级，需模拟 Query 链在 select 之后才 reject
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(() => ({
        select: () => Promise.reject(new Error('db down (故障注入)')),
      }));
      try {
        await expect(mfaService.recordMfaFailure(userDoc)).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaLockUntil).toBeFalsy();
    });
  });

  describe('mfaService.resetMfaFailures', () => {
    test('清零失败计数并解除锁定', async () => {
      const u = await makeUser('resetok', {
        mfaFailCount: 3,
        mfaLockUntil: new Date(Date.now() + 60000),
      });
      await mfaService.resetMfaFailures(u._id);
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(0);
      expect(after.mfaLockUntil).toBeNull();
    });
  });

  describe('恢复码 pepper 降级路径', () => {
    test('未配置 HMAC 密钥时退化为普通 sha256（无 pepper）', () => {
      // getRecoveryPepper 读 require('../config').hmacSecret——与本测试引用
      // 同一模块单例，临时置空即可驱动降级分支，测后恢复
      const config = require('../../config');
      const saved = config.hmacSecret;
      config.hmacSecret = '';
      try {
        expect(mfaService.getRecoveryPepper()).toBe('');
        const code = 'ABCD-EFGH';
        const expected = crypto.createHash('sha256').update(code, 'utf8').digest('hex');
        expect(mfaService.hashRecoveryCode(code)).toBe(expected);
        // 与有 pepper 路径产物不同，证明算法确实切换
        expect(mfaService.hashRecoveryCode(code)).not.toBe(
          crypto.createHmac('sha256', 'anything').update(code, 'utf8').digest('hex')
        );
      } finally {
        config.hmacSecret = saved;
      }
    });
  });

  describe('tokenService 轻量探测', () => {
    test('isAccessTokenValid：畸形令牌吞错返回 false', async () => {
      await expect(tokenService.isAccessTokenValid('not-a-jwt')).resolves.toBe(false);
    });

    test('isRefreshTokenValid：有效令牌 → true', async () => {
      const u = await makeUser('refreshok');
      const token = tokenService.generateRefreshToken(u._id, 0, null);
      await expect(tokenService.isRefreshTokenValid(token)).resolves.toBe(true);
    });

    test('isRefreshTokenValid：非 active 用户 → false', async () => {
      const u = await makeUser('refreshlocked', { status: 'locked' });
      const token = tokenService.generateRefreshToken(u._id, 0, null);
      await expect(tokenService.isRefreshTokenValid(token)).resolves.toBe(false);
    });

    test('isRefreshTokenValid：tokenVersion 不匹配 → false', async () => {
      const u = await makeUser('refreshver');
      await User.findByIdAndUpdate(u._id, { $inc: { tokenVersion: 1 } });
      const token = tokenService.generateRefreshToken(u._id, 0, null);
      await expect(tokenService.isRefreshTokenValid(token)).resolves.toBe(false);
    });

    test('isRefreshTokenValid：畸形令牌吞错返回 false', async () => {
      await expect(tokenService.isRefreshTokenValid('garbage')).resolves.toBe(false);
    });

    test('isRefreshTokenValid：已删除用户 → false', async () => {
      const u = await makeUser('refreshgone');
      const token = tokenService.generateRefreshToken(u._id, 0, null);
      await User.deleteOne({ _id: u._id });
      await expect(tokenService.isRefreshTokenValid(token)).resolves.toBe(false);
    });
  });
});
