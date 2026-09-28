/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：mfaService / tokenService 的安全原语分支
 * 守护的不变式：pepper 缺失必须降级而非放行；失败计数 DB 故障必须「收紧：尝试锁定 + 告警」；令牌版本必须校验
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `securityPrimitivesGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * mfaService / tokenService 安全原语分支补齐（覆盖率棘轮）
 *
 * mfaService 缺口：pepper 缺失降级路径（26/35）、锁定窗口三态（60-63）、
 * 失败计数 DB 故障路径（74， 起为"收紧：尝试锁定 + 告警"而非静默降级）、
 * 达阈值触发锁定 + 审计（77-85）。
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

    test('失败计数 DB 故障时不抛错，且必须转而尝试锁定（观测不到防线时要收紧）', async () => {
      const u = await makeUser('dbfail');
      const userDoc = await User.findById(u._id);
      const updates = [];
      const rejected = Promise.reject(new Error('db down (故障注入)'));
      // recordMfaFailure 会在返回值上链式调用 .select()：裸 reject Promise 会
      // 触发 TypeError 而非业务降级，需模拟 Query 链在 select 之后才 reject。
      // 同理，锁定那条更新用的是 .catch() ⇒ 桩必须两个都有，否则测的是桩的形状。
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((id, update) => {
        updates.push(update);
        return { select: () => rejected, catch: (h) => rejected.catch(h) };
      });
      try {
        await expect(mfaService.recordMfaFailure(userDoc)).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      // 本用例原断言是 `expect(after.mfaLockUntil).toBeFalsy()`，标题写着"降级
      // （计数按 1 处理）…不锁定"——那是把"计数器写不进 ⇒ 防爆破防线静默失效且无告警"
      // 当成了契约。它存在的理由见本文件头（为覆盖率棘轮补旧实现的 line 74 分支），
      // 不是一次策略裁定，所以这里按新策略改写断言（只增不减：不抛错那条仍在）。
      expect(updates.some((upd) => upd && upd.mfaLockUntil instanceof Date)).toBe(true);
      // 全库故障时锁定那条同样写不进 ⇒ 正当用户不会被误锁，可用性与旧行为一致
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaLockUntil).toBeFalsy();
    });

    // 上一用例把两次写入都打成失败，只能证明"不抛错"；计数失败、锁定可用才是
    // 真实故障形态（计数器所在的文档/索引出问题，普通更新仍能落库）。
    // 只有这一格能杀死"计数写不进就顺带跳过锁定"的变异。
    test('仅计数写入失败时锁定必须真的落库（fail-closed 的可兑现形式）', async () => {
      const u = await makeUser('dbfail2');
      const userDoc = await User.findById(u._id);
      // recordMfaFailure 在计数调用上链式 `.select().catch()`，在锁定调用上链式 `.catch()`
      // ⇒ 桩必须两种形状都有，否则 TypeError 会伪装成"降级已测过"。
      const originalFindAndUpdate = User.findByIdAndUpdate;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((id, payload) => {
        if (payload && payload.$inc) {
          const failed = Promise.reject(new Error('db down (故障注入)'));
          return { select: () => failed, catch: (h) => failed.catch(h) };
        }
        return originalFindAndUpdate.call(User, id, payload);
      });
      try {
        await expect(mfaService.recordMfaFailure(userDoc)).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      // 6 位动态口令（10^6 空间）不得在故障窗口内退化成可无限在线尝试
      expect(after.mfaLockUntil).toBeTruthy();
      expect(after.mfaLockUntil.getTime()).toBeGreaterThan(Date.now());
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
