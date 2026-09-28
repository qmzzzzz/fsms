/**
 * mfaService 三处「写不进库但主流程照常走」的留痕测试
 *
 * 被测修复：MFA 的三处 User 集合写入原本挂着 `.catch(() => {})`——
 * 锁定写入、过期锁定的惰性清零、验证成功后的计数清零。业务语义不变
 * （仍不阻断主流程），但不再静默。
 *
 * 为什么这不是"加日志"式的装饰：
 *  1. 锁定写入失败时，下一行的 `logger.warn('MFA 验证触发临时锁定')` 会照常
 *     写下"已锁定"。运维/SIEM 据此认为防线在位，而 6 位动态口令
 *     （10^6 空间）在故障窗口内仍可被无限次在线尝试——日志谎报防线状态，
 *     比没有日志更坏。现在 warn 载荷带 `lockApplied`，失败另有 error 留痕。
 *  2. 两处清零失败会让 mfaFailCount 停留在阈值上：用户到期后手滑一次即
 *     立即再锁（等效"每 10 分钟只能试一次"）。这是可用性问题，不留痕就
 *     只能看到"他为什么总被锁"，看不到根因。
 *
 * 注意 `AuditLog.record(...)` 那条不在本文件范围内：它自带失败处理
 * （models/auditLogWriteStatics.js 的 record() 落 logger.error + medium 指标，
 * 恒 resolve null），调用方的 `.catch(() => {})` 只是冗余保险，不是静默吞错。
 *
 * 桩的形状：recordMfaFailure 在计数调用上链式 `.select().catch()`、在锁定调用上
 * 链式 `.catch()`；两处清零调用只链 `.catch()`。桩必须与真实链式形状一致，
 * 否则 TypeError 会伪装成"降级路径已测"。
 */

const mongoose = require('mongoose');

describe('mfaService 静默写入失败必须留痕', () => {
  let User;
  let AuditLog;
  let mfaService;
  let logger;
  let errorSpy;
  let warnSpy;
  const stamp = `mfsw${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  /** 只暴露 `.catch` 的桩：对应"没有 .select 链"的更新调用 */
  const rejectCatchOnly = (msg) => ({
    catch: (handler) => Promise.reject(new Error(msg)).catch(handler),
  });

  const makeUser = async (name, extra = {}) =>
    User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: 'Qz7#Lm42vTx9',
      ...extra,
    });

  const lastWarnMeta = () => {
    const hit = [...warnSpy.mock.calls]
      .reverse()
      .find((c) => String(c[0]).includes('MFA 验证触发临时锁定'));
    return hit ? hit[1] : undefined;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    mfaService = require('../../services/mfaService');
    logger = require('../../utils/logger');
  });

  beforeEach(() => {
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    warnSpy.mockRestore();
  });

  afterAll(async () => {
    await User.deleteMany({ username: new RegExp(`^${stamp}`) });
    // 审计集合是 append-only（models/auditLogHooks.js 的护栏），清理只能尽力而为
    await AuditLog.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('recordMfaFailure：锁定写入', () => {
    test('锁定写不进库时不得留一条"已锁定"的假证据：error 留痕 + warn 载荷标锁未生效', async () => {
      const u = await makeUser('lockfail', { mfaFailCount: mfaService.MFA_MAX_FAILS - 1 });
      const userDoc = await User.findById(u._id).select('+mfaFailCount');
      const original = User.findByIdAndUpdate.bind(User);
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((id, payload, opts) => {
        // 计数那条走真实实现（本用例只测锁定那一格失败）
        if (payload && payload.$inc) return original(id, payload, opts);
        return rejectCatchOnly('db down (故障注入：锁定写入)');
      });

      try {
        await expect(mfaService.recordMfaFailure(userDoc)).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }

      const errorMsg = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(errorMsg).toContain('MFA 临时锁定写入失败');
      expect(errorMsg).toContain('db down (故障注入：锁定写入)');

      const meta = lastWarnMeta();
      expect(meta).toBeTruthy();
      expect(meta.lockApplied).toBe(false);

      // 防线确实没生效（证明 error/lockApplied 描述的是真实现状，不是恒定的兜底文案）
      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaLockUntil).toBeFalsy();
    });

    test('反向对照：锁定真的落库时 lockApplied 必须为 true 且没有失败留痕', async () => {
      const u = await makeUser('lockok', { mfaFailCount: mfaService.MFA_MAX_FAILS - 1 });
      const userDoc = await User.findById(u._id).select('+mfaFailCount');

      await mfaService.recordMfaFailure(userDoc);

      const after = await User.findById(u._id).select('+mfaLockUntil');
      expect(after.mfaLockUntil).toBeTruthy();

      const meta = lastWarnMeta();
      expect(meta.lockApplied).toBe(true);
      expect(errorSpy.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain(
        'MFA 临时锁定写入失败'
      );
    });
  });

  describe('isMfaLocked：过期锁定的惰性清零', () => {
    test('清零写不进库时不得静默：留痕且不改变"已解锁"的判定', async () => {
      const u = await makeUser('lazyreset', {
        mfaFailCount: mfaService.MFA_MAX_FAILS,
        mfaLockUntil: new Date(Date.now() - 60 * 1000),
      });
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockImplementation(() => rejectCatchOnly('db down (故障注入：惰性清零)'));

      try {
        await expect(mfaService.isMfaLocked(u._id)).resolves.toBe(false);
      } finally {
        spy.mockRestore();
      }

      const errorMsg = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(errorMsg).toContain('MFA 过期锁定的惰性清零失败');
      expect(errorMsg).toContain('db down (故障注入：惰性清零)');
    });

    test('反向对照：清零成功时不写 error，且计数真的归零', async () => {
      const u = await makeUser('lazyresetok', {
        mfaFailCount: mfaService.MFA_MAX_FAILS,
        mfaLockUntil: new Date(Date.now() - 60 * 1000),
      });

      await expect(mfaService.isMfaLocked(u._id)).resolves.toBe(false);

      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(0);
      expect(after.mfaLockUntil).toBeNull();
      expect(errorSpy).not.toHaveBeenCalled();
    });
  });

  describe('resetMfaFailures：验证成功后的清零', () => {
    test('清零失败不得抛给调用方，但必须留痕', async () => {
      const u = await makeUser('resetfail');
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockImplementation(() => rejectCatchOnly('db down (故障注入：成功清零)'));

      try {
        // 验证已成功，不能因为记不上就把用户判成失败 ⇒ 必须 resolve
        await expect(mfaService.resetMfaFailures(u._id)).resolves.toBeUndefined();
      } finally {
        spy.mockRestore();
      }

      const errorMsg = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(errorMsg).toContain('MFA 验证成功后的计数清零失败');
      expect(errorMsg).toContain('db down (故障注入：成功清零)');
    });

    test('反向对照：清零成功时不写 error', async () => {
      const u = await makeUser('resetfailok', {
        mfaFailCount: 3,
        mfaLockUntil: new Date(Date.now() + 60000),
      });

      await mfaService.resetMfaFailures(u._id);

      const after = await User.findById(u._id).select('+mfaFailCount +mfaLockUntil');
      expect(after.mfaFailCount).toBe(0);
      expect(after.mfaLockUntil).toBeNull();
      expect(errorSpy).not.toHaveBeenCalled();
    });
  });
});
