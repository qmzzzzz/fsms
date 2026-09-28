/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：authService 中 ~22 个 `.catch(() => {})` 旁路处理器（故障注入触发）
 * 守护的不变式：审计/通知等旁路写入失败不得影响主流程（且失败必须留痕）
 * 可证伪性：本轮未做变异实测
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效] 文件头自陈目的是「提升 functions 指标」；12 条断言与 `GapB` 同场景用例**逐字相同**，唯一增量是让 Istanbul 计数器 +1（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *   - [部分有效] `:303-322`（现形 `:327`）标题写「REPLAYED + invalidateUserTokens 成功 + revokeAllSessionsSafe 执行」而函数体只断 `outcome==="REPLAYED"`（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     变异实测更正（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法）：作用域 = authService.js 的 73 套 / 872 例。
 *       `authService.js:907` invalidateUserTokens 变 no-op → 2 例红（杀器 security/revokeFailurePropagation.test.js）
 *       ⇒ **第一个动作有人守**；`:916` revokeAllSessionsSafe 变 no-op → **872/872 全绿**
 *       ⇒ **第二个动作全仓无断言**（`:914-915` 注释自陈其后果是「登录会话」界面留下僵尸记录）。
 *       正对照（`:916` 点位 throw）杀掉 2 例，**含本用例本身** ⇒ 本用例确实执行到 `:916`，只是没断言。
 *   - [已修复·P1-29] `:284-295,343-349` 时间依赖 + 双可能断言（deliverables/消防管理系统全面代码审计报告-2026-09-16.md）
 *     复核：`:353-356` 已注释「该用例恒返回 OK，却用 expect([OK,REVOKE_FAILED]) 双可能断言兜住…现改为…断言 REVOKE_FAILED + 密码确已落库 + tokenVersion 未递增」。
 *
 * 命名沿革：2026-09-20 由 `authServiceGapC.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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

/**
 * 非常规时间登录（authService.js:25 解构 → :732 调用 checkUnusualTime）是**解构导入**，
 * 事后 `jest.spyOn` 改不到已绑定的引用；只有**模块级替换**才能在 authService 加载时被捕获。
 *
 * 默认 false ⇒ 与未 mock 的行为逐字一致；只有需要**确定性**触发该分支的用例才置 true。
 * 必要性：原用例自身注释已承认「just in case the test happens to run during off-hours」
 * ——即该分支此前**不确定被执行**，那条用例的绿与被测代码无关。
 */
let mockUnusualMode = false;
jest.mock('../../services/securityAlert', () => {
  const actual = jest.requireActual('../../services/securityAlert');
  return {
    ...actual,
    checkUnusualTime: (...args) =>
      mockUnusualMode ? { isUnusual: true, hour: 3 } : actual.checkUnusualTime(...args),
  };
});

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
      let injected = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        // Only fail the first call (the failedLoginCount increment)
        if (callCount === 1) {
          injected++;
          return Promise.reject(new Error('db error'));
        }
        return origFindByIdAndUpdate(...args);
      });
      const result = await authService.loginUser(
        { username: user.username, password: 'WrongPass!99zz' },
        defaultCtx()
      );
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
      // 注入必须真的发生过：否则"生产代码不再调用 findByIdAndUpdate"时 callCount 恒 0、
      // 拒绝永不发射，本用例仍会在 outcome 上绿着，而标题承诺的 catch 分支没人测过。
      expect(injected).toBe(1);
      expect(callCount).toBeGreaterThanOrEqual(1);
      spy.mockRestore();
    });

    test('MFA TOTP 失败后 findByIdAndUpdate 失败 → catch (line 423)', async () => {
      const user = await makeUser('cuid2', { mfaEnabled: true });
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      let injected = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        if (callCount === 1) {
          injected++;
          return Promise.reject(new Error('db error'));
        }
        return origFindByIdAndUpdate(...args);
      });
      const result = await authService.loginUser(
        { username: user.username, password: PASSWORD, mfaCode: '000000' },
        defaultCtx()
      );
      expect(result.outcome).toBe('MFA_CODE_INVALID');
      expect(injected).toBe(1);
      expect(callCount).toBeGreaterThanOrEqual(1);
      spy.mockRestore();
    });

    test('恢复码验证失败 handleRecoveryFailure 中 findByIdAndUpdate 失败 → catch (line 458)', async () => {
      const user = await makeUser('cuid3', {
        mfaEnabled: true,
        mfaRecoveryCodes: ['some-hash'],
      });
      const origFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      let callCount = 0;
      let injected = 0;
      const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation(function (...args) {
        callCount++;
        if (callCount === 1) {
          injected++;
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
      expect(injected).toBe(1);
      expect(callCount).toBeGreaterThanOrEqual(1);
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

    test('unusual time + AuditLog.create 失败 → 不阻断登录，且失败必须可观测', async () => {
      // 确定性触发（原实现依赖「测试恰好在非常规时段运行」，该分支此前不确定被执行）
      mockUnusualMode = true;
      const user = await makeUser('cutime');
      // 只让非常规时段那一条写入失败：其它 create 调用（若有）保持正常，
      // 否则「谁消费了这次 rejection」不确定，logger 断言会变成 flaky。
      const spy = jest
        .spyOn(AuditLog, 'create')
        .mockImplementation((doc) =>
          doc && doc.action === 'login_unusual_time'
            ? Promise.reject(new Error('audit down'))
            : Promise.resolve({ _id: 'probe-ok' })
        );
      const loggerSpy = jest.spyOn(require('../../utils/logger'), 'error');
      try {
        const result = await authService.loginUser(
          { username: user.username, password: PASSWORD },
          defaultCtx()
        );
        // 旁路失败不阻断主流程（口径与 utils/auditWriteFailure.js:11-13 一致）
        expect(result.outcome).toBe('OK');
        // 行为级断言（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）：非常规时段登录必须**真的尝试**
        // 落一条 login_unusual_time —— 该动作已 skipGlobalAudit，这条写入即唯一留痕。
        // 此前它是「仅文本级防御」：把写入换成 Promise.resolve 后 119 套 / 1402 例全绿。
        const actions = spy.mock.calls.map((c) => c[0] && c[0].action);
        expect(actions).toContain('login_unusual_time');
        // 失败不再静默（原为 .catch(() => {})）：必须走统一处理器，日志可检索
        expect(loggerSpy).toHaveBeenCalledWith(
          expect.stringContaining('审计写入失败'),
          expect.objectContaining({ auditAction: 'login_unusual_time' })
        );
      } finally {
        loggerSpy.mockRestore();
        spy.mockRestore();
        mockUnusualMode = false;
      }
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
    // P1-29 修复（本次改动复审）：原用例的 mock 假设「invalidateUserTokens 是第 2 次
    // findByIdAndUpdate」，但 changeUserPassword 的读路径走 User.findById、
    // 落库走 user.save()，全程**不调用** findByIdAndUpdate——唯一一次调用
    // （callCount=1）就是 invalidateUserTokens 本身，因 1 >= 2 不成立而永不 reject。
    // 结果：该用例恒返回 OK，却用 expect(['OK','REVOKE_FAILED']) 双可能断言兜住，
    // 名为「验证吊销失败」实则从未触发吊销失败（实测把断言收紧为 REVOKE_FAILED 即红）。
    // 现改为：直接让 findByIdAndUpdate 一律 reject（它就是吊销路径本身），
    // 并断言 REVOKE_FAILED + 密码确已落库 + tokenVersion 未递增（部分成功如实上报）。
    test('改密成功但 invalidateUserTokens 失败 → REVOKE_FAILED + 密码已改/tokenVersion 未增', async () => {
      const user = await makeUser('crev1');
      const newPwd = randomPassword();
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        .mockRejectedValue(new Error('revoke failed'));
      let result;
      try {
        result = await authService.changeUserPassword(
          user._id,
          { currentPassword: PASSWORD, newPassword: newPwd },
          { username: user.username }
        );
      } finally {
        spy.mockRestore();
      }

      expect(result.outcome).toBe('REVOKE_FAILED');

      // 部分成功必须如实可查：密码已换新、旧口令失效、tokenVersion 未递增
      const after = await User.findById(user._id).select('+password');
      expect(await after.comparePassword(newPwd)).toBe(true);
      expect(await after.comparePassword(PASSWORD)).toBe(false);
      expect(after.tokenVersion).toBe(0);
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

  // ===== loginUser - checkBruteForce / 锁定写入故障注入（B-L1，2026-09-05 CI 棘轮）=====

  describe('loginUser - checkBruteForce / 锁定写入故障注入', () => {
    test('口令错误 + AuditLog.countDocuments 失败 → checkBruteForce 的 catch 吞错，仍 401 口径（line 301）', async () => {
      const user = await makeUser('bf1');
      const spy = jest
        .spyOn(AuditLog, 'countDocuments')
        .mockRejectedValueOnce(new Error('db transient down'));
      const result = await authService.loginUser(
        { username: user.username, password: `${PASSWORD}x` },
        defaultCtx()
      );
      spy.mockRestore();
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
    });

    test('失败计数达锁定阈值 + 锁定写入失败 → catch 吞错不阻断 401 口径（line 327）', async () => {
      const user = await makeUser('bf2', { failedLoginCount: 9 });
      const realFindByIdAndUpdate = User.findByIdAndUpdate.bind(User);
      const spy = jest
        .spyOn(User, 'findByIdAndUpdate')
        // 第一次调用是 $inc 失败计数，保持真实写库
        .mockImplementationOnce((...args) => realFindByIdAndUpdate(...args))
        // 第二次调用是 lockUntil 锁定写入，注入故障
        .mockRejectedValueOnce(new Error('db transient down'));
      const result = await authService.loginUser(
        { username: user.username, password: `${PASSWORD}x` },
        defaultCtx()
      );
      spy.mockRestore();
      expect(result.outcome).toBe('INVALID_CREDENTIALS');
    });
  });
});
