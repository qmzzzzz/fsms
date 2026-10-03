/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：authService.registerUser / loginUser / refreshSession
 * 守护的不变式：登录失败计数与锁定必须生效；刷新会话必须轮换而非复用
 * 可证伪性：本轮未做变异实测
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效·已实测] `:230-242`（现形 `:251`）标题写「降级为无 sid 令牌」而未验证 sid 缺失（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     变异实测确认 + 措辞更正（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法）：让 services/authService.js:789-797
 *       的**降级分支仍传 `sid`**（正是 :777-779 注释自己警告的形态：下发查不到会话的带 sid 令牌
 *       ⇒ `authenticate` 拒绝该令牌，用户登录成功却立刻无法访问任何接口）
 *       → 本文件 **26/26 全绿**；同点位 throw 正对照杀 **2 例**（含该标题用例本身）。
 *     **措辞更正**：`loginUser` 返回体**没有 `sid` 字段**（:811-823 仅 outcome/token/refreshToken/user），
 *       可观测物应是**解码 JWT 后的 `sid` claim**，不是 `result.sid`。
 *
 * 命名沿革：2026-09-20 由 `authServiceGapB.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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
const { USER_STATUS } = require('../../utils/constants');

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
      // 注册验证码默认开启（src/config/index.js:72 顶层 registerCaptchaEnabled；
      // models/SystemConfig.js:207 的 fallback 同读顶层；全仓无任何地方设
      // REGISTER_CAPTCHA_ENABLED=false），而 authService.registerUser 的验证码闸
      // （src/services/authService.js:127）排在密文解密
      // （src/services/authService.js:137）**之前** ⇒ 不打桩就会被 CAPTCHA_INVALID 拦下，
      // 永远到不了本用例要测的解密失败分支。被测对象是解密分支，故显式关掉验证码闸
      // （与上方 CAPTCHA_INVALID 用例同一手法，只是方向相反）。
      const SysConfig = require('../../models').SystemConfig;
      const cfgSpy = jest.spyOn(SysConfig, 'isRegisterCaptchaEnabled').mockResolvedValueOnce(false);
      const badEnc = Buffer.from(JSON.stringify({ v: 1, x: 'bad', y: 'bad', c: 'bad' })).toString(
        'base64'
      );
      const result = await authService.registerUser({
        username: `${stamp}enc1`,
        email: `${stamp}enc1@example.com`,
        encPassword: badEnc,
      });
      cfgSpy.mockRestore();
      expect(result.outcome).toBe('ENC_INVALID');
    });

    test('OK - 正常注册（验证码已通过）', async () => {
      // 注册验证码默认开启（config.registerCaptchaEnabled 默认 true），所以这里要让它
      // **通过**，而不是把闸关掉。
      // 原注释写的是「falls back to config which defaults to true」——那句在修复前是错的：
      // 该键曾被写在 config.rateLimit 子对象里，顶层读到 undefined，
      // 于是 toConfigBoolean(undefined,false)===false，注册验证码实际是**静默关闭**的。
      // 修复（把该键移回顶层）之后这句注释才名副其实。
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
    // F-162：账户状态是**允许清单**判据（只有 active 可用），不是"把已知坏值列一遍"。
    // 写成遍历 USER_STATUS 而不是两条硬编码用例：将来加一档（pending/suspended/…）时，
    // 这一条会自动要求它被拒绝——按枚举拒绝的旧写法会静默放行，而 refresh 那边才拒绝。
    test.each(Object.values(USER_STATUS).filter((s) => s !== USER_STATUS.ACTIVE))(
      'INVALID_CREDENTIALS - 账户状态 %s（清单内非 active 一律拒）',
      async (status) => {
        const user = await makeUser(`st_${status}`, { status });
        const result = await authService.loginUser(
          { username: user.username, password: PASSWORD },
          defaultCtx()
        );
        expect(result.outcome).toBe('INVALID_CREDENTIALS');
      }
    );

    test('INVALID_CREDENTIALS - 清单外的状态值（口令正确也必须拒）', async () => {
      // 旧写法在这里给出**完整会话**：`=== inactive || === locked` 两个都不匹配 ⇒ 落到口令
      // 校验并通过。schema 的 enum 挡不住备份还原/裸写（updateOne 默认不跑校验），
      // 所以运行期判据必须独立成立——这正是"允许清单 vs 按枚举拒绝"的差别所在。
      const user = await makeUser('st_offenum');
      await User.updateOne({ _id: user._id }, { $set: { status: 'zz_not_in_enum' } });
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

    // NOTE: 非常规时间分支依赖「当前时刻」且 checkUnusualTime 是加载时解构
    // （authService.js:25 解构 → :732 调用），事后 spyOn 确实改不到。
    // 但**模块级 jest.mock 可以**，且已在 authServiceSideEffectFailureTolerance.test.js
    // 做过确定性触发 + 行为级断言（该文件的 mockUnusualMode）。
    // 本文件不重复造同一场景，避免同一条不变量两处实现漂移。

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
