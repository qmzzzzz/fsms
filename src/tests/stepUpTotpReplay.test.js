/**
 * 步进二次验证的 TOTP 必须防重放、防硬猜
 *
 * 修复前：`requireReAuthentication` 的 MFA 分支用裸 `verifyTotp`（只回布尔）——
 *   ① 不消费匹配到的时间窗：同一个合法码在 ±1 窗口（约 90s）内可无限次通过步进验证；
 *   ② 不记失败、不接锁定：而 6 位码空间只有 10^6，且本端点原先没有凭据型限流。
 * 仓内另外两处 TOTP 消费点（authService.verifyTotpChallenge 的 P2-12、mfaController）
 * 都做了"原子推进 mfaLastCounter + isMfaLocked/recordMfaFailure"，
 * 本端点是唯一漏掉的一处——典型的"同一语义多处各写一遍、漏一处"。
 *
 * 本套件直接驱动中间件本身（真库、真口令），断言四条：
 *   重放被拒 / 失败计数增长 / 达阈值后通道锁定 / 下一个新码仍可用（反向保护）。
 */

const mongoose = require('mongoose');

/** 调一次中间件，返回 { nextCalled, code } */
const runMiddleware = async (mw, userId, username, body) => {
  const req = { user: { userId, username }, body };
  const res = {
    _status: 0,
    _code: null,
    statusCode: null,
    status(s) {
      res._status = s;
      return res;
    },
    json(payload) {
      const errs = payload && payload.errors;
      res._code = (errs && (errs.errorCode || (errs.error && errs.error.code))) || null;
      return res;
    },
  };
  let nextCalled = false;
  await mw(req, res, () => {
    nextCalled = true;
  });
  return { nextCalled, code: res._code, status: res._status, req };
};

describe('步进二次验证（/api/security/view-sensitive）的 TOTP 消费语义', () => {
  let User;
  let requireReAuthentication;
  let generateSecret;
  let hotp;
  let base32Decode;
  let encryptMfaSecret;
  let mfaService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    requireReAuthentication = require('../middleware/security').requireReAuthentication;
    const totp = require('../utils/totp');
    generateSecret = totp.generateSecret;
    hotp = totp.hotp;
    base32Decode = totp.base32Decode;
    encryptMfaSecret = require('../utils/mfaSecret').encryptMfaSecret;
    mfaService = require('../services/mfaService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  let secret;
  let uid;
  const username = 'zzqoder_stepup';

  /** 当前时间窗（counter）的合法码；counter 与生产实现同一算法 */
  const codeFor = (offsetWindows = 0) => {
    const counter = Math.floor(Date.now() / 1000 / 30) + offsetWindows;
    return hotp(base32Decode(secret), counter);
  };

  beforeEach(async () => {
    await User.deleteMany({ username });
    secret = generateSecret();
    const created = await User.create({
      username,
      email: `${username}@example.com`,
      password: 'Aa1!aaaaaaaaaaaaaaaa',
      status: 'active',
      roles: [],
      mfaEnabled: true,
      // 落库形态与生产一致：AES-GCM 密文（middleware 里由 decryptMfaSecret 解开）
      mfaSecret: encryptMfaSecret(secret),
      mfaFailCount: 0,
      mfaLockUntil: null,
      mfaLastCounter: 0,
    });
    uid = created._id;
  });

  test('同一个合法码不得被重放：第二次调用必须被拒', async () => {
    const mw = requireReAuthentication();
    const code = codeFor();

    const first = await runMiddleware(mw, uid, username, { mfaCode: code });
    expect(first.nextCalled).toBe(true);
    expect(first.req.reAuthenticated).toBe(true);

    // 修复前这里是绿的（verifyTotp 只比窗口，不消费 counter）
    const second = await runMiddleware(mw, uid, username, { mfaCode: code });
    expect(second.nextCalled).toBe(false);
    expect(second.code).toBe('REAUTH_MFA_INCORRECT');
  });

  test('重放尝试要计入失败计数（不记计数=可以无限试）', async () => {
    const mw = requireReAuthentication();
    const code = codeFor();
    await runMiddleware(mw, uid, username, { mfaCode: code });
    await runMiddleware(mw, uid, username, { mfaCode: code });

    const after = await User.findById(uid).select('mfaFailCount mfaLastCounter');
    expect(after.mfaFailCount).toBe(1);
    expect(after.mfaLastCounter).toBeGreaterThan(0);
  });

  test('连续错码达阈值后通道临时锁定，并回 429 语义', async () => {
    const mw = requireReAuthentication();
    for (let i = 0; i < 5; i++) {
      const r = await runMiddleware(mw, uid, username, { mfaCode: '000000' });
      expect(r.nextCalled).toBe(false);
    }
    expect(await mfaService.isMfaLocked(uid)).toBe(true);

    // 锁定后即使给出**正确**的码也必须拒绝，否则锁定形同虚设
    const locked = await runMiddleware(mw, uid, username, { mfaCode: codeFor(1) });
    expect(locked.nextCalled).toBe(false);
    expect(locked.code).toBe('MFA_ATTEMPTS_EXCEEDED');
  });

  test('反向保护：下一个新码仍可通过（防重放不得变成"一次性以后全废"）', async () => {
    const mw = requireReAuthentication();
    const first = codeFor();
    expect((await runMiddleware(mw, uid, username, { mfaCode: first })).nextCalled).toBe(true);

    const next = codeFor(1);
    const r = await runMiddleware(mw, uid, username, { mfaCode: next });
    expect(r.nextCalled).toBe(true);
    // 成功验证后失败计数清零（与登录侧同口径）
    const after = await User.findById(uid).select('mfaFailCount mfaLockUntil');
    expect(after.mfaFailCount).toBe(0);
    expect(after.mfaLockUntil).toBeNull();
  });

  test('密码分支仍按原语义工作（本用例只动 MFA 分支，不得波及 currentPassword 路径）', async () => {
    const mw = requireReAuthentication();
    const ok = await runMiddleware(mw, uid, username, { currentPassword: 'Aa1!aaaaaaaaaaaaaaaa' });
    expect(ok.nextCalled).toBe(true);

    const bad = await runMiddleware(mw, uid, username, { currentPassword: 'wrong-password-1' });
    expect(bad.nextCalled).toBe(false);
    expect(bad.code).toBe('REAUTH_PASSWORD_INCORRECT');
  });
});
