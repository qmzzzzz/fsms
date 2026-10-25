/**
 * 回归：`mfaEnable` 必须**原子认领** TOTP 时间窗，不得再用 `$max`。
 *
 * 历史：另外两个生命周期端点（disable / regenerate）早已改为 claimTotpWindow，
 * 本端点曾保留 `$max`。当时的理由是"校验前 MFA_ALREADY_ENABLED 已挡掉启用态，
 * 开启动作本身不授予访问 ⇒ 无状态可双花"。这个理由漏了两条真实路径：
 *   ① 并发两次 enable 携带同一个码：两次校验都通过，`$max` 从不拒绝任何请求；
 *   ② 账号关闭 MFA 后重新 enroll/enable 时 mfaLastCounter 仍保留上一次生命周期的
 *      水位（disable 有意不清），等于水位的旧窗口在 `$max` 下照样能通过。
 * 现与 disable / regenerate / 登录统一为 claimTotpWindow：同一时间窗只能用一次，
 * 互斥由 DB 条件更新保证。本文件把该选择钉死：用 $max 或顶层赋值 → 红。
 */

jest.mock('../../models/User', () => ({
  findById: jest.fn(() => ({ select: jest.fn() })),
  findByIdAndUpdate: jest.fn(() => Promise.resolve()),
  // enable 用条件更新（mfaEnabled:false + 同一密钥）兜住"相邻窗口的并发 enable"，
  // 默认返回命中的文档；认领失败用例里不应被调用。
  findOneAndUpdate: jest.fn(() => Promise.resolve({ _id: 'u1', mfaEnabled: true })),
}));
jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve()),
  // F-03：MFA 状态变更成功路径改走 services/auditOutbox.js
  buildSensitiveActionDoc: jest.fn(() => ({ action: 'mfa_enable', category: 'auth' })),
  create: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../services/mfaService', () => {
  const actual = jest.requireActual('../../services/mfaService');
  return {
    ...actual,
    hashRecoveryCode: jest.fn((c) => `hash:${c}`),
    generateRecoveryCodes: jest.fn(() => ['r1', 'r2']),
    isMfaLocked: jest.fn(() => Promise.resolve(false)),
    recordMfaFailure: jest.fn(),
    resetMfaFailures: jest.fn(() => Promise.resolve()),
    claimTotpWindow: jest.fn(() => Promise.resolve(true)),
  };
});
jest.mock('../../utils/mfaSecret', () => ({
  decryptMfaSecret: jest.fn(() => 'plain-secret'),
  encryptMfaSecret: jest.fn(),
}));
jest.mock('../../utils/totp', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  otpauthUri: jest.fn(() => 'otpauth://totp/x'),
  verifyTotpDetailed: jest.fn(),
}));
jest.mock('../../middleware/auth', () => ({ invalidateUserCache: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../utils/metrics', () => ({ incMfaAction: jest.fn() }));

const User = require('../../models/User');
const mfaService = require('../../services/mfaService');
const { verifyTotpDetailed } = require('../../utils/totp');
const controller = require('../../controllers/mfaController');

const makeRes = () => {
  const res = { statusCode: 200 };
  res.status = jest.fn((c) => {
    res.statusCode = c;
    return res;
  });
  res.json = jest.fn((b) => {
    res.body = b;
    return res;
  });
  return res;
};

const run = async (fn, req) => {
  const res = makeRes();
  const next = jest.fn((e) => {
    if (e) throw e;
  });
  await fn(req, res, next);
  await new Promise((r) => setImmediate(r));
  return res;
};

beforeEach(() => {
  jest.clearAllMocks();
  User.findById.mockImplementation(() => ({
    select: jest.fn(() =>
      Promise.resolve({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc', email: 'a@b.c' })
    ),
  }));
});

describe('MFA 端点原子认领时间窗（防 TOTP 重放）', () => {
  test('mfaEnable 成功时用 claimTotpWindow 认领，且不再写 mfaLastCounter', async () => {
    // 模拟：本端点消费的是较低窗口 N=555（登录此前已推进到更高值）
    verifyTotpDetailed.mockReturnValue({ valid: true, counter: 555 });

    await run(controller.mfaEnable, {
      body: { mfaCode: '123456' },
      ip: '127.0.0.1',
      get: () => 'jest',
      user: { userId: 'u1', username: 'alice' },
    });

    expect(mfaService.claimTotpWindow).toHaveBeenCalledWith('u1', 555);
    expect(User.findOneAndUpdate).toHaveBeenCalledTimes(1);
    const [filter, update] = User.findOneAndUpdate.mock.calls[0];
    // 条件更新：只有"仍未开启且密钥未被换掉"时才能落库
    expect(filter).toMatchObject({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc' });
    expect(update.$set.mfaEnabled).toBe(true);
    // 水位由 claim 推进；此处再写一次会重新制造"验证与写库之间"的窗口
    expect(update.$max).toBeUndefined();
    expect(update.$set.mfaLastCounter).toBeUndefined();
    expect(update.mfaLastCounter).toBeUndefined();
    // 【2026-10-24 补】顺序也是一条安全判据：必须**先认领再写库**。
    // 反过来的话，两个并发请求可以双双通过校验、双双写库成功，认领只是事后记账——
    // 这正是本文件要防的双花，而上面的断言（各自都成立）对顺序完全不敏感。
    expect(mfaService.claimTotpWindow.mock.invocationCallOrder[0]).toBeLessThan(
      User.findOneAndUpdate.mock.invocationCallOrder[0]
    );
  });

  test('认领失败（窗口已被消费）时不得开启 MFA', async () => {
    verifyTotpDetailed.mockReturnValue({ valid: true, counter: 0 });
    mfaService.claimTotpWindow.mockResolvedValueOnce(false);

    const res = await run(controller.mfaEnable, {
      body: { mfaCode: '000000' },
      ip: '127.0.0.1',
      get: () => 'jest',
      user: { userId: 'u1', username: 'alice' },
    });

    expect(mfaService.recordMfaFailure).toHaveBeenCalledTimes(1);
    expect(User.findOneAndUpdate).not.toHaveBeenCalled();
    expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('MFA_CODE_INVALID_SYNC');
  });
});
