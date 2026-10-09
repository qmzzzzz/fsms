/**
 * 回归：`mfaEnable` 必须以「单调推进」方式记录 mfaLastCounter。
 *
 * verifyTotp 有 ±1 窗口（utils/totp.js），因此本端点校验通过的码可能是
 * 比登录/step-up 已推进值更低的时间窗。旧实现无条件覆写
 * `mfaLastCounter: totpResult.counter` 会把登录侧条件更新
 * （authService.js:527，`mfaLastCounter < counter`）刚刚推进的守卫拉回，
 * 令那条已消费的码在其残余有效期内重放换第二个会话——即 TOTP 双花。
 *
 * 本测把不变式钉死：写库时必须用 `$max:{mfaLastCounter}`，且不得再出现
 * 顶层 `mfaLastCounter` 直接赋值。pre-fix（顶层赋值）→ 红；post-fix（$max）→ 绿。
 *
 * 范围修订（2026-09-19）：本文件标题原是"MFA 生命周期端点"，但用例只覆盖
 * `mfaEnable`，而那正是**唯一**该用 $max 的端点——`mfaDisable` 与
 * `regenerateRecoveryCodes` 已升级为「原子认领」（$lt 条件更新 + 不命中即拒绝），
 * 因为 $max 从不拒绝请求，等于水位的码（登录刚消费掉的那个）照样能冒关 MFA /
 * 铸 10 张恢复码。mfaEnable 没有这个洞：口令校验之前 `MFA_ALREADY_ENABLED`
 * 已把"启用态"挡掉，且开启动作本身不授予访问 ⇒ 无状态可双花。
 * 那两处的门禁在 `mfaLifecycleTotpClaim.test.js`（行为）与
 * `mfaTotpClaimImplementation.test.js`（计数不翻倍 / 审计可区分 / fail-closed）。
 * 若有人把这里的 $max "顺手统一"成认领，本文件会红——那是提示不是回归：
 * 请先确认 mfaEnable 真的出现了可双花的状态，再一起改三处。
 */

jest.mock('../../models/User', () => ({
  findById: jest.fn(() => ({ select: jest.fn() })),
  findByIdAndUpdate: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../models/AuditLog', () => ({ record: jest.fn(() => Promise.resolve()) }));
jest.mock('../../services/mfaService', () => ({
  hashRecoveryCode: jest.fn((c) => `hash:${c}`),
  generateRecoveryCodes: jest.fn(() => ['r1', 'r2']),
  isMfaLocked: jest.fn(() => Promise.resolve(false)),
  recordMfaFailure: jest.fn(),
  resetMfaFailures: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../utils/mfaSecret', () => ({
  decryptMfaSecret: jest.fn(() => 'plain-secret'),
  encryptMfaSecret: jest.fn(),
}));
jest.mock('../../utils/totp', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  otpauthUri: jest.fn(() => 'otpauth://totp/x'),
  verifyTotpDetailed: jest.fn(),
}));
jest.mock('../../utils/loginCipher', () => ({ decryptLoginCredential: jest.fn() }));
jest.mock('../../middleware/auth', () => ({ invalidateUserCache: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../utils/metrics', () => ({ incMfaAction: jest.fn() }));

const User = require('../../models/User');
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
  res.cookie = jest.fn();
  return res;
};

const run = async (fn, req) => {
  const next = jest.fn((e) => {
    if (e) throw e;
  });
  await fn(req, makeRes(), next);
  await new Promise((r) => setImmediate(r));
};

beforeEach(() => {
  jest.clearAllMocks();
  User.findById.mockImplementation(() => ({
    select: jest.fn(() =>
      Promise.resolve({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc', email: 'a@b.c' })
    ),
  }));
});

describe('MFA 端点 mfaLastCounter 单调推进（防 TOTP 重放守卫被拉回）', () => {
  test('mfaEnable 成功时用 $max 记录时间窗，不再顶层直接赋值', async () => {
    // 模拟：本端点消费的是较低窗口 N=555（登录此前已推进到更高值，$max 不得拉回）
    verifyTotpDetailed.mockReturnValue({ valid: true, counter: 555 });

    await run(controller.mfaEnable, {
      body: { mfaCode: '123456' },
      ip: '127.0.0.1',
      get: () => 'jest',
      user: { userId: 'u1', username: 'alice' },
    });

    expect(User.findByIdAndUpdate).toHaveBeenCalledTimes(1);
    const update = User.findByIdAndUpdate.mock.calls[0][1];
    expect(update.mfaEnabled).toBe(true);
    // 核心不变式：单调推进
    expect(update.$max).toEqual({ mfaLastCounter: 555 });
    // 且绝不能退回旧的顶层无条件覆写
    expect(update.mfaLastCounter).toBeUndefined();
  });

  test('verifyTotp 返回 null 计数器时仍不应出现顶层 mfaLastCounter 覆写', async () => {
    // 边界：counter 合法但为 0（窗口序号可为小值），$max 仍应包裹它
    verifyTotpDetailed.mockReturnValue({ valid: true, counter: 0 });

    await run(controller.mfaEnable, {
      body: { mfaCode: '000000' },
      ip: '127.0.0.1',
      get: () => 'jest',
      user: { userId: 'u1', username: 'alice' },
    });

    const update = User.findByIdAndUpdate.mock.calls[0][1];
    expect(update.$max).toEqual({ mfaLastCounter: 0 });
    expect(update.mfaLastCounter).toBeUndefined();
  });
});
