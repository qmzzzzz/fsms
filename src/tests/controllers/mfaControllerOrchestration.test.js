jest.mock('express-validator', () => ({
  validationResult: (req) => ({
    isEmpty: () => !req._invalid,
    array: () => req._errors || [{ msg: 'mock validation error' }],
  }),
}));

jest.mock('../../models/User', () => ({
  findById: jest.fn(() => ({ select: jest.fn().mockReturnThis() })),
  findByIdAndUpdate: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../services/mfaService', () => {
  // 纯函数（因子路径判定、TOTP 因子验证）走真实实现：在测试里再手写一遍判定，
  // 就是"两份口径靠注释保持一致"的老毛病；被断言的行为仍由下面的 spy 控制。
  //
  // 【2026-10-24 复核：claimTotpWindow 被 mock 成 true 会不会让"认领失败"不可见】
  // 本文件确实看不到该分支，但这不是缺口——职责已经分到三个文件，各有各的介质：
  //   · 本文件（单元）：分支编排——重复开启 / 码错 / 缺凭据 / 缺第二因子。
  //   · mfaReplayGuardMax.test.js（单元）：认领失败必须拒绝开启，且**先认领再写库**。
  //   · mfaLifecycleTotpClaim.test.js 与 mfaWriteCasConcurrency.test.js（真实 Mongo）：
  //     `mfaLastCounter` 条件更新的原子性、并发交错、重放被拒。
  // 所以在**这里**再断言一次认领语义只会重复，不会增加可证伪性。
  const actual = jest.requireActual('../../services/mfaService');
  return {
    ...actual,
    hashRecoveryCode: jest.fn((code) => `hash:${code}`),
    generateRecoveryCodes: jest.fn(),
    isMfaLocked: jest.fn(),
    recordMfaFailure: jest.fn(),
    resetMfaFailures: jest.fn(),
    claimTotpWindow: jest.fn(async () => true),
  };
});
jest.mock('../../utils/loginCipher', () => ({
  decryptLoginCredential: jest.fn(),
}));
jest.mock('../../middleware/auth', () => ({
  invalidateUserCache: jest.fn(),
}));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const User = require('../../models/User');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const controller = require('../../controllers/mfaController');

const makeRes = () => {
  const res = {};
  res.statusCode = 200;
  res.status = jest.fn((code) => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  res.cookie = jest.fn();
  return res;
};

const makeReq = (over = {}) => ({
  body: {},
  ip: '127.0.0.1',
  get: jest.fn(() => 'jest-agent'),
  user: { userId: 'user-id', username: 'alice' },
  ...over,
});

const invoke = async (fn, req, res) => {
  const next = jest.fn((error) => {
    if (error) throw error;
  });
  await fn(req, res, next);
  await new Promise((resolve) => setImmediate(resolve));
  return res;
};

const whenUserFound = (user) => {
  User.findById.mockImplementationOnce(() => ({
    select: jest.fn(() => Promise.resolve(user)),
  }));
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe('mfaController 安全编排分支', () => {
  test('mfaEnable 在用户启用后拒绝重复开启', async () => {
    whenUserFound({ _id: 'u1', mfaEnabled: true, mfaSecret: 'enc' });

    const res = await invoke(
      controller.mfaEnable,
      makeReq({ body: { mfaCode: '123456' } }),
      makeRes()
    );

    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('MFA_ALREADY_ENABLED');
  });

  test('mfaEnable 在动态码错误时记失败并拒绝同步', async () => {
    whenUserFound({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc' });

    const res = await invoke(
      controller.mfaEnable,
      makeReq({ body: { mfaCode: '654321' } }),
      makeRes()
    );

    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('MFA_CODE_INVALID_SYNC');
  });

  test('mfaEnable 在缺少确认凭据时拒绝', async () => {
    const res = await invoke(controller.mfaEnable, makeReq(), makeRes());

    expect(User.findById).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('MFA_CODE_FORMAT');
  });

  test('mfaDisable 仅提供密码密文时拒绝：密码不再是可单独放行的第二因子', async () => {
    whenUserFound({
      _id: 'u1',
      mfaEnabled: true,
      mfaSecret: 'enc',
      comparePassword: jest.fn(),
    });

    const res = await invoke(
      controller.mfaDisable,
      makeReq({ body: { encCurrentPassword: 'encrypted' } }),
      makeRes()
    );

    expect(res.statusCode).toBe(403);
    expect(res.body.errors.errorCode).toBe('MFA_SECOND_FACTOR_REQUIRED');
    expect(decryptLoginCredential).not.toHaveBeenCalled();
    expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
  });

  test('mfaDisable 在既无动态码也无恢复码时拒绝', async () => {
    whenUserFound({
      _id: 'u1',
      mfaEnabled: true,
      mfaSecret: 'enc',
      comparePassword: jest.fn(),
    });

    const res = await invoke(controller.mfaDisable, makeReq(), makeRes());

    expect(res.statusCode).toBe(403);
    expect(res.body.errors.errorCode).toBe('MFA_SECOND_FACTOR_REQUIRED');
    expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
  });
});
