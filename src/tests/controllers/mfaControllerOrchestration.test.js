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
jest.mock('../../services/mfaService', () => ({
  hashRecoveryCode: jest.fn((code) => `hash:${code}`),
  generateRecoveryCodes: jest.fn(),
  isMfaLocked: jest.fn(),
  recordMfaFailure: jest.fn(),
  resetMfaFailures: jest.fn(),
}));
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

  test('mfaDisable 在关闭密文无效时拒绝且不改动用户', async () => {
    whenUserFound({
      _id: 'u1',
      mfaEnabled: true,
      mfaSecret: 'enc',
      comparePassword: jest.fn(),
    });
    decryptLoginCredential.mockRejectedValueOnce(
      Object.assign(new Error('bad envelope'), { code: 'ENVELOPE_FORMAT' })
    );

    const res = await invoke(
      controller.mfaDisable,
      makeReq({ body: { encCurrentPassword: 'encrypted' } }),
      makeRes()
    );

    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
  });

  test('mfaDisable 在既无动态码也无登录密码时拒绝', async () => {
    whenUserFound({
      _id: 'u1',
      mfaEnabled: true,
      mfaSecret: 'enc',
      comparePassword: jest.fn(),
    });

    const res = await invoke(controller.mfaDisable, makeReq(), makeRes());

    expect(res.statusCode).toBe(403);
    expect(res.body.errors.errorCode).toBe('MFA_VERIFY_FAILED');
    expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
  });
});
