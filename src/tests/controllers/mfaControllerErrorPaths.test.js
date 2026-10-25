/**
 * T-1：mfaController 错误路径补测（分支覆盖率 64.58% → ≥80%）
 *
 * 审计 §7.2 T-1 指出：MFA 是账号的第二道防线，但控制器里大量「拒绝路径」
 * 没有用例——锁定态、重放认领失败后的读回分支、登记/开启的条件更新输家
 * 分支、恢复码重生成的 CAS 输家分支等。这些分支恰恰决定「失败时是否
 * 误发恢复码 / 误报成功」。
 *
 * 本文件只做编排层单元测试：DB、TOTP 原语、审计与 MFA 服务都打桩，
 * 断言的是「给定这些返回值时控制器走哪条分支、回哪个错误码」。
 * 真实 Mongo 下的并发语义由 mfaWriteCasConcurrency / mfaLifecycleTotpClaim 覆盖。
 */

jest.mock('express-validator', () => ({
  validationResult: (req) => ({
    isEmpty: () => !req._invalid,
    array: () => req._errors || [{ msg: 'mock validation error' }],
  }),
}));

jest.mock('../../models/User', () => ({
  findById: jest.fn(),
  findOneAndUpdate: jest.fn(),
}));

jest.mock('../../utils/totp', () => ({
  generateSecret: jest.fn(),
  verifyTotpDetailed: jest.fn(),
  otpauthUri: jest.fn(() => 'otpauth://totp/mock'),
}));

jest.mock('../../utils/mfaSecret', () => ({
  encryptMfaSecret: jest.fn((secret) => `enc:${secret}`),
  decryptMfaSecret: jest.fn(),
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

jest.mock('../../utils/metrics', () => ({
  incMfaAction: jest.fn(),
}));

jest.mock('../../services/auditOutbox', () => ({
  recordDurably: jest.fn(async () => undefined),
}));

jest.mock('../../services/mfaDisable', () => ({
  disableWithSecondFactor: jest.fn(),
}));

jest.mock('../../services/mfaService', () => {
  const actual = jest.requireActual('../../services/mfaService');
  return {
    ...actual,
    hashRecoveryCode: jest.fn((code) => `hash:${code}`),
    generateRecoveryCodes: jest.fn(),
    isMfaLocked: jest.fn(),
    recordMfaFailure: jest.fn(async () => undefined),
    resetMfaFailures: jest.fn(async () => undefined),
    claimTotpWindow: jest.fn(),
    recordMfaFailureAudit: jest.fn(),
    recordMfaDisableFailure: jest.fn(),
    recordMfaDisableSuccess: jest.fn(async () => undefined),
    revokeOtherSessionsAfterMfaChange: jest.fn(async () => undefined),
  };
});

const User = require('../../models/User');
const totp = require('../../utils/totp');
const mfaSecret = require('../../utils/mfaSecret');
const mfaService = require('../../services/mfaService');
const { disableWithSecondFactor } = require('../../services/mfaDisable');
const logger = require('../../utils/logger');
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
  return res;
};

const makeReq = (over = {}) => ({
  body: {},
  ip: '127.0.0.1',
  get: jest.fn(() => 'jest-agent'),
  user: { userId: 'user-id', username: 'alice', sid: 'sid-1' },
  ...over,
});

const invoke = async (fn, req) => {
  const res = makeRes();
  const next = jest.fn((error) => {
    if (error) throw error;
  });
  await fn(req, res, next);
  return res;
};

/** 按调用顺序排队 findById 的返回值（每次返回带 select 的链式对象） */
const queueUserLookups = (...users) => {
  for (const user of users) {
    User.findById.mockImplementationOnce(() => ({
      select: jest.fn(() => Promise.resolve(user)),
    }));
  }
};

const errorCodeOf = (res) => res.body.errors.errorCode;

beforeEach(() => {
  jest.clearAllMocks();
  totp.verifyTotpDetailed.mockReturnValue({ valid: false, counter: 0 });
  mfaSecret.decryptMfaSecret.mockReturnValue('SECRET');
  mfaService.isMfaLocked.mockResolvedValue(false);
  mfaService.claimTotpWindow.mockResolvedValue(true);
  mfaService.generateRecoveryCodes.mockReturnValue(
    Array.from({ length: 10 }, (_, i) => `CODE${i}`)
  );
  totp.generateSecret.mockReturnValue('NEWSECRET');
});

describe('regenerateRecoveryCodes 错误路径', () => {
  test('校验失败：不查库，直接 VALIDATION_FAILED', async () => {
    const res = await invoke(controller.regenerateRecoveryCodes, makeReq({ _invalid: true }));

    expect(User.findById).not.toHaveBeenCalled();
    expect(errorCodeOf(res)).toBe('VALIDATION_FAILED');
  });

  test('MFA 未开启或密钥缺失：MFA_NOT_ENABLED_NO_CODES', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaRecoveryCodes: [] });

    const res = await invoke(
      controller.regenerateRecoveryCodes,
      makeReq({ body: { mfaCode: '123456' } })
    );

    expect(errorCodeOf(res)).toBe('MFA_NOT_ENABLED_NO_CODES');
    expect(totp.verifyTotpDetailed).not.toHaveBeenCalled();
  });

  test('锁定态：不校验动态码，直接 MFA_ATTEMPTS_EXCEEDED', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: true, mfaSecret: 'enc:ok', mfaRecoveryCodes: [] });
    mfaService.isMfaLocked.mockResolvedValue(true);

    const res = await invoke(
      controller.regenerateRecoveryCodes,
      makeReq({ body: { mfaCode: '123456' } })
    );

    expect(errorCodeOf(res)).toBe('MFA_ATTEMPTS_EXCEEDED');
    expect(totp.verifyTotpDetailed).not.toHaveBeenCalled();
  });

  test('非字符串 mfaCode 归一为空串：按无效动态码拒绝（不抛类型错）', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: true, mfaSecret: 'enc:ok', mfaRecoveryCodes: [] });

    const res = await invoke(
      controller.regenerateRecoveryCodes,
      makeReq({ body: { mfaCode: 123456 } })
    );

    expect(totp.verifyTotpDetailed).toHaveBeenCalledWith('SECRET', '');
    expect(errorCodeOf(res)).toBe('MFA_REGEN_CODE_INVALID');
    expect(mfaService.recordMfaFailure).toHaveBeenCalled();
  });

  test('CAS 输家且用户已关闭 MFA：不回发本次恢复码，返回 MFA_NOT_ENABLED_NO_CODES', async () => {
    queueUserLookups(
      { _id: 'u1', mfaEnabled: true, mfaSecret: 'enc:ok', mfaRecoveryCodes: ['h1'] },
      { _id: 'u1', mfaEnabled: false } // 条件更新失败后的重读
    );
    totp.verifyTotpDetailed.mockReturnValue({ valid: true, counter: 7 });
    User.findOneAndUpdate.mockResolvedValueOnce(null);

    const res = await invoke(
      controller.regenerateRecoveryCodes,
      makeReq({ body: { mfaCode: '123456' } })
    );

    expect(errorCodeOf(res)).toBe('MFA_NOT_ENABLED_NO_CODES');
    expect(res.body.success).toBe(false);
    expect(res.body.data).toBeUndefined();
  });
});

describe('mfaEnroll 错误路径与 CAS 输家', () => {
  test('待确认密钥无法解密：告警后重新生成（不返回废二维码）', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc:broken' });
    mfaSecret.decryptMfaSecret.mockReturnValue(null);
    User.findOneAndUpdate.mockResolvedValueOnce({ _id: 'u1' });

    const res = await invoke(controller.mfaEnroll, makeReq());

    expect(logger.warn).toHaveBeenCalledWith(
      'MFA 待确认密钥无法解密，将重新生成',
      expect.objectContaining({ userId: 'u1' })
    );
    expect(res.statusCode).toBe(200);
    expect(res.body.data.secret).toBe('NEWSECRET');
  });

  test('CAS 输家且用户已被删除：AUTH_USER_NOT_FOUND', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: '' }, null);
    User.findOneAndUpdate.mockResolvedValueOnce(null);

    const res = await invoke(controller.mfaEnroll, makeReq());

    expect(errorCodeOf(res)).toBe('AUTH_USER_NOT_FOUND');
  });

  test('CAS 输家且并发请求已开启：MFA_ALREADY_ENABLED_NO_REPEAT', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: '' }, { mfaEnabled: true });
    User.findOneAndUpdate.mockResolvedValueOnce(null);

    const res = await invoke(controller.mfaEnroll, makeReq());

    expect(errorCodeOf(res)).toBe('MFA_ALREADY_ENABLED_NO_REPEAT');
  });

  test('CAS 输家且赢家密钥也不可解密：USER_STATE_CONFLICT，绝不盲覆盖', async () => {
    queueUserLookups(
      { _id: 'u1', mfaEnabled: false, mfaSecret: '' },
      { mfaEnabled: false, mfaSecret: 'enc:broken' }
    );
    User.findOneAndUpdate.mockResolvedValueOnce(null);
    mfaSecret.decryptMfaSecret.mockReturnValue(null);

    const res = await invoke(controller.mfaEnroll, makeReq());

    expect(errorCodeOf(res)).toBe('USER_STATE_CONFLICT');
  });

  test('CAS 输家但赢家密钥可用：返回同一把密钥（本次配置的唯一事实）', async () => {
    queueUserLookups(
      { _id: 'u1', mfaEnabled: false, mfaSecret: '' },
      { mfaEnabled: false, mfaSecret: 'enc:WINNER' }
    );
    User.findOneAndUpdate.mockResolvedValueOnce(null);
    mfaSecret.decryptMfaSecret.mockReturnValue('WINNER');

    const res = await invoke(controller.mfaEnroll, makeReq());

    expect(res.statusCode).toBe(200);
    expect(res.body.data.secret).toBe('WINNER');
  });
});

describe('mfaEnable 错误路径与 CAS 输家', () => {
  test('锁定态：不校验动态码，直接 MFA_ATTEMPTS_EXCEEDED', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc:ok' });
    mfaService.isMfaLocked.mockResolvedValue(true);

    const res = await invoke(controller.mfaEnable, makeReq({ body: { mfaCode: '123456' } }));

    expect(errorCodeOf(res)).toBe('MFA_ATTEMPTS_EXCEEDED');
    expect(totp.verifyTotpDetailed).not.toHaveBeenCalled();
  });

  test('CAS 输家且用户已被删除：AUTH_USER_NOT_FOUND，不回发恢复码', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc:ok' }, null);
    totp.verifyTotpDetailed.mockReturnValue({ valid: true, counter: 9 });
    User.findOneAndUpdate.mockResolvedValueOnce(null);

    const res = await invoke(controller.mfaEnable, makeReq({ body: { mfaCode: '123456' } }));

    expect(errorCodeOf(res)).toBe('AUTH_USER_NOT_FOUND');
    expect(res.body.data).toBeUndefined();
  });

  test('CAS 输家且已被并发开启：MFA_ALREADY_ENABLED，不回发恢复码', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: false, mfaSecret: 'enc:ok' }, { mfaEnabled: true });
    totp.verifyTotpDetailed.mockReturnValue({ valid: true, counter: 9 });
    User.findOneAndUpdate.mockResolvedValueOnce(null);

    const res = await invoke(controller.mfaEnable, makeReq({ body: { mfaCode: '123456' } }));

    expect(errorCodeOf(res)).toBe('MFA_ALREADY_ENABLED');
    expect(res.body.data).toBeUndefined();
  });
});

describe('mfaDisable 错误路径', () => {
  test('校验失败：不查库，直接 VALIDATION_FAILED', async () => {
    const res = await invoke(controller.mfaDisable, makeReq({ _invalid: true }));

    expect(User.findById).not.toHaveBeenCalled();
    expect(errorCodeOf(res)).toBe('VALIDATION_FAILED');
  });

  test('锁定态：恢复码路径同样被拦住（不能绕过 TOTP 限额）', async () => {
    queueUserLookups({ _id: 'u1', mfaEnabled: true, mfaSecret: 'enc:ok' });
    mfaService.isMfaLocked.mockResolvedValue(true);

    const res = await invoke(
      controller.mfaDisable,
      makeReq({ body: { recoveryCode: 'ABCD-EFGH' } })
    );

    expect(errorCodeOf(res)).toBe('MFA_ATTEMPTS_EXCEEDED');
    expect(disableWithSecondFactor).not.toHaveBeenCalled();
  });
});

describe('getMfaStatus：状态查询端点（此前零用例，函数覆盖缺的那一格）', () => {
  // 这个端点只读，但它是前端「恢复码余量」提示的唯一数据源：余量报错会让人
  // 以为还有备用码，真到丢失认证器那天才发现没有。
  test('已开启：如实回报剩余恢复码数量（不暴露码本身）', async () => {
    queueUserLookups({ mfaEnabled: true, mfaRecoveryCodes: ['a', 'b', 'c'] });
    const res = await invoke(controller.getMfaStatus, makeReq());

    expect(res.statusCode).toBe(200);
    expect(res.body.data).toEqual({ enabled: true, recoveryCodesRemaining: 3 });
    // 反向：响应体里不得出现码本身
    expect(JSON.stringify(res.body)).not.toContain('"a"');
  });

  test('已关闭且恢复码已清空：余量为 0（而不是 undefined/缺字段）', async () => {
    queueUserLookups({ mfaEnabled: false, mfaRecoveryCodes: [] });
    const res = await invoke(controller.getMfaStatus, makeReq());

    expect(res.body.data).toEqual({ enabled: false, recoveryCodesRemaining: 0 });
  });

  test('用户不存在：按未开启处理，不抛错（避免探针把 500 当成状态未知）', async () => {
    queueUserLookups(null);
    const res = await invoke(controller.getMfaStatus, makeReq());

    expect(res.body.data).toEqual({ enabled: false, recoveryCodesRemaining: 0 });
  });
});
