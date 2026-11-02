/**
 * 启动期密钥治理留痕（services/startupAuditTrail.js）
 *
 * 为什么值得单独一套：这段逻辑从 src/index.js 抽出，而 index.js 被 collectCoverageFrom
 * 排除——抽出后它就落进了覆盖率分母。若不补测，等于「拆文件」顺手把一段生产逻辑
 * 变成不可见代码；而它承担的正是「密钥治理持续有效」的事后证据，退化的形态不是报错，
 * 而是**少一条审计**（安全结论错误，最不该被均值稀释的那类）。
 *
 * 判据口径：本模块对外的唯一承诺是「不阻断启动」——两条写入失败都必须只告警、
 * 不抛。所以用例除正向断言外，专门覆盖两个 catch 分支。
 */

jest.mock('../../config/validate', () => ({
  requiresProductionSemantics: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(),
}));
jest.mock('../../services/jwtKeyRotationAudit', () => ({
  recordJwtKeyRotation: jest.fn(),
}));

const { requiresProductionSemantics } = require('../../config/validate');
const AuditLog = require('../../models/AuditLog');
const { recordJwtKeyRotation } = require('../../services/jwtKeyRotationAudit');
const logger = require('../../utils/logger');
const { recordStartupAuditTrail } = require('../../services/startupAuditTrail');

describe('services/startupAuditTrail — 启动期密钥治理留痕', () => {
  let warnSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    AuditLog.record.mockResolvedValue({});
    recordJwtKeyRotation.mockResolvedValue(undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('非生产语义：两条留痕都不写（弱密钥已在 config/validate 阻断级拦截）', async () => {
    requiresProductionSemantics.mockReturnValue(false);

    await recordStartupAuditTrail();

    expect(AuditLog.record).not.toHaveBeenCalled();
    expect(recordJwtKeyRotation).not.toHaveBeenCalled();
  });

  test('生产语义：先记密钥强度审计，再记 JWT 轮换', async () => {
    requiresProductionSemantics.mockReturnValue(true);

    await recordStartupAuditTrail();

    expect(AuditLog.record).toHaveBeenCalledTimes(1);
    const payload = AuditLog.record.mock.calls[0][0];
    expect(payload).toMatchObject({
      action: 'security_key_strength_audit',
      category: 'security',
      username: 'system',
      success: true,
      riskLevel: 'low',
    });
    expect(payload.reason).toContain('密钥均满足强度要求');
    expect(recordJwtKeyRotation).toHaveBeenCalledTimes(1);
  });

  test('密钥强度审计写入失败：只告警，不抛出，且不阻断轮换留痕', async () => {
    requiresProductionSemantics.mockReturnValue(true);
    AuditLog.record.mockRejectedValue(new Error('mongo down'));

    await expect(recordStartupAuditTrail()).resolves.toBeUndefined();

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('密钥强度审计留痕写入失败'));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('mongo down'));
    // 关键：前一步失败不得短路后一步（原 index.js 内联实现即如此）
    expect(recordJwtKeyRotation).toHaveBeenCalledTimes(1);
  });

  test('JWT 轮换留痕失败：同样只告警不抛出', async () => {
    requiresProductionSemantics.mockReturnValue(true);
    recordJwtKeyRotation.mockRejectedValue(new Error('kid read failed'));

    await expect(recordStartupAuditTrail()).resolves.toBeUndefined();

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('JWT 密钥轮换审计留痕失败'));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('kid read failed'));
  });
});
