'use strict';

/**
 * MFA 服务的两条 fail-soft / fail-open 边界：
 *  1) 开关 MFA 后吊销其他设备会话失败：状态已落库，会话吊销只是加强项，
 *     失败必须只留 error 痕迹，不能把已成功的 MFA 变更回滚成 500；
 *  2) 配置模块不可读时恢复码摘要的 pepper 回退环境变量：pepper 缺失会退化成
 *     无盐 sha256，而生产侧由 config/validate 强制注入，本地/测试靠这条回退。
 */

jest.mock('../../services/sessionService', () => ({ revokeOtherSessions: jest.fn() }));

const sessionService = require('../../services/sessionService');
const mfaService = require('../../services/mfaService');

describe('revokeOtherSessionsAfterMfaChange', () => {
  afterEach(() => jest.clearAllMocks());

  test('没有当前 sid（旧令牌无法定向保留）时直接跳过，不查会话表', async () => {
    await expect(
      mfaService.revokeOtherSessionsAfterMfaChange({
        userId: 'u1',
        exceptSid: null,
        username: 'u',
        reason: 'mfa_enabled',
      })
    ).resolves.toBeUndefined();
    expect(sessionService.revokeOtherSessions).not.toHaveBeenCalled();
  });

  test('吊销失败只记录错误，不抛出（MFA 状态已经落库，不能回滚成失败响应）', async () => {
    sessionService.revokeOtherSessions.mockRejectedValue(new Error('session store down'));

    await expect(
      mfaService.revokeOtherSessionsAfterMfaChange({
        userId: 'u1',
        exceptSid: 'sid-1',
        username: 'u',
        reason: 'mfa_disabled',
      })
    ).resolves.toBeUndefined();
    expect(sessionService.revokeOtherSessions).toHaveBeenCalledWith({
      userId: 'u1',
      exceptSid: 'sid-1',
      reason: 'mfa_disabled',
    });
  });
});

describe('getRecoveryPepper', () => {
  test('配置模块不可读时回退 HMAC_SECRET 环境变量', () => {
    const previous = process.env.HMAC_SECRET;
    process.env.HMAC_SECRET = 'env-only-pepper';
    try {
      jest.isolateModules(() => {
        jest.doMock('../../config', () => {
          throw new Error('config unavailable');
        });
        // mfaService 在模块顶层还会 require User/AuditLog，而两者自身就 require config。
        // 不隔离掉它们的话，配置不可读会在模块加载期直接抛出，根本走不到
        // getRecoveryPepper 的 try/catch——测的就不是这条回退了。
        jest.doMock('../../models/User', () => ({}));
        jest.doMock('../../models/AuditLog', () => ({}));
        const isolated = require('../../services/mfaService');
        expect(isolated.getRecoveryPepper()).toBe('env-only-pepper');
      });
    } finally {
      jest.dontMock('../../config');
      jest.dontMock('../../models/User');
      jest.dontMock('../../models/AuditLog');
      if (previous === undefined) delete process.env.HMAC_SECRET;
      else process.env.HMAC_SECRET = previous;
    }
  });
});
