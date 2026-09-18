/**
 * 手写审计写入失败处理器（P0-5 回归防护）单测
 *
 * 为什么需要：P0-5 修复后 `res.locals.skipGlobalAudit` 真正生效，「控制器手写
 * AuditLog.create」成为该类操作在审计库中的**唯一留痕**。修复前该标志恒失效、
 * 全局中间件总会补记一条，故控制器侧 `.catch(() => {})` 静默吞错仍有兜底；
 * 修复后同样的静默吞错会让整个操作**零留痕**且无任何可观测信号。
 *
 * 本测试锁定三件事（任一被破坏都会红）：
 *   1. 失败时确实写 error 日志（含可检索的 auditAction 与 operator）；
 *   2. 失败时确实计入 security_alerts_total{type=audit_write_failed}；
 *   3. 失败不冒泡（返回 undefined，调用方 await 不抛）——业务不被审计故障阻断。
 *
 * 另含「指标端故障时不得反过来炸掉调用方」的兜底用例。
 */

const mockLogger = { error: jest.fn(), warn: jest.fn(), info: jest.fn() };
const mockIncSecurityAlert = jest.fn();

jest.mock('../../utils/logger', () => mockLogger);
jest.mock('../../utils/metrics', () => ({
  incSecurityAlert: (...args) => mockIncSecurityAlert(...args),
}));

const { onAuditWriteFailure } = require('../../utils/auditWriteFailure');

beforeEach(() => {
  jest.clearAllMocks();
});

describe('onAuditWriteFailure（P0-5 回归防护）', () => {
  test('写 error 日志：含 {审计写入失败} 前缀、auditAction 与 operator', () => {
    const req = { user: { username: 'alice' } };
    onAuditWriteFailure('security_config_change', req)(new Error('mongo down'));

    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    const [message, meta] = mockLogger.error.mock.calls[0];
    expect(message).toContain('审计写入失败');
    expect(message).toContain('mongo down');
    expect(meta).toEqual({ auditAction: 'security_config_change', operator: 'alice' });
  });

  test('计入 security_alerts_total{type=audit_write_failed, level=high}', () => {
    onAuditWriteFailure('ip_list_change', { user: { username: 'bob' } })(new Error('x'));
    expect(mockIncSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
  });

  test('失败不冒泡：处理器同步返回 undefined，不抛错（业务不被审计故障阻断）', () => {
    const handler = onAuditWriteFailure('audit_chain_verify', undefined);
    expect(() => handler(new Error('boom'))).not.toThrow();
    expect(handler(new Error('boom'))).toBeUndefined();
  });

  test('req 缺省或 user 缺失时 operator 为 undefined，但日志与指标照常', () => {
    onAuditWriteFailure('audit_chain_verify')(new Error('no req'));

    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    expect(mockLogger.error.mock.calls[0][1]).toEqual({
      auditAction: 'audit_chain_verify',
      operator: undefined,
    });
    expect(mockIncSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
  });

  test('指标端自身抛错时不得反向炸掉调用方（仅保留日志）', () => {
    mockIncSecurityAlert.mockImplementationOnce(() => {
      throw new Error('metrics exploded');
    });
    expect(() =>
      onAuditWriteFailure('ip_list_change', undefined)(new Error('db down'))
    ).not.toThrow();
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
  });
});
