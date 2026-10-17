/**
 * 敏感操作审计的可靠 outbox（F-03，services/auditOutbox.js）
 *
 * 钉住四条语义（这四条合起来才是「返回成功 ⇒ 审计已持久化」）：
 *  ① 落库成功 ⇒ 不写 WAL、不产生失败记账（正常路径零额外开销）；
 *  ② 落库失败 + WAL 可用 ⇒ 文档进 WAL、返回 null（调用方继续回成功），
 *     且 error 日志 + audit_write_failed{high} 指标都在（不静默）；
 *  ③ 落库失败 + 文档本身非法 ⇒ 重抛（写进 WAL 也会被预铸造拒掉，"已落 WAL"是假话）；
 *  ④ 落库失败 + WAL 未启用 ⇒ 重抛（没有可靠介质就不能声称已留痕）。
 *
 * 为什么 ③④ 是重抛而不是"尽力而为"：这两条的共同点是**无法兑现承诺**。
 * 静默返回成功会让客户端与合规审计都以为"操作已记账"，而实际没有任何介质留下它。
 */

// 直接改写真实 model 的静态方法，而不是 `{ ...actual }` 展开：
// 展开会把 mongoose Model（构造器）变成普通对象，`new AuditLog(entry)` 立刻抛
// "AuditLog is not a constructor" —— 而 spool 的 schema 校验正是靠它。
jest.mock('../../models/AuditLog', () => {
  const actual = jest.requireActual('../../models/AuditLog');
  actual.create = jest.fn();
  actual.buildSensitiveActionDoc = jest.fn(() => ({
    action: 'change_password',
    category: 'auth',
  }));
  return actual;
});

jest.mock('../../services/auditBuffer', () => ({
  push: jest.fn(),
  isWalEnabled: jest.fn(() => true),
}));

const AuditLog = require('../../models/AuditLog');
const auditBuffer = require('../../services/auditBuffer');
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');
const { recordDurably, recordSensitiveActionDurably } = require('../../services/auditOutbox');

/** 一份能通过 AuditLog schema 的最小文档 */
const validEntry = () => ({
  action: 'password_changed',
  category: 'auth',
  userId: '507f1f77bcf86cd799439011',
  username: 'alice',
  success: true,
});

beforeEach(() => {
  jest.clearAllMocks();
  jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
  jest.spyOn(logger, 'error').mockImplementation(() => {});
  jest.spyOn(logger, 'warn').mockImplementation(() => {});
  auditBuffer.isWalEnabled.mockReturnValue(true);
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('F-03 审计可靠 outbox', () => {
  test('落库成功 ⇒ 不写 WAL、不产生失败记账', async () => {
    AuditLog.create.mockResolvedValue({ _id: 'audit-1' });
    const doc = await recordDurably(validEntry(), { auditAction: 'password_changed' });
    expect(doc).toEqual({ _id: 'audit-1' });
    expect(auditBuffer.push).not.toHaveBeenCalled();
    expect(metrics.incSecurityAlert).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('落库失败 + WAL 可用 ⇒ 转 WAL，返回 null，且失败可观测', async () => {
    AuditLog.create.mockRejectedValue(new Error('db down'));
    const doc = await recordDurably(validEntry(), { auditAction: 'password_changed' });

    // 调用方据此继续回成功——前提是文档已经进了可重放的介质
    expect(doc).toBeNull();
    expect(auditBuffer.push).toHaveBeenCalledTimes(1);
    const spooled = auditBuffer.push.mock.calls[0][0];
    expect(spooled).toMatchObject({ action: 'password_changed', category: 'auth' });

    // 不静默：error 日志 + high 档指标 + 一条"已补偿"的 warn
    expect(metrics.incSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('审计写入失败'),
      expect.objectContaining({ auditAction: 'password_changed' })
    );
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('已转入审计 WAL'));
  });

  test('落库失败 + 文档非法 ⇒ 重抛，且绝不写 WAL（"已落 WAL"会是假话）', async () => {
    AuditLog.create.mockRejectedValue(new Error('validation failed'));
    await expect(
      recordDurably({ action: 'not-a-real-action', category: 'nope' }, { auditAction: 'x' })
    ).rejects.toThrow('validation failed');
    expect(auditBuffer.push).not.toHaveBeenCalled();
  });

  test('落库失败 + WAL 未启用 ⇒ 重抛（没有可靠介质就不许声称已留痕）', async () => {
    AuditLog.create.mockRejectedValue(new Error('db down'));
    auditBuffer.isWalEnabled.mockReturnValue(false);
    await expect(recordDurably(validEntry(), { auditAction: 'password_changed' })).rejects.toThrow(
      'db down'
    );
    expect(auditBuffer.push).not.toHaveBeenCalled();
  });

  test('recordSensitiveActionDurably 复用模型上的字段构造（口径不分叉）', async () => {
    AuditLog.create.mockResolvedValue({ _id: 'audit-2' });
    const req = { method: 'PUT', ip: '203.0.113.9', user: { username: 'alice' } };
    const res = { statusCode: 200 };

    await recordSensitiveActionDurably({
      userId: 'u-1',
      username: 'alice',
      action: 'change_password',
      category: 'auth',
      req,
      res,
      auditAction: 'password_changed',
    });

    expect(AuditLog.buildSensitiveActionDoc).toHaveBeenCalledWith(
      'u-1',
      'alice',
      'change_password',
      'auth',
      req,
      res,
      undefined
    );
    expect(AuditLog.create).toHaveBeenCalledWith({
      action: 'change_password',
      category: 'auth',
    });
  });
});
