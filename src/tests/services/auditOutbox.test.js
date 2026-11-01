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
  // 替身：真实 auditBuffer.assignDocId 是纯函数（没有 _id 就补一个新的），这里按同语义
  // 内联实现，而不是 `jest.fn(() => doc)`——后者会让「WAL 行带 _id」这条断言假绿。
  // 不 requireActual 真实模块：它会把真实 wal 依赖也拖进来（本文件把 wal 也 mock 了）。
  assignDocId: (doc) => {
    const { Types } = jest.requireActual('mongoose');
    if (doc && !doc._id) doc._id = new Types.ObjectId();
    return doc;
  },
}));

jest.mock('../../services/auditBufferWal', () => ({
  assignSeq: jest.fn(),
  appendLineDurable: jest.fn(() => Promise.resolve(true)),
}));

const AuditLog = require('../../models/AuditLog');
const auditBuffer = require('../../services/auditBuffer');
const wal = require('../../services/auditBufferWal');
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
    expect(wal.appendLineDurable).not.toHaveBeenCalled();
    expect(metrics.incSecurityAlert).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('落库失败 + WAL 可用 ⇒ 转 WAL，返回 null，且失败可观测', async () => {
    AuditLog.create.mockRejectedValue(new Error('db down'));
    const doc = await recordDurably(validEntry(), { auditAction: 'password_changed' });

    // 调用方据此继续回成功——前提是文档已经进了可重放的介质
    expect(doc).toBeNull();
    expect(wal.appendLineDurable).toHaveBeenCalledTimes(1);
    const line = wal.appendLineDurable.mock.calls[0][0];
    expect(JSON.parse(line)).toMatchObject({ action: 'password_changed', category: 'auth' });
    // 身份键必须进 WAL 行：跨重启重放靠它撞唯一索引实现幂等（见 auditBuffer.assignDocId）
    expect(JSON.parse(line)._id).toMatch(/^[0-9a-f]{24}$/);
    // 已等待 WAL 落盘，进缓冲时不得再 fire-and-forget 追加一次（否则 WAL 行重复）
    expect(auditBuffer.push).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'password_changed', category: 'auth' }),
      true
    );

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
    expect(wal.appendLineDurable).not.toHaveBeenCalled();
  });

  test('落库失败 + WAL 追加失败 ⇒ 重抛（fsync 没成功就不能声称已留痕）', async () => {
    AuditLog.create.mockRejectedValue(new Error('db down'));
    wal.appendLineDurable.mockResolvedValueOnce(false);

    await expect(recordDurably(validEntry(), { auditAction: 'password_changed' })).rejects.toThrow(
      'db down'
    );
    expect(wal.appendLineDurable).toHaveBeenCalledTimes(1);
    // fsync 没成功 ⇒ 绝不能进缓冲（否则重放会把它当已持久化）
    expect(auditBuffer.push).not.toHaveBeenCalled();
  });

  test('落库失败 + WAL 未启用 ⇒ 重抛（没有可靠介质就不许声称已留痕）', async () => {
    AuditLog.create.mockRejectedValue(new Error('db down'));
    auditBuffer.isWalEnabled.mockReturnValue(false);
    await expect(recordDurably(validEntry(), { auditAction: 'password_changed' })).rejects.toThrow(
      'db down'
    );
    expect(auditBuffer.push).not.toHaveBeenCalled();
    expect(wal.appendLineDurable).not.toHaveBeenCalled();
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
