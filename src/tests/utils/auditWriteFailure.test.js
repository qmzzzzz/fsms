/**
 * 手写审计写入失败处理器（回归防护）单测
 *
 * 为什么需要：修复后 `res.locals.skipGlobalAudit` 真正生效，「控制器手写
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
 *
 * 第 6 轮补的两件事（同一纪律，落在"被 catch 的东西不保证是 Error"上）：
 *   4. 记账这一步自己不得抛——原先两处写 `${err.message}`，`Promise.reject(undefined)`
 *      或 `throw '字符串'` 时这里读 `.message` 会再抛一个 TypeError。对
 *      `onAuditWriteFailure` 而言那是登录路径上的一个新 rejection（500 而不是 401）；
 *      对 `guardDetection` 而言那直接违背它 @returns 里"永不 reject"的契约，
 *      而调用方（authService 五处、rbac 一处）全是 `.catch(() => {})` ⇒ 又被吞掉，
 *      最终形态与不修时相同：检测失效且零痕迹。
 *   5. `guardDetection` 与 `onAuditWriteFailure` 观测档位对齐：只写日志的话，
 *      故障期"自动封禁与权限滥用告警整体失效"要人翻日志才发现，监控面没有那一格。
 */

const mockLogger = { error: jest.fn(), warn: jest.fn(), info: jest.fn() };
const mockIncSecurityAlert = jest.fn();

jest.mock('../../utils/logger', () => mockLogger);
jest.mock('../../utils/metrics', () => ({
  incSecurityAlert: (...args) => mockIncSecurityAlert(...args),
}));

const {
  onAuditWriteFailure,
  guardDetection,
  awaitAuditWrite,
} = require('../../utils/auditWriteFailure');

const { flushEventLoop, waitFor } = require('../helpers/waitFor');

beforeEach(() => {
  jest.clearAllMocks();
});

describe('onAuditWriteFailure（回归防护）', () => {
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

describe('被 catch 的东西不保证是 Error（记账代码自己不得抛）', () => {
  test.each([
    ['undefined（Promise.reject() 的形态）', undefined],
    ['字符串（throw "boom" 的形态）', 'boom'],
    ['裸对象（driver 超时里 reject 的形态）', { code: 'BUF_TIMEOUT' }],
    ['数字 0（falsy 但不是 Error）', 0],
  ])('%s ⇒ 日志照写、处理器不抛', (_label, value) => {
    const handler = onAuditWriteFailure('login_audit_write', { user: { username: 'carol' } });
    expect(() => handler(value)).not.toThrow();
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    // 可检索性：日志里必须还能看出"这是一次审计写入失败"，而不是一行 undefined
    expect(mockLogger.error.mock.calls[0][0]).toContain('审计写入失败');
    expect(mockIncSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
  });

  test('正向对照：Error 走的是同一句人话（不是把非 Error 特殊化成另一种文案）', () => {
    onAuditWriteFailure('x', undefined)(new Error('E11000 dup key'));
    expect(mockLogger.error.mock.calls[0][0]).toContain('E11000 dup key');
  });
});

describe('guardDetection：契约"永不 reject"与非 Error 的 reject', () => {
  test('检测函数 reject 一个非 Error 时，包裹层既不抛也不静默', async () => {
    const guarded = guardDetection('暴力破解检测', () => Promise.reject(undefined));
    await expect(guarded('alice', '1.2.3.4')).resolves.toBeUndefined();
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    // 用例按"检测"这一族筛日志，措辞必须含它（防止把无关 error 当成通过）
    expect(mockLogger.error.mock.calls[0][0]).toContain('暴力破解检测失败（本轮不检测）');
  });

  test('故障计入监控面：security_alerts_total{type=security_detection_failed, level=medium}', async () => {
    await guardDetection('权限滥用检测', () => Promise.reject(new Error('count down')))();
    expect(mockIncSecurityAlert).toHaveBeenCalledWith('security_detection_failed', 'medium');
  });

  test('指标端炸了也不得让包裹层 reject（那会被调用方的空 catch 吃掉）', async () => {
    mockIncSecurityAlert.mockImplementationOnce(() => {
      throw new Error('metrics exploded');
    });
    await expect(
      guardDetection('暴力破解检测', () => Promise.reject(new Error('db down')))()
    ).resolves.toBeUndefined();
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
  });

  test('反向保护：检测正常返回时零日志、零告警（不得把成功演成失效）', async () => {
    let called = 0;
    await guardDetection('暴力破解检测', async () => {
      called += 1;
    })('alice', '1.2.3.4');
    expect(called).toBe(1);
    expect(mockLogger.error).not.toHaveBeenCalled();
    expect(mockIncSecurityAlert).not.toHaveBeenCalled();
  });

  test('实参原样透传（包裹层不得改变检测函数的入口形状）', async () => {
    const detect = jest.fn().mockResolvedValue(undefined);
    await guardDetection('暴力破解检测', detect)('alice', '1.2.3.4', { extra: 1 });
    expect(detect).toHaveBeenCalledWith('alice', '1.2.3.4', { extra: 1 });
  });
});

describe('awaitAuditWrite：超时后迟到失败的单独记账（F-01）', () => {
  const deferred = () => {
    let settle;
    let fail;
    const promise = new Promise((resolve, reject) => {
      settle = resolve;
      fail = reject;
    });
    return { promise, settle, fail };
  };

  test('超时后才失败 ⇒ 除超时那条外，迟到失败必须再单独记一次（修前此处只记超时）', async () => {
    const gate = deferred();
    await awaitAuditWrite(gate.promise, 'late_write_fail', { user: { username: 'dave' } }, 10);
    expect(mockLogger.error).toHaveBeenCalledTimes(1); // 返回时只有超时那条
    gate.fail(new Error('迟到写库失败'));
    await waitFor(() => mockLogger.error.mock.calls.length === 2, { label: '迟到记账出现' });
    const [message, meta] = mockLogger.error.mock.calls[1];
    expect(message).toContain('迟到写库失败');
    expect(message).toContain('迟到记账');
    expect(meta).toEqual({ auditAction: 'late_write_fail', operator: 'dave' });
    expect(mockIncSecurityAlert).toHaveBeenCalledTimes(2);
  });

  test('超时时限生效：返回时只记了超时那一条（写入仍在途，没有被等）', async () => {
    const gate = deferred();
    await awaitAuditWrite(gate.promise, 'bounded_wait', undefined, 20);
    expect(mockLogger.error).toHaveBeenCalledTimes(1); // 真正的证据：闸到点即返回，写入尚未落地
    gate.fail(new Error('晚到'));
    await waitFor(() => mockLogger.error.mock.calls.length === 2, {
      label: '迟到记账出现（时限用例）',
    });
  });

  test('迟到失败不得变成 unhandledRejection（接住它的那条链自己也不得抛）', async () => {
    const escapes = [];
    const onEscape = (reason) => escapes.push(reason);
    process.on('unhandledRejection', onEscape);
    try {
      const gate = deferred();
      await awaitAuditWrite(gate.promise, 'late_rejection_escape', undefined, 10);
      gate.fail(new Error('不得逃逸'));
      await waitFor(() => mockLogger.error.mock.calls.length === 2, {
        label: '迟到记账出现（逃逸面）',
      });
      expect(escapes).toEqual([]);
    } finally {
      process.removeListener('unhandledRejection', onEscape);
    }
  });

  test('超时后写入最终成功：只记超时，不得凭空多记一条失败', async () => {
    const gate = deferred();
    await awaitAuditWrite(gate.promise, 'late_write_ok', undefined, 10);
    gate.settle('ok');
    await flushEventLoop(2); // 反向断言没有可等待的条件：只让出事件循环，不承诺时长
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    expect(mockIncSecurityAlert).toHaveBeenCalledTimes(1);
  });

  test('未超时就失败：仍只记一次，且不得出现“迟到记账”字样（防重复记账）', async () => {
    await awaitAuditWrite(Promise.reject(new Error('早到失败')), 'early_write_fail', undefined, 50);
    await flushEventLoop(2);
    expect(mockLogger.error).toHaveBeenCalledTimes(1);
    expect(mockLogger.error.mock.calls[0][0]).toContain('早到失败');
    expect(mockLogger.error.mock.calls[0][0]).not.toContain('迟到记账');
  });

  test('迟到值不可读（取 .then 抛错）时也不得留下 unhandledRejection', async () => {
    const escapes = [];
    const onEscape = (reason) => escapes.push(reason);
    process.on('unhandledRejection', onEscape);
    try {
      const gate = deferred();
      await awaitAuditWrite(gate.promise, 'late_unreadable', undefined, 10);
      // 被 catch 的值不保证可读：settled 的 onRejected 原样返回它，解析过程会再取一次 .then
      gate.fail({
        get then() {
          throw new Error('不可读的迟到值');
        },
      });
      // 反向断言没有可等待的条件；Node 在「本 tick 微任务清空后」才判定未处理拒绝，故跨过该时点再断言
      await flushEventLoop(3);
      expect(escapes).toEqual([]);
    } finally {
      process.removeListener('unhandledRejection', onEscape);
    }
  });
});
