/**
 * 取证捕获：告警通道自身故障不得穿透 fail-open 边界（round-14 P0-1 / P0-2 回归）
 *
 * 这里的 incSecurityAlert 被替换成**必抛**的桩：这是唯一能证明"告警抛错时仍不丢批、
 * 仍不外抛"的方法——真实现内部自带 try/catch，所以在集成层面这个缺陷是潜伏的，
 * 但它把 fail-open 的正确性押在了"另一个模块今天恰好不抛"上。契约要求是绝对口径。
 */

process.env.FORENSIC_CAPTURE_ENABLED = 'true';
process.env.FORENSIC_WAL_PATH = '';

const mockState = { alertThrows: true, alertCalls: [] };
jest.mock('../../utils/metrics', () => ({
  incSecurityAlert: (type, level) => {
    mockState.alertCalls.push([type, level]);
    if (mockState.alertThrows) throw new Error('metrics boom');
  },
}));

const mockTrigger = { target: null, throws: false };
jest.mock('../../services/forensicTrigger', () => ({
  isForensicTarget: () => {
    if (mockTrigger.throws) throw new Error('trigger boom');
    return Boolean(mockTrigger.target);
  },
  getForensicTarget: () => mockTrigger.target,
  markForensicTarget: () => true,
  clearForensicTarget: () => true,
  getForensicTriggerStats: () => ({ enabled: true, lastMark: null }),
}));

jest.mock('../../models/ForensicCapture', () => ({
  insertMany: jest.fn(async () => ({ insertedCount: 1 })),
  find: jest.fn(async () => []),
}));

const svc = require('../../services/forensicCapture');
const Model = require('../../models/ForensicCapture');

const reqOf = () => ({
  method: 'POST',
  originalUrl: '/api/probe',
  path: '/api/probe',
  query: {},
  params: {},
  httpVersion: '1.1',
  headers: { 'user-agent': 'jest' },
  get(name) {
    return this.headers[String(name).toLowerCase()];
  },
});
const recordOne = (ip = '203.0.113.7') =>
  svc.record({
    req: reqOf(),
    ip,
    trigger: null,
    response: { status: 200, headers: {}, contentType: 'application/json', body: '{}' },
  });

beforeEach(() => {
  svc.resetForTests();
  mockState.alertThrows = true;
  mockState.alertCalls = [];
  mockTrigger.throws = false;
  mockTrigger.target = {
    reason: 'honeypot_login',
    source: 'hook',
    evidence: null,
    markedAt: new Date(0),
    ttlMs: 1000,
  };
  Model.insertMany.mockReset();
  Model.insertMany.mockImplementation(async () => ({ insertedCount: 1 }));
  Model.find.mockImplementation(async () => []);
});

describe('告警抛错时的取证行为', () => {
  test('触发判据不可用 + 告警抛错：shouldCapture 返回 false 且绝不冒泡', () => {
    mockTrigger.throws = true;
    // 判据抛错 ⇒ 跳过捕获；同时告警通道也在抛错，两者叠加仍不得外抛
    expect(() => svc.shouldCapture('203.0.113.7')).not.toThrow();
    expect(svc.shouldCapture('203.0.113.7')).toBe(false);
    // 降级被计数、被留痕（fail-visible），且告警确实被尝试过（隔离而非"没调用"）
    const stats = svc.getForensicCaptureStats();
    expect(stats.rejected).toBeGreaterThanOrEqual(2);
    expect(stats.lastError || '').toContain('trigger boom');
    expect(mockState.alertCalls.some(([t2]) => t2 === 'forensic_capture_trigger_unavailable')).toBe(
      true
    );
  });

  test('落库失败 + 告警抛错：整批仍被回填，计数与 lastError 都在，flush 不外抛', async () => {
    Model.insertMany.mockImplementation(async () => {
      throw new Error('db down');
    });
    recordOne();
    await expect(svc.flush()).resolves.toBeUndefined();

    const stats = svc.getForensicCaptureStats();
    // 这两条同时成立才说明"回填一定发生在告警之前"：
    //   ① 错误被记下来（说明 catch 走到了）；② 缓冲没被掏空（说明回填没被告警炸掉）
    expect(stats.lastError).toContain('db down');
    // 契约 §2.2 只冻结七个字段：诊断用的累计次数不上统计面，避免改口径
    expect(Object.keys(stats).sort()).toEqual([
      'bytes',
      'captured',
      'dropped',
      'lastError',
      'rejected',
      'sampled',
      'walDropped',
    ]);
    // 告警确实抛了（证明隔离生效，而不是"根本没调用"）
    expect(mockState.alertCalls.length).toBeGreaterThanOrEqual(1);

    // 重试能成功：回填真的在缓冲里
    Model.insertMany.mockImplementation(async () => ({ insertedCount: 1 }));
    await svc.flush();
    expect(Model.insertMany).toHaveBeenCalledTimes(2);
  });
});
