/**
 * 攻击检测面单测（W1/W2）：injectionDetector 与 scanProbeDetector 的纯逻辑面。
 *
 * 模型边界全部 mock：本文件钉「输入 → 检测行为」矩阵（留痕/去重/风暴阈值/fail-open），
 * 真实 HTTP 链路（sanitize 剥离 → 留痕、SPA 吞没 → 计数）由
 * tests/middleware/attackDetectionIntegration.test.js 在真实 express + 内存 Mongo 上钉。
 */

'use strict';

jest.mock('../../models/AuditLog', () => ({ record: jest.fn() }));
jest.mock('../../utils/metrics', () => ({ incSecurityAlert: jest.fn() }));
jest.mock('../../services/forensicTrigger', () => ({ markForensicTarget: jest.fn() }));
jest.mock('../../utils/fingerprint', () => ({ computeFingerprint: jest.fn(() => 'fp-stub') }));
jest.mock('../../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));
// auditClientAddress 按桩取 ip（真实实现依赖 socket/头袋，桩上不可用）；其余保持真身
jest.mock('../../utils/ipUtils', () => ({
  ...jest.requireActual('../../utils/ipUtils'),
  auditClientAddress: (req) => ({ ip: req.__testIp || '203.0.113.1' }),
}));

const AuditLog = require('../../models/AuditLog');
const { incSecurityAlert } = require('../../utils/metrics');
const { markForensicTarget } = require('../../services/forensicTrigger');

// 风暴阈值压到 3：模块在 require 时读 env，必须先设再 require
process.env.SCAN_404_THRESHOLD = '3';
process.env.SCAN_404_WINDOW_MS = '60000';
const {
  recordNosqlStripAttempt,
  resetInjectionDetector,
} = require('../../services/injectionDetector');
const {
  noteUnmatchedRequest,
  resetScanProbeDetector,
  KNOWN_SCANNER_UA_RE,
} = require('../../services/scanProbeDetector');

const reqStub = (over = {}) => ({
  method: 'GET',
  path: '/whatever',
  originalUrl: '/whatever',
  headers: {},
  get: () => 'jest/1.0',
  user: null,
  ...over,
});

const rowsByAction = (action) =>
  AuditLog.record.mock.calls.map(([entry]) => entry).filter((e) => e.action === action);

/** 等 setImmediate 里的直写落地 */
const flushWrites = () => new Promise((resolve) => setImmediate(() => setImmediate(resolve)));

beforeEach(() => {
  jest.clearAllMocks();
  AuditLog.record.mockReturnValue(Promise.resolve());
  resetScanProbeDetector();
  resetInjectionDetector();
});

describe('injectionDetector · NoSQL 操作符剥离留痕', () => {
  test('剥离 → 审计行 + 指标：键样本有界（前 5 个）、reason 带面与键', async () => {
    recordNosqlStripAttempt({
      keys: ['$ne', '$gt', '$where', '$regex', '$options', '$sixth', '$seventh'],
      surface: 'body',
      req: reqStub(),
    });
    await flushWrites();
    expect(rowsByAction('nosql_injection_attempt')).toHaveLength(1);
    const row = rowsByAction('nosql_injection_attempt')[0];
    expect(row.riskLevel).toBe('medium');
    expect(row.riskFactors).toEqual(['mongo_operator_strip']);
    expect(row.reason).toContain('body');
    expect(row.reason).toContain('$ne');
    expect(row.reason).not.toContain('$seventh'); // 样本上界 5
    expect(row.statusCode).toBeUndefined(); // 剥离时最终走向不可知，记了就是猜
    expect(row.success).toBe(false);
    expect(incSecurityAlert).toHaveBeenCalledWith('nosql_injection_attempt', 'medium');
  });

  test('60s 去重：同 IP+同面+同键不重复落行；换键/换面/换 IP 都算新指纹', async () => {
    const base = { keys: ['$ne'], surface: 'body', req: reqStub() };
    recordNosqlStripAttempt(base);
    recordNosqlStripAttempt(base); // 同指纹：吸收
    await flushWrites();
    expect(rowsByAction('nosql_injection_attempt')).toHaveLength(1);

    recordNosqlStripAttempt({ ...base, keys: ['$gt'] }); // 换键
    recordNosqlStripAttempt({ ...base, surface: 'query' }); // 换面
    recordNosqlStripAttempt({ ...base, req: reqStub({ __testIp: '203.0.113.9' }) }); // 换 IP
    await flushWrites();
    expect(rowsByAction('nosql_injection_attempt')).toHaveLength(4);
  });

  test('fail-open：AuditLog.record 抛错不上抛、指标照发（剥离主流程不受影响）', async () => {
    AuditLog.record.mockImplementationOnce(() => {
      throw new Error('connection reset');
    });
    expect(() =>
      recordNosqlStripAttempt({ keys: ['$ne'], surface: 'body', req: reqStub() })
    ).not.toThrow();
    await flushWrites();
    expect(incSecurityAlert).toHaveBeenCalled();
  });

  test('同步段防御：req 桩缺 get 等成员也不得上抛（剥离热路径零负担）', () => {
    expect(() =>
      recordNosqlStripAttempt({ keys: ['$ne'], surface: 'body', req: {} })
    ).not.toThrow();
    expect(() =>
      recordNosqlStripAttempt({ keys: [], surface: 'body', req: reqStub() })
    ).not.toThrow();
  });
});

describe('scanProbeDetector · 路径指纹与风暴', () => {
  test('SCANNER_PATH_RE 命中 → scan_probe_detected + 取证标记；同 IP+path 60s 去重', async () => {
    noteUnmatchedRequest(reqStub({ path: '/.env', __testIp: '203.0.113.7' }));
    noteUnmatchedRequest(reqStub({ path: '/.env', __testIp: '203.0.113.7' })); // 去重吸收
    await flushWrites();
    expect(rowsByAction('scan_probe_detected')).toHaveLength(1);
    const row = rowsByAction('scan_probe_detected')[0];
    expect(row.riskFactors).toEqual(['scanner_path']);
    expect(markForensicTarget).toHaveBeenCalledWith(
      '203.0.113.7',
      expect.objectContaining({ reason: 'scan_probe', source: 'scanProbeDetector' })
    );
  });

  test('扫描器 UA 命中 → riskFactors 补 scanner_user_agent 因子', async () => {
    expect(KNOWN_SCANNER_UA_RE.test('sqlmap/1.5')).toBe(true);
    noteUnmatchedRequest(
      reqStub({ path: '/wp-login.php', get: () => 'sqlmap/1.5', __testIp: '203.0.113.8' })
    );
    await flushWrites();
    expect(rowsByAction('scan_probe_detected')[0].riskFactors).toContain('scanner_user_agent');
  });

  test('风暴阈值：前 N-1 次无行，第 N 次 storm 行一次 + 取证标记 + 同窗不再重复', async () => {
    const hit = (i) =>
      noteUnmatchedRequest(reqStub({ path: `/probe-${i}`, __testIp: '198.51.100.3' }));
    hit(1);
    hit(2);
    await flushWrites();
    expect(rowsByAction('scan_probe_storm')).toHaveLength(0); // 阈值 3：前两次无声

    hit(3);
    await flushWrites();
    expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
    const row = rowsByAction('scan_probe_storm')[0];
    expect(row.riskLevel).toBe('high');
    expect(row.riskFactors).toContain('unmatched_path_storm');
    expect(markForensicTarget).toHaveBeenCalledWith(
      '198.51.100.3',
      expect.objectContaining({ reason: 'scan_probe_storm' })
    );

    hit(4);
    hit(5);
    await flushWrites();
    // 触顶后计数器**不删除**：reported 标记保留到窗口过期，同窗内再打多少次都只有一条。
    // 旧实现在此删计数器 ⇒ 第 4、5 次重新起窗（阈值 3 时永远到不了），窗口一长就"每 N 次一条"。
    expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
  });

  test('同窗持续请求只记一次，窗口边界重新计数', async () => {
    let now = 1000000;
    const clock = jest.spyOn(Date, 'now').mockImplementation(() => now);
    try {
      const hit = () =>
        noteUnmatchedRequest(reqStub({ path: '/missing', __testIp: '198.51.100.6' }));
      for (let i = 0; i < 12; i += 1) hit();
      await flushWrites();
      expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
      now += 60000;
      hit();
      hit();
      await flushWrites();
      expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
      hit();
      await flushWrites();
      expect(rowsByAction('scan_probe_storm')).toHaveLength(2);
    } finally {
      clock.mockRestore();
    }
  });

  test('路径证据去重不能吞掉风暴计数', async () => {
    const hit = () => noteUnmatchedRequest(reqStub({ path: '/.env', __testIp: '198.51.100.7' }));
    for (let i = 0; i < 9; i += 1) hit();
    await flushWrites();
    expect(rowsByAction('scan_probe_detected')).toHaveLength(1);
    expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
  });

  test('已知指纹与普通未匹配路径合并计数', async () => {
    for (const path of ['/.env', '/missing', '/wp-login.php']) {
      noteUnmatchedRequest(reqStub({ path, __testIp: '198.51.100.8' }));
    }
    await flushWrites();
    expect(rowsByAction('scan_probe_detected')).toHaveLength(2);
    expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
  });

  test('阈值为一时首次请求即留痕', async () => {
    const previous = process.env.SCAN_404_THRESHOLD;
    try {
      process.env.SCAN_404_THRESHOLD = '1';
      let isolated;
      jest.isolateModules(() => {
        isolated = require('../../services/scanProbeDetector');
      });
      isolated.noteUnmatchedRequest(reqStub({ path: '/threshold-one' }));
      await flushWrites();
      expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
    } finally {
      process.env.SCAN_404_THRESHOLD = previous;
    }
  });

  test('默认档（40 次/5 分钟）：同一时刻 80 次普通未知路径只写一条风暴行', async () => {
    // 审计复现口径：离线实测"同一时刻 80 次普通未知路径产生 2 条 storm"——旧实现达阈值即删
    // 计数器，第 41 次重新起窗、第 80 次再触顶。本文件其余用例都跑在压低的阈值 3 上，
    // 默认档（也是线上真实档）无人覆盖，这里按报告的数字逐字复现。
    const previousThreshold = process.env.SCAN_404_THRESHOLD;
    const previousWindow = process.env.SCAN_404_WINDOW_MS;
    try {
      delete process.env.SCAN_404_THRESHOLD;
      delete process.env.SCAN_404_WINDOW_MS;
      let isolated;
      jest.isolateModules(() => {
        isolated = require('../../services/scanProbeDetector');
      });
      expect(isolated.getScanProbeDetectorStats()).toEqual(
        expect.objectContaining({ threshold: 40, windowMs: 5 * 60 * 1000 })
      );
      const clock = jest.spyOn(Date, 'now').mockImplementation(() => 1000000);
      try {
        for (let i = 0; i < 80; i += 1) {
          isolated.noteUnmatchedRequest(
            reqStub({ path: `/unknown-${i}`, __testIp: '198.51.100.9' })
          );
        }
      } finally {
        clock.mockRestore();
      }
      await flushWrites();
      expect(rowsByAction('scan_probe_detected')).toHaveLength(0); // 普通未知路径不含扫描器指纹
      expect(rowsByAction('scan_probe_storm')).toHaveLength(1);
    } finally {
      process.env.SCAN_404_THRESHOLD = previousThreshold;
      process.env.SCAN_404_WINDOW_MS = previousWindow;
    }
  });

  test('风暴计数按 IP 分账：另一个 IP 的计数不叠加', async () => {
    noteUnmatchedRequest(reqStub({ path: '/a-1', __testIp: '198.51.100.4' }));
    noteUnmatchedRequest(reqStub({ path: '/a-2', __testIp: '198.51.100.4' }));
    noteUnmatchedRequest(reqStub({ path: '/b-1', __testIp: '198.51.100.5' }));
    await flushWrites();
    expect(rowsByAction('scan_probe_storm')).toHaveLength(0); // 各自 2/1 次，都未达阈值 3
  });

  test('fail-open：检测内部异常不影响调用方（404 兜底照常返回）', () => {
    expect(() => noteUnmatchedRequest(null)).not.toThrow();
    expect(() => noteUnmatchedRequest({ path: 123 })).not.toThrow();
  });
});
