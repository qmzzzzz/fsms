/**
 * E3：审计 CSV 导出占独立并发槽（audit-export 池）。
 *
 * 闸满 ⇒ 429 EXPORT_BUSY + Retry-After，且**不得**被 exportAuditLogs 自管的
 * try/catch 折算成 AUDIT_EXPORT_FAILED（那会让"忙，请重试"变成"服务故障"，
 * 客户端对着一个永远不会成功的导出疯狂退避）。拒绝发生在任何响应头/流写出之前。
 * 导出体的下游协作者全部打桩：本文件只测闸的接线与拒绝形态。
 */

jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn, // 不桩会把内部结果吞进 next()，断言读不到响应
  markResponseAbortedByError: jest.fn(),
}));
jest.mock('../../services/auditScopeFilter', () => ({
  applyAuditDataScope: async (query) => ({ query }),
}));
jest.mock('../../services/auditExportService', () => ({
  sendAuditExportHeaders: jest.fn(async () => {}),
  streamAuditExport: jest.fn(async () => ({ recordCount: 2 })),
  buildAuditExportManifest: jest.fn(() => ({ recordCount: 2 })),
  MANIFEST_LINE_PREFIX: '# manifest: ',
  EXPORT_CSV_HEADER: 'timestamp,action\n',
}));
jest.mock('../../services/securityAlert', () => ({
  checkBulkExport: jest.fn(async () => {}),
}));

const { exportAuditLogs } = require('../../controllers/auditController');
const { acquireExportSlot, POOLS } = require('../../services/exportConcurrency');
const { streamAuditExport } = require('../../services/auditExportService');

const makeRes = () => ({
  statusCode: null,
  payload: null,
  headers: {},
  writableEnded: false,
  headersSent: false,
  locals: {},
  setHeader(k, v) {
    this.headers[k] = v;
    return this;
  },
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(data) {
    this.payload = data;
    return this;
  },
  write() {
    return true;
  },
  end() {
    this.writableEnded = true;
    return this;
  },
});
const makeReq = () => ({
  method: 'GET',
  originalUrl: '/api/security/audit-logs/export',
  query: {},
  user: { userId: 'op-1', username: 'op' },
  get: () => 'jest-ua',
  ip: '203.0.113.9',
  headers: {},
});

describe('E3：审计 CSV 导出占槽（audit-export 池）', () => {
  let envBackup;

  beforeEach(() => {
    envBackup = {
      EXPORT_MAX_QUEUE: process.env.EXPORT_MAX_QUEUE,
      EXPORT_MAX_CONCURRENCY: process.env.EXPORT_MAX_CONCURRENCY,
    };
    delete process.env.EXPORT_MAX_CONCURRENCY; // 出厂 max=2，避免外部 env 干扰占满数
    jest.clearAllMocks();
  });

  afterEach(() => {
    if (envBackup.EXPORT_MAX_QUEUE === undefined) delete process.env.EXPORT_MAX_QUEUE;
    else process.env.EXPORT_MAX_QUEUE = envBackup.EXPORT_MAX_QUEUE;
    if (envBackup.EXPORT_MAX_CONCURRENCY === undefined) delete process.env.EXPORT_MAX_CONCURRENCY;
    else process.env.EXPORT_MAX_CONCURRENCY = envBackup.EXPORT_MAX_CONCURRENCY;
  });

  test('池名闭合集合里有 audit-export（否则 acquire 直接抛"未知导出池"）', () => {
    expect(POOLS).toContain('audit-export');
  });

  test('闸满 ⇒ 429 EXPORT_BUSY + Retry-After，不折算成 AUDIT_EXPORT_FAILED，流未开', async () => {
    process.env.EXPORT_MAX_QUEUE = '0'; // 排队位归零：第 3 个并发立刻 queue_full，用例不等超时
    const held = [];
    try {
      while (true) {
        try {
          held.push(await acquireExportSlot('audit-export'));
        } catch (err) {
          break; // 池满：正常出口
        }
      }
      expect(held.length).toBeGreaterThanOrEqual(1); // 前提自证：确实占到了槽
      const res = makeRes();
      await exportAuditLogs(makeReq(), res);
      expect(res.statusCode).toBe(429);
      expect(res.headers['Retry-After']).toBeTruthy();
      expect(JSON.stringify(res.payload)).toContain('EXPORT_BUSY');
      expect(JSON.stringify(res.payload)).not.toContain('AUDIT_EXPORT_FAILED');
      expect(streamAuditExport).not.toHaveBeenCalled(); // 拒绝先于任何流写出
    } finally {
      while (held.length) held.pop()();
    }
  });

  test('有槽时正常进入导出体（闸没有把健康路径一起堵死）', async () => {
    const res = makeRes();
    await exportAuditLogs(makeReq(), res);
    expect(streamAuditExport).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(res.payload)).not.toContain('EXPORT_BUSY');
    expect(res.writableEnded).toBe(true);
  });
});
