/**
 * E2 消费即扣减的控制器侧语义：配额在**写出之前**扣，写前扣减发现越限 ⇒ 429 且
 * workbook 一个字节都不写。中间件检查与本次写出之间插入的并发越界者在此收口。
 * piiExportQuota / workbook / 模型计数全打桩——被测的只有 exportReport 编排里的
 * 扣减点位与拒绝形态（PII_EXPORT_QUOTA_EXCEEDED=429，与中间件同一错误码）。
 */

jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  getDataScope: jest.fn(async () => ({ type: 'all' })),
}));

jest.mock('../../utils/permissionHelper', () => ({
  hasPermission: jest.fn(async () => true),
}));

jest.mock('../../services/securityAlert', () => ({
  checkBulkExport: jest.fn(async () => {}),
}));

jest.mock('../../services/piiExportQuota', () => ({
  consumePiiExportQuota: (...args) => mockConsume(...args),
  checkPiiExportQuota: jest.fn(),
}));

jest.mock('../../services/reportWorkbookService', () => ({
  writeExportWorkbook: (...args) => mockWrite(...args),
  fetchExportRows: jest.fn(), // E9① 前名 streamExportRows
}));

jest.mock('../../services/reportExportService', () => {
  const actual = jest.requireActual('../../services/reportExportService');
  return {
    ...actual,
    EXPORT_MODEL_CONFIG: {
      ...actual.EXPORT_MODEL_CONFIG,
      alarms: {
        ...actual.EXPORT_MODEL_CONFIG.alarms,
        model: { countDocuments: (...args) => mockCount(...args) },
      },
    },
  };
});

const mockConsume = jest.fn();
const mockWrite = jest.fn();
const mockCount = jest.fn(async () => 3);

const { exportReport } = require('../../controllers/reportController');

const makeRes = () => ({
  statusCode: null,
  payload: null,
  headers: {},
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
});
const makeReq = () => ({
  method: 'POST',
  originalUrl: '/api/reports/export/pii',
  query: { type: 'alarms', format: 'xlsx' },
  body: {},
  user: { userId: 'op-1', username: 'op' },
  ip: '203.0.113.9',
  get: () => 'jest-ua',
  headers: {},
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe('E2：PII 导出配额写前扣减（consume 前置）', () => {
  test('写前扣减发现越限 ⇒ 429 + Retry-After，workbook 未写出；扣减先于写出', async () => {
    mockConsume.mockResolvedValue({
      used: 6,
      limit: 5,
      allowed: false,
      retryAfterSeconds: 123,
    });
    const res = makeRes();
    await exportReport(makeReq(), res);
    expect(res.statusCode).toBe(429);
    expect(res.headers['Retry-After']).toBe('123');
    expect(JSON.stringify(res.payload)).toContain('PII_EXPORT_QUOTA_EXCEEDED');
    // 扣减点先于写出点；越限时 workbook 一个字节都不落
    expect(mockConsume).toHaveBeenCalledTimes(1);
    expect(mockWrite).not.toHaveBeenCalled();
    expect(mockConsume.mock.invocationCallOrder[0]).toBeLessThan(
      mockWrite.mock.invocationCallOrder[0] ?? Number.MAX_SAFE_INTEGER
    );
  });

  test('扣减未越限 ⇒ 照常写出；未配置 Redis（null）⇒ 保持现状直接写出', async () => {
    mockConsume.mockResolvedValue({ used: 1, limit: 5, allowed: true, retryAfterSeconds: 0 });
    const res1 = makeRes();
    await exportReport(makeReq(), res1);
    expect(mockWrite).toHaveBeenCalledTimes(1);
    expect(res1.payload).toBeNull(); // 没有任何错误响应

    mockConsume.mockResolvedValue(null); // 未配置 Redis：现状口径，不拦
    const res2 = makeRes();
    await exportReport(makeReq(), res2);
    expect(mockWrite).toHaveBeenCalledTimes(2);
    expect(res2.payload).toBeNull();
  });
});
