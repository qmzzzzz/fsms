/**
 * auditController 导出流的失败出口（2026-09-18）
 *
 * 与 auditControllerGaps.test.js 分开的理由：本文件需要 jest.resetModules() +
 * jest.doMock() 替换 auditExportService，才能稳定复现「流中途抛错」。
 * isolateModules 会重置模块注册表，若与依赖真实 DB 连接的用例同文件，
 * 会让后者的 mongoose 模型失去连接（实测：buffering timed out 10s → 500）。
 * 拆开后本文件完全不碰数据库。
 *
 * 断言两条真实契约：
 *   1. 头已发出 → 不能再改状态码（会抛 ERR_HTTP_HEADERS_SENT），只能 res.end() 收尾；
 *   2. 头未发出 → 回 AUDIT_EXPORT_FAILED（500），而不是半截 CSV。
 * 两条都要求 logger.error 留痕，否则导出静默失败无从察觉。
 */

// logger 在 beforeEach 内随 isolateModules 重新解析，此处不提前 require（会拿到旧实例）
// 合法 ObjectId：applyAuditDataScope 会对 userId 走 User.findById（本文件已 mock 掉，
// 但保持与真实调用一致的形状，避免替身掩盖类型错误）
const VALID_OID = '507f1f77bcf86cd799439011';

describe('导出流失败（auditController.js:60-68 的 catch 出口）', () => {
  let isolated;
  let errorSpy;

  beforeEach(() => {
    jest.resetModules();
    // 数据范围翻译依赖真实 User 查询；本组只关心导出失败出口，
    // 用透传替身隔离（否则 isolateModules 后连接未就绪会 buffering timeout）
    jest.doMock('../../services/auditQueryService', () => ({
      applyAuditDataScope: async (query) => ({ query }),
      queryAuditLogs: async () => ({ data: [], meta: {} }),
    }));
    errorSpy = jest.spyOn(require('../../utils/logger'), 'error');
  });

  afterEach(() => {
    errorSpy.mockRestore();
    jest.resetModules();
  });

  const makeRes = () => {
    const res = {
      statusCode: null,
      body: null,
      headersSent: false,
      ended: false,
      headers: {},
      setHeader(k, v) {
        this.headers[k] = v;
        return this;
      },
      write() {
        return true;
      },
      end() {
        this.ended = true;
        return this;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      },
    };
    return res;
  };

  const makeReq = () => ({
    query: {},
    user: { userId: VALID_OID, username: 'tester' },
    method: 'GET',
    params: {},
    ip: '::1',
    get: () => undefined,
  });

  test('头已发出 + stream 抛错 → 不覆盖状态码，res.end() 收尾且 logger.error 留痕', async () => {
    jest.doMock('../../services/auditExportService', () => ({
      buildAuditExportManifest: () => ({}),
      sendAuditExportHeaders: async () => {},
      streamAuditExport: async () => {
        throw new Error('游标读取失败（模拟）');
      },
      MANIFEST_LINE_PREFIX: '#__MANIFEST__:',
      EXPORT_CSV_HEADER: 'timestamp,action',
    }));
    isolated = require('../../controllers/auditController');

    const res = makeRes();
    res.headersSent = true; // 头已发出：真实流式导出的失败时刻
    const next = jest.fn();

    await isolated.exportAuditLogs(makeReq(), res, next);

    // 不得抛给 next（否则 Express 默认处理器会尝试改状态码 → ERR_HTTP_HEADERS_SENT）
    expect(next).not.toHaveBeenCalled();
    expect(res.ended).toBe(true);
    // 关键：头已发出时不得再调用 res.status()（会抛 ERR_HTTP_HEADERS_SENT）
    expect(res.statusCode).toBeNull();
    expect(res.body).toBeNull();
    const logged = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('审计日志导出失败');
    expect(logged).toContain('游标读取失败（模拟）');
  });

  test('头未发出 + 准备阶段抛错 → AUDIT_EXPORT_FAILED（500），不改用 res.end()', async () => {
    jest.doMock('../../services/auditExportService', () => ({
      buildAuditExportManifest: () => ({}),
      sendAuditExportHeaders: async () => {
        throw new Error('countDocuments 失败（模拟）');
      },
      streamAuditExport: async () => ({}),
      MANIFEST_LINE_PREFIX: '#__MANIFEST__:',
      EXPORT_CSV_HEADER: 'timestamp,action',
    }));
    isolated = require('../../controllers/auditController');

    const res = makeRes();
    res.headersSent = false;
    const next = jest.fn();

    await isolated.exportAuditLogs(makeReq(), res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(500);
    expect(res.body.errors.errorCode).toBe('AUDIT_EXPORT_FAILED');
    expect(res.ended).toBe(false);
  });
});
