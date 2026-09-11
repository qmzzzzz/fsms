const {
  EXPORT_CSV_HEADER,
  MANIFEST_LINE_PREFIX,
  buildAuditExportManifest,
  sendAuditExportHeaders,
  streamAuditExport,
} = require('../../services/auditExportService');

jest.mock('../../models/AuditLog', () => ({
  countDocuments: jest.fn(),
  find: jest.fn(),
}));

const AuditLog = require('../../models/AuditLog');

describe('audit export service', () => {
  test('escapes dates, objects, quotes and formula-like values in CSV', async () => {
    const rows = [
      {
        timestamp: new Date('2026-09-08T00:00:00.000Z'),
        action: 'auth,login',
        username: 'user "quoted"',
        path: { nested: 'value' },
        statusCode: 200,
      },
    ];
    AuditLog.countDocuments.mockResolvedValueOnce(rows.length);
    AuditLog.find.mockImplementationOnce(() => ({
      sort: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      cursor: jest.fn(() => ({
        close: jest.fn(),
        eachAsync: async (callback) => {
          for (const row of rows) await callback(row);
        },
      })),
    }));

    const res = {
      setHeader: jest.fn(),
      write: jest.fn(() => true),
      once: jest.fn(),
    };

    await sendAuditExportHeaders({ action: 'auth_login' }, res);
    const result = await streamAuditExport({ action: 'auth_login' }, res);
    const manifest = buildAuditExportManifest(result);

    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv; charset=utf-8');
    expect(res.setHeader).toHaveBeenCalledWith('X-Audit-Manifest-Records', String(rows.length));
    expect(result.recordCount).toBe(1);
    expect(result.sha256).toMatch(/[0-9a-f]{64}/);
    expect(manifest.startTime).toBe('2026-09-08T00:00:00.000Z');
    expect(manifest).not.toHaveProperty('truncated');

    const csv = res.write.mock.calls.map(([line]) => line).join('');
    expect(EXPORT_CSV_HEADER).toContain('prevHash,hash');
    expect(csv).toContain('"user ""quoted"""');
    expect(csv).toContain('"{""nested"":""value""}"');
  });

  test('marks hard-limit truncation and waits for stream drain', async () => {
    AuditLog.countDocuments.mockResolvedValueOnce(50001);
    AuditLog.find.mockImplementationOnce(() => ({
      sort: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      cursor: jest.fn(() => ({
        close: jest.fn(),
        eachAsync: async (callback) => {
          for (let index = 0; index < 50001; index += 1) {
            await callback({
              timestamp: '2026-09-08T00:00:00.000Z',
              action: 'auth_login',
              username: 'limit-user',
            });
          }
        },
      })),
    }));

    const drainListeners = [];
    let writeCount = 0;
    const res = {
      setHeader: jest.fn(),
      write: jest.fn((line) => {
        if (line === EXPORT_CSV_HEADER) return true;
        writeCount += 1;
        if (writeCount === 1) {
          setTimeout(() => drainListeners.forEach((listener) => listener()), 0);
          return false;
        }
        return true;
      }),
      once: jest.fn((event, listener) => {
        if (event === 'drain') drainListeners.push(listener);
      }),
    };

    await sendAuditExportHeaders({}, res);
    const counters = await streamAuditExport({}, res);
    const manifest = buildAuditExportManifest(counters);

    expect(res.setHeader).toHaveBeenCalledWith('X-Audit-Truncated', 'true');
    expect(res.setHeader).toHaveBeenCalledWith('X-Audit-Manifest-Records', '50000');
    expect(counters.truncated).toBe(true);
    expect(manifest.truncated).toBe(true);
    expect(manifest.notice).toContain('50000');
    expect(MANIFEST_LINE_PREFIX).toContain('MANIFEST');
  });
});
