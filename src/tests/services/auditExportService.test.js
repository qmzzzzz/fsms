const {
  EXPORT_CSV_HEADER,
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
        // 链字段必须进固件：manifest 的 sha256 是「逐条 doc.hash 顺次摘要」，
        // 原先固件里没有 hash → 实际算的是 SHA-256('')，删掉 hasher.update(doc.hash)
        // 这行（导出签名退化为与内容无关的固定常量）用例仍全绿。
        prevHash: null,
        hash: 'a'.repeat(64),
        // 攻击面：导出把 hmac 带出去，等于给出离线爆破 HMAC_SECRET 的样本
        hmac: 'deadbeefdeadbeefdeadbeefdeadbeef',
      },
      {
        timestamp: new Date('2026-09-08T00:00:01.000Z'),
        action: 'auth_logout',
        username: 'user2',
        path: '/api/auth/logout',
        statusCode: 200,
        prevHash: 'a'.repeat(64),
        hash: 'b'.repeat(64),
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
    expect(result.recordCount).toBe(2);

    // 签名必须可复算，且真的依赖内容（这是"导出未被中途删改"的唯一凭证）
    const expected = require('crypto')
      .createHash('sha256')
      .update(rows.map((r) => r.hash).join(''), 'utf8')
      .digest('hex');
    expect(result.sha256).toBe(expected);
    expect(manifest.sha256).toBe(expected);
    const flipped = require('crypto')
      .createHash('sha256')
      .update(`${'a'.repeat(63)}0${'b'.repeat(64)}`, 'utf8')
      .digest('hex');
    expect(flipped).not.toBe(expected);

    expect(manifest.startTime).toBe('2026-09-08T00:00:00.000Z');
    expect(manifest).not.toHaveProperty('truncated');

    const csv = res.write.mock.calls.map(([line]) => line).join('');
    expect(csv).toContain('"user ""quoted"""');
    expect(csv).toContain('"{""nested"":""value""}"');
    // 表头声明的列与导出列必须一致，且 hmac 一个字节都不许出现
    expect(EXPORT_CSV_HEADER).toContain('prevHash,hash');
    expect(csv).toContain('a'.repeat(64));
    expect(csv).not.toContain('deadbeef');
    expect(csv).not.toContain('hmac');
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
    // 原先这里断的是 MANIFEST_LINE_PREFIX 常量自身含 'MANIFEST'（同义反复）。
    // 换成真正需要被证明的事：游标在 50000 条处早停，多给的那一条不得被写出。
    expect(counters.recordCount).toBe(50000);
    expect(manifest.recordCount).toBe(50000);
    expect(writeCount).toBe(50000);
  });
});
