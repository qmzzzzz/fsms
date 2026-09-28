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
    const chain1 = {
      sort: jest.fn().mockReturnThis(),
      // 导出查询自带 limit(硬上限+1) 作截断探针 ⇒ 桩必须支持这一环，
      // 并且断言它真的被调用（光"能跑"不够，跑错方向也要能发现）
      limit: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      cursor: jest.fn(() => ({
        close: jest.fn(),
        eachAsync: async (callback) => {
          for (const row of rows) await callback(row);
        },
      })),
    };
    AuditLog.find.mockImplementationOnce(() => chain1);

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

    // 摘要必须可复算，且真的依赖记录内容。但注意口径：`sha256` 覆盖的是**记录的 hash 字段
    // 串联**，不是 CSV 字节 ⇒ 它证明"这些记录出自哈希链"，**不能**当作
    // "导出文件未被中途删改"的凭证（改一个单元格它也不变）。文件完整性看 `csvSha256`，
    // 两口径的差异与各自的复算方式钉在 auditExportManifestScope.test.js。
    const expected = require('crypto')
      .createHash('sha256')
      .update(rows.map((r) => r.hash).join(''), 'utf8')
      .digest('hex');
    expect(result.sha256).toBe(expected);
    expect(manifest.sha256).toBe(expected);
    // 差分对照：换掉一条记录的 hash 再跑一遍，摘要必须跟着变、且等于按新内容重算的值。
    // 这里原先写的是 `expect(flipped).not.toBe(expected)`，而 flipped 由两个硬编码字符串
    // 拼出来、与被测函数没有任何数据流关系 ⇒ 只有 SHA-256 碰撞才会红，是条装饰性断言，
    // 却让上面那句"摘要真的依赖记录内容"看起来像被验过。
    const rowsAlt = [{ ...rows[0], hash: 'c'.repeat(64) }, rows[1]];
    // 这里刻意**不**再排一次 countDocuments：sendAuditExportHeaders 与 streamAuditExport
    // 各数一遍，本用例开头只排了一个值（第二个拿到 undefined）—— 想复用同一条通路做差分，
    // 就多排一个，会把尾巴漏给下一个用例（同文件的模型桩是模块级 jest.fn，
    // mockImplementationOnce 的队列跨用例）。
    const chainAlt = {
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      lean: jest.fn().mockReturnThis(),
      cursor: jest.fn(() => ({
        close: jest.fn(),
        eachAsync: async (callback) => {
          for (const row of rowsAlt) await callback(row);
        },
      })),
    };
    AuditLog.find.mockImplementationOnce(() => chainAlt);
    const resAlt = { setHeader: jest.fn(), write: jest.fn(() => true), once: jest.fn() };
    const alt = await streamAuditExport({ action: 'auth_login' }, resAlt);
    const altExpected = require('crypto')
      .createHash('sha256')
      .update(rowsAlt.map((r) => r.hash).join(''), 'utf8')
      .digest('hex');
    expect(alt.sha256).toBe(altExpected);
    expect(alt.sha256).not.toBe(expected);

    expect(manifest.startTime).toBe('2026-09-08T00:00:00.000Z');
    expect(manifest).not.toHaveProperty('truncated');
    // 截断探针 —— 查询必须向 DB 只要 上限+1 条，而不是全量拉回再早退
    expect(chain1.limit).toHaveBeenCalledWith(50001);

    const csv = res.write.mock.calls.map(([line]) => line).join('');
    expect(csv).toContain('"user ""quoted"""');
    expect(csv).toContain('"{""nested"":""value""}"');
    // 表头声明的列与导出列必须一致，且 hmac 一个字节都不许出现。
    // 判据用**外部字面量**：原写法 `toContain('prevHash,hash')` 对"表头多加一列"
    // 之类的漂移完全不红。表头与数据行现已同源于 EXPORT_CSV_COLUMNS（此前是两份
    // 各写一遍的字面量，改一侧不改另一侧会让整份 CSV 列错位），再用真实行反证一次列数。
    expect(EXPORT_CSV_HEADER).toBe(
      'timestamp,action,category,username,ip,path,statusCode,success,riskLevel,prevHash,hash'
    );
    const plainRow = csv.split('\n').find((line) => line.includes('auth_logout'));
    expect(plainRow.split(',')).toHaveLength(EXPORT_CSV_HEADER.split(',').length);
    expect(csv).toContain('a'.repeat(64));
    expect(csv).not.toContain('deadbeef');
    expect(csv).not.toContain('hmac');
  });

  test('marks hard-limit truncation and waits for stream drain', async () => {
    AuditLog.countDocuments.mockResolvedValueOnce(50001);
    const chain2 = {
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(), // 链式桩必须跟得上生产链
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
    };
    AuditLog.find.mockImplementationOnce(() => chain2);

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
    // 截断路径同样必须带探针 limit（早退不是截断，DB 侧少取才是）
    expect(chain2.limit).toHaveBeenCalledWith(50001);
  });
});
