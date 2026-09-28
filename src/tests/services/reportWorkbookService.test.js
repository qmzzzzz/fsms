const { streamExportRows, writeExportWorkbook } = require('../../services/reportWorkbookService');

jest.mock('exceljs');
const { Workbook } = require('exceljs');
const FireDevice = require('../../models/FireDevice');

/**
 * 成功导出现在要等目的端表态（writeExportWorkbook → writeWorkbookToResponse），
 * 而这里打桩的 workbook.xlsx.write 不产生真实流事件。桩按"正常收尾"办事：
 * 注册 finish 时立刻回调，close/error 留空（正常收尾时它们只在 finish 之后才到，
 * 而函数在 finish 那一刻就已经返回）。
 */
const completedRes = (extra = {}) => ({
  setHeader: jest.fn(),
  once: (event, handler) => {
    if (event === 'finish') handler();
  },
  ...extra,
});

describe('report workbook service', () => {
  test('hydrates populated rows in ordered batches and skips deleted documents', async () => {
    const first = { _id: 'id-1', name: 'first', handler: { username: 'one' } };
    const second = { _id: 'id-2', name: 'second', handler: { username: 'two' } };
    const third = { _id: 'id-3', name: 'third', handler: { username: 'three' } };
    const find = jest.fn();
    find.mockImplementationOnce(() => ({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      lean: jest
        .fn()
        .mockResolvedValue([{ _id: first._id }, { _id: second._id }, { _id: third._id }]),
    }));
    find.mockImplementationOnce(() => ({
      populate: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue([first, third]),
    }));
    find.mockImplementationOnce(() => ({
      populate: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue([]),
    }));
    const config = {
      model: { find },
      sort: { occurredAt: -1 },
      populate: [{ path: 'handler' }],
      select: 'name handler',
    };
    const worksheet = { addRow: jest.fn() };

    const out = await streamExportRows(worksheet, config, { scope: true }, (doc) => doc);

    // "跳过"不能是静默的：消失的行数必须是返回值的一部分，否则调用方无从声明文件不完整
    expect(out).toEqual({ written: 2, truncated: false, rowsLost: 1 });
    expect(find).toHaveBeenNthCalledWith(2, {
      $and: [{ scope: true }, { _id: { $in: [first._id, second._id, third._id] } }],
    });
    expect(worksheet.addRow).toHaveBeenNthCalledWith(1, first);
    expect(worksheet.addRow).toHaveBeenNthCalledWith(2, third);
  });

  test('streams unpopulated rows through a cursor', async () => {
    const rows = [{ name: 'one' }, { name: 'two' }];
    const find = jest.fn(() => ({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      cursor: jest.fn(async function* generate() {
        yield* rows;
      }),
    }));
    const worksheet = { addRow: jest.fn() };

    await streamExportRows(
      worksheet,
      { model: { find }, sort: { deviceCode: 1 }, populate: [], select: 'name' },
      { type: 'devices' },
      (doc) => doc
    );

    expect(find).toHaveBeenCalledWith({ type: 'devices' });
    expect(worksheet.addRow.mock.calls.map(([row]) => row)).toEqual(rows);
  });

  test('writes headers, columns, styled first row and workbook bytes', async () => {
    const rows = [{ deviceCode: 'DEV-001', deviceName: '烟雾报警器' }];
    const find = jest.fn(() => ({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      cursor: jest.fn(async function* generate() {
        yield* rows;
      }),
    }));
    const findSpy = jest.spyOn(FireDevice, 'find').mockImplementation(find);
    const worksheet = {
      properties: {},
      columns: undefined,
      addRow: jest.fn(),
      getRow: jest.fn(() => ({ eachCell: (callback) => callback({}) })),
    };
    const workbook = {
      addWorksheet: jest.fn(() => worksheet),
      xlsx: { write: jest.fn().mockResolvedValue() },
    };
    Workbook.mockImplementationOnce(() => workbook);
    const res = completedRes({
      write: jest.fn(),
      end: jest.fn(),
      on: jest.fn(),
      emit: jest.fn(),
      writableFinished: false,
    });
    await writeExportWorkbook(res, { type: 'devices', query: { status: 'normal' } });

    expect(find).toHaveBeenCalledWith({ status: 'normal' });
    expect(res.setHeader).toHaveBeenCalledWith(
      'Content-Type',
      expect.stringContaining('spreadsheetml')
    );
    expect(res.setHeader).toHaveBeenCalledWith(
      'Content-Disposition',
      expect.stringContaining('attachment; filename=')
    );
    expect(workbook.addWorksheet).toHaveBeenCalledWith('设备列表');
    expect(worksheet.columns).toEqual(
      expect.arrayContaining([expect.objectContaining({ key: 'deviceCode' })])
    );
    expect(workbook.xlsx.write).toHaveBeenCalledWith(res);
    expect(worksheet.addRow.mock.calls.map(([row]) => row)).toEqual([
      {
        deviceCode: 'DEV-001',
        deviceName: '烟雾报警器',
        deviceType: "'-",
        status: "'-",
        location: "'-",
        nextCheckDate: "'-",
        expiryDate: "'-",
      },
    ]);
    findSpy.mockRestore();
  });
});

describe('xlsx export truncation must be declared', () => {
  const { EXPORT_LIMIT } = require('../../services/reportExportService');
  const LIMIT = EXPORT_LIMIT;

  const cursorModel = (docs) => {
    const limit = jest.fn().mockReturnThis();
    const find = jest.fn(() => ({
      sort: jest.fn().mockReturnThis(),
      limit,
      select: jest.fn().mockReturnThis(),
      cursor: jest.fn(async function* generate() {
        yield* docs;
      }),
    }));
    return { find, limit };
  };
  const docs = (n) => Array.from({ length: n }, (_, i) => ({ deviceCode: `DEV-${i}` }));

  test('cursor branch: queries one extra probe row and never writes it', async () => {
    const { find, limit } = cursorModel(docs(LIMIT + 1));
    const worksheet = { addRow: jest.fn() };

    const out = await streamExportRows(
      worksheet,
      { model: { find }, sort: { deviceCode: 1 }, populate: [], select: 'deviceCode' },
      { scope: true },
      (doc) => doc
    );

    expect(limit).toHaveBeenCalledWith(LIMIT + 1);
    expect(out).toEqual({ written: LIMIT, truncated: true, rowsLost: 0 });
    expect(worksheet.addRow).toHaveBeenCalledTimes(LIMIT);
    // 最后一条写进去的必须是第 LIMIT 条，而不是探针那条
    expect(worksheet.addRow.mock.calls.at(-1)[0]).toEqual({ deviceCode: `DEV-${LIMIT - 1}` });
  });

  test('boundary: exactly LIMIT rows must NOT be reported as truncated', async () => {
    // 这条是"+1 探针"存在的全部理由：判成 `>= LIMIT` 的实现会在这里红。
    const { find } = cursorModel(docs(LIMIT));
    const worksheet = { addRow: jest.fn() };

    const out = await streamExportRows(
      worksheet,
      { model: { find }, sort: { deviceCode: 1 }, populate: [], select: 'deviceCode' },
      {},
      (doc) => doc
    );

    expect(out).toEqual({ written: LIMIT, truncated: false, rowsLost: 0 });
    expect(worksheet.addRow).toHaveBeenCalledTimes(LIMIT);
  });

  test('populate branch: the probe id is dropped from every back-fill batch', async () => {
    const ids = Array.from({ length: LIMIT + 1 }, (_, i) => `id-${i}`);
    const secondFindArgs = [];
    const find = jest.fn((q) => {
      if (q && q.$and) {
        secondFindArgs.push(q.$and[1]._id.$in);
        return {
          populate: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          lean: jest.fn().mockResolvedValue(q.$and[1]._id.$in.map((id) => ({ _id: id }))),
        };
      }
      return {
        sort: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue(ids.map((id) => ({ _id: id }))),
      };
    });
    const worksheet = { addRow: jest.fn() };

    const out = await streamExportRows(
      worksheet,
      { model: { find }, sort: { occurredAt: -1 }, populate: [{ path: 'handler' }], select: 'x' },
      { scope: true },
      (doc) => doc
    );

    expect(out).toEqual({ written: LIMIT, truncated: true, rowsLost: 0 });
    expect(worksheet.addRow).toHaveBeenCalledTimes(LIMIT);
    // 探针那条 id 不得进入任何一次回填查询
    expect(secondFindArgs.flat()).not.toContain(`id-${LIMIT}`);
    expect(secondFindArgs.flat()).toContain(`id-${LIMIT - 1}`);
  });

  test('populate branch boundary: exactly LIMIT ids are not truncated', async () => {
    // 与 cursor 那条同一格判据：`>` 写成 `>=` 只会在这里红（两条分支各写一遍比较，
    // 正是本仓"同一条规则两份实现"的老病，所以两边都要有边界用例）。
    const ids = Array.from({ length: LIMIT }, (_, i) => `id-${i}`);
    const find = jest.fn((q) => {
      if (q && q.$and) {
        return {
          populate: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          lean: jest.fn().mockResolvedValue(q.$and[1]._id.$in.map((id) => ({ _id: id }))),
        };
      }
      return {
        sort: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue(ids.map((id) => ({ _id: id }))),
      };
    });
    const worksheet = { addRow: jest.fn() };

    const out = await streamExportRows(
      worksheet,
      { model: { find }, sort: { occurredAt: -1 }, populate: [{ path: 'handler' }], select: 'x' },
      {},
      (doc) => doc
    );

    expect(out).toEqual({ written: LIMIT, truncated: false, rowsLost: 0 });
    expect(worksheet.addRow).toHaveBeenCalledTimes(LIMIT);
  });

  test('writeExportWorkbook: truncated ⇒ X-Export-Truncated header + in-sheet footer row', async () => {
    const findSpy = jest.spyOn(FireDevice, 'find').mockImplementation(() => {
      const chain = {
        sort: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        cursor: jest.fn(async function* generate() {
          yield* docs(LIMIT + 1);
        }),
      };
      return chain;
    });
    const worksheet = {
      properties: {},
      columns: undefined,
      addRow: jest.fn(),
      getRow: jest.fn(() => ({ eachCell: (callback) => callback({}) })),
    };
    const workbook = {
      addWorksheet: jest.fn(() => worksheet),
      xlsx: { write: jest.fn().mockResolvedValue() },
    };
    Workbook.mockImplementationOnce(() => workbook);
    const res = completedRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: LIMIT + 37 });

    expect(res.setHeader).toHaveBeenCalledWith('X-Export-Truncated', 'true');
    const footer = worksheet.addRow.mock.calls.at(-1)[0];
    expect(Array.isArray(footer)).toBe(true);
    expect(String(footer[0])).toMatch(/截断/);
    expect(String(footer[0])).toContain(String(LIMIT));
    expect(String(footer[0])).toContain(`命中总数 ${LIMIT + 37}`); // 总数来自调用方已有的 countDocuments
    // 数据行 + 脚注行：脚注不得冒充数据（只多一行）
    expect(worksheet.addRow).toHaveBeenCalledTimes(LIMIT + 1);
    findSpy.mockRestore();
  });

  test('negative premise: an export that fits gets no header and no footer row', async () => {
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorModel([{ deviceCode: 'DEV-0' }]).find);
    const worksheet = {
      properties: {},
      columns: undefined,
      addRow: jest.fn(),
      getRow: jest.fn(() => ({ eachCell: (callback) => callback({}) })),
    };
    const workbook = {
      addWorksheet: jest.fn(() => worksheet),
      xlsx: { write: jest.fn().mockResolvedValue() },
    };
    Workbook.mockImplementationOnce(() => workbook);
    const res = completedRes();

    await writeExportWorkbook(res, { type: 'devices', query: {} });

    expect(res.setHeader).not.toHaveBeenCalledWith('X-Export-Truncated', expect.anything());
    expect(worksheet.addRow).toHaveBeenCalledTimes(1);
    findSpy.mockRestore();
  });
});
