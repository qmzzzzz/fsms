const { streamExportRows, writeExportWorkbook } = require('../../services/reportWorkbookService');

jest.mock('exceljs');
const { Workbook } = require('exceljs');
const FireDevice = require('../../models/FireDevice');

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

    await streamExportRows(worksheet, config, { scope: true }, (doc) => doc);

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
    const res = {
      setHeader: jest.fn(),
      write: jest.fn(),
      end: jest.fn(),
      on: jest.fn(),
      once: jest.fn(),
      emit: jest.fn(),
      writableFinished: false,
    };
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
