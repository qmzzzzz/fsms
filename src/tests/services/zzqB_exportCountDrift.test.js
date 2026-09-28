/**
 * xlsx 导出的"计数—写出"对账缺口（services/reportWorkbookService.js）
 *
 * 由来：`writeExportWorkbook` 只在 `truncated || rowsLost > 0` 时宣布"不完整"。
 * 这两样各有覆盖不到的一格：
 *   - `rowsLost` 只在 **populate 分支**算得出来 —— 那条路径分两步取数
 *     （先拿一批 `_id`，再回填文档），中间被删掉的行"点了名"；
 *   - **游标分支**（`devices` / `audit`）是一条流，导出期间被删除或改得不再匹配筛选
 *     条件的行**根本不会到达**，既没有 else 分支可数，也没有任何异常。
 * 于是同一件事（"计数时 5 条、文件里 3 条"）在两条路径上的表态相反：
 * populate 分支会加脚注，游标分支静默交付一份看起来完整的合规材料。
 * controller 侧本来就把计数前的 `total` 传了进来（reportController.js:285），
 * 只是这个数从没和 `written` 对过账 —— 对账不补，传参就是装饰。
 *
 * 判据要同时挡住三个方向，所以每格都配了控制臂：
 *   1) 计数 > 写出（真丢行）必须说出来；
 *   2) 写出 = 计数、以及"没传计数"时必须闭嘴（否则每次导出都自带警告，
 *      等于把这条声明的信用花光）；
 *   3) 同一批行不得被 `rowsLost` 与对账各报一次（populate 分支会同时满足两式），
 *      撞上限那一档也不得再算成"丢行"（那是 truncated 的活）。
 */
jest.mock('exceljs');

const { Workbook } = require('exceljs');
const { writeExportWorkbook } = require('../../services/reportWorkbookService');
const { EXPORT_LIMIT } = require('../../services/reportExportService');
const FireDevice = require('../../models/FireDevice');
const FireAlarm = require('../../models/FireAlarm');

const LIMIT = EXPORT_LIMIT;

const makeWorksheet = () => ({
  properties: {},
  columns: undefined,
  addRow: jest.fn(),
  getRow: jest.fn(() => ({ eachCell: (callback) => callback({}) })),
});

const makeRes = () => {
  const handlers = {};
  const res = {
    setHeader: jest.fn(),
    once: (event, fn) => {
      (handlers[event] = handlers[event] || []).push(fn);
    },
    destroyed: false,
    writableFinished: false,
    locals: {},
  };
  res.fire = (event, err) => {
    const list = handlers[event] || [];
    delete handlers[event];
    for (const fn of list) fn(err);
  };
  return res;
};

const injectWorkbook = () => {
  const worksheet = makeWorksheet();
  const workbook = {
    addWorksheet: jest.fn(() => worksheet),
    xlsx: {
      write: jest.fn(async (res) => {
        res.fire('finish');
      }),
    },
  };
  Workbook.mockImplementationOnce(() => workbook);
  return { workbook, worksheet };
};

/** 游标分支（devices / audit）：一条流，没有回填窗口 */
const spyCursor = (Model, docs) =>
  jest.spyOn(Model, 'find').mockImplementation(() => ({
    sort: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    cursor: jest.fn(async function* generate() {
      yield* docs;
    }),
  }));

/** populate 分支（alarms / inspections）：先取 id，再回填文档 */
const spyPopulate = (Model, ids, docs) =>
  jest.spyOn(Model, 'find').mockImplementation((query) => {
    if (query && query.$and) {
      const wanted = new Set(query.$and[1]._id.$in.map((id) => String(id)));
      return {
        populate: jest.fn().mockReturnThis(),
        select: jest.fn().mockReturnThis(),
        lean: jest.fn().mockResolvedValue(docs.filter((d) => wanted.has(String(d._id)))),
      };
    }
    return {
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue(ids.map((id) => ({ _id: id }))),
    };
  });

const footerOf = (worksheet) => String(worksheet.addRow.mock.calls.at(-1)[0][0]);
const saidIncomplete = (res) =>
  res.setHeader.mock.calls.some(([k, v]) => k === 'X-Export-Truncated' && v === 'true');

describe('游标分支的"计数—写出"差额必须被对账出来', () => {
  let spy;
  afterEach(() => {
    if (spy) spy.mockRestore();
    spy = undefined;
  });

  it('计数 5 条、游标只送到 3 条 ⇒ 必须声明不完整并给出差额', async () => {
    spy = spyCursor(FireDevice, [{ deviceCode: 'D1' }, { deviceCode: 'D2' }, { deviceCode: 'D3' }]);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: 5 });

    expect(saidIncomplete(res)).toBe(true);
    const footer = footerOf(worksheet);
    expect(footer).toContain('数据不完整');
    expect(footer).toContain('2 行在计数之后被删除或不再匹配筛选条件');
    expect(footer).toContain('实际写入 3 行');
    expect(footer).toContain('计数时 5 行');
    // 丢行不得被说成"后面还有记录"（那是撞上限的措辞）
    expect(footer).not.toContain('仅包含前');
  });

  it('控制臂：计数与写出相等时不许出现任何"不完整"声明', async () => {
    spy = spyCursor(FireDevice, [{ deviceCode: 'D1' }, { deviceCode: 'D2' }, { deviceCode: 'D3' }]);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: 3 });

    expect(saidIncomplete(res)).toBe(false);
    expect(worksheet.addRow).toHaveBeenCalledTimes(3);
  });

  it('控制臂：调用方没传计数时无从对账，不许凭空宣布丢行', async () => {
    spy = spyCursor(FireDevice, [{ deviceCode: 'D1' }]);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {} });

    expect(saidIncomplete(res)).toBe(false);
    expect(worksheet.addRow).toHaveBeenCalledTimes(1);
  });

  it('控制臂：计数之后**新增**的行（写出 > 计数）不是丢行，不许报警', async () => {
    spy = spyCursor(FireDevice, [{ deviceCode: 'D1' }, { deviceCode: 'D2' }]);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: 1 });

    expect(saidIncomplete(res)).toBe(false);
    expect(worksheet.addRow).toHaveBeenCalledTimes(2);
  });
});

describe('对账不得与 rowsLost / truncated 重复计同一件事', () => {
  let spy;
  afterEach(() => {
    if (spy) spy.mockRestore();
    spy = undefined;
  });

  it('populate 分支：差额已点名成 rowsLost，脚注里只出现一次"1 行"', async () => {
    spy = spyPopulate(FireAlarm, ['a', 'b', 'c'], [{ _id: 'a' }, { _id: 'b' }]);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'alarms', query: {}, total: 3 });

    expect(saidIncomplete(res)).toBe(true);
    const footer = footerOf(worksheet);
    expect(footer).toContain('1 行在导出期间被删除或不再匹配筛选条件');
    // 同一批行被报两次（"1 行…"+对账再来一句）会让差额数字自相矛盾
    expect(footer.match(/1 行/g)).toHaveLength(1);
  });

  it('撞上限那一档由 truncated 独家表态，不再叠加"计数后未能写出"', async () => {
    const docs = Array.from({ length: LIMIT + 1 }, (_, i) => ({ deviceCode: `D${i}` }));
    spy = spyCursor(FireDevice, docs);
    const { worksheet } = injectWorkbook();
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: LIMIT + 1 });

    expect(saidIncomplete(res)).toBe(true);
    const footer = footerOf(worksheet);
    expect(footer).toContain(`仅包含前 ${LIMIT} 行`);
    expect(footer).toContain('命中总数');
    expect(footer).not.toContain('计数之后');
  });
});
