/**
 * xlsx 导出的两处完整性缺口（services/reportWorkbookService.js）
 *
 * 缺口一：populate 分支**静默少行**。
 *   该分支分两步取数：先查一批 `_id`，再按 200 个一把回填文档。两次查询之间
 *   被删除（或改得不再匹配筛选条件）的行，原实现写作 `if (doc) { …写… }`——
 *   没有 else，也没有计数。后果不是"少一行数据"而是**少行这件事不可知**：
 *   `truncated` 仍是 false，响应头没有 X-Export-Truncated，表里没有脚注，
 *   拿到文件的人看到的是一份"看起来完整"的合规材料。
 *
 * 缺口二：写响应时对**客户端中断完全无感**。
 *   `workbook.xlsx.write(res)` 等的是 zip 自己收工，不是目的端收工。探针实测
 *   （正常与中断两侧都一样）：它 resolve 的那一刻 `res` 上一个流事件都没发。
 *   原实现 await 完就返回 ⇒ 半截文件照样报成功、controller 无 try/catch、
 *   审计里一条 error 都没有。CSV 侧早就为同一情形立了判据
 *   （auditExportService.js:85-101、150-152），这里补齐 xlsx 这半边。
 *
 * 每条断连用例都配了反向对照：把"任何 close 都算中断"当成修法，
 * 会让每一次**成功**导出都变成 500（Node 正常收尾时也发 close）。
 */
jest.mock('exceljs');

const { Workbook } = require('exceljs');
const { Writable } = require('stream');
const { streamExportRows, writeExportWorkbook } = require('../../services/reportWorkbookService');
const { EXPORT_LIMIT } = require('../../services/reportExportService');
const FireAlarm = require('../../models/FireAlarm');
const FireDevice = require('../../models/FireDevice');

const LIMIT = EXPORT_LIMIT;

const makeWorksheet = () => ({
  properties: {},
  columns: undefined,
  addRow: jest.fn(),
  getRow: jest.fn(() => ({ eachCell: (callback) => callback({}) })),
});

/** 目的端由测试亲自摆位的 res 桩：`fire(event, err)` 按 once 语义派发 */
const makeRes = () => {
  const handlers = {};
  const res = {
    setHeader: jest.fn(),
    once: (event, fn) => {
      (handlers[event] = handlers[event] || []).push(fn);
    },
    fired: [],
    destroyed: false,
    writableFinished: false,
    locals: {},
  };
  res.fire = (event, err) => {
    res.fired.push(event);
    const list = handlers[event] || [];
    delete handlers[event];
    for (const fn of list) fn(err);
  };
  return res;
};

/** workbook 桩：`xlsx.write(res)` 演一遍给定的"目的端剧本"，然后照常 resolve */
const injectWorkbook = (script) => {
  const worksheet = makeWorksheet();
  const workbook = {
    addWorksheet: jest.fn(() => worksheet),
    xlsx: {
      write: jest.fn(async (res) => {
        if (script) script(res);
        // 没有剧本就是"正常收尾"：真实目的流一定会发 finish（write() 之后），
        // 而实现要等这个表态，桩不回话就只能把用例挂死在这里。
        else res.fire('finish');
      }),
    },
  };
  Workbook.mockImplementationOnce(() => workbook);
  return { workbook, worksheet };
};

const populateConfig = (ids, docs) => ({
  model: {
    find: jest.fn((query) => {
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
    }),
  },
  sort: { occurredAt: -1 },
  populate: [{ path: 'handler' }],
  select: 'handler',
});

const cursorConfig = (docs) => ({
  model: {
    find: jest.fn(() => ({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      cursor: jest.fn(async function* generate() {
        yield* docs;
      }),
    })),
  },
  sort: { deviceCode: 1 },
  populate: [],
  select: 'deviceCode',
});

describe('回填阶段消失的行必须计入 rowsLost 并说出来', () => {
  test('populate 分支：id 有 4 个、回填只拿到 3 个 ⇒ rowsLost=1', async () => {
    const ids = ['a', 'b', 'c', 'd'];
    const docs = [{ _id: 'a' }, { _id: 'c' }, { _id: 'd' }];
    const worksheet = makeWorksheet();

    const out = await streamExportRows(
      worksheet,
      populateConfig(ids, docs),
      { scope: true },
      (doc) => doc
    );

    expect(out).toEqual({ written: 3, truncated: false, rowsLost: 1 });
    expect(worksheet.addRow).toHaveBeenCalledTimes(3);
  });

  test('负前提：一条没丢时 rowsLost 必须是 0（不能把写进去的行也算成丢的）', async () => {
    const ids = ['a', 'b', 'c', 'd'];
    const docs = ids.map((id) => ({ _id: id }));

    const out = await streamExportRows(
      makeWorksheet(),
      populateConfig(ids, docs),
      {},
      (doc) => doc
    );

    expect(out).toEqual({ written: 4, truncated: false, rowsLost: 0 });
  });

  test('负前提：游标分支没有两次查询的窗口，rowsLost 恒为 0', async () => {
    const out = await streamExportRows(
      makeWorksheet(),
      cursorConfig([{ deviceCode: 'DEV-0' }, { deviceCode: 'DEV-1' }]),
      {},
      (doc) => doc
    );

    expect(out).toEqual({ written: 2, truncated: false, rowsLost: 0 });
  });

  test('rowsLost 与 truncated 各说各的：只丢行不得被说成"仅包含前 N 行"', async () => {
    const findSpy = jest
      .spyOn(FireAlarm, 'find')
      .mockImplementation(populateConfig(['a', 'b', 'c'], [{ _id: 'a' }, { _id: 'b' }]).model.find);
    const { worksheet } = injectWorkbook(null);
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'alarms', query: {}, total: 3 });

    expect(res.setHeader).toHaveBeenCalledWith('X-Export-Truncated', 'true');
    const footer = String(worksheet.addRow.mock.calls.at(-1)[0][0]);
    // 一句"仅包含前 5000 行"会把"那些行已经不存在了"说成"后面还有记录"，
    // 而这两种情况的追查方向完全不同 ⇒ 这一格是本案的可证伪点
    expect(footer).not.toContain('仅包含前');
    expect(footer).toContain('数据不完整');
    expect(footer).toContain('1 行在导出期间被删除或不再匹配筛选条件');
    expect(footer).toContain('实际写入 2 行');
    findSpy.mockRestore();
  });

  test('撞上限那一侧的脚注文案不得因这次改动漂移（逐字钉住）', async () => {
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(
        cursorConfig(Array.from({ length: LIMIT + 1 }, (_, i) => ({ deviceCode: `DEV-${i}` })))
          .model.find
      );
    const { worksheet } = injectWorkbook(null);
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'devices', query: {}, total: LIMIT + 37 });

    expect(String(worksheet.addRow.mock.calls.at(-1)[0][0])).toBe(
      `⚠ 数据已截断：本文件仅包含前 ${LIMIT} 行（命中总数 ${LIMIT + 37}），` +
        '请缩小时间范围或增加筛选条件后重新导出。'
    );
    findSpy.mockRestore();
  });

  test('两种不完整同时发生 ⇒ 脚注必须把两条都写出来', async () => {
    const ids = Array.from({ length: LIMIT + 1 }, (_, i) => `id-${i}`);
    // 回填只拿到前 LIMIT 个 id 里的 LIMIT-2 个 ⇒ 探针那条不算丢行
    const docs = ids.slice(0, LIMIT - 2).map((id) => ({ _id: id }));
    const findSpy = jest
      .spyOn(FireAlarm, 'find')
      .mockImplementation(populateConfig(ids, docs).model.find);
    const { worksheet } = injectWorkbook(null);
    const res = makeRes();

    await writeExportWorkbook(res, { type: 'alarms', query: {}, total: LIMIT + 9 });

    const footer = String(worksheet.addRow.mock.calls.at(-1)[0][0]);
    expect(footer).toContain('数据已截断');
    expect(footer).toContain(`本文件仅包含前 ${LIMIT} 行（命中总数 ${LIMIT + 9}）`);
    expect(footer).toContain('2 行在导出期间被删除或不再匹配筛选条件');
    expect(footer).toContain('实际写入 4998 行');
    findSpy.mockRestore();
  });
});

describe('xlsx 写出只对真正送完的响应报成功', () => {
  const abortCases = [
    {
      name: 'close 单独到达（连接提前结束，没有 error）⇒ 报中断',
      script: (res) => res.fire('close'),
      expect: /中途断开/,
    },
    {
      name: 'error 带自己的错因 ⇒ 抛的就是那个错因，不被通用文案盖掉',
      script: (res) => res.fire('error', new Error('socket 被对端重置')),
      expect: /socket 被对端重置/,
    },
  ];

  test.each(abortCases)('$name', async ({ script, expect: re }) => {
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig([{ deviceCode: 'DEV-0' }]).model.find);
    injectWorkbook(script);
    const res = makeRes();

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).rejects.toThrow(re);
    findSpy.mockRestore();
  });

  /**
   * F-155：终局事件**早于**监听器就发完了
   *
   * 上面那批用例演的是"写完之前/之后事件才到"，监听器收得到。还有一种收不到：
   * 客户端在 write() 之前就已断开——finish/close 都已经发完，`once` 挂上去只能等
   * 未来事件 ⇒ `await settled` 永久挂住（不 error、不 resolve，成功与中断两条出口
   * 都到不了，workbook 与游标随 async 栈常驻）。判据只能来自状态位。
   */
  test('F-155 客户端在 write() 之前就已断开 ⇒ 必须报中断，而不是把 handler 挂死', async () => {
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig([{ deviceCode: 'DEV-0' }]).model.find);
    // 剧本：什么都不发（事件早已在挂监听之前发完），只摆状态位
    injectWorkbook(() => {});
    const res = makeRes();
    res.destroyed = true;
    res.writableEnded = true;

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).rejects.toThrow(
      /中途断开/
    );
    findSpy.mockRestore();
  });

  test('F-155 反向对照：写完且已被正常销毁（writableFinished）不得读成中断', async () => {
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig([{ deviceCode: 'DEV-0' }]).model.find);
    injectWorkbook(() => {});
    const res = makeRes();
    // 真实目的流收工后 Node 也会 destroy socket：先认 writableFinished，
    // 反过来写会把每一次"事件早于监听的成功导出"报成 500。
    res.writableFinished = true;
    res.destroyed = true;

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).resolves.not.toThrow();
    findSpy.mockRestore();
  });

  test('实测的那个窗口：write() 先 resolve、断连事件后到 ⇒ 必须等目的端表态', async () => {
    // 探针事实：xlsx.write() resolve 时 res 一个事件都没发。所以"写完读一下状态"
    // 抓不到任何一次中断；只有等 finish/close 才可能知道。
    // 这里把剧本设为"resolve 时什么都不做，下一拍才 close"，
    // 删掉 `await settled` 的实现会在这里红（它在 close 之前就已返回成功）。
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig([{ deviceCode: 'DEV-0' }]).model.find);
    injectWorkbook((res) => {
      setImmediate(() => res.fire('close'));
    });
    const res = makeRes();

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).rejects.toThrow(
      /中途断开/
    );
    expect(res.fired).toEqual(['close']);
    findSpy.mockRestore();
  });

  test('反向对照：正常收尾时 finish 之后紧跟的 close 不得被读成中断', async () => {
    // Node 的 http 响应在成功结束时**也会**发 close。
    // 把"任何 close 都算中断"当成修法，会让每一次成功导出都变成 500。
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig([{ deviceCode: 'DEV-0' }]).model.find);
    injectWorkbook((res) => {
      res.writableFinished = true;
      res.destroyed = true; // 收尾完成后 destroyed 也是 true
      res.fire('finish');
      res.fire('close');
    });
    const res = makeRes();

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).resolves.toBeUndefined();
    expect(res.fired).toEqual(['finish', 'close']);
    findSpy.mockRestore();
  });

  test('真实 exceljs + 真实目的流：全部收下时不得报中断，且字节确实进了目的端', async () => {
    const rows = Array.from({ length: 1500 }, (_, i) => ({ deviceCode: `DEV-${i}` }));
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig(rows).model.find);
    const RealExcelJS = jest.requireActual('exceljs');
    Workbook.mockImplementationOnce(() => new RealExcelJS.Workbook());

    const res = new Writable({
      write(chunk, enc, cb) {
        res.received += chunk.length;
        cb();
      },
    });
    res.received = 0;
    res.setHeader = () => {};
    res.locals = {};

    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).resolves.toBeUndefined();
    // 等过目的端终局事件才算成功：这里必须已经 finish
    expect(res.writableFinished).toBe(true);
    expect(res.received).toBeGreaterThan(1000);
    findSpy.mockRestore();
  });

  test('真实 exceljs + 目的流写到一半自毁 ⇒ 必须报失败（不能报成功）', async () => {
    const rows = Array.from({ length: 3000 }, (_, i) => ({ deviceCode: `DEV-${i}` }));
    const findSpy = jest
      .spyOn(FireDevice, 'find')
      .mockImplementation(cursorConfig(rows).model.find);
    const RealExcelJS = jest.requireActual('exceljs');
    Workbook.mockImplementationOnce(() => new RealExcelJS.Workbook());

    const res = new Writable({
      write(chunk, enc, cb) {
        res.received += chunk.length;
        if (res.received >= 2048) {
          res.destroy(new Error('EPIPE: 对端已关闭'));
          return; // 故意不回调：模拟字节再也不会被确认
        }
        cb();
      },
    });
    res.received = 0;
    res.setHeader = () => {};
    res.locals = {};

    // 探针实测：这种情况 xlsx.write() 仍然 resolve。若实现只 await write()，
    // 这里就会拿到"成功"，本用例红。
    await expect(writeExportWorkbook(res, { type: 'devices', query: {} })).rejects.toThrow(
      /对端已关闭|中途断开/
    );
    findSpy.mockRestore();
  });
});
