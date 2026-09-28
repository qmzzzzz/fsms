/**
 * 被错误截断的流式响应不得被审计记成"成功"
 *
 * 全局审计中间件的结论是这么来的：`success = res.statusCode < 400`。
 * 流式导出（审计 CSV / Excel / 报表）在第一个 chunk 之前就必须把状态码发出去，
 * 之后无论出什么事都改不了 200 —— 于是：
 *   客户端中途断开、序列化抛错、DB 游标断流……
 *   全都留下一条 `success: true` 的审计记录，仿佛那次导出完整交付了。
 * 审计库是事后追责的依据，替失败的导出背书是它最不该犯的错。
 *
 * 修法分两种情形，因为它们能做到的事不同：
 *   ① 记录还没写出（错误发生在第一个 chunk 之前，或生产者只用 writeHead/end）：
 *      错误处理器打 `res.locals.responseAbortedByError` 标记，auditLog 见到它就把
 *      success 翻成 false —— 一条记录，结论正确。
 *   ② 记录已经写出（流式响应的常态：auditLog 刻意在**第一个 chunk** 就记一条，
 *      崩溃也不丢；且 auditBuffer.push 同步写 WAL）：此时改内存对象只会让
 *      WAL 与库不一致，append-only 审计的正确做法是**追加一条更正事件**
 *      （action=response_aborted_after_headers，success:false，body 带原因）。
 * 两条路径都绝不产生重复记录：②的更正只在 res.locals.auditRecordWritten 为真时发出。
 *
 * 断言观察 `auditBuffer.push`（真实落库通道），不起整栈、不连库：
 * 这里要证的是"结论字段怎么算出来的"，与存储无关。
 */
const express = require('express');
const request = require('supertest');

const auditBuffer = require('../services/auditBuffer');
const { auditLog } = require('../middleware/security');
const errorHandler = require('../middleware/errorHandler');

describe('错误截断的响应在审计里必须是失败', () => {
  let pushSpy;

  beforeEach(() => {
    pushSpy = jest.spyOn(auditBuffer, 'push').mockImplementation(() => {});
  });

  afterEach(() => {
    pushSpy.mockRestore();
  });

  const buildApp = (routes) => {
    const app = express();
    app.use(express.json());
    app.use(
      '/api/probe-stream',
      (req, _res, next) => {
        req.auditAction = 'stream_probe';
        req.auditCategory = 'security';
        next();
      },
      // 探针路径本身不在生产 GET 审计白名单里（auditGetPaths 只列 6 个前缀），
      // 必须显式把它加进去，否则中间件在入口就 next() 了，一条审计都不会产生。
      auditLog({ auditGetPaths: ['/api/probe-stream'] }),
      routes
    );
    app.use(errorHandler);
    return app;
  };

  // doLog 在 setImmediate 里 push，断言前必须让出事件循环
  const settle = () => new Promise((resolve) => setTimeout(resolve, 60));
  const pushed = () => {
    expect(pushSpy).toHaveBeenCalledTimes(1);
    return pushSpy.mock.calls[0][0];
  };

  test('反向保护：正常 200 响应仍记 success=true（标记不得变成一律失败）', async () => {
    const app = buildApp((_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/api/probe-stream');
    await settle();

    expect(res.status).toBe(200);
    expect(pushed().success).toBe(true);
  });

  test('已发头并由 errorHandler 截断：首块记录无法回改，必须追加一条更正事件', async () => {
    const app = buildApp((_req, res, next) => {
      // 真实形态：导出已经把 CSV 头与首块写出去了（auditLog 在 write 时就记了那条），随后才炸
      res.status(200);
      res.write('partial-csv-line\n');
      next(new Error('导出流断开'));
    });

    const res = await request(app).get('/api/probe-stream');
    await settle();

    // 前提自证：响应状态码确实还是 200（否则这条用例其实在测 5xx 分支）
    expect(res.status).toBe(200);
    // 两条记录：① 首块时 latch 的那条（success 只能按当时状态码判，为 true）
    //            ② errorHandler 追加的更正事件（success:false）
    // 顺序不作前提：常规记录走 setImmediate，更正事件是同步 push，实测反而先到。
    expect(pushSpy).toHaveBeenCalledTimes(2);
    const records = pushSpy.mock.calls.map((c) => c[0]);
    const streamed = records.find((r) => r.action !== 'response_aborted_after_headers');
    const correction = records.find((r) => r.action === 'response_aborted_after_headers');
    expect(streamed.statusCode).toBe(200);
    expect(correction.success).toBe(false);
    expect(correction.statusCode).toBe(200);
    expect(JSON.stringify(correction.body)).toContain('导出流断开');
  });

  test('只 writeHead、记录尚未写出：靠标记翻转即可，不得再多记一条更正事件', async () => {
    const app = buildApp((_req, res, next) => {
      // writeHead 不经过 auditLog 包装的 json/send/write → 此刻还没有任何审计记录
      res.writeHead(200, { 'content-type': 'text/csv' });
      next(new Error('头已发但记录还没写'));
    });

    const res = await request(app).get('/api/probe-stream');
    await settle();

    expect(res.status).toBe(200);
    expect(pushSpy).toHaveBeenCalledTimes(1);
    const rec = pushSpy.mock.calls[0][0];
    expect(rec.action).not.toBe('response_aborted_after_headers');
    // 结论仍然必须是对的：这条由 res.locals.responseAbortedByError 翻转得来
    expect(rec.success).toBe(false);
  });

  test('未写出过审计的错误不得追加更正事件（一条事实只记一次）', async () => {
    const app = buildApp((_req, _res, next) => next(new Error('还没碰过响应')));

    const res = await request(app).get('/api/probe-stream');
    await settle();

    expect(res.status).toBe(500);
    expect(pushSpy).toHaveBeenCalledTimes(1);
    expect(pushSpy.mock.calls[0][0].success).toBe(false);
  });

  test('控制器自行结束流时打的标记同样生效（不依赖 errorHandler）', async () => {
    const app = buildApp((_req, res) => {
      res.locals.responseAbortedByError = '审计导出第 3 块写入失败';
      res.send('truncated');
    });

    await request(app).get('/api/probe-stream');
    await settle();

    expect(pushed().success).toBe(false);
  });

  test('真 5xx 路径不受影响（success 仍按状态码判，标记不是唯一入口）', async () => {
    const app = buildApp((_req, res) => {
      res.status(500).json({ ok: false });
    });

    const res = await request(app).get('/api/probe-stream');
    await settle();

    expect(res.status).toBe(500);
    expect(pushed().success).toBe(false);
  });

  test('标记缺失（res.locals 不可用的替身）不得让错误处理器自己抛出去', async () => {
    // Express 恒提供 res.locals；这条钉的是"错误处理器绝不能二次抛错"这一约束：
    // 一旦它因 res.locals 为 undefined 而抛，真实原因就被掩盖成"处理器坏了"。
    const reason = require('../middleware/errorHandler');
    expect(typeof reason).toBe('function');
    let thrown = null;
    const res = {
      headersSent: true,
      writableEnded: true,
      end() {},
      // 故意不给 locals
    };
    try {
      reason(
        new Error('x'),
        { originalUrl: '/api/zz', method: 'GET', ip: '1.1.1.1' },
        res,
        () => {}
      );
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeNull();
  });
});
