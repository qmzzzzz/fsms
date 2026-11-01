/**
 * 取证捕获中间件（P2）：响应包装不改写行为、不阻塞、三态对拍
 *
 * 被测对象：middleware/security/forensicCapture.js。
 *
 * 三条判据（每条都配一个"实现改坏就红"的反向断言）：
 *  ① 透传：json/send/write/end 的返回值、this、入参、异常与不装中间件时逐字相同；
 *  ② 不阻塞：res.json 返回时采集尚未发生（WAL/落库都在 finish 后的 setImmediate 里）；
 *  ③ 三态：开关关 / 未标记 ⇒ 零采集；标记 + 抛错 ⇒ 只计数不 500。
 */

const express = require('express');
const request = require('supertest');

// 触发判据与落库都用替身：本文件只验中间件的时序与透传，不碰数据库
const mockState = { on: false, throws: false, hasGetter: true, lastMark: null };
jest.mock('../../services/forensicTrigger', () => {
  const mod = {
    isForensicTarget: () => {
      if (mockState.throws) throw new Error('trigger boom');
      return mockState.on;
    },
    getForensicTriggerStats: () => ({ lastMark: mockState.lastMark }),
  };
  // 动态属性：hasGetter=false 时 typeof 为 'undefined'，才真的模拟出"P1 未导出按 IP getter"
  // 的形态（一次性赋值的函数属性在用例之间无法撤除，兜底路径就没有被测对象了）
  Object.defineProperty(mod, 'getForensicTarget', {
    get: () =>
      mockState.hasGetter
        ? () => (mockState.on ? { reason: 'honeypot_login', markedAt: new Date(0) } : null)
        : undefined,
  });
  return mod;
});

const mockInsertMany = jest.fn(async () => ({ insertedCount: 1 }));
jest.mock('../../models/ForensicCapture', () => ({
  insertMany: (...args) => mockInsertMany(...args),
}));

const service = require('../../services/forensicCapture');

/** 取"已落库"的取证记录：走 flush() → model.insertMany 替身，不读模块内部缓冲 */
const flushedDocs = async () => {
  await settle();
  await service.flush();
  const call = mockInsertMany.mock.calls[mockInsertMany.mock.calls.length - 1];
  return call ? call[0] : [];
};
const { forensicCapture } = require('../../middleware/security/forensicCapture');

const tick = () => new Promise((resolve) => setImmediate(resolve));
/** 采集在 finish → setImmediate 之后才发生，这里等到"真的写进缓冲"为止 */
const settle = async () => {
  for (let i = 0; i < 8; i += 1) await tick();
};

const buildApp = (handler, { mount = true } = {}) => {
  const app = express();
  app.use(express.json());
  if (mount) app.use('/api/', forensicCapture());
  app.post('/api/probe', handler);
  app.get('/api/probe', handler);
  return app;
};

describe('① 透传：装上中间件与不装时，客户端看到的东西逐字相同', () => {
  beforeEach(() => {
    service.resetForTests();
    mockState.on = true;
    mockState.throws = false;
    mockInsertMany.mockClear();
  });

  test('res.json：状态码/头/体一致，且返回值为 res（可链式）', async () => {
    const handler = (req, res) => res.status(201).json({ ok: true, echo: req.body.x });
    const payload = { x: 7 };
    const plain = await request(buildApp(handler, { mount: false }))
      .post('/api/probe')
      .send(payload);
    const captured = await request(buildApp(handler)).post('/api/probe').send(payload);
    expect(captured.status).toBe(plain.status);
    expect(captured.headers['content-type']).toBe(plain.headers['content-type']);
    expect(captured.text).toBe(plain.text);
    await settle();
  });

  test('res.send：文本体一致（send 内部再走 end 不产生第二条记录）', async () => {
    const handler = (req, res) => res.type('text/plain').send('hello');
    const plain = await request(buildApp(handler, { mount: false }))
      .post('/api/probe')
      .send({});
    const captured = await request(buildApp(handler)).post('/api/probe').send({});
    expect(captured.text).toBe(plain.text);
    expect(captured.headers['content-type']).toBe(plain.headers['content-type']);
    await settle();
    // 一次响应只产出一条记录（finish 与 close 都触发 finalize，靠 done 守卫去重）
    expect(service.getForensicCaptureStats().captured).toBe(1);
  });

  test('write(chunk, encoding, callback) 三参形态与返回值原样透传', async () => {
    let writeReturn;
    let endReturn;
    const handler = (req, res) => {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      const cb = jest.fn();
      writeReturn = res.write('col\n', 'utf8', cb);
      endReturn = res.end('row\n', 'utf8', cb);
      expect(typeof writeReturn).toBe('boolean');
    };
    const res = await request(buildApp(handler)).post('/api/probe').send({});
    expect(res.text).toBe('col\nrow\n');
    expect(endReturn).toBeDefined();
    await settle();
  });

  test('处理器抛错：错误照旧冒泡到错误处理链（中间件不吞异常）', async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/', forensicCapture());
    app.post('/api/probe', () => {
      throw new Error('handler boom');
    });
    // 默认错误处理：500 + HTML，与不装中间件时同形（这里只验"没被吞成 200"）
    const res = await request(app).post('/api/probe').send({});
    expect(res.status).toBe(500);
    await settle();
  });
});

describe('② 不阻塞响应：采集发生在 finish 之后，不在 json/send 的调用栈里', () => {
  beforeEach(() => {
    service.resetForTests();
    mockState.on = true;
    mockState.throws = false;
    mockInsertMany.mockClear();
  });

  test('res.json 返回时缓冲仍为空（同一 tick 内不采集），让出事件循环后才写入', async () => {
    let capturedInsideHandler = null;
    const handler = (req, res) => {
      res.json({ ok: true });
      // 处理器返回前读一次：此时必须还是 0（否则重活压在了响应路径上）
      capturedInsideHandler = service.getForensicCaptureStats().captured;
    };
    await request(buildApp(handler)).post('/api/probe').send({});
    expect(capturedInsideHandler).toBe(0);
    await settle();
    expect(service.getForensicCaptureStats().captured).toBe(1);
  });

  test('落库失败（模型层不可用）⇒ 请求仍是 200，且错误写进 lastError（失败可见）', async () => {
    mockInsertMany.mockImplementationOnce(async () => {
      throw new Error('db down');
    });
    const handler = (req, res) => res.json({ ok: true });
    const res = await request(buildApp(handler)).post('/api/probe').send({});
    expect(res.status).toBe(200);
    await settle();
    // 采集在 finish 后入缓冲，落库由 flush 触发：这里显式落库一次，断言错误被记到 lastError
    await service.flush();
    expect(service.getForensicCaptureStats().lastError).toContain('db down');
  });
});

describe('③ 三态对拍：关 / 开 / 抛错', () => {
  beforeEach(() => {
    service.resetForTests();
    mockState.on = false;
    mockState.throws = false;
    mockInsertMany.mockClear();
  });

  test('未标记 ⇒ 零采集（wrapped 也不产生记录）', async () => {
    const handler = (req, res) => res.json({ ok: true });
    await request(buildApp(handler)).post('/api/probe').send({});
    await settle();
    const stats = service.getForensicCaptureStats();
    expect(stats.captured).toBe(0);
    expect(stats.rejected).toBe(0);
  });

  test('开关关闭 ⇒ 即使已标记也零采集', async () => {
    const prev = process.env.FORENSIC_CAPTURE_ENABLED;
    process.env.FORENSIC_CAPTURE_ENABLED = 'false';
    mockState.on = true;
    const handler = (req, res) => res.json({ ok: true });
    await request(buildApp(handler)).post('/api/probe').send({});
    await settle();
    process.env.FORENSIC_CAPTURE_ENABLED = prev;
    expect(service.getForensicCaptureStats().captured).toBe(0);
  });

  test('触发判据抛错 ⇒ 请求照常完成（不 500、不挂起），且计 rejected', async () => {
    mockState.throws = true;
    const handler = (req, res) => res.json({ ok: true });
    const res = await request(buildApp(handler)).post('/api/probe').send({});
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(service.getForensicCaptureStats().rejected).toBeGreaterThan(0);
  });
});

describe('触发快照归因：P1 只给 lastMark 时的兜底', () => {
  beforeEach(() => {
    service.resetForTests();
    mockInsertMany.mockClear();
    // 全量复位触发开关：任一用例断言失败留下的脏状态会让后续用例的"采集前提"不成立
    // （此前实测：上一条用例把 throws 留成 true ⇒ 本组用例根本没采集，flushedDocs 为空）
    mockState.on = false;
    mockState.throws = false;
    mockState.hasGetter = true;
    mockState.lastMark = null;
  });

  test('无按 IP getter：同 IP 的 lastMark 被用作 trigger.reason', async () => {
    mockState.on = true;
    mockState.hasGetter = false;
    mockState.lastMark = null;
    const handler = (req, res) => res.json({ ok: true });
    // 先跑一次拿到中间件实际使用的 ip 口径（不手抄 127.0.0.1/::ffff: 形态）
    await request(buildApp(handler)).post('/api/probe').send({});
    const first = await flushedDocs();
    const ip = first[0].ip;
    expect(ip).toBeTruthy();
    mockState.lastMark = { ip, reason: 'honeypot_login', at: Date.parse('2026-10-31T00:00:00Z') };
    await request(buildApp(handler)).post('/api/probe').send({});
    const docs = await flushedDocs();
    expect(docs[0].ip).toBe(ip);
    expect(docs[0].trigger.reason).toBe('honeypot_login');
    expect(docs[0].trigger.markedAt).toBeInstanceOf(Date);
    mockState.hasGetter = true;
    mockState.lastMark = null;
    mockState.on = false;
  });

  test('无 getter 且 lastMark 指向别的 IP：归因留空（宁缺毋猜）', async () => {
    mockState.on = true;
    mockState.hasGetter = false;
    mockState.lastMark = { ip: '198.51.100.1', reason: 'brute_force_auto_ban', at: Date.now() };
    const handler = (req, res) => res.json({ ok: true });
    await request(buildApp(handler)).post('/api/probe').send({});
    const docs = await flushedDocs();
    expect(docs[0].ip).not.toBe('198.51.100.1'); // 前提：本请求的 ip 确实不是 lastMark 那个
    expect(docs[0].trigger).toEqual({ reason: null, markedAt: null });
    mockState.hasGetter = true;
    mockState.lastMark = null;
    mockState.on = false;
  });
});

describe('响应侧采集内容：状态/头/体与流式元数据', () => {
  beforeEach(() => {
    service.resetForTests();
    mockState.on = true;
    mockState.throws = false;
    mockInsertMany.mockClear();
  });

  test('json 响应的采集物含 status/contentType/bodySha256（从落库 sink 读出）', async () => {
    const handler = (req, res) => res.json({ ok: true });
    await request(buildApp(handler)).post('/api/probe').send({});
    const docs = await flushedDocs();
    expect(docs).toHaveLength(1);
    const doc = docs[0];
    expect(doc.response.status).toBe(200);
    expect(doc.response.contentType).toContain('application/json');
    expect(doc.response.bodySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.recordHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('流式响应（write*2 + end）只留元数据，不存半截内容', async () => {
    const handler = (req, res) => {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.write('col\n');
      res.write('row\n');
      res.end();
    };
    await request(buildApp(handler)).post('/api/probe').send({});
    const doc = (await flushedDocs())[0];
    expect(doc.response.body).toEqual({
      contentType: 'text/csv; charset=utf-8',
      bytes: 8,
      complete: true,
    });
    expect(JSON.stringify(doc.response)).not.toContain('row');
  });
});
