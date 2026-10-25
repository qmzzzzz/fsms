/**
 * 请求级日志关联测试（报告 O-5：AsyncLocalStorage 注入 requestId）
 *
 * 覆盖：logContext 单元语义（上下文存取/异步链继承/隔离性）、
 * requestId 中间件把请求包进上下文（logger format 据此合并 requestId）。
 */

const request = require('supertest');
const express = require('express');
const winston = require('winston');
const { runWithLogContext, getLogContext, extendLogContext } = require('../../utils/logContext');
const requestId = require('../../middleware/requestId');
const logger = require('../../utils/logger');
const { flushEventLoop } = require('../helpers/waitFor');

describe('logContext（O-5 请求级日志关联）', () => {
  test('脱离上下文读取返回 null（定时任务/启动期日志行为不变）', () => {
    expect(getLogContext()).toBeNull();
  });

  test('runWithLogContext 内可读到注入的上下文', () => {
    runWithLogContext({ requestId: 'abc123' }, () => {
      expect(getLogContext()).toEqual({ requestId: 'abc123' });
    });
    expect(getLogContext()).toBeNull(); // 退出上下文后恢复
  });

  test('异步链（await/setImmediate）天然继承 store', async () => {
    const observed = await runWithLogContext({ requestId: 'ctx-1' }, async () => {
      // 跨过一次事件循环即可证明 ALS 在异步链上传播，不需要计时时长
      await flushEventLoop();
      return getLogContext();
    });
    expect(observed).toEqual({ requestId: 'ctx-1' });
  });

  test('嵌套上下文内层覆盖外层，互不串扰', () => {
    runWithLogContext({ requestId: 'outer' }, () => {
      runWithLogContext({ requestId: 'inner' }, () => {
        expect(getLogContext().requestId).toBe('inner');
      });
      expect(getLogContext().requestId).toBe('outer');
    });
  });

  test('requestId 中间件把后续处理包进 ALS：处理器内读到的 requestId 与 req.id/X-Request-Id 一致', async () => {
    const app = express();
    app.use(requestId);
    app.get('/probe', (req, res) => {
      res.json({
        reqId: req.id,
        clientRequestId: req.clientRequestId ?? null,
        ctx: getLogContext() ?? null,
      });
    });

    // 客户端传入 X-Request-Id：**不得**成为关联主键，只作为独立的 clientRequestId 进日志上下文。
    // 旧断言（`reqId === 'client-id-1'`）是"复用客户端值"时期的契约，与现实现相反：
    // 复用等于让攻击者自选一个看起来像服务端签发的 ID（甚至与他人请求撞号），
    // 事后按 reqId 取证无法区分两条链路。此处的三条断言正是那次反转的门禁。
    const res = await request(app).get('/probe').set('X-Request-Id', 'client-id-1');
    expect(res.status).toBe(200);
    expect(res.body.reqId).toMatch(/^[0-9a-f]{16}$/);
    expect(res.body.reqId).not.toBe('client-id-1');
    // 响应头必须是服务端生成的那个值（回显客户端值等于把伪造 ID 洗白成"服务端签发"）
    expect(res.headers['x-request-id']).toBe(res.body.reqId);
    // 但客户端值不能丢：跨服务关联要用它，故另存 req.clientRequestId 并进 ALS 上下文
    expect(res.body.clientRequestId).toBe('client-id-1');
    expect(res.body.ctx.clientRequestId).toBe('client-id-1');
    // 关键断言：ALS 上下文与请求 ID 一致 → logger format 注入的是正确值
    expect(res.body.ctx.requestId).toBe(res.body.reqId);
  });

  test('不合规的客户端 X-Request-Id 一律丢弃，且不污染 req.id', async () => {
    const app = express();
    app.use(requestId);
    app.get('/probe', (req, res) => {
      res.json({ reqId: req.id, clientRequestId: req.clientRequestId ?? null });
    });

    // 含空格（日志注入面）与超长（放大面）两种形态都必须被 CLIENT_ID_RE 挡掉
    const bad = await request(app).get('/probe').set('X-Request-Id', 'id with space');
    expect(bad.body.clientRequestId).toBeNull();
    expect(bad.body.reqId).toMatch(/^[0-9a-f]{16}$/);

    const tooLong = await request(app).get('/probe').set('X-Request-Id', 'a'.repeat(65));
    expect(tooLong.body.clientRequestId).toBeNull();
    expect(tooLong.body.reqId).toMatch(/^[0-9a-f]{16}$/);
  });

  test('未传 X-Request-Id 时生成新 ID 并同样进入上下文', async () => {
    const app = express();
    app.use(requestId);
    app.get('/probe', (req, res) => {
      res.json({ reqId: req.id, ctxRequestId: getLogContext()?.requestId ?? null });
    });

    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
    expect(res.body.reqId).toMatch(/^[0-9a-f]{16}$/);
    expect(res.body.ctxRequestId).toBe(res.body.reqId);
  });

  describe('extendLogContext（报告 5.6：userId 自动注入）', () => {
    test('脱离上下文为无操作，不抛错', () => {
      expect(() => extendLogContext({ userId: 'u0' })).not.toThrow();
      expect(getLogContext()).toBeNull();
    });

    test('请求中途增量合并：requestId 保留、userId 追加，异步链可见', async () => {
      const observed = await runWithLogContext({ requestId: 'r-1' }, async () => {
        extendLogContext({ userId: 'u-1' });
        // 让出事件循环即可验证合并后的上下文在异步链上可见
        await flushEventLoop();
        return getLogContext();
      });
      expect(observed).toEqual({ requestId: 'r-1', userId: 'u-1' });
    });

    test('logger format 把上下文 userId 合并进日志条目', () => {
      const captured = [];
      class MemTransport extends winston.Transport {
        log(info, callback) {
          captured.push(info);
          callback();
        }
      }
      const mem = new MemTransport();
      logger.add(mem);
      try {
        runWithLogContext({ requestId: 'r-fmt' }, () => {
          extendLogContext({ userId: 'u-fmt' });
          logger.info('format probe');
        });
        const entry = captured.find((i) => i.message === 'format probe');
        expect(entry).toBeTruthy();
        expect(entry.requestId).toBe('r-fmt');
        expect(entry.userId).toBe('u-fmt');
      } finally {
        logger.remove(mem);
      }
    });
  });
});
