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

  test('异步链（await/定时器）天然继承 store', async () => {
    const observed = await runWithLogContext({ requestId: 'ctx-1' }, async () => {
      await new Promise((r) => setTimeout(r, 10));
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
        ctxRequestId: getLogContext()?.requestId ?? null,
        headerId: req.get('X-Request-Id'),
      });
    });

    // 客户端传入 X-Request-Id 时复用
    const res = await request(app).get('/probe').set('X-Request-Id', 'client-id-1');
    expect(res.status).toBe(200);
    expect(res.body.reqId).toBe('client-id-1');
    expect(res.body.headerId).toBe('client-id-1');
    // 关键断言：ALS 上下文与请求 ID 一致 → logger format 注入的是正确值
    expect(res.body.ctxRequestId).toBe('client-id-1');
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
        await new Promise((r) => setTimeout(r, 10));
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
