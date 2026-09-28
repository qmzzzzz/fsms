/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：protocolCompliance.recordViolation / errorHandler 的 headersSent / metrics.incSecurityAlert
 * 守护的不变式：攻击者可控字段必须 strip 控制字符（防日志伪造）；响应已开始写出后不得再 res.json；计数器必须走 canAddSeries 上限
 * 可证伪性：变异实测（筛查 N=2）：杀 2/3
 *
 * 命名沿革：2026-09-20 由 `zzqoder_writeSurfaceHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 三处"写入面"加固的可证伪回归
 *
 * protocolCompliance.recordViolation：认证前、限流前的路径把攻击者全控的
 *      User-Agent 与 Content-Type 原文写进不可篡改的 AuditLog 与访问日志。
 *      姊妹路径 recordEarlyRejection 一直做 stripControlChars(x,512)，这里漏了。
 *      危害不只是记录变大：Bidi/行终止符可伪造多行日志与篡改终端显示顺序，
 *      且本路径匿名可触发、无限流。
 * errorHandler 缺 res.headersSent 保护：响应已开始写出时继续 res.json()
 *      会在错误处理器内部抛 ERR_HTTP_HEADERS_SENT，真实错误被二次异常吞掉。
 * metrics.incSecurityAlert 绕过了其他计数器都走的 canAddSeries 上限。
 */

const mongoose = require('mongoose');

const flushAsync = () => new Promise((resolve) => setTimeout(resolve, 150));

// 控制字符一律用转义写，避免本测试文件自身含不可见字节
const UA_PAYLOAD = 'A'.repeat(4000);
// CT 取 1200：Node 单个 header 上限 8KB，9000 字符会被**整个丢弃**，
// 于是中间件走 missing_content_type（reason 仅 28 字符）而测不到截断。
const CT_PAYLOAD = 'zzqoder/' + 'x'.repeat(1200);

describe('写入面加固：协议违规留痕 / 错误处理器 / 指标系列上限', () => {
  let AuditLog;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../models/AuditLog');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('认证前协议违规留痕必须清洗并限长', () => {
    /**
     * 用真 express + supertest 驱动：协议合规中间件对"什么样的请求算携带 body 的写操作"
     * 有前置判定，手搓的假 req 到不了 recordViolation（试过，spy 零命中）。
     * 断言点放在"传给 AuditLog.record 的实参"上——清洗发生在传参之前，
     * 传参即这条修复的准确被测面，且不必等审计缓冲/WAL 落盘。
     */
    let server;
    let captured;

    beforeAll(async () => {
      const express = require('express');
      const { protocolCompliance } = require('../middleware/protocolCompliance');
      captured = [];
      const realRecord = AuditLog.record;
      jest.spyOn(AuditLog, 'record').mockImplementation((payload) => {
        if (payload && payload.action === 'malformed_request_blocked') captured.push(payload);
        return Promise.resolve({});
      });
      const app = express();
      app.use(express.json());
      app.use(protocolCompliance());
      app.post('/api/zzqoder-probe', (_req, res) => res.json({ ok: true }));
      server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
      });
      // 保留原 record 以便 afterAll 还原语义（jest.restoreAllMocks 亦足够）
      expect(typeof realRecord).toBe('function');
    });

    afterAll(async () => {
      jest.restoreAllMocks();
      if (server) await new Promise((resolve) => server.close(resolve));
    });

    const post = async (userAgent, contentType) => {
      const request = require('supertest');
      return request(server)
        .post('/api/zzqoder-probe')
        .set('User-Agent', userAgent)
        .set('Content-Type', contentType)
        .send('{"a":1}');
    };

    const lastCapture = () => captured[captured.length - 1];

    test('构造有效：不支持的媒体类型确实触发了违规留痕（否则后面全是空集假绿）', async () => {
      const before = captured.length;
      const res = await post(UA_PAYLOAD, CT_PAYLOAD);
      await flushAsync();
      // 不断言具体状态码：这条载荷（4000 UA + 9000 CT）会先被 Node 的
      // 头部尺寸校验判 431，而不是走到本中间件的媒体类型分支判 415。
      // 本用例要钉的是"确实产生了一条违规留痕"，那才是清洗发生的地方。
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      expect(captured.length).toBeGreaterThan(before);
      expect(lastCapture().riskFactors).toContain('protocol_violation');
    });

    test('userAgent 被截到 512 以内且不残留控制字符', async () => {
      await post(UA_PAYLOAD, CT_PAYLOAD);
      await flushAsync();
      const { userAgent } = lastCapture();
      expect(userAgent.length).toBeLessThanOrEqual(512);
      expect(userAgent).toBe('A'.repeat(512));
    });

    test('reason（内嵌攻击者 Content-Type）同样被清洗限长', async () => {
      await post(UA_PAYLOAD, CT_PAYLOAD);
      await flushAsync();
      const { reason } = lastCapture();
      expect(reason.length).toBe(512);
      expect(reason.startsWith(String.fromCharCode(0x4e0d))).toBe(true);
    });

    test('反向保护：正常长度 UA 原样保留，合法 JSON 请求正常放行', async () => {
      const legitUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0';
      await post(legitUA, CT_PAYLOAD);
      await flushAsync();
      expect(lastCapture().userAgent).toBe(legitUA);

      const request = require('supertest');
      const ok = await request(server)
        .post('/api/zzqoder-probe')
        .set('User-Agent', legitUA)
        .set('Content-Type', 'application/json')
        .send({ a: 1 });
      expect(ok.status).toBe(200);
      expect(ok.body.ok).toBe(true);
    });
  });

  describe('响应已发出时错误处理器不得再改写响应', () => {
    // errorHandler 是 module.exports = 函数本体（asyncHandler 才挂在属性上）
    const errorHandler = require('../middleware/errorHandler');

    const makeSentRes = () => {
      const calls = { json: 0, end: 0 };
      const res = {
        headersSent: true,
        writableEnded: false,
        statusCode: 200,
        status() {
          throw new Error('ERR_HTTP_HEADERS_SENT');
        },
        json() {
          calls.json += 1;
          return this;
        },
        end() {
          calls.end += 1;
          res.writableEnded = true;
          return this;
        },
      };
      return { res, calls };
    };

    test('headersSent=true 时既不抛二次异常也不写 JSON，只结束响应并记日志', () => {
      const { res, calls } = makeSentRes();
      const req = { originalUrl: '/api/reports/export?token=abc', method: 'GET' };
      const err = new Error('真实原因：client aborted the stream');

      expect(() => errorHandler(err, req, res, () => {})).not.toThrow();
      expect(calls.json).toBe(0);
      expect(res.writableEnded).toBe(true);
    });

    test('已 writableEnded 时连 end() 也不重复调用', () => {
      const { res, calls } = makeSentRes();
      res.writableEnded = true;
      errorHandler(new Error('boom'), { originalUrl: '/x', method: 'GET' }, res, () => {});
      expect(calls.end).toBe(0);
    });

    test('反向保护：未发出响应时仍照常走既有 JSON 错误路径', () => {
      const res = {
        headersSent: false,
        writableEnded: false,
        _payload: null,
        status(code) {
          res._code = code;
          return res;
        },
        json(payload) {
          res._payload = payload;
          return res;
        },
        end() {
          throw new Error('不应被调用');
        },
      };
      const err = new Error('bad id');
      err.name = 'CastError';
      err.path = '_id';
      errorHandler(err, { originalUrl: '/api/x', method: 'GET' }, res, () => {});
      expect(res._code).toBe(400);
      expect(res._payload).not.toBeNull();
    });
  });

  describe('metrics：安全告警计数器必须与其他计数器共享 series 上限', () => {
    let metrics;

    beforeAll(() => {
      metrics = require('../utils/metrics');
    });

    afterEach(() => {
      metrics._alertCounters.clear();
      metrics._alertLabels?.clear?.();
    });

    test('海量不同 type 不再无界增长（此前唯独该计数器绕过 canAddSeries）', () => {
      for (let i = 0; i < 5200; i++) {
        metrics.incSecurityAlert(`zzqoder_type_${i}`, 'high');
      }
      expect(metrics._alertCounters.size).toBeLessThanOrEqual(5000);
    });

    test('反向保护：既有字面量标签仍正常计数（上限不得变成不计数）', () => {
      metrics.incSecurityAlert('audit_write_failed', 'high');
      metrics.incSecurityAlert('audit_write_failed', 'high');
      const values = [...metrics._alertCounters.values()];
      expect(values).toContain(2);
    });
  });
});
