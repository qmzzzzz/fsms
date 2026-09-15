/**
 * 请求协议合规校验中间件单测
 */

const { protocolCompliance } = require('../../middleware/protocolCompliance');
const { TEST_CLIENT_IP } = require('../fixtures');

jest.mock('../../models/AuditLog', () => ({
  record: jest.fn(),
}));

const buildReq = ({
  method = 'GET',
  headers = {},
  originalUrl = '/api/devices',
  ip = TEST_CLIENT_IP,
} = {}) => ({
  method,
  headers,
  originalUrl,
  url: originalUrl,
  path: originalUrl,
  ip,
  get: (name) => headers[String(name).toLowerCase()],
});

const buildRes = () => {
  const res = {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
  return res;
};

describe('protocolCompliance 协议合规校验', () => {
  let mw;

  beforeEach(() => {
    mw = protocolCompliance();
  });

  it('正常 GET 请求放行', () => {
    const next = jest.fn();
    mw(buildReq(), buildRes(), next);
    expect(next).toHaveBeenCalled();
  });

  it('正常 JSON POST 请求放行', () => {
    const next = jest.fn();
    mw(
      buildReq({
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8', 'content-length': '42' },
      }),
      buildRes(),
      next
    );
    expect(next).toHaveBeenCalled();
  });

  it('TRACE 方法被拒绝（405）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ method: 'TRACE' }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(405);
  });

  it('带 body 的 POST 缺少 Content-Type 被拒绝（400）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ method: 'POST', headers: { 'content-length': '10' } }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('不支持的 Content-Type 被拒绝（415）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(
      buildReq({
        method: 'POST',
        headers: { 'content-type': 'application/xml', 'content-length': '10' },
      }),
      res,
      next
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(415);
  });

  it('无 body 的 POST 不强制要求 Content-Type', () => {
    const next = jest.fn();
    mw(buildReq({ method: 'POST', headers: { 'content-length': '0' } }), buildRes(), next);
    expect(next).toHaveBeenCalled();
  });

  it('Content-Length 超限被拒绝（413）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(
      buildReq({
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': String(20 * 1024 * 1024) },
      }),
      res,
      next
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(413);
  });

  it('Content-Length 非数值被拒绝（400）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ headers: { 'content-length': 'abc' } }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('头部数量超限被拒绝（431）', () => {
    const headers = {};
    for (let i = 0; i < 80; i++) headers[`x-custom-${i}`] = 'v';
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ headers }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(431);
  });

  it('单个头部值超长被拒绝（431）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ headers: { 'x-big': 'y'.repeat(9000) } }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(431);
  });

  it('非法头名被拒绝（400）', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ headers: { 'bad header': 'v' } }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('配置 allowedHosts 后 Host 不匹配被拒绝（400）', () => {
    const scoped = protocolCompliance({ allowedHosts: ['api.example.com'] });
    const next = jest.fn();
    const res = buildRes();
    scoped(buildReq({ headers: { host: 'evil.com' } }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('配置 allowedHosts 且 Host 匹配时放行', () => {
    const scoped = protocolCompliance({ allowedHosts: ['api.example.com'] });
    const next = jest.fn();
    scoped(buildReq({ headers: { host: 'api.example.com' } }), buildRes(), next);
    expect(next).toHaveBeenCalled();
  });

  it('skipPaths 命中时跳过全部校验', () => {
    const next = jest.fn();
    mw(buildReq({ method: 'TRACE', originalUrl: '/health' }), buildRes(), next);
    expect(next).toHaveBeenCalled();
  });

  it('multipart/form-data 上传被允许', () => {
    const next = jest.fn();
    mw(
      buildReq({
        method: 'POST',
        headers: {
          'content-type': 'multipart/form-data; boundary=----abc',
          'content-length': '1024',
        },
      }),
      buildRes(),
      next
    );
    expect(next).toHaveBeenCalled();
  });

  it('chunked 传输的 POST 仍校验 Content-Type', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(
      buildReq({
        method: 'POST',
        headers: { 'transfer-encoding': 'chunked' },
      }),
      res,
      next
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});

describe('protocolCompliance 边界补齐（2026-09-15）', () => {
  let mw;
  const AuditLog = require('../../models/AuditLog');

  beforeEach(() => {
    mw = protocolCompliance();
    AuditLog.record.mockClear();
  });

  it('同名 header 多值：各单值合法但求和超限 → 拒绝（reduce 求和分支）', () => {
    const next = jest.fn();
    const req = buildReq({
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-multi': Array.from({ length: 10 }, (_, i) => 'v'.repeat(1000) + i),
      },
    });
    const res = buildRes();
    mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(431); // HEADER_VALUE_TOO_LONG → 431
  });

  it('请求违规 → setImmediate 异步审计落库（malformed_request_blocked）', async () => {
    const next = jest.fn();
    const req = buildReq({ method: 'TRACE', headers: {} });
    const res = buildRes();
    mw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    // 等待 setImmediate 回调执行
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(AuditLog.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'malformed_request_blocked' })
    );
  });

  it('审计写入抛错 → 容忍（debug 跳过），不向外抛出', async () => {
    AuditLog.record.mockImplementationOnce(() => {
      throw new Error('audit down');
    });
    const next = jest.fn();
    const req = buildReq({ method: 'TRACE', headers: {} });
    const res = buildRes();
    expect(() => mw(req, res, next)).not.toThrow();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    // 主流程结论不受审计故障影响
    expect(next).not.toHaveBeenCalled();
  });
});
