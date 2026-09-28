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

/**
 * 放行分支的完整判据：必须"什么都没写"。
 *
 * 只断 `next()` 被调用等于默认了"先 res.status(405).json(...) 再 next()"也算通过——
 * 而那恰恰是这道协议闸被绕开的形态（响应已发出，请求仍继续走下游中间件并产生副作用）。
 * 所以三件事一起钉：走了 next、statusCode 仍是 buildRes 的初值、body 仍是 null。
 */
const expectAllowed = (res, next) => {
  expect(next).toHaveBeenCalled();
  expect(res.statusCode).toBe(200);
  expect(res.body).toBeNull();
};

describe('protocolCompliance 协议合规校验', () => {
  let mw;

  beforeEach(() => {
    mw = protocolCompliance();
  });

  it('正常 GET 请求放行', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq(), res, next);
    expectAllowed(res, next);
  });

  it('正常 JSON POST 请求放行', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(
      buildReq({
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8', 'content-length': '42' },
      }),
      res,
      next
    );
    expectAllowed(res, next);
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
    const res = buildRes();
    mw(buildReq({ method: 'POST', headers: { 'content-length': '0' } }), res, next);
    expectAllowed(res, next);
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
    const res = buildRes();
    scoped(buildReq({ headers: { host: 'api.example.com' } }), res, next);
    expectAllowed(res, next);
  });

  it('探针请求（GET/HEAD + 精确探针路径）跳过全部校验', () => {
    // 判据用"与探针方法无关的头部数量超限"：GET /health 带 70 个头部仍然整体放行，
    // 同一份请求换成 POST /health 就必须被拒——豁免的对象是**探活请求**，
    // 不是"以 /health 开头的任意流量"（后者原先成立：前缀语义 + 不看方法）
    const manyHeaders = {};
    for (let i = 0; i < 70; i += 1) manyHeaders[`x-h-${i}`] = 'v';

    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ method: 'GET', originalUrl: '/health', headers: manyHeaders }), res, next);
    expectAllowed(res, next);

    const postNext = jest.fn();
    const postRes = buildRes();
    mw(
      buildReq({ method: 'POST', originalUrl: '/health', headers: manyHeaders }),
      postRes,
      postNext
    );
    expect(postNext).not.toHaveBeenCalled();
    expect(postRes.body.errors.errorCode).toBe('HEADER_COUNT_EXCESSIVE');
  });

  it('非探针方法打到探针路径不再免检（子树 + 方法两个维度都收口）', () => {
    // 原形态：`matchesAnyPathPrefix(skipPaths, '/health/x')` 为真且不看方法 ⇒
    // TRACE /health 得到 404（闸门没碰它）、POST /health/zznope 得到 404 且免 Content-Type
    // 校验。现在探针路径上的普通请求回归普通表面语义：先过方法白名单。
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ method: 'TRACE', originalUrl: '/health' }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.body.errors.errorCode).toBe('HTTP_METHOD_UNSUPPORTED');

    const subNext = jest.fn();
    const subRes = buildRes();
    mw(
      buildReq({
        method: 'POST',
        originalUrl: '/health/zznope',
        headers: { 'content-type': 'text/plain', 'content-length': '64' },
      }),
      subRes,
      subNext
    );
    expect(subNext).not.toHaveBeenCalled();
    expect(subRes.body.errors.errorCode).toBe('CONTENT_TYPE_UNSUPPORTED');
  });

  it('multipart/form-data 上传被允许', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(
      buildReq({
        method: 'POST',
        headers: {
          'content-type': 'multipart/form-data; boundary=----abc',
          'content-length': '1024',
        },
      }),
      res,
      next
    );
    expectAllowed(res, next);
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

  /**
   * 写方法清单必须与 originCheck 同源（同一概念两份实现是本仓反复出现的漂移族）。
   * 本文件曾自列 `['POST','PUT','PATCH']`，少 DELETE —— 而 express.json 对 DELETE
   * 同样解析 body，于是"带 JSON 载荷的写请求要过媒体类型闸门"这道防线
   * 对 DELETE 整个不设防，而 CORS/来源校验那边却把 DELETE 当写操作。
   */
  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])(
    '%s 带非 JSON 内容类型 → 与 POST 同口径拒绝',
    (method) => {
      const next = jest.fn();
      const res = buildRes();
      mw(
        buildReq({ method, headers: { 'content-type': 'text/plain', 'content-length': '42' } }),
        res,
        next
      );
      expect(next).not.toHaveBeenCalled();
      expect(res.statusCode).toBe(415);
    }
  );

  it('对照：GET 带 text/plain 不属于"写方法带体"，不得因此被拒', () => {
    const next = jest.fn();
    const res = buildRes();
    mw(buildReq({ method: 'GET', headers: { 'content-type': 'text/plain' } }), res, next);
    expectAllowed(res, next);
  });
});
