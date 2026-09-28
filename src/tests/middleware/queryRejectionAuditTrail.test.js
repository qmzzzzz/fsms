/**
 * 查询参数守卫的拒绝必须留审计痕迹
 *
 * 被测对象：src/middleware/queryLimit.js（queryLengthLimit / queryScalarGuard）
 * 守护的不变式：两类查询拒绝（参数超长、取值是对象/数组）都写一条 security 类审计，
 * 状态码记真实值 400，且"是否留痕"与"是否真的拒绝"严格绑定。
 *
 * 为什么这是缺陷而不只是日志不够：两个守卫都挂在 auditLog 之前（它们必须在任何
 * 业务查询前把畸形参数挡掉），此前其 400 只进 logger ⇒ NoSQL 操作符探测
 * （?search[$regex]=…）与超长参数轰炸这段"攻击者还没拿到凭据就能做"的流量，
 * 在合规留存里是一片空白——事后既无法统计探测趋势，也无法证明拦截曾经生效。
 * 姊妹路径（IP 黑名单、来源校验、IP 段、协议合规）早已通过 recordEarlyRejection 补齐，
 * 这里是把同一格补全，不另起机制。
 *
 * 可证伪性：删掉任一 recordQueryRejection 调用 ⇒ 对应用例红；把 statusCode 写死回 403
 * ⇒ 状态码断言红；让放行路径或白名单豁免路径也留痕 ⇒ 两条负向用例红。
 */

'use strict';

const AuditLog = require('../../models/AuditLog');
const { queryLengthLimit, queryScalarGuard } = require('../../middleware/queryLimit');

const tick = () => new Promise((resolve) => setImmediate(resolve));

const makeRes = () => ({
  statusCode: null,
  body: null,
  status(c) {
    this.statusCode = c;
    return this;
  },
  json(b) {
    this.body = b;
    return this;
  },
});

const makeReq = (query, extra = {}) => ({
  method: 'GET',
  originalUrl: '/api/devices',
  url: '/api/devices',
  path: '/api/devices',
  query,
  ip: '203.0.113.50',
  id: 'req-test',
  headers: { 'user-agent': 'jest-agent' },
  get: (name) => (String(name).toLowerCase() === 'user-agent' ? 'jest-agent' : undefined),
  app: { get: () => undefined },
  ...extra,
});

describe('queryLimit 拒绝的审计留痕', () => {
  let recordSpy;

  beforeEach(() => {
    recordSpy = jest.spyOn(AuditLog, 'record').mockResolvedValue({});
  });

  afterEach(() => {
    recordSpy.mockRestore();
  });

  const recorded = () => recordSpy.mock.calls.map(([doc]) => doc).filter(Boolean);

  /** next 未被调用 = 请求确实被挡在守卫里（用布尔命名，避免 passed 一词两侧反义） */
  const blocked = (next) => next.mock.calls.length === 0;

  test('取值形态非法（对象/数组）被拒时留一条 security 审计，状态码记 400', async () => {
    const req = makeReq({ search: { $regex: '^a' } });
    const res = makeRes();
    const next = jest.fn();

    queryScalarGuard()(req, res, next);
    await tick();

    // 前提自证：确实走了拒绝分支（否则"没留痕"会被读成"根本没触发这条路径"）
    expect({ blocked: blocked(next), status: res.statusCode }).toEqual({
      blocked: true,
      status: 400,
    });

    const docs = recorded();
    expect(docs).toHaveLength(1);
    expect({
      action: docs[0].action,
      category: docs[0].category,
      statusCode: docs[0].statusCode,
      success: docs[0].success,
      riskFactors: docs[0].riskFactors,
      path: docs[0].path,
    }).toEqual({
      action: 'query_param_rejected',
      category: 'security',
      statusCode: 400,
      success: false,
      riskFactors: ['query_operator_violation'],
      path: '/api/devices',
    });
    expect(docs[0].reason).toContain('search');
  });

  test('参数超长被拒时留痕，风险因子与形态拒绝可区分（两类探测要能分开统计）', async () => {
    const req = makeReq({ keyword: 'a'.repeat(300) });
    const res = makeRes();
    const next = jest.fn();

    queryLengthLimit(200)(req, res, next);
    await tick();

    expect({ blocked: blocked(next), status: res.statusCode }).toEqual({
      blocked: true,
      status: 400,
    });
    const docs = recorded();
    expect(docs).toHaveLength(1);
    expect(docs[0].action).toBe('query_param_rejected');
    expect(docs[0].riskFactors).toEqual(['query_length_violation']);
    expect(docs[0].reason).toMatch(/超过 200 字符/);
  });

  test('放行路径一律不留痕（留痕必须与拒绝严格绑定，不能退化成每请求一条）', async () => {
    const ok = makeReq({ keyword: '泵房', page: '1' });
    const res = makeRes();
    const next = jest.fn();

    queryLengthLimit(200)(ok, res, next);
    await tick();
    queryScalarGuard()(ok, res, next);
    await tick();

    expect(next).toHaveBeenCalledTimes(2);
    expect(recorded()).toEqual([]);
  });

  test('两种豁免口径的留痕各自正确：长度豁免不留痕，形态不豁免必留痕', async () => {
    const nextLen = jest.fn();
    queryLengthLimit(200)(
      makeReq({ keyword: 'a'.repeat(300) }, { ipWhitelisted: true }),
      makeRes(),
      nextLen
    );
    await tick();
    expect({ passed: nextLen.mock.calls.length === 1, records: recorded().length }).toEqual({
      passed: true,
      records: 0,
    });

    // 形态守卫不设白名单豁免（Express 5 下 sanitizeMongo/hpp 对 req.query 均已失效，
    // 它是 query 侧唯一防线）⇒ 白名单来源同样拒绝、同样留痕
    const nextScalar = jest.fn();
    queryScalarGuard()(makeReq({ a: { $ne: 1 } }, { ipWhitelisted: true }), makeRes(), nextScalar);
    await tick();
    expect(nextScalar).not.toHaveBeenCalled();
    expect(recorded()).toHaveLength(1);
  });

  test('进审计的键名经过清洗：控制字符与超长键不得原样落库', async () => {
    const bell = String.fromCharCode(7);
    const nastyKey = `x${bell}${'y'.repeat(80)}`;
    const res = makeRes();

    queryScalarGuard()(makeReq({ [nastyKey]: { $where: '1' } }), res, jest.fn());
    await tick();

    const docs = recorded();
    expect(docs).toHaveLength(1);
    expect(docs[0].reason.includes(bell)).toBe(false);
    // sanitizeParamName 把非法字符换成 *，并截到 50 字符
    expect(docs[0].reason).toContain('x*');
    expect(docs[0].reason.length).toBeLessThan(200);
  });
});
