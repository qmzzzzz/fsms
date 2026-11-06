/**
 * 事件型审计的请求上下文补采（auditRequestContext / recordLogin）。
 *
 * 背景：requestHeaders/responseHeaders/responseBody 等溯源字段是哈希载荷 v6
 * （2026-11-03）才入模型的，而登录/MFA/蜜罐这类事件在此之前只落 ip/UA/指纹，
 * 详情页的「请求溯源」整块为空。本次只补值、不新增字段、不动哈希版本。
 *
 * 两条铁律各有反向对照：
 *   1) 有 req ⇒ method/path/params/query/requestHeaders 五项落库且已脱敏；
 *   2) 无 req（测试替身/可选 ctx.req）⇒ 五项不写入且不得抛错。
 */
const mongoose = require('mongoose');

describe('审计请求上下文补采', () => {
  let AuditLog;
  let auditRequestContext;
  const stamp = `arq${Date.now().toString(36)}`;

  const fakeReq = {
    method: 'POST',
    originalUrl: '/api/auth/login?token=RAWSECRET123',
    url: '/api/auth/login?token=RAWSECRET123',
    baseUrl: '',
    route: { path: '/auth/login' },
    get: (name) => (String(name).toLowerCase() === 'user-agent' ? 'jest-ua' : undefined),
    headers: { authorization: 'Bearer SECRETABC', 'user-agent': 'jest-ua' },
    params: { id: 'u-1' },
    query: { token: 'RAWSECRET123' },
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    ({ auditRequestContext } = require('../../models/auditLogWriteStatics'));
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      AuditLog._setAppendOnlyEnforced(false);
      await AuditLog.deleteMany({ username: stamp }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('helper 五字段齐备，且凭据类值已被脱敏', () => {
    const ctx = auditRequestContext(fakeReq);
    expect(ctx.method).toBe('POST');
    expect(ctx.path).toContain('auth/login');
    expect(ctx.params).toEqual({ id: 'u-1' });
    // 正向对照：字段在
    expect(Object.keys(ctx).sort()).toEqual([
      'method',
      'params',
      'path',
      'query',
      'requestHeaders',
    ]);
    // 反向对照：任何一处都不得出现明文凭据
    expect(JSON.stringify(ctx)).not.toContain('RAWSECRET123');
    expect(JSON.stringify(ctx)).not.toContain('SECRETABC');
  });

  test('无 req / 非请求对象一律返回空对象，不得抛错（可选 ctx.req 形态）', () => {
    expect(auditRequestContext()).toEqual({});
    expect(auditRequestContext(null)).toEqual({});
    expect(auditRequestContext({})).toEqual({});
    expect(auditRequestContext({ headers: {} })).toEqual({});
  });

  test('recordLogin 带 req 时落库五项；不带 req 时不写五项且不报错', async () => {
    const withReq = await AuditLog.recordLogin(
      null,
      stamp,
      '10.0.0.1',
      false,
      'jest-ua',
      { reason: 'unit_test' },
      fakeReq
    );
    const doc = await AuditLog.findById(withReq._id).lean();
    expect(doc.method).toBe('POST');
    expect(doc.path).toContain('auth/login');
    expect(doc.requestHeaders).toBeTruthy();
    expect(JSON.stringify(doc.requestHeaders)).not.toContain('SECRETABC');
    expect(JSON.stringify(doc.query || {})).not.toContain('RAWSECRET123');

    const noReq = await AuditLog.recordLogin(null, stamp, '10.0.0.1', false, 'jest-ua', {
      reason: 'unit_test',
    });
    const bare = await AuditLog.findById(noReq._id).lean();
    expect(bare.method).toBeUndefined();
    expect(bare.path).toBeUndefined();
    expect(bare.requestHeaders).toBeUndefined();
  });
});
