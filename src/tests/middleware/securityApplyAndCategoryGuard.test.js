'use strict';

/**
 * security/index.js 的两处「启动期/挂载期」分支：
 *  1) applySecurity 是仍保留的「一次性挂载」入口（供不区分 body 阶段的调用方），
 *     顺序不变量 = 响应头（6 个）→ 解析前（1 个）→ 解析后（2 个）；
 *  2) ROUTE_CATEGORY_MAP 的取值必须全部落在 AuditLog 的 category enum 内，
 *     否则该分类的审计记录会被 insertMany 静默丢弃 —— 启动期必须直接抛错。
 */

// 允许用例逐条改映射：合法值证明挂载顺序，非法值证明启动期断言。
// 其余导出（auditPath/deriveAuditMeta…）必须保持真实：本模块链路里的
// protocolCompliance / auditLog / ipBlacklist 会在加载期解构它们。
const mockRouteCategoryMap = { '/api/mock': 'auth' };
jest.mock('../../utils/auditMeta', () => ({
  ...jest.requireActual('../../utils/auditMeta'),
  ROUTE_CATEGORY_MAP: mockRouteCategoryMap,
}));

const AuditLog = require('../../models/AuditLog');
const config = require('../../config');
const {
  applySecurity,
  applyPreBodySecurity,
  requireReAuthentication,
} = require('../../middleware/security');

const invokeReauth = async (body) => {
  const res = { statusCode: null, jsonBody: null };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (payload) => {
    res.jsonBody = payload;
    return res;
  };
  const next = jest.fn();
  await requireReAuthentication()({ body, user: { userId: 'u1', username: 'tester' } }, res, next);
  return { res, next };
};

describe('security/index.js 挂载入口与启动期断言', () => {
  beforeEach(() => {
    mockRouteCategoryMap['/api/mock'] = AuditLog.schema.path('category').enumValues[0];
  });

  test('applySecurity 按「响应头 → 解析前 → 解析后」挂载全部 9 个中间件', () => {
    const app = { use: jest.fn() };
    applySecurity(app);
    // 响应头 6 + protocolCompliance 1 + sanitizeMongo/preventHPP 2
    expect(app.use).toHaveBeenCalledTimes(9);
  });

  test('审计 category 映射含非法值时 applyPreBodySecurity 直接抛错（阻止带病启动）', () => {
    mockRouteCategoryMap['/api/mock'] = '__NOT_A_CATEGORY__';

    expect(() => applyPreBodySecurity({ use: jest.fn() })).toThrow(/审计 category 枚举不一致/);
  });
});

describe('requireReAuthentication 的入参形态闸', () => {
  const originalStrict = config.loginEncryptStrict;
  afterEach(() => {
    config.loginEncryptStrict = originalStrict;
  });

  test('req.body 为 undefined（解析器跳过）⇒ 403 要求重新验证，不是 500', async () => {
    // Express 5 在无 Content-Type 时不初始化 req.body；`req.body || {}` 的
    // 右侧只有这一条路径能走到，缺了它就会对 undefined 解构抛 TypeError。
    const { res, next } = await invokeReauth(undefined);
    expect(res.statusCode).toBe(403);
    expect(res.jsonBody.errors.errorCode).toBe('REAUTH_REQUIRED');
    expect(next).not.toHaveBeenCalled();
  });

  test('明文口令为对象 ⇒ 400 密码格式无效（不让 bcrypt 抛 TypeError）', async () => {
    const { res, next } = await invokeReauth({ currentPassword: { $ne: '' } });
    expect(res.statusCode).toBe(400);
    expect(res.jsonBody.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.jsonBody.message).toBe('密码格式无效');
    expect(next).not.toHaveBeenCalled();
  });

  test('strict 模式：密文与明文并存 ⇒ 400 协议违规', async () => {
    config.loginEncryptStrict = true;
    const { res, next } = await invokeReauth({
      encCurrentPassword: 'envelope',
      currentPassword: 'Plain1!pass',
    });
    expect(res.statusCode).toBe(400);
    expect(res.jsonBody.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.jsonBody.message).toContain('禁止同时携带明文口令');
    expect(next).not.toHaveBeenCalled();
  });

  test('strict 模式：只带明文 ⇒ 400 要求前端改用加密传输', async () => {
    config.loginEncryptStrict = true;
    const { res, next } = await invokeReauth({ currentPassword: 'Plain1!pass' });
    expect(res.statusCode).toBe(400);
    expect(res.jsonBody.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.jsonBody.message).toContain('已启用口令加密传输');
    expect(next).not.toHaveBeenCalled();
  });
});
