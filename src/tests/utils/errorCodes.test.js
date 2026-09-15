/**
 * 错误码注册表与 ApiResponse.codeError 单测
 *
 * 核心断言：
 * 1. 注册表完整性：每个码有合法 status 与非空 message（validateRegistry 返回空）
 * 2. codeError 响应形状：errorCode 抵达 errors.errorCode（前端契约），message/status 取自注册表
 * 3. 未注册码：日志告警 + 兜底 400，不抛错
 * 4. 快捷方法透传 errors——回归锁定 FULL_RANGE_FORBIDDEN 死码 bug
 *    （forbidden 此前忽略第三参，前端映射从未收到过码）
 */

const { ERROR_CODES, validateRegistry } = require('../../utils/errorCodes');
const ApiResponse = require('../../utils/apiResponse');

// mock logger：断言告警调用且不产生真实 IO
jest.mock('../../utils/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

const logger = require('../../utils/logger');

const mockRes = () => {
  const res = {
    statusCode: null,
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

describe('errorCodes 注册表', () => {
  test('注册表完整性：status 合法且 message 非空', () => {
    expect(Object.keys(ERROR_CODES).length).toBeGreaterThanOrEqual(19);
    expect(validateRegistry()).toEqual([]);
  });

  test('关键防枚举路径使用统一凭证码（M-5）：登录链路不产生区分性码', () => {
    // M-5 口径（2026-09-15 收紧后对齐）：登录/凭据校验失败一律返回
    // AUTH_INVALID_CREDENTIALS。注册表中的 ACCOUNT_DISABLED/LOCKED 等码
    // 仅供管理端操作与前端结构化错误映射使用（ authService 登录链路
    // grep 无引用），因此防枚举断言落在「登录链路不引用」而非「码不存在」。
    const forbiddenCodes = ['AUTH_ACCOUNT_INACTIVE', 'AUTH_ACCOUNT_LOCKED'];
    forbiddenCodes.forEach((c) => expect(ERROR_CODES[c]).toBeUndefined());
    // 统一凭证码必须存在
    expect(ERROR_CODES.AUTH_INVALID_CREDENTIALS).toBeDefined();
    // 静态回归：登录服务不得引用区分性账户状态码（防未来回归引入枚举面）
    const authServiceSrc = require('fs').readFileSync(
      require('path').join(__dirname, '../../services/authService.js'),
      'utf8'
    );
    ['ACCOUNT_DISABLED', 'ACCOUNT_LOCKED', 'ACCOUNT_TEMP_LOCKED'].forEach((code) => {
      expect(authServiceSrc).not.toContain(`errorCodes.${code}`);
      expect(authServiceSrc).not.toContain(`'${code}'`);
    });
  });

  test('状态码均为 4xx/5xx 错误区间', () => {
    Object.values(ERROR_CODES).forEach((def) => {
      expect(def.status).toBeGreaterThanOrEqual(400);
      expect(def.status).toBeLessThanOrEqual(599);
    });
  });

  test('超管不可变约束码已注册（前端 i18n 依赖这批码翻译）', () => {
    const required = [
      'CANNOT_DELETE_SELF',
      'CANNOT_DELETE_SUPER_ADMIN',
      'CANNOT_DISABLE_SUPER_ADMIN',
      'CANNOT_LOCK_SUPER_ADMIN',
      'CANNOT_RESET_MFA_SUPER_ADMIN',
      'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE',
      'SUPER_ADMIN_ROLE_NOT_DETACHABLE',
      'SUPER_ADMIN_ROLE_NOT_GRANTABLE',
      'SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED',
      'SUPER_ADMIN_ROLE_NOT_CLONABLE',
    ];
    // jest 的 expect 不支持第二个自定义消息参数（那是 vitest 的能力），
    // 故用「缺失码列表」整体比对，失败时 diff 直接给出缺哪些码
    const missing = required.filter((code) => !ERROR_CODES[code]);
    expect(missing).toEqual([]);
    // 删除自身是客户端参数问题（400），其余均为权限约束（403）
    expect(ERROR_CODES.CANNOT_DELETE_SELF.status).toBe(400);
    required
      .filter((c) => c !== 'CANNOT_DELETE_SELF')
      .forEach((code) => expect(ERROR_CODES[code].status).toBe(403));
  });
});

describe('ApiResponse.codeError', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('errorCode 抵达 errors.errorCode，message/status 取自注册表', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'MFA_CODE_INVALID');
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({
      success: false,
      message: '两步验证码错误',
      errors: { errorCode: 'MFA_CODE_INVALID' },
    });
  });

  test('params 合并进 errors（供前端动态文案使用）', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS', { params: { retry: 3 } });
    expect(res.body.errors).toEqual({
      errorCode: 'AUTH_INVALID_CREDENTIALS',
      retry: 3,
    });
  });

  test('未注册码：不抛错，日志告警，兜底 400', () => {
    const res = mockRes();
    expect(() => ApiResponse.codeError(res, 'NOT_A_REAL_CODE')).not.toThrow();
    expect(logger.error).toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('NOT_A_REAL_CODE');
    expect(res.body.message).toBe('操作失败');
  });

  test('options 覆盖注册表的 message 与 statusCode（动态文案场景）', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS', {
      message: '自定义文案',
      statusCode: 401,
    });
    expect(res.body.message).toBe('自定义文案');
    expect(res.statusCode).toBe(401);
  });
});

describe('快捷方法透传 errors（FULL_RANGE_FORBIDDEN 死码回归）', () => {
  test('forbidden 第三参抵达 errors——修复前被签名丢弃', () => {
    const res = mockRes();
    ApiResponse.forbidden(res, '权限不足说明', {
      errorCode: 'FULL_RANGE_FORBIDDEN',
      ip: '0.0.0.0/0',
    });
    expect(res.statusCode).toBe(403);
    expect(res.body.errors).toEqual({
      errorCode: 'FULL_RANGE_FORBIDDEN',
      ip: '0.0.0.0/0',
    });
  });

  test('unauthorized/notFound/serverError 同样透传', () => {
    const r1 = mockRes();
    ApiResponse.unauthorized(r1, '未授权', { errorCode: 'X1' });
    expect(r1.body.errors.errorCode).toBe('X1');

    const r2 = mockRes();
    ApiResponse.notFound(r2, '不存在', { errorCode: 'X2' });
    expect(r2.body.errors.errorCode).toBe('X2');

    const r3 = mockRes();
    ApiResponse.serverError(r3, '内部错误', { errorCode: 'X3' });
    expect(r3.body.errors.errorCode).toBe('X3');
  });

  test('既有二参调用不受影响（errors 为 null）', () => {
    const res = mockRes();
    ApiResponse.forbidden(res, '您没有执行此操作的权限');
    expect(res.statusCode).toBe(403);
    expect(res.body.errors).toBeNull();
  });
});
