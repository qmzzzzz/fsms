/**
 * 安全配置开关处理器单测（注册开关 / 登录验证码 / 注册验证码）
 *
 * 为什么补这组测试：注册验证码开关（getRegisterCaptchaConfig /
 * setRegisterCaptchaConfig）随功能一起进了 securityController，但没有任何
 * 测试触达 —— 直接后果是 jest.config.js 里 securityController 的函数覆盖率
 * 棘轮基线（29%）从此不达标（实测 27.45%）。
 *
 * 处理方式是补测试而不是下调基线：基线的意义就是「不许悄悄退化」，
 * 一旦养成「不达标就下调」的习惯，棘轮立刻失效。
 *
 * 这些处理器只依赖 SystemConfig / AuditLog 两个模型，用 jest.mock 替换后
 * 可脱离数据库直接调用，成本远低于起 supertest + 内存库。
 */

const mockSystemConfig = {
  set: jest.fn(),
  isRegistrationAllowed: jest.fn(),
  isLoginCaptchaEnabled: jest.fn(),
  isRegisterCaptchaEnabled: jest.fn(),
  invalidateRegistrationCache: jest.fn(),
  invalidateLoginCaptchaCache: jest.fn(),
  invalidateRegisterCaptchaCache: jest.fn(),
};

const mockAuditLog = {
  create: jest.fn(() => Promise.resolve({})),
};

jest.mock('../../models/SystemConfig', () => mockSystemConfig);
jest.mock('../../models/AuditLog', () => mockAuditLog);

const {
  getRegistrationConfig,
  setRegistrationConfig,
  getLoginCaptchaConfig,
  setLoginCaptchaConfig,
  getRegisterCaptchaConfig,
  setRegisterCaptchaConfig,
} = require('../../controllers/securityController');
const { TEST_CLIENT_IP } = require('../fixtures');

/** 构造最小 req/res 替身；res 记录 status 与 json 载荷供断言 */
const makeCtx = (body = {}) => {
  const res = {
    statusCode: null,
    payload: null,
    locals: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.payload = data;
      return this;
    },
  };
  const req = {
    body,
    ip: TEST_CLIENT_IP,
    user: { userId: 'u-admin', username: 'admin' },
    get: () => 'jest-agent',
  };
  return { req, res, next: jest.fn() };
};

/**
 * 调用被 asyncHandler 包裹的处理器并等到它真正跑完
 *
 * 关键点：asyncHandler 的返回值是 `(req,res,next) => { Promise...catch(next) }`，
 * 它**不返回** Promise。因此 `await handler(req,res,next)` 只等一个微任务
 * （await undefined），而处理器内部有多个 await —— 断言会在响应写入之前执行，
 * 表现为 res.statusCode 恒为 null。这类「测试写法本身有缺陷」的失败最费时间，
 * 因为看起来像是被测代码没返回响应。
 * 用 setImmediate 让出一整轮事件循环，把全部已就绪的微任务清空。
 */
const invoke = async (handler, req, res, next) => {
  handler(req, res, next);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
};

beforeEach(() => {
  jest.clearAllMocks();
  mockSystemConfig.set.mockResolvedValue({});
  mockAuditLog.create.mockReturnValue(Promise.resolve({}));
});

describe('注册开关配置', () => {
  test('GET 返回当前开关与说明', async () => {
    mockSystemConfig.isRegistrationAllowed.mockResolvedValue(false);
    const { req, res, next } = makeCtx();
    await invoke(getRegistrationConfig, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.payload.data.allowPublicRegistration).toBe(false);
    expect(typeof res.payload.data.description).toBe('string');
  });

  test('PUT 落库并失效缓存', async () => {
    const { req, res, next } = makeCtx({ allowPublicRegistration: true });
    await invoke(setRegistrationConfig, req, res, next);
    expect(mockSystemConfig.set).toHaveBeenCalledWith('allowPublicRegistration', true, 'u-admin');
    expect(mockSystemConfig.invalidateRegistrationCache).toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
  });

  test('PUT 拒绝非布尔值（避免 "false" 字符串被判真）', async () => {
    const { req, res, next } = makeCtx({ allowPublicRegistration: 'false' });
    await invoke(setRegistrationConfig, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(mockSystemConfig.set).not.toHaveBeenCalled();
  });
});

describe('登录验证码开关配置', () => {
  test('GET 返回当前开关', async () => {
    mockSystemConfig.isLoginCaptchaEnabled.mockResolvedValue(true);
    const { req, res, next } = makeCtx();
    await invoke(getLoginCaptchaConfig, req, res, next);
    expect(res.payload.data.loginCaptchaEnabled).toBe(true);
  });

  test('PUT 落库、失效缓存并写专用审计（跳过全局审计避免重复记录）', async () => {
    const { req, res, next } = makeCtx({ loginCaptchaEnabled: true });
    await invoke(setLoginCaptchaConfig, req, res, next);
    expect(mockSystemConfig.set).toHaveBeenCalledWith('loginCaptchaEnabled', true, 'u-admin');
    expect(mockSystemConfig.invalidateLoginCaptchaCache).toHaveBeenCalled();
    expect(res.locals.skipGlobalAudit).toBe(true);
    expect(mockAuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'login_captcha_enabled',
        category: 'system',
        riskLevel: 'medium',
      })
    );
  });

  test('PUT 关闭时审计 action 为 disabled（开关两态可区分追溯）', async () => {
    const { req, res, next } = makeCtx({ loginCaptchaEnabled: false });
    await invoke(setLoginCaptchaConfig, req, res, next);
    expect(mockAuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'login_captcha_disabled' })
    );
  });

  test('PUT 拒绝非布尔值', async () => {
    const { req, res, next } = makeCtx({ loginCaptchaEnabled: 1 });
    await invoke(setLoginCaptchaConfig, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(mockSystemConfig.set).not.toHaveBeenCalled();
  });
});

describe('注册验证码开关配置', () => {
  test('GET 返回当前开关', async () => {
    mockSystemConfig.isRegisterCaptchaEnabled.mockResolvedValue(true);
    const { req, res, next } = makeCtx();
    await invoke(getRegisterCaptchaConfig, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.payload.data.registerCaptchaEnabled).toBe(true);
  });

  test('PUT 落库、失效缓存并写专用审计', async () => {
    const { req, res, next } = makeCtx({ registerCaptchaEnabled: false });
    await invoke(setRegisterCaptchaConfig, req, res, next);
    expect(mockSystemConfig.set).toHaveBeenCalledWith('registerCaptchaEnabled', false, 'u-admin');
    expect(mockSystemConfig.invalidateRegisterCaptchaCache).toHaveBeenCalled();
    expect(res.locals.skipGlobalAudit).toBe(true);
    expect(mockAuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'register_captcha_disabled' })
    );
  });

  test('PUT 拒绝非布尔值', async () => {
    const { req, res, next } = makeCtx({ registerCaptchaEnabled: null });
    await invoke(setRegisterCaptchaConfig, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(mockSystemConfig.set).not.toHaveBeenCalled();
  });

  test('审计落库失败不影响开关生效（.catch 吞错，配置已成功写入）', async () => {
    mockAuditLog.create.mockReturnValue(Promise.reject(new Error('audit down')));
    const { req, res, next } = makeCtx({ registerCaptchaEnabled: true });
    await invoke(setRegisterCaptchaConfig, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.payload.data.registerCaptchaEnabled).toBe(true);
  });
});

describe('审计 action 白名单与路由派生对齐', () => {
  test('registerCaptchaEnabled 的派生 action 已进白名单', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    // 缺失时审计页按该 action 筛选会被 validateEnum 打 400——
    // 记录进了库却查不出来，等于审计留痕形同虚设
    expect(AUDIT_LOG_ACTIONS).toContain('security_config_registerCaptchaEnabled');
    expect(AUDIT_LOG_ACTIONS).toContain('security_config_loginCaptchaEnabled');
    expect(AUDIT_LOG_ACTIONS).toContain('security_config_allowPublicRegistration');
  });
});
