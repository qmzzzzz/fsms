/**
 * securityController 未覆盖分支补齐（覆盖率棘轮修复）
 *
 * 背景：并行开发新增了代码但没补测试，branches 63.27% / functions 64.51%，
 * 低于 jest.config.js 门槛 { branches: 68, functions: 68 }。
 * 本文件用 mock 方式直接调用控制器函数，精确命中未覆盖行：
 *   - getMySecurityInfo: failedLogins > 3 分支（57-58）、recentLogins.map（71）
 *   - changePasswordSecure: 密码不一致(96)、弱密码(102)、用户不存在(107)、
 *     当前密码错误(113-114)、新旧密码相同(119)
 *   - viewSensitiveData: 用户不存在(203)、email 分支(217-224)
 *   - reportSuspiciousActivity: 缺 targetType/reason(312)
 *   - toggleUserLock: 用户不存在(384)、同级拦截(402)、inactive 解锁(415)、
 *     inactive 锁定(427)
 *   - resetUserMfa: 验证失败(488)、用户不存在(494)、内置超管(517)
 *   - getSecurityOverview: 空数据(577)、字段缺失(585)、建议分支(609/612/615)、
 *     合规异常(652)、外层异常(656-657)
 *   - getRecentAlerts: 空数组(672)、filter/map(683-685)、summary(706-709)、
 *     外层异常(727-728)
 */

const { TEST_CLIENT_IP } = require('../fixtures');

// ===== mock 声明区（必须在 require 控制器之前） =====

// User 模型 mock
const mockUserFindById = jest.fn();
const mockUserFindByIdAndUpdate = jest.fn();
jest.mock('../../models/User', () => ({
  findById: (...args) => mockUserFindById(...args),
  findByIdAndUpdate: (...args) => mockUserFindByIdAndUpdate(...args),
}));

// AuditLog 模型 mock
const mockAuditLogFind = jest.fn();
const mockAuditLogCreate = jest.fn(() => Promise.resolve({ _id: 'audit-id' }));
const mockAuditLogCountDocuments = jest.fn(() => Promise.resolve(0));
const mockAuditLogDetectAnomalies = jest.fn(() =>
  Promise.resolve({ failedOperations: [], unusualTimeOperations: [] })
);
const mockAuditLogGetUserActivity = jest.fn(() => Promise.resolve([]));
jest.mock('../../models/AuditLog', () => ({
  find: (...args) => mockAuditLogFind(...args),
  create: (...args) => mockAuditLogCreate(...args),
  countDocuments: (...args) => mockAuditLogCountDocuments(...args),
  detectAnomalies: (...args) => mockAuditLogDetectAnomalies(...args),
  getUserActivity: (...args) => mockAuditLogGetUserActivity(...args),
}));

// SystemConfig mock
jest.mock('../../models/SystemConfig', () => ({
  isRegistrationAllowed: jest.fn(() => Promise.resolve(false)),
  set: jest.fn(() => Promise.resolve({})),
  invalidateRegistrationCache: jest.fn(),
}));

// encryption utils mock
jest.mock('../../utils/encryption', () => ({
  DataMasking: {
    maskPhone: (v) => (v ? '***' + v.slice(-4) : ''),
    maskEmail: (v) => (v ? '***@example.com' : ''),
    maskIP: (v) => (v ? '***.' + v.split('.').pop() : ''),
  },
}));

// helpers mock
const mockValidatePasswordStrength = jest.fn();
jest.mock('../../utils/helpers', () => ({
  validatePasswordStrength: (...args) => mockValidatePasswordStrength(...args),
}));

// superAdmin mock
const mockIsSuperAdminRole = jest.fn(() => false);
jest.mock('../../utils/superAdmin', () => ({
  isSuperAdminRole: (...args) => mockIsSuperAdminRole(...args),
}));

// permissionHelper mock
const mockGetOperatorMaxLevel = jest.fn(() => Promise.resolve(10));
jest.mock('../../utils/permissionHelper', () => ({
  getOperatorMaxLevel: (...args) => mockGetOperatorMaxLevel(...args),
}));

// logger mock（避免测试输出噪音）
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

// sessionService mock
jest.mock('../../services/sessionService', () => ({
  revokeAllSessionsSafe: jest.fn(() => Promise.resolve()),
}));

// tokenBlacklist mock（changePasswordSecure 内部 require）
jest.mock('../../middleware/tokenBlacklist', () => ({
  invalidateUserTokens: jest.fn(() => Promise.resolve()),
}));

// auth middleware mock（toggleUserLock 内部 require）
jest.mock('../../middleware/auth', () => ({
  invalidateUserCache: jest.fn(),
}));

// statsCache mock（toggleUserLock 内部 require）
jest.mock('../../services/statsCache', () => ({
  invalidateByUserId: jest.fn(),
}));

// Role 模型 mock（toggleUserLock / resetUserMfa 内部 require）
const mockRoleFind = jest.fn();
jest.mock('../../models/Role', () => ({
  find: (...args) => mockRoleFind(...args),
}));

// securityAlert 服务 mock（getSecurityOverview / getRecentAlerts 内部 require）
const mockGetSecurityOverview = jest.fn();
const mockGetRecentAlerts = jest.fn();
jest.mock('../../services/securityAlert', () => ({
  getSecurityOverview: (...args) => mockGetSecurityOverview(...args),
  getRecentAlerts: (...args) => mockGetRecentAlerts(...args),
}));

// auditChain / auditMonitor / auditBuffer mock（compliance 子块内部 require）
jest.mock('../../utils/auditChain', () => ({
  getLatestHash: jest.fn(() => Promise.resolve('abc123')),
}));
jest.mock('../../services/auditMonitor', () => ({
  isRunning: jest.fn(() => true),
}));
jest.mock('../../services/auditBuffer', () => ({
  isWalEnabled: jest.fn(() => true),
}));

// retention 常量 mock
jest.mock('../../constants/retention', () => ({
  RETENTION_DAYS: 90,
  wasAdjusted: false,
}));

// errorHandler mock：asyncHandler 直接返回原始 async 函数以便 await
jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn,
}));

// express-validator mock
const mockValidationResult = jest.fn(() => ({ isEmpty: () => true, array: () => [] }));
jest.mock('express-validator', () => ({
  validationResult: (...args) => mockValidationResult(...args),
}));

// 加载被测控制器（所有依赖已被 mock 替换）
const {
  getMySecurityInfo,
  changePasswordSecure,
  viewSensitiveData,
  reportSuspiciousActivity,
  toggleUserLock,
  resetUserMfa,
  getSecurityOverview,
  getRecentAlerts,
} = require('../../controllers/securityController');

// ===== 辅助工具 =====

/** 构造最小 req/res 替身 */
const makeCtx = (overrides = {}) => {
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
    body: overrides.body || {},
    params: overrides.params || {},
    query: overrides.query || {},
    ip: TEST_CLIENT_IP,
    user: overrides.user || { userId: 'u-admin', username: 'admin' },
    get: (header) => {
      if (header === 'user-agent') return 'jest-agent';
      return '';
    },
  };
  return { req, res, next: jest.fn() };
};

/** 直接 await 被 asyncHandler 解包后的控制器函数 */
const invoke = async (handler, req, res, next) => {
  await handler(req, res, next);
};

beforeEach(() => {
  jest.clearAllMocks();
  // 默认通过校验
  mockValidationResult.mockReturnValue({ isEmpty: () => true, array: () => [] });
  // 默认密码强度通过
  mockValidatePasswordStrength.mockReturnValue(null);
  // 默认角色查询返回普通角色
  mockRoleFind.mockReturnValue({
    select: jest.fn().mockResolvedValue([{ level: 1, code: 'USER', isBuiltIn: false }]),
  });
  // 默认操作者层级为 10
  mockGetOperatorMaxLevel.mockResolvedValue(10);
  // 默认不是内置超管
  mockIsSuperAdminRole.mockReturnValue(false);
});

// ============================================================
// getMySecurityInfo 未覆盖分支
// ============================================================
describe('getMySecurityInfo 分支补齐', () => {
  test('failedLogins > 3 时扣分并给出建议（行 57-58）', async () => {
    // 模拟用户有 5 次失败登录记录，触发 securityScore -= 15 与建议
    const fakeUser = {
      toObject: () => ({
        username: 'testuser',
        email: 'test@example.com',
        phone: '13800138000',
        lastLoginAt: new Date(),
        createdAt: new Date(),
        status: 'active',
      }),
      phone: '13800138000',
      email: 'test@example.com',
      lastLoginAt: new Date(),
    };
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue(fakeUser),
    });

    // 构造含 4 条失败记录的 recentLogins（覆盖 map + failedLogins > 3）
    const failedLogins = Array.from({ length: 4 }, (_, i) => ({
      action: 'login_failed',
      ip: `192.168.1.${i}`,
      timestamp: new Date(),
      success: false,
    }));
    const successLogins = [
      { action: 'login_success', ip: '10.0.0.1', timestamp: new Date(), success: true },
    ];
    const allLogins = [...failedLogins, ...successLogins];

    // AuditLog.find().sort().limit().select() 链式调用
    mockAuditLogFind.mockReturnValue({
      sort: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(allLogins),
    });

    const { req, res, next } = makeCtx({ user: { userId: 'u-test', username: 'testuser' } });
    await invoke(getMySecurityInfo, req, res, next);

    expect(res.statusCode).toBe(200);
    // securityScore = 100 - 15 = 85
    expect(res.payload.data.securityScore).toBe(85);
    expect(res.payload.data.suggestions).toContain('检测到多次登录失败，建议修改密码');
    // recentLogins.map 应返回掩码后的 IP（行 71）
    expect(res.payload.data.recentLogins.length).toBe(allLogins.length);
    expect(res.payload.data.recentLogins[0].ip).toBeTruthy();
  });
});

// ============================================================
// changePasswordSecure 未覆盖分支
// ============================================================
describe('changePasswordSecure 分支补齐', () => {
  test('新密码不一致返回 400（行 96）', async () => {
    const { req, res, next } = makeCtx({
      body: {
        currentPassword: 'OldPass1!xy2',
        newPassword: 'NewPass1!abc',
        confirmPassword: 'DifferentPass1!',
      },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('两次输入的新密码不一致');
  });

  test('密码强度不足返回 400（行 102）', async () => {
    mockValidatePasswordStrength.mockReturnValue('密码太弱');
    const { req, res, next } = makeCtx({
      body: {
        currentPassword: 'OldPass1!xy2',
        newPassword: 'weak',
        confirmPassword: 'weak',
      },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('密码太弱');
  });

  test('用户不存在返回 401（行 107）', async () => {
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });
    const { req, res, next } = makeCtx({
      body: {
        currentPassword: 'OldPass1!xy2',
        newPassword: 'NewPass1!abc',
        confirmPassword: 'NewPass1!abc',
      },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(401);
  });

  test('当前密码错误返回 400（行 113-114）', async () => {
    const fakeUser = {
      username: 'testuser',
      comparePassword: jest.fn().mockResolvedValue(false),
    };
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue(fakeUser),
    });
    const { req, res, next } = makeCtx({
      body: {
        currentPassword: 'WrongPass1!x',
        newPassword: 'NewPass1!abc',
        confirmPassword: 'NewPass1!abc',
      },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('当前密码错误');
  });

  test('新密码与当前密码相同返回 400（行 119）', async () => {
    // 第一次 comparePassword(currentPassword) → true（当前密码正确）
    // 第二次 comparePassword(newPassword) → true（新旧相同）
    const fakeUser = {
      username: 'testuser',
      comparePassword: jest.fn().mockResolvedValue(true),
      save: jest.fn(),
    };
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue(fakeUser),
    });
    const { req, res, next } = makeCtx({
      body: {
        currentPassword: 'SamePass1!xy3',
        newPassword: 'SamePass1!xy3',
        confirmPassword: 'SamePass1!xy3',
      },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('新密码不能与当前密码相同');
  });
});

// ============================================================
// viewSensitiveData 未覆盖分支
// ============================================================
describe('viewSensitiveData 分支补齐', () => {
  test('用户不存在返回 401（行 203）', async () => {
    mockUserFindById.mockResolvedValue(null);
    const { req, res, next } = makeCtx({ body: { dataType: 'phone' } });
    await invoke(viewSensitiveData, req, res, next);
    expect(res.statusCode).toBe(401);
  });

  test('dataType=email 返回邮箱敏感数据（行 217-224）', async () => {
    mockUserFindById.mockResolvedValue({
      username: 'testuser',
      phone: '13800138000',
      email: 'secret@example.com',
    });
    const { req, res, next } = makeCtx({ body: { dataType: 'email' } });
    await invoke(viewSensitiveData, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.payload.data.type).toBe('email');
    expect(res.payload.data.full).toBe('secret@example.com');
  });
});

// ============================================================
// reportSuspiciousActivity 未覆盖分支
// ============================================================
describe('reportSuspiciousActivity 分支补齐', () => {
  test('缺少 targetType 或 reason 返回 400（行 312）', async () => {
    // 无 targetType
    const {
      req: r1,
      res: res1,
      next: n1,
    } = makeCtx({
      body: { reason: 'test' },
    });
    await invoke(reportSuspiciousActivity, r1, res1, n1);
    expect(res1.statusCode).toBe(400);
    expect(res1.payload.message).toBe('请提供目标类型和原因');

    // 无 reason
    const {
      req: r2,
      res: res2,
      next: n2,
    } = makeCtx({
      body: { targetType: 'user' },
    });
    await invoke(reportSuspiciousActivity, r2, res2, n2);
    expect(res2.statusCode).toBe(400);
  });
});

// ============================================================
// toggleUserLock 未覆盖分支
// ============================================================
describe('toggleUserLock 分支补齐', () => {
  const makeLockCtx = (locked, userOverrides = {}) => {
    const fakeUser = {
      _id: 'target-user-id',
      username: 'target',
      status: 'active',
      roles: ['role-1'],
      save: jest.fn().mockResolvedValue(undefined),
      ...userOverrides,
    };
    mockUserFindById.mockResolvedValue(fakeUser);
    return {
      fakeUser,
      ctx: makeCtx({
        params: { userId: 'target-user-id' },
        body: { locked, reason: 'test' },
      }),
    };
  };

  test('目标用户不存在返回 404（行 384）', async () => {
    mockUserFindById.mockResolvedValue(null);
    const { req, res, next } = makeCtx({
      params: { userId: 'nonexistent-id' },
      body: { locked: true },
    });
    await invoke(toggleUserLock, req, res, next);
    expect(res.statusCode).toBe(404);
  });

  test('同级或更高级别用户拦截返回 403（行 402）', async () => {
    // 目标用户层级 = 10，操作者层级 = 10 → 同级拦截
    mockRoleFind.mockReturnValue({
      select: jest.fn().mockResolvedValue([{ level: 10, code: 'ADMIN', isBuiltIn: false }]),
    });
    mockGetOperatorMaxLevel.mockResolvedValue(10);
    const { ctx } = makeLockCtx(true);
    await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
    expect(ctx.res.statusCode).toBe(403);
    expect(ctx.res.payload.message).toBe('无权操作同级或更高级别的用户');
  });

  test('inactive 用户不能解锁返回 400（行 415）', async () => {
    const { ctx } = makeLockCtx(false, { status: 'inactive' });
    await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
    expect(ctx.res.statusCode).toBe(400);
    expect(ctx.res.payload.message).toContain('不能通过解锁恢复');
  });

  test('inactive 用户不能锁定返回 400（行 427）', async () => {
    const { ctx } = makeLockCtx(true, { status: 'inactive' });
    await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
    expect(ctx.res.statusCode).toBe(400);
    expect(ctx.res.payload.message).toContain('不能重复锁定');
  });
});

// ============================================================
// resetUserMfa 未覆盖分支
// ============================================================
describe('resetUserMfa 分支补齐', () => {
  test('validation 失败返回 400（行 488）', async () => {
    mockValidationResult.mockReturnValue({
      isEmpty: () => false,
      array: () => [{ msg: 'invalid' }],
    });
    const { req, res, next } = makeCtx({ params: { userId: 'some-id' } });
    await invoke(resetUserMfa, req, res, next);
    expect(res.statusCode).toBe(400);
  });

  test('目标用户不存在返回 404（行 494）', async () => {
    mockUserFindById.mockResolvedValue(null);
    const { req, res, next } = makeCtx({ params: { userId: 'nonexistent' } });
    await invoke(resetUserMfa, req, res, next);
    expect(res.statusCode).toBe(404);
  });

  test('重置内置超管 MFA 被拒绝（行 517）', async () => {
    // 目标用户存在且开启了 MFA、非自身
    mockUserFindById.mockResolvedValue({
      _id: 'super-target-id',
      username: 'builtInSuper',
      mfaEnabled: true,
      roles: ['role-super'],
    });
    // 目标角色是内置超管
    mockRoleFind.mockReturnValue({
      select: jest.fn().mockResolvedValue([{ level: 10, code: 'SUPER_ADMIN', isBuiltIn: true }]),
    });
    // 操作者层级必须严格高于目标（否则行 513 的同级拦截先触发，永远到不了 517）
    mockGetOperatorMaxLevel.mockResolvedValue(20);
    mockIsSuperAdminRole.mockReturnValue(true);

    const { req, res, next } = makeCtx({
      params: { userId: 'super-target-id' },
      user: { userId: 'operator-id', username: 'operator' },
    });
    await invoke(resetUserMfa, req, res, next);
    // codeError 将错误码放在 errors.errorCode，断言命中了行 517 分支即可
    expect(res.payload.errors).toBeTruthy();
    expect(res.payload.errors.errorCode).toBe('CANNOT_RESET_MFA_SUPER_ADMIN');
  });
});

// ============================================================
// getSecurityOverview 未覆盖分支
// ============================================================
describe('getSecurityOverview 分支补齐', () => {
  test('overview 为非对象时返回 404（行 577）', async () => {
    mockGetSecurityOverview.mockResolvedValue(null);
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(404);
    expect(res.payload.message).toBe('安全概览数据格式错误');
  });

  test('overview 缺少必需数字字段时返回 404（行 585）', async () => {
    // criticalAlerts 不是 number
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 'not-a-number',
      highAlerts: 0,
      failedLogins: 0,
    });
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(404);
    expect(res.payload.message).toBe('安全概览数据结构错误');
  });

  test('riskScore>70 / failedLogins>10 / unusualAccess>5 触发三条建议（行 609/612/615）', async () => {
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 10,
      highAlerts: 5,
      failedLogins: 20,
      unusualAccess: 10,
      riskScore: 80,
    });
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(200);
    const suggestions = res.payload.data.suggestions;
    expect(suggestions).toContain('高风险：建议立即审查最近的操作日志');
    expect(suggestions).toContain('登录失败次数过多：建议检查账户安全');
    expect(suggestions).toContain('非常规时间访问：建议确认操作合法性');
  });

  test('compliance 子块抛异常时降级为 error 对象（行 652）', async () => {
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    });
    // 让 getLatestHash 抛错以触发 compliance catch
    const { getLatestHash } = require('../../utils/auditChain');
    getLatestHash.mockRejectedValueOnce(new Error('chain broken'));

    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.payload.data.compliance).toEqual({ error: '合规指标获取失败' });
  });

  test('securityAlert.getSecurityOverview 抛异常时返回 500（行 656-657）', async () => {
    mockGetSecurityOverview.mockRejectedValue(new Error('service down'));
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(500);
  });
});

// ============================================================
// getRecentAlerts 未覆盖分支
// ============================================================
describe('getRecentAlerts 分支补齐', () => {
  test('getRecentAlerts 返回非数组时返回 404（行 672）', async () => {
    mockGetRecentAlerts.mockResolvedValue(null);
    const { req, res, next } = makeCtx();
    await invoke(getRecentAlerts, req, res, next);
    expect(res.statusCode).toBe(404);
    expect(res.payload.message).toBe('最近告警数据为空');
  });

  test('正常告警经过 filter/map/summary 处理（行 683-685, 706-709）', async () => {
    // 构造包含各风险级别的告警，覆盖 filter 条件与 summary 统计
    const alerts = [
      {
        _id: 'a1',
        timestamp: new Date().toISOString(),
        action: 'login_failed',
        category: 'auth',
        username: 'alice',
        riskLevel: 'critical',
        ip: '10.0.0.1',
      },
      {
        _id: 'a2',
        timestamp: new Date().toISOString(),
        action: 'export_data',
        riskLevel: 'high',
        username: 'bob',
      },
      {
        _id: 'a3',
        timestamp: new Date().toISOString(),
        action: 'config_change',
        riskLevel: 'medium',
      },
      {
        _id: 'a4',
        timestamp: new Date().toISOString(),
        action: 'read_file',
        riskLevel: 'low',
      },
      // 无效告警（缺 _id）应被 filter 剔除
      { timestamp: new Date().toISOString(), action: 'orphan' },
    ];
    mockGetRecentAlerts.mockResolvedValue(alerts);

    const { req, res, next } = makeCtx();
    await invoke(getRecentAlerts, req, res, next);

    expect(res.statusCode).toBe(200);
    const meta = res.payload.data.meta;
    // 有效告警 4 条（第 5 条缺 _id 被过滤）
    expect(meta.summary.total).toBe(4);
    expect(meta.summary.critical).toBe(1);
    expect(meta.summary.high).toBe(1);
    expect(meta.summary.medium).toBe(1);
    expect(meta.summary.low).toBe(1);
    // 可选字段兜底
    const items = res.payload.data.data;
    const anonymousItem = items.find((i) => i._id === 'a3');
    expect(anonymousItem.username).toBe('anonymous');
    expect(anonymousItem.category).toBe('unknown');
  });

  test('getRecentAlerts 抛异常时返回 500（行 727-728）', async () => {
    mockGetRecentAlerts.mockRejectedValue(new Error('db error'));
    const { req, res, next } = makeCtx();
    await invoke(getRecentAlerts, req, res, next);
    expect(res.statusCode).toBe(500);
  });
});
