/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：securityController：改密 outcome → HTTP 映射、越权 403、内置超管保护、锁定/解锁状态机
 * 守护的不变式：authService 的 9 种 outcome 必须映射到既定 HTTP 状态；越权与内置超管保护必须落点
 * 可证伪性：变异实测（N=8 + flake 守卫 + `--no-cache`）：杀 7/12，基线 27 passed
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [部分有效·判定在别处已设防] `:361`（现形 `:395`）在**无中间件环境**断言 `res.locals.skipGlobalAudit === true`（原出处 2026-09-16 全面代码审计报告；**该报告已删除**，问题编号保留原样）
 *     变异实测更正（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法）：前半句事实成立（`invoke(changePasswordSecure,…)`
 *       直调控制器、无中间件链），但原推论「⇒ **掩盖了全局审计双写缺陷（P0-5）**」**不成立**。
 *       忠实回退 P0-5（middleware/security.js 的 `skipGlobalAudit` 判定由响应时刻改回请求入口读取）
 *       → **2 套 5 例红**：controllers/skipGlobalAuditEndToEnd.test.js（3 例）
 *       + middleware/skipGlobalAuditTiming.test.js（2 例）；同点位 throw 正对照 3 例红。
 *       该缺陷已被这两套专项用例守着（前者文件头 :7-9 点名了被批评处，即为此洞而建）。
 *   - [已自陈] `:504-517` 为触达分支构造操作者层级 **20**，而 `Role.js` 的 `max: 10` 使该值现实中不可达（原出处 2026-09-16 全面代码审计报告；**该报告已删除**，问题编号保留原样）
 *     复核：事实成立，但用例 `:552-559` 已自陈「这里的 20 是**测试替身**…该分支在真实数据下**不可达**（属纵深防御的冗余层）」，并给出保留理由（一旦放宽 Role.level 上限即成唯一防线）。
 *   - [已修复·F-51] **F-51**：全仓没有任何控制器路径断言 `view_sensitive_data` 审计落库（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     修复（2026-09-20，用户选定「最小修复」）：**仅在本文件 `dataType=email` 用例末尾加 1 条断言**
 *     （不新增文件 / 不新增用例 / 不新增场景），锁 `action:'view_sensitive_data'`
 *     + `username`(操作者) 与 `targetUsername`(被查看者) 不得混同（L-06）。
 *     原缺口实测：`securityController.js:253-266` 整段删掉后 66 套 / 717 例仍全绿（`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）。
 *     复核（2026-09-20 **变异实测**，非静态）：删除 `securityController.js:253-266` 后，该 controller 的
 *     66 套 / 717 个 related 用例**全绿**；同位置插 `throw` 则 5 条用例被杀 ⇒ 用例集确实执行该代码、
 *     只是不检查这条审计。唯一碰到该 action 的 `models/auditLogFieldRetention.test.js:74-90` 是
 *     **模型层直写**，验的是 schema 能否存 `dataType`，对删除完全不敏感。
 *     ⇒ 最锋利的表述：这条审计**schema 有测试，写入路径没有**。证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕。
 *
 * 命名沿革：2026-09-20 由 `securityCoverageGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * securityController 未覆盖分支补齐（覆盖率棘轮修复）
 *
 * 背景：并行开发新增了代码但没补测试，branches 63.27% / functions 64.51%，
 * 低于 jest.config.js 门槛 { branches: 68, functions: 68 }。
 * 本文件用 mock 方式直接调用控制器函数，精确命中未覆盖行：
 *   - getMySecurityInfo: failedLogins > 3 分支（57-58）、recentLogins.map（71）
 *   - changePasswordSecure: #15 收敛后委托 authService.changeUserPassword，
 *     覆盖 outcome → HTTP 映射（ENC_INVALID/MISSING/CONFIRM_MISMATCH/WEAK/
 *     USER_NOT_FOUND/CURRENT_WRONG/SAME_PASSWORD/REVOKE_FAILED/OK）
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

// 对象级范围闸（本轮新加）经 rbac.assertRecordInScope → getDataScope →
// User.findById().populate() 取操作者数据范围。本套件是"结论/分支映射"的单元级用例，
// 把 User 模型整体桩成裸对象，那条链会直接 TypeError。范围闸本身由
// permissionUserValidationGuards 与 assignRoles 两组真库用例覆盖，这里只置为放行。
jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  assertRecordInScope: jest.fn(async () => ({ allowed: true, dataScope: { type: 'all' } })),
}));

// User 模型 mock
const mockUserFindById = jest.fn();
const mockUserFindByIdAndUpdate = jest.fn();
jest.mock('../../models/User', () => ({
  findById: (...args) => mockUserFindById(...args),
  findByIdAndUpdate: (...args) => mockUserFindByIdAndUpdate(...args),
  // 与真实模型同形：载入端（authService.setUserLockStatus / updateUserProfile、
  // userService/roleService 的 findUserForUpdate）会调它构造"排除凭证列"的投影。
  // 桩缺这个符号 ⇒ 生产代码抛 TypeError，用例测到的是崩溃而不是它想钉的分支。
  unselectedCredentialProjection: () => ({}),
}));

// AuditLog 模型 mock
const mockAuditLogFind = jest.fn();
const mockAuditLogCreate = jest.fn(() => Promise.resolve({ _id: 'audit-id' }));
const mockAuditLogCountDocuments = jest.fn(() => Promise.resolve(0));
const mockAuditLogDetectAnomalies = jest.fn(() =>
  Promise.resolve({ failedOperations: [], unusualTimeOperations: [] })
);
const mockAuditLogGetUserActivity = jest.fn(() => Promise.resolve([]));
// 合规面板要读护栏的**实际生效值**（securityController 的 compliance 块）。
// 桩里不带这个符号 ⇒ 控制器抛 TypeError ⇒ 整段 compliance 静默降级成 {error}，
// 用例仍然全绿但测的是降级路径（夹具不忠于生产形状）。值的真假由
// security/complianceGuardStateIsReal.test.js 在**不 mock 模型**的一侧钉住。
const mockAppendOnlyEnforced = jest.fn(() => true);
jest.mock('../../models/AuditLog', () => ({
  find: (...args) => mockAuditLogFind(...args),
  create: (...args) => mockAuditLogCreate(...args),
  countDocuments: (...args) => mockAuditLogCountDocuments(...args),
  detectAnomalies: (...args) => mockAuditLogDetectAnomalies(...args),
  getUserActivity: (...args) => mockAuditLogGetUserActivity(...args),
  isAppendOnlyEnforced: (...args) => mockAppendOnlyEnforced(...args),
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
  // maxRoleLevel 用真实实现：它是层级判定的单一事实来源，在本套件 mock 里再抄一份
  // （或以 undefined 缺席）都会让"被测代码调它"这条路径失真。
  maxRoleLevel: jest.requireActual('../../utils/permissionHelper').maxRoleLevel,
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

// authService mock（评价报告 #15 收敛后，changePasswordSecure 委托业务层单一实现）。
// 注意：必须保留真实模块的其余导出——toggleUserLock 依赖 authService.setUserLockStatus
const mockChangeUserPassword = jest.fn();
jest.mock('../../services/authService', () => {
  const actual = jest.requireActual('../../services/authService');
  return {
    ...actual,
    changeUserPassword: (...args) => mockChangeUserPassword(...args),
  };
});

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
  // 同 auditBuffer.getStats 的教训（见下方注释）：控制器读 compliance.monitorHealth，
  // 桩不带 getHealth 会让该字段恒走 null 兜底——面板看着绿、跑的却是降级分支。
  getHealth: jest.fn(() => ({
    runs: 3,
    failures: 1,
    consecutiveFailures: 0,
    skippedOverlaps: 0,
    lastRunAt: '2026-09-25T00:00:00.000Z',
    lastFailureAt: '2026-09-24T23:55:00.000Z',
    lastFailureMessage: 'mongo timeout',
    intervalMs: 300000,
    running: true,
  })),
}));
jest.mock('../../services/auditBuffer', () => ({
  isWalEnabled: jest.fn(() => true),
  // 控制器现在会读丢失指标（compliance.auditLoss）。桩不带 getStats 会让整段
  // compliance 抛 TypeError 落进 catch、静默降级成 `{error}` —— 29 条用例照样绿，
  // 但被测的其实是"降级路径"而不是合规面板（本仓反复踩过的"夹具不忠于生产形状"）。
  // 形状**从真模块现取**而不是手抄键名：这里少抄一个键，jest 的 toEqual 会忽略
  // 值为 undefined 的键，用例仍绿而合规面板从此少一项（见本文件 auditLoss 用例注释）。
  getStats: jest.fn(() => jest.requireActual('../../services/auditBuffer').getStats()),
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
  getAccountBindings,
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
      // P1-29：见 securityConfigHandlers.test.js 同款说明——记录响应写出时刻的标志值，
      // 静态值断言无法区分「入口前置位」与「响应前置位」的时序差异。
      this.flagAtJson = this.locals.skipGlobalAudit;
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
    // i18n：suggestions 出的是**稳定码**而非中文句子（文案归前端词表）
    expect(res.payload.data.suggestions).toContain('repeated_login_failures');
    // 反向闸：不得再往 suggestions 里塞中文成句（英文界面下无法翻译）
    expect(res.payload.data.suggestions.join('')).not.toMatch(/[\u4e00-\u9fa5]/);
    // recentLogins.map 应返回掩码后的 IP（行 71）
    expect(res.payload.data.recentLogins.length).toBe(allLogins.length);
    expect(res.payload.data.recentLogins[0].ip).toBeTruthy();
  });
});

// ============================================================
// getAccountBindings：未设置的部门不得下发中文占位（i18n 缺口回归）
// ============================================================
describe('getAccountBindings 占位符口径', () => {
  test('部门未设置：value 为空串 + verified=false，且响应里没有任何中文', async () => {
    // 原实现 `user.department || '未设置'` + `verified: true`：
    // 把一句中文塞进数据字段（英文界面下无法翻译），并让"没有部门"显示成
    // "已绑定 + 未设置"这一自相矛盾的状态。占位符应由前端词表渲染。
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue({
        email: 'a@example.com',
        phone: '13800138000',
        department: '',
      }),
    });

    const { req, res, next } = makeCtx();
    await invoke(getAccountBindings, req, res, next);

    expect(res.statusCode).toBe(200);
    const dept = res.payload.data.bindings.find((b) => b.type === 'department');
    expect(dept.value).toBe('');
    // 与 email/phone 同口径：verified = 「该项有值」
    expect(dept.verified).toBe(false);
    // 整个响应不得含中文（脱敏后的邮箱/手机号也不该有）
    expect(JSON.stringify(res.payload.data)).not.toMatch(/[\u4e00-\u9fa5]/);
  });

  test('部门已设置：原样透传并标 verified=true', async () => {
    mockUserFindById.mockReturnValue({
      select: jest.fn().mockResolvedValue({
        email: 'a@example.com',
        phone: '13800138000',
        department: '消防科',
      }),
    });

    const { req, res, next } = makeCtx();
    await invoke(getAccountBindings, req, res, next);

    const dept = res.payload.data.bindings.find((b) => b.type === 'department');
    // 真实部门名是**业务数据**，原样透传（中文在这里是数据，不是占位文案）
    expect(dept.value).toBe('消防科');
    expect(dept.verified).toBe(true);
  });
});

// ============================================================
// changePasswordSecure 分支补齐（#15 收敛后：业务分支在 authService 单一实现内，
// 此处验证控制器 outcome → HTTP 映射）
// ============================================================
describe('changePasswordSecure 分支补齐（委托 authService 后的映射）', () => {
  test('CONFIRM_MISMATCH → 400 两次输入的新密码不一致', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'CONFIRM_MISMATCH' });
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
    expect(mockChangeUserPassword).toHaveBeenCalledWith('u-admin', req.body, {
      username: 'admin',
    });
  });

  test('WEAK → 400 强度文案', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'WEAK', message: '密码太弱' });
    const { req, res, next } = makeCtx({
      body: { currentPassword: 'OldPass1!xy2', newPassword: 'weak' },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('密码太弱');
  });

  test('USER_NOT_FOUND → 401', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'USER_NOT_FOUND' });
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(401);
    // 401 需要点名是「用户不存在」这条路：authService 的其余失败原因同样映射 401
    expect(res.payload.errors.errorCode).toBe('USER_NOT_FOUND_OR_DELETED');
  });

  test('CURRENT_WRONG → 400 当前密码错误', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'CURRENT_WRONG' });
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('当前密码错误');
  });

  test('SAME_PASSWORD → 400 新密码不能与当前密码相同', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'SAME_PASSWORD' });
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.message).toBe('新密码不能与当前密码相同');
  });

  test('ENC_INVALID → codeError 统一错误码', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'ENC_INVALID' });
    const { req, res, next } = makeCtx({
      body: { encCurrentPassword: 'bad', encNewPassword: 'bad' },
    });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(400);
    expect(res.payload.errors.errorCode).toBe('AUTH_ENCRYPTED_CREDENTIAL_INVALID');
  });

  test('REVOKE_FAILED → 503（已改未吊销，如实告知）', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'REVOKE_FAILED', username: 'admin' });
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(503);
    expect(res.payload.message).toContain('会话吊销服务暂不可用');
  });

  test('OK → 200 + 审计落库（skipGlobalAudit + password_changed）', async () => {
    mockChangeUserPassword.mockResolvedValue({ outcome: 'OK', username: 'admin' });
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(res.flagAtJson).toBe(true);
    expect(mockAuditLogCreate).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'password_changed', username: 'admin' })
    );
  });

  test('审计写入失败不阻断改密结果，但必须可观测（「500 失真」的反面）', async () => {
    // 2026-09-20（`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）：该站点原为**裸 await** ⇒ 审计写失败时
    // asyncHandler 把异常交给 next ⇒ 客户端收到 500，而密码**已经落库**、缓存已失效
    // ⇒ 「状态已改却报错」：管理员会重试，用户会以为没改成功。
    // 改为 onAuditWriteFailure 后：业务语义不变（改密确实成功了，200 才诚实），
    // 但失败必须留痕（error 日志 + audit_write_failed 指标），不再静默、也不再失真。
    mockChangeUserPassword.mockResolvedValue({ outcome: 'OK', username: 'admin' });
    mockAuditLogCreate.mockRejectedValueOnce(new Error('audit down'));
    const { req, res, next } = makeCtx({ body: { currentPassword: 'x', newPassword: 'y' } });
    await invoke(changePasswordSecure, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(next).not.toHaveBeenCalled();
    const logger = require('../../utils/logger');
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('审计写入失败'),
      expect.objectContaining({ auditAction: 'password_changed' })
    );
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
    // 与 changePasswordSecure 同码：两处的「用户没了」必须统一，不能各自为政
    expect(res.payload.errors.errorCode).toBe('USER_NOT_FOUND_OR_DELETED');
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
    // F-51 最小修复（2026-09-20，用户选定「最小修复」）：本操作已设 skipGlobalAudit
    // （securityController.js:253），下面这条审计是**唯一留痕**——此前全仓无任何用例
    // 断言它落库（实测：该段整删后 66 套 / 717 例仍全绿，见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）。
    // 同时锁 L-06：username 必须是**操作者**、targetUsername 才是**被查看者**，不得混同。
    expect(mockAuditLogCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'view_sensitive_data',
        username: 'admin',
        targetUsername: 'testuser',
      })
    );
  });

  /**
   * 上面那条 `objectContaining` 只锁三个字段，对 `ip` 取哪一个是瞎的（假绿审计报告同判）。
   * 而 `ip` 恰恰是这条留痕里唯一有归因价值的一维：本操作设了 skipGlobalAudit，
   * 没有第二条记录。控制器原先写 `req.ip`——开着 trust proxy 时那就是请求方自己写的
   * XFF 首值，读别人手机号的人可以顺手挑一个地址写进取证里。
   * 口径与 auth.js 的 `ip_range_denied` 审计一致（`clientIpForSecurityDecision`）：
   * 可信边界内取 req.ip，边界外退回不可伪造的 socket 对端。
   * 下面两条是一对可证伪对照（变异：控制器改回 `ip: req.ip` ⇒ 第一条红、第二条仍绿，
   * 即"只钉住分叉方向、不禁止合理取值"）。
   */
  const xffForgedCtx = (peerAddress) => {
    const ctx = makeCtx({ body: { dataType: 'phone' } });
    ctx.req.app = { get: (key) => key === 'trust proxy' };
    ctx.req.ip = '198.51.100.7'; // proxy-addr 在 trust proxy 开时把 XFF 首值原样给 req.ip
    ctx.req.get = (header) =>
      String(header).toLowerCase() === 'x-forwarded-for' ? '198.51.100.7' : 'jest-agent';
    ctx.req.socket = { remoteAddress: peerAddress };
    return ctx;
  };
  const mockedViewer = () =>
    mockUserFindById.mockResolvedValue({
      username: 'testuser',
      phone: '13800138000',
      email: 'secret@example.com',
    });
  const auditIpOfLastCall = () => {
    const calls = mockAuditLogCreate.mock.calls;
    return calls[calls.length - 1][0].ip;
  };

  test('留痕 IP 取不可伪造的 socket 对端（公网对端 + 伪造 XFF）', async () => {
    mockedViewer();
    const { req, res, next } = xffForgedCtx('203.0.113.9');
    await invoke(viewSensitiveData, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(auditIpOfLastCall()).toBe('203.0.113.9');
    expect(auditIpOfLastCall()).not.toBe(req.ip);
  });

  test('反向对照：对端确为内网可信反代时仍取 req.ip，不"一律丢 XFF"', async () => {
    mockedViewer();
    const { req, res, next } = xffForgedCtx('10.0.0.2');
    await invoke(viewSensitiveData, req, res, next);
    expect(res.statusCode).toBe(200);
    expect(auditIpOfLastCall()).toBe('198.51.100.7');
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
    // 同一份桩要同时满足两个调用形状：
    //   · securityController 的裸 `await User.findById(userId)`（范围判定要读字段）；
    //   · authService 的 `await User.findById(userId).select(排除投影)`（读-改-save 的载入端）。
    // 必须用 mockReturnValue 而不是 mockResolvedValue：后者让 findById 返回 Promise，
    // 链式的 .select 就落在 Promise 上（TypeError: select is not a function）。
    // 返回普通对象时 `await` 照样把它解析出来，两条路都拿到同一份文档。
    fakeUser.select = jest.fn().mockReturnValue(fakeUser);
    mockUserFindById.mockReturnValue(fakeUser);
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
    expect(res.payload.errors.errorCode).toBe('USER_NOT_FOUND');
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
    expect(ctx.res.payload.errors.errorCode).toBe('USER_OPERATE_PEER_OR_HIGHER_FORBIDDEN');
  });

  test('inactive 用户不能解锁返回 400（行 415）', async () => {
    const { ctx } = makeLockCtx(false, { status: 'inactive' });
    await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
    expect(ctx.res.statusCode).toBe(400);
    expect(ctx.res.payload.message).toContain('不能通过解锁恢复');
    expect(ctx.res.payload.errors.errorCode).toBe('UNLOCK_INACTIVE_ACCOUNT');
  });

  test('inactive 用户不能锁定返回 400（行 427）', async () => {
    const { ctx } = makeLockCtx(true, { status: 'inactive' });
    await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
    expect(ctx.res.statusCode).toBe(400);
    expect(ctx.res.payload.message).toContain('不能重复锁定');
    expect(ctx.res.payload.errors.errorCode).toBe('LOCK_INACTIVE_ACCOUNT');
  });

  test('未知 outcome 不得落到成功分支（fail-closed）', async () => {
    // 2026-09-20（`deliverables/AGENT工作总账与待办-2026-09-21.md` §2.3 审计链与合规留痕）：源码原为 `default: break;`——业务层一旦新增
    // outcome 而控制器忘了映射，会**静默按成功处理**并写一条 user_locked/user_unlocked 审计
    // （把「映射表漏项」变成一条假的成功留痕）。现改为
    // `case 'OK': break; default: → INTERNAL_ERROR`，与 changePasswordSecure 同口径。
    const authServiceReal = require('../../services/authService');
    const spy = jest
      .spyOn(authServiceReal, 'setUserLockStatus')
      .mockResolvedValueOnce({ outcome: 'SOMETHING_NEW' });
    try {
      const { ctx } = makeLockCtx(true);
      await invoke(toggleUserLock, ctx.req, ctx.res, ctx.next);
      expect(ctx.res.statusCode).toBe(500);
      expect(ctx.res.payload.success).toBe(false);
      expect(ctx.res.payload.errors.errorCode).toBe('INTERNAL_ERROR');
      // 反向保护：未知 outcome 不得留下任何「成功」痕迹
      expect(mockAuditLogCreate).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
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
    // 「validation 失败」的判据是字段明细透传，不是 400
    expect(res.payload.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.payload.errors.fieldErrors).toEqual([{ msg: 'invalid' }]);
  });

  test('目标用户不存在返回 404（行 494）', async () => {
    mockUserFindById.mockResolvedValue(null);
    const { req, res, next } = makeCtx({ params: { userId: 'nonexistent' } });
    await invoke(resetUserMfa, req, res, next);
    expect(res.statusCode).toBe(404);
    expect(res.payload.errors.errorCode).toBe('USER_NOT_FOUND');
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
    // 层级须严格高于目标才能走到「内置超管」分支。这里的 20 是**测试替身**，
    // 不是现实值——Role.js:44-45 限定 level ∈ [1,10]，且内置超管恒为 10，故
    // 现实中 operatorMaxLevel 最大也只能到 10，10 >= 10 会先命中上一行的
    // MFA_RESET_PEER_OR_HIGHER_FORBIDDEN；换言之下面这个 CANNOT_RESET_MFA_SUPER_ADMIN
    // 分支在真实数据下**不可达**（属纵深防御的冗余层）。
    // 仍需测它：一旦有人放宽 Role.level 上限，或给超管角色以外的路径加豁免，
    // 这层就会变成唯一防线——测试保证它届时是正确工作的。
    // 目标值 10 与超管实际值一致，此处的 20 仅用于制造无可争议的层级差。
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
    expect(suggestions).toContain('high_risk_score');
    expect(suggestions).toContain('excessive_failed_logins');
    expect(suggestions).toContain('unusual_time_access');
    // 每一条都必须是 constants/securitySuggestions.js 里的码：
    // 这条闸挡的是「将来有人再写一个字面量中文句子进去」——那种缺陷只在
    // 切到英文界面时才看得见，后端断言若不钉码表就完全测不到。
    const { SECURITY_SUGGESTION_VALUES } = require('../../constants/securitySuggestions');
    expect(suggestions.every((s) => SECURITY_SUGGESTION_VALUES.includes(s))).toBe(true);
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

  test('compliance.appendOnlyEnforced 取的是 getter 的实际返回值（不是写死的 true）', async () => {
    // 缺陷：控制器把这一键写成常量 true ⇒ 护栏被关掉这种最该被发现的对外状态，
    // 在合规面板上永远显示"在防"。本用例只钉控制器边界这一半：读 getter、原样外发；
    // getter 本身是否反映真实开关状态，由 security/complianceGuardStateIsReal.test.js
    // 在**不 mock 模型**的一侧钉（本套件的 AuditLog 是桩，值不来自真闭包）。
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    });
    const AuditLog = require('../../models/AuditLog');
    expect(typeof AuditLog.isAppendOnlyEnforced).toBe('function');

    mockAppendOnlyEnforced.mockReturnValueOnce(false);
    const off = makeCtx();
    await invoke(getSecurityOverview, off.req, off.res, off.next);
    expect(off.res.payload.data.compliance.error).toBeUndefined(); // 没走降级分支
    expect(off.res.payload.data.compliance.appendOnlyEnforced).toBe(false);

    const on = makeCtx();
    await invoke(getSecurityOverview, on.req, on.res, on.next);
    expect(on.res.payload.data.compliance.appendOnlyEnforced).toBe(true);
  });

  test('compliance.auditLoss 值逐项透传、不掺运行噪声、不发明键', async () => {
    // 本用例钉的是投影的**忠实性**：从 getStats() 取的每个键都原样外发（键名不串位、
    // 值不被改写），且 bufferLength/hardLimit 这类运行噪声不混进合规口径。
    // 与 securityOverviewAuditLossProjection.test.js 的分工：那边用命名谓词钉「该出现
    // 哪几个计数键」；这里钉「出现的东西对不对」。两边都不抄对方的清单——抄一份就是
    // 第二个私有副本，生产加计数时它只会跟着变绿，不会跟着变红。
    // 夹具的键集合从真模块**现取**：手抄漏一个键，jest 的 toEqual 会忽略值为 undefined
    // 的键 ⇒ 用例绿、面板从此少一项（本仓反复踩过的"夹具不忠于生产形状"）。
    const auditBuffer = require('../../services/auditBuffer');
    const realKeys = Object.keys(jest.requireActual('../../services/auditBuffer').getStats());
    const NOISE = ['bufferLength', 'hardLimit', 'consecutiveFailures', 'walEnabled'];
    const fixture = {};
    // 每个键一个互不相同的值：控制器若把 droppedCount 读进 walDroppedLines，
    // 下面的逐项比对必红（同名 0 值夹具永远抓不到串位）。
    realKeys.forEach((k, i) => {
      fixture[k] = k === 'walEnabled' ? true : i + 1;
    });
    auditBuffer.getStats.mockReturnValueOnce(fixture);
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    });
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);

    const compliance = res.payload.data.compliance;
    expect(compliance.error).toBeUndefined(); // 没走降级分支（否则断的是 {error} 形状）
    const loss = compliance.auditLoss;

    // ① 不发明键：面板上的每个键都必须是 getStats 真有的
    expect(Object.keys(loss).filter((k) => !realKeys.includes(k))).toEqual([]);
    // ② 值原样透传
    for (const k of Object.keys(loss)) expect(loss[k]).toBe(fixture[k]);
    // ③ 运行噪声不进合规口径
    for (const k of NOISE) expect(loss).not.toHaveProperty(k);
    // ④ 反向：getStats 里除噪声之外的计数键**一个都不许漏投**。
    //    生产新增了计数而控制器没投影 ⇒ 这里红（此时要么该键确实要进面板，
    //    要么它是噪声、把它加进 NOISE——两条都是显式决策，没有静默变绿的路径）。
    expect(Object.keys(loss).sort()).toEqual(realKeys.filter((k) => !NOISE.includes(k)).sort());
  });

  test('compliance.monitorHealth 原样透出监控计数（isRunning 之外的"真在跑"凭据）', async () => {
    // 定时任务的静默失效形态是「isRunning()===true、实际每轮都失败」。
    // getHealth() 是唯一能区分这两种的读数，此前没有任何生产出口能读到它。
    // 本用例只钉控制器这一半：调用了、原样外发、不丢字段。
    const auditMonitor = require('../../services/auditMonitor');
    auditMonitor.getHealth.mockReturnValueOnce({
      runs: 5,
      failures: 4,
      consecutiveFailures: 4,
      skippedOverlaps: 2,
      lastRunAt: '2026-09-25T01:00:00.000Z',
      lastFailureAt: '2026-09-25T01:00:00.000Z',
      lastFailureMessage: 'mongo timeout',
      intervalMs: 30000,
      running: true,
    });
    mockGetSecurityOverview.mockResolvedValue({
      criticalAlerts: 0,
      highAlerts: 0,
      failedLogins: 0,
      unusualAccess: 0,
      riskScore: 0,
    });
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    const compliance = res.payload.data.compliance;
    expect(compliance.error).toBeUndefined();
    expect(compliance.monitorHealth).toEqual({
      runs: 5,
      failures: 4,
      consecutiveFailures: 4,
      skippedOverlaps: 2,
      lastRunAt: '2026-09-25T01:00:00.000Z',
      lastFailureAt: '2026-09-25T01:00:00.000Z',
      lastFailureMessage: 'mongo timeout',
      intervalMs: 30000,
      running: true,
    });
    // 与新字段必须成对外发：只给一个就退回到"面板说活着"的旧口径
    expect(compliance.monitorRunning).toBe(true);
  });

  test('反向：桩缺 getHealth 时只降级这一个字段，不得抹掉整段 compliance', async () => {
    // 这块 try/catch 的降级粒度是"整段 → {error}"（见上面的降级用例）。
    // 一个可选字段读不到就把留存天数/链尾哈希/丢失计数全抹掉，代价远大于收益
    // ⇒ 取值走 typeof 兜底，而本用例钉的就是"兜底只吃掉一个字段"这个形状。
    const auditMonitor = require('../../services/auditMonitor');
    const realGetHealth = auditMonitor.getHealth;
    auditMonitor.getHealth = undefined;
    try {
      mockGetSecurityOverview.mockResolvedValue({
        criticalAlerts: 0,
        highAlerts: 0,
        failedLogins: 0,
        unusualAccess: 0,
        riskScore: 0,
      });
      const { req, res, next } = makeCtx();
      await invoke(getSecurityOverview, req, res, next);
      const compliance = res.payload.data.compliance;
      expect(compliance.monitorHealth).toBeNull();
      expect(compliance.error).toBeUndefined();
      expect(compliance.monitorRunning).toBe(true);
      expect(compliance.auditLoss).toBeDefined();
    } finally {
      auditMonitor.getHealth = realGetHealth;
    }
  });

  test('securityAlert.getSecurityOverview 抛异常时返回 500（行 656-657）', async () => {
    mockGetSecurityOverview.mockRejectedValue(new Error('service down'));
    const { req, res, next } = makeCtx();
    await invoke(getSecurityOverview, req, res, next);
    expect(res.statusCode).toBe(500);
    // 500 的判据是「点名了概览查询失败」：笼统的 INTERNAL_ERROR 会掩盖服务层故障定位
    expect(res.payload.errors.errorCode).toBe('SECURITY_OVERVIEW_QUERY_FAILED');
    // 故障详情不得随响应外泄（错误文案固定，不带 e.message）
    expect(res.payload.message).toBe('安全概览查询失败');
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
    expect(res.payload.errors.errorCode).toBe('RECENT_ALERTS_EMPTY');
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
    // 摘要的档位键集由 AUDIT_RISK_LEVELS 派生（F-149）：手写四行 filter 时加一档会漏计
    // ——total 里算它、桶里都没有。这两条把"桶必须覆盖等级全集"钉成可证伪的断言，
    // 且键集从常量派生、不在这儿再抄一份档位名。
    const { AUDIT_RISK_LEVELS } = require('../../constants/audit');
    expect(
      Object.keys(meta.summary)
        .filter((k) => k !== 'total')
        .sort()
    ).toEqual([...AUDIT_RISK_LEVELS].sort());
    expect(AUDIT_RISK_LEVELS.reduce((n, l) => n + meta.summary[l], 0)).toBe(meta.summary.total);
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
    expect(res.payload.errors.errorCode).toBe('RECENT_ALERTS_QUERY_FAILED');
    expect(res.payload.message).toBe('最近告警查询失败');
  });
});
