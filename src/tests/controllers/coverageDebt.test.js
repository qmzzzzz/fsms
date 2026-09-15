/**
 * 控制器覆盖率债务补齐（2026-09-15，coverage 步骤 CI 实证）
 *
 * 本轮整改（评价报告 #6/#12/#15）给三个文件新增了分支，导致
 * coverageThreshold 跌破基线，Run tests with coverage 在 CI 挂掉：
 *   - inspectionController：6 个写端点的 isInspectionInScope 越权 403 分支
 *   - securityController.viewSensitiveData：查他人的层级越权 403 /
 *     目标不存在 404 / 非法 dataType 400 分支
 * 直调 handler + mock 依赖（对齐 securityCoverageGap.test.js 模式），
 * 只断言分支落点，不重复端到端语义。
 */

const mockInspectionService = {
  getInspectionById: jest.fn(),
  updateInspection: jest.fn(),
  startInspection: jest.fn(),
  completeInspection: jest.fn(),
  reviewInspection: jest.fn(),
  cancelInspection: jest.fn(),
  deleteInspection: jest.fn(),
};

jest.mock('../../services/InspectionService', () => mockInspectionService);

jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  assertRecordInScope: jest.fn(),
}));

jest.mock('express-validator', () => ({
  validationResult: () => ({ isEmpty: () => true, array: () => [] }),
}));

const mockPermissionHelper = {
  getOperatorMaxLevel: jest.fn(),
  maxRoleLevel: (roles) => (roles || []).reduce((m, r) => Math.max(m, r.level ?? 9), 9),
};

jest.mock('../../utils/permissionHelper', () => mockPermissionHelper);

const mockUserDoc = { _id: 'u_self', phone: '13800138000', email: 'a@b.c' };
// findById 双用：查目标（select/populate/lean 链）与查 user 本体
let mockFindByIdQueue = [];

jest.mock('../../models/User', () => ({
  findById: jest.fn(() => {
    const v = mockFindByIdQueue.shift();
    if (v && v.__chained) {
      return {
        select: () => ({
          populate: () => ({
            lean: async () => v.value,
          }),
        }),
      };
    }
    return Promise.resolve(v ? v.value : null);
  }),
}));

const makeRes = () => {
  const res = { statusCode: null, body: null, locals: {} };
  res.status = jest.fn((c) => {
    res.statusCode = c;
    return res;
  });
  res.json = jest.fn((b) => {
    res.body = b;
    return res;
  });
  return res;
};

jest.mock('../../models/AuditLog', () => ({ create: jest.fn().mockResolvedValue({}) }));

const inspectionController = require('../../controllers/inspectionController');
const rbac = require('../../middleware/rbac');
const securityController = require('../../controllers/securityController');
const User = require('../../models/User');

describe('inspectionController 写端点越权分支（6 处 403）', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockInspectionService.getInspectionById.mockResolvedValue({
      _id: 'insp1',
      assignedTo: 'someone',
    });
    rbac.assertRecordInScope.mockResolvedValue({ allowed: false });
  });

  const reqOf = (body = {}) => ({
    params: { id: 'insp1' },
    body,
    query: {},
    user: { userId: 'u_op', username: 'op' },
  });

  const cases = [
    ['updateInspection', 'update', () => inspectionController.updateInspection],
    ['startInspection', 'start', () => inspectionController.startInspection],
    [
      'completeInspection',
      'complete',
      () => inspectionController.completeInspection,
    ],
    ['reviewInspection', 'review', () => inspectionController.reviewInspection],
    ['cancelInspection', 'cancel', () => inspectionController.cancelInspection],
    ['deleteInspection', 'delete', () => inspectionController.deleteInspection],
  ];

  for (const [name, label, getHandler] of cases) {
    test(`${name}：数据范围外 → 403 且不触碰 service`, async () => {
      const res = makeRes();
      await getHandler()(reqOf({}), res);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(mockInspectionService[label === 'delete' ? 'deleteInspection' : name]).not.toHaveBeenCalled();
    });
  }

  test('数据范围内 → 正常推进 service', async () => {
    rbac.assertRecordInScope.mockResolvedValue({ allowed: true });
    mockInspectionService.updateInspection.mockResolvedValue({ _id: 'insp1' });
    const res = makeRes();
    await inspectionController.updateInspection(reqOf({ title: 'x' }), res);
    expect(mockInspectionService.updateInspection).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
  });
});

describe('securityController.viewSensitiveData 数据范围分支', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFindByIdQueue = [];
  });

  const reqOf = (body) => ({
    body,
    user: { userId: 'u_op' },
    ip: '192.0.2.9',
    get: () => 'jest-agent',
  });

  test('查他人：目标不存在 → 404', async () => {
    mockPermissionHelper.getOperatorMaxLevel.mockResolvedValue(5);
    // 队列：先目标（chained→null），本体查询不会发生
    mockFindByIdQueue = [{ __chained: true, value: null }];
    const res = makeRes();
    await securityController.viewSensitiveData(
      reqOf({ dataType: 'phone', targetUserId: 'u_missing' }),
      res
    );
    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('查他人：目标层级高于操作者 → 403', async () => {
    mockPermissionHelper.getOperatorMaxLevel.mockResolvedValue(5);
    mockFindByIdQueue = [
      { __chained: true, value: { roles: [{ level: 7 }] } }, // targetLevel 7 > opLevel 5
    ];
    const res = makeRes();
    await securityController.viewSensitiveData(
      reqOf({ dataType: 'phone', targetUserId: 'u_high' }),
      res
    );
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('查他人：层级足够 → 放行查本体并返回脱敏数据', async () => {
    mockPermissionHelper.getOperatorMaxLevel.mockResolvedValue(9);
    mockFindByIdQueue = [
      { __chained: true, value: { roles: [{ level: 7 }] } },
      { value: mockUserDoc },
    ];
    const res = makeRes();
    await securityController.viewSensitiveData(
      reqOf({ dataType: 'phone', targetUserId: 'u_low' }),
      res
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(User.findById).toHaveBeenCalledWith('u_low');
  });

  test('非法 dataType → 400（default 分支）', async () => {
    mockFindByIdQueue = [{ value: mockUserDoc }];
    const res = makeRes();
    await securityController.viewSensitiveData(reqOf({ dataType: 'weird' }), res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('本人查看 phone → 200', async () => {
    mockFindByIdQueue = [{ value: mockUserDoc }];
    const res = makeRes();
    await securityController.viewSensitiveData(reqOf({ dataType: 'phone' }), res);
    expect(res.status).toHaveBeenCalledWith(200);
  });
});
