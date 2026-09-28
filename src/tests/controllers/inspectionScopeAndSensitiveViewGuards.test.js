/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：inspectionController 写端点的越权 403 分支 + securityController.viewSensitiveData 的层级/404/400
 * 守护的不变式：写端点必须按 isInspectionInScope 落 403；查看敏感数据必须按层级落 403、目标不存在落 404、dataType 非法落 400
 * 可证伪性：变异实测（N=8）：全部 7 个模块共杀 3/49，基线 12 passed
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [部分有效·判定在别处已设防] **F-35**：`:22-28` 把 `rbac.assertRecordInScope` 整体 mock 掉，6 条「越权 403」只断 `res.status` ⇒ **数据范围的真实判定完全在本文件之外**（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     复核（2026-09-20 **变异实测**）：前半句**事实正确**，但它隐含的"因此没设防"**错误**。
 *     把真实 `assertRecordInScope` 改成永远 `{allowed:true}`，`rbac.js` 的 99 套全量 related（1162 例）
 *     中**杀掉 5 例 / 4 套**（`alarmInspectionErrorPaths` 的 self 范围看他人 403、`permissionUserValidationGuards`
 *     的 `getUserById` 范围外 403、`adversarialProbeRegression` 的跨部门设备 403、报警指派反向保护 403）
 *     ⇒ 真实判定**在别处被 4 套用例守着**。证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法。
 *   - [部分有效·真实语义在别处已设防] `:34-43`（现形 `:66-68`）在 mock 里**重新实现**了 `maxRoleLevel`（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     变异实测更正（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法）：前半句事实正确，但「口径漂移不会被发现」**错误**。
 *       把真实 `maxRoleLevel` 改成**空数组返回 0**（permissionHelper.js:363-365 自陈这是安全回归）
 *       → utils/permissionHelper.test.js 的「空数组返回 -Infinity（fail-closed）」**变红**
 *       （正对照：恒返回 999 杀 6 例）。残留：mock 与真实实现的**文件内漂移**无自动检测
 *       （维护风险，**非**覆盖洞）。
 *
 * 命名沿革：2026-09-20 由 `coverageDebt.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 控制器覆盖率债务补齐（2026-09-15，coverage 步骤 CI 实证）
 *
 * 本次改动整改（评价报告 #6/#12/#15）给三个文件新增了分支，导致
 * coverageThreshold 跌破基线，Run tests with coverage 在 CI 挂掉：
 *   - inspectionController：6 个写端点的 isInspectionInScope 越权 403 分支
 *   - securityController.viewSensitiveData：查他人的层级越权 403 /
 *     目标不存在 404 / 非法 dataType 400 分支
 * 直调 handler + mock 依赖（对齐 securityControllerOutcomeAndGuards.test.js 模式），
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
  // 写路径新增的对象级范围闸会先取一次数据范围（getDataScope 查真实 User 文档）。
  // 本套件测的是"各道 403 分支的先后与响应码"，不是范围档位本身——
  // 档位行为由 zzqoder_inspectionWriteScopeGates.test.js 用真库端到端覆盖。
  // 这里把范围固定为 all，避免夹具里那只"半链式"的 User mock 被 populate 打穿。
  getDataScope: jest.fn(async () => ({ type: 'all' })),
}));

jest.mock('express-validator', () => ({
  validationResult: () => ({ isEmpty: () => true, array: () => [] }),
}));

const mockPermissionHelper = {
  getOperatorMaxLevel: jest.fn(),
  // 直接取真实实现（permissionHelper.maxRoleLevel 是层级判定的单一事实来源）。
  // 此前这里手抄了一份等价式子：真实实现一改（例如空角色集的 -Infinity 语义），
  // mock 仍按旧口径算，用例就会"绿着放过"一个真实环境里已改变的判定。
  maxRoleLevel: jest.requireActual('../../utils/permissionHelper').maxRoleLevel,
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
    ['completeInspection', 'complete', () => inspectionController.completeInspection],
    ['reviewInspection', 'review', () => inspectionController.reviewInspection],
    ['cancelInspection', 'cancel', () => inspectionController.cancelInspection],
    ['deleteInspection', 'delete', () => inspectionController.deleteInspection],
  ];

  for (const [name, label, getHandler] of cases) {
    test(`${name}：数据范围外 → 403 且不触碰 service`, async () => {
      const res = makeRes();
      await getHandler()(reqOf({}), res);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(
        mockInspectionService[label === 'delete' ? 'deleteInspection' : name]
      ).not.toHaveBeenCalled();
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
