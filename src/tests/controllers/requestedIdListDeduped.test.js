/**
 * 请求体 id 列表：归一必须在「存在性比对」之前，且归一后的那份必须参与写入
 * （C2 回归闸，无数据库）
 *
 * 【缺陷本体】
 * 本仓判断「请求的 id 里有不存在的」只用一把尺子：`查到的文档数 !== 请求的 id 数`。
 * 而 MongoDB 的 `$in` 天生只回**去重后**的文档 ⇒ 请求里重复一个合法 id 就会被算成
 * 「有一个 id 不存在」，一次本来合法的写操作回 400：
 *   PUT    /api/users/:id/roles  重复角色 → ROLE_ID_INVALID
 *   POST   /api/users            重复角色 → ROLE_NOT_FOUND_IN_LIST
 *   DELETE /api/users/batch      重复 id  → USER_ID_NOT_FOUND_IN_LIST
 * 另一侧同样错：即便放行，未去重的数组会被原样写库——`assignRoles` 走
 * `findByIdAndUpdate({$set:{roles}})`，schema 里 roles 是 [ObjectId] 且不做去重，
 * 于是文档里留下重复引用。
 * 路由层只有 `isArray({min,max})`（userRoutes.js 对 roles/ids 的三条校验链），
 * **没有任何唯一性要求** ⇒ 「重复提交」是完全可达的输入形状，不是臆想。
 *
 * 【为什么必须两条臂都钉住】
 * 只测「不再 400」会漏掉半个修复：把归一挪到比对之后（或只在校验处去重、写入仍用原值），
 * 400 那条臂照样绿。所以每个接口都有「接受」与「写入的到底是哪一份」两条腿，
 * 变异台账里两者分别可红（见文末 dedup-assign-compare-raw 与 dedup-assign-write-raw 的色差）。
 *
 * 【为什么这个门禁不用数据库】
 * 被测面是「控制器拿请求列表去比服务层返回的文档数，再把哪一份写下去」——
 * 纯编排逻辑，DB 在这里唯一的语义责任是 `$in` 的去重。替身显式复现这一条，
 * 并把「替身自己去重」本身写成第 0 组的腿：假绿族第 3 族（判据依赖的替身形状没人断言）
 * 一旦替身退化成「一条请求回一个文档」，本闸就会空转，第 0 组必须先红。
 * 数据范围/层级/权限子集这些**邻近闸门**不在本闸射程内：rbac 整块用替身（不参与判定），
 * 而 `maxRoleLevel`/`matchesPermissionCodes`/`isSuperAdminRole`/`checkSuperAdminMembership`
 * 保留真实实现——它们参与本次判定，替身化就会把「去重没有削弱下游闸门」那几条腿变成自证。
 *
 * 【变异台账】预测先写、实测后记，见文件末尾。
 */

const mongoose = require('mongoose');

/** 固定 24 位 hex：同时满足路由层 isMongoId 与 `$in` 的 ObjectId 形状 */
const mockIds = {
  operator: '0000000000000000000000a1',
  target: '0000000000000000000000b1',
  peerA: '0000000000000000000000b2',
  peerB: '0000000000000000000000b3',
  created: '0000000000000000000000b9',
  missing: '0000000000000000000000ff',
  roleGuest: '0000000000000000000000c1',
  roleOps: '0000000000000000000000c2',
  roleRich: '0000000000000000000000c3',
  roleForeign: '0000000000000000000000c4',
  // 第 7 组：角色权限改写路径（PUT /api/roles/:id/permissions）用的三份文档
  rolePermTarget: '0000000000000000000000cc',
  permRead: '0000000000000000000000d1',
  permAssign: '0000000000000000000000d2',
};

/**
 * 世界状态：roles/users/perms 三张表。
 * 声明在 jest.mock 之前且以 mock 开头——真实 jest 会把 jest.mock 提到文件顶部，
 * 而工厂体到 require 被测模块时才执行，此时这里已初始化（既符合 hoist 规则又不踩 TDZ）。
 */
const mockStore = { roles: {}, users: {}, perms: {}, permDocs: {}, savedRole: null };

const mockSeed = () => {
  mockStore.savedRole = null;
  mockStore.roles = {
    [mockIds.roleGuest]: {
      _id: mockIds.roleGuest,
      level: 1,
      code: 'GUEST',
      isBuiltIn: true,
      status: 'active',
      permissions: [{ code: 'user:read' }],
    },
    // 与操作者同级（level 4）且操作者自己持有：B-2 同级归属闸应当放行
    // 权限码清单即"操作者可授予的码"的唯一事实来源（下面的 mockStore.perms 由它派生）。
    [mockIds.roleOps]: {
      _id: mockIds.roleOps,
      level: 4,
      code: 'OPS_ADMIN',
      isBuiltIn: false,
      status: 'active',
      permissions: [{ code: 'user:read' }, { code: 'user:update' }, { code: 'role:assign' }],
    },
    // 高于操作者（level 4）：层级闸必须仍然拦住，去重不得给它松口
    [mockIds.roleRich]: {
      _id: mockIds.roleRich,
      level: 9,
      code: 'RICH_ADMIN',
      isBuiltIn: false,
      status: 'active',
      permissions: [{ code: 'user:read' }],
    },
    // 同级但操作者未持有：B-2 拦它，去重同样不得给它松口
    [mockIds.roleForeign]: {
      _id: mockIds.roleForeign,
      level: 4,
      code: 'FOREIGN_PEER',
      isBuiltIn: false,
      status: 'active',
      permissions: [{ code: 'user:read' }],
    },
  };
  mockStore.users = {
    [mockIds.operator]: {
      _id: mockIds.operator,
      username: 'ops_admin',
      status: 'active',
      roles: [mockIds.roleOps],
      department: 'D1',
      createdBy: mockIds.operator,
    },
    [mockIds.target]: {
      _id: mockIds.target,
      username: 'target_user',
      status: 'active',
      // 目标层级 1 < 操作者 4：目标侧层级保护放行，请求才能走到角色列表判定
      roles: [mockIds.roleGuest],
      department: 'D1',
      createdBy: mockIds.operator,
    },
    [mockIds.peerA]: {
      _id: mockIds.peerA,
      username: 'peer_a',
      status: 'active',
      roles: [mockIds.roleGuest],
      department: 'D1',
      createdBy: mockIds.operator,
    },
    [mockIds.peerB]: {
      _id: mockIds.peerB,
      username: 'peer_b',
      status: 'active',
      roles: [mockIds.roleGuest],
      department: 'D1',
      createdBy: mockIds.operator,
    },
  };
  // 操作者可用的权限码**由角色图派生**，不手写第二份清单。
  // 手写的那份曾经与角色图矛盾（roles 只给 user:read，perms 却写死三条），
  // 于是 rolePermissionController 的"不得授予自己没有的权限"子集臂被替身的缝悄悄绕过
  // ——第 7 组的放行腿就绿在一个不存在的前提上。派生之后两处不可能分叉；
  // 子集臂本身由 src/tests/controllers/createUserPeerRoleGate.test.js 负责（分工不是遗漏）。
  mockStore.perms = {
    [mockIds.operator]: (mockStore.roles[mockIds.roleOps].permissions || []).map((p) => p.code),
  };
  // 第 7 组的世界：一条"低于操作者、非内置"的角色（改写分支要求 level < operatorMaxLevel=4），
  // 以及权限文档表——findPermissionsByIds 的返回形状照真实投影（_id + code）。
  mockStore.roles[mockIds.rolePermTarget] = {
    _id: mockIds.rolePermTarget,
    level: 2,
    code: 'OPS_VIEWER',
    name: '运维只读',
    isBuiltIn: false,
    status: 'active',
    permissions: [],
  };
  mockStore.permDocs = {
    [mockIds.permRead]: { _id: mockIds.permRead, code: 'user:read' },
    [mockIds.permAssign]: { _id: mockIds.permAssign, code: 'role:assign' },
  };
};
mockSeed();

/**
 * 服务层替身：需要复现的 DB 语义只有两条——
 *   1) `find({_id:{$in:list}})` 每条 id 至多回一个文档（重复项不重复回）；
 *   2) `deleteMany` 的 deletedCount 是实际存在的文档数。
 * populate 的返回形状照 userService 的真实投影：findBatchUsers 的 roles 是角色文档数组。
 */
jest.mock('../../services/userService', () => {
  // 查表按"驱动怎么解析 id"，不按字符串相等：Mongoose 的 findById/findByIdAndUpdate/$in
  // 都会把入参 cast 成 ObjectId（12 字节），所以 `67ED…` 与 `67ed…` 命中同一份文档。
  // 少了这一维，第 5 组的大小写腿测的就是替身的字典而不是被测码（第 3 族假绿：
  // 正确的产品代码会让错误的替身隐身）。
  //
  // 这一维必须**同时**用在列表入口和单个 :id 入口上：只给列表补小写、单个入口仍按
  // String(id) 取表，替身就比驱动更严（大写 :id 在替身里 404、在生产里正常），
  // 那等于把本闸要杀的那类缺陷复制进仪器里。第 8 组用一条"大写 :id 改的是同一个人"
  // 的行为腿盯着这里。
  const castId = (id) => String(id).toLowerCase();
  const pickUnique = (map, ids) =>
    [...new Set((ids || []).map(castId))].map((id) => map[id]).filter(Boolean);

  return {
    findUserForUpdate: jest.fn(async (id) => mockStore.users[castId(id)] || null),
    findRolesByIds: jest.fn(async (ids) => pickUnique(mockStore.roles, ids).map((r) => ({ ...r }))),
    findRolePermissionDocs: jest.fn(async (ids) => pickUnique(mockStore.roles, ids)),
    findActiveRolePermissionDocs: jest.fn(async (ids) => pickUnique(mockStore.roles, ids)),
    getPermissions: jest.fn(async (userId) => mockStore.perms[castId(userId)] || []),
    // User.findByIdAndUpdate($set:{roles})：数组原样入库，重复项不会被 DB 消化
    updateRoles: jest.fn(async (id, roles) => {
      const doc = mockStore.users[castId(id)];
      if (doc) doc.roles = roles;
      return doc;
    }),
    createUser: jest.fn(async (fields) => {
      const doc = { _id: mockIds.created, ...fields };
      mockStore.users[mockIds.created] = doc;
      return doc;
    }),
    getCreatedUser: jest.fn(async (id) => mockStore.users[castId(id)] || null),
    getUpdatedUser: jest.fn(async (id) => mockStore.users[castId(id)] || null),
    findDuplicateUsername: jest.fn(async () => null),
    findOneUser: jest.fn(async () => null),
    findBatchUsers: jest.fn(async (ids) =>
      pickUnique(mockStore.users, ids).map((u) => ({
        ...u,
        roles: pickUnique(mockStore.roles, u.roles),
      }))
    ),
    deleteMany: jest.fn(async (filter) => {
      const requested = ((filter && filter._id && filter._id.$in) || []).map(castId);
      const existing = [...new Set(requested)].filter((id) => mockStore.users[id]);
      existing.forEach((id) => {
        delete mockStore.users[id];
      });
      return { deletedCount: existing.length, acknowledged: true };
    }),
  };
});

/** 层级解析走 DB，替身给一个常量（4）；maxRoleLevel/matchesPermissionCodes 保留真实实现 */
jest.mock('../../utils/permissionHelper', () => {
  const actual = jest.requireActual('../../utils/permissionHelper');
  return { ...actual, getOperatorMaxLevel: jest.fn(async () => 4) };
});

/**
 * 数据范围闸不是本闸的射程（它有自己的套件），整块替身。
 * 这里**不**用 requireActual：rbac 的判定要读 getDataScope 的 DB 结果，
 * 真加载它只会让「范围放行」变成未定义行为。
 */
jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(async () => ({ type: 'all' })),
  buildDataScopeFilter: jest.fn(() => ({})),
  assertRecordInScope: jest.fn(async () => ({ allowed: true })),
  isRecordInScope: jest.fn(() => true),
  isDepartmentValueAllowed: jest.fn(() => true),
}));

/** 角色变更后的权限推送要连 socket 与 DB：只钉「被调用」这件事 */
jest.mock('../../utils/permissionSync', () => ({
  syncPermissionsToUsers: jest.fn(async () => {}),
}));

/** auth 的用户缓存失效：真实模块会拉起口令黑名单与会话链路 */
jest.mock('../../middleware/auth', () => ({
  invalidateUserCache: jest.fn(),
}));

/**
 * 第 6 组（巡检写入侧）用的两个替身：
 *  - InspectionService 整块替身：本组只看"控制器交出去的那份字段"，不碰库。
 *  - inspectionGuards **部分**替身：rejectOutOfScopeReferences 桩成"放行"，
 *    而 normalizeInspectionRefLists 保留真实实现——第 6 组测的就是"控制器有没有真的调用它"，
 *    整块桩掉会把要钉的接线一起桩掉（第 3 族：替身把自己该被证明的东西当成了前提）。
 */
jest.mock('../../services/InspectionService', () => ({
  // 忠实复刻驱动 services/InspectionService.js 的 findActiveUserIds：
  // `User.find({_id:{$in:ids}, status:'active'})` —— 按 12 字节去重、只回真实存在且启用的、
  // 返回**库里**的小写 hex。原先桩成 `ids.map(String)` 的原样回显，等于把"指派给不存在的
  // 人"这一臂判死（第 3 族：替身比驱动宽松），rejectUnusableAssignees 在本文件永远不可能拒；
  // 而驱动恒返回小写，控制器又拿裸值去 `usable.has(String(id))`，所以桩忠实之后，
  // "大写写法的既有执行人"就会被判成不存在——这正是第 6 组那两条新腿要钉的时序。
  findActiveUserIds: jest.fn(async (ids) => {
    const seen = [...new Set((ids || []).map((id) => String(id).toLowerCase()))];
    return seen
      .map((id) => mockStore.users[id])
      .filter((u) => u && u.status === 'active')
      .map((u) => String(u._id));
  }),
  createInspection: jest.fn(async (fields) => ({ _id: 'insp1', ...fields })),
  // PUT 一侧的两个出口：getInspectionById 给一条"改前在范围内"的记录
  // （范围判定本身由 rbac 替身放行，不是本组射程），updateInspection 记录
  // 控制器交下来的 updates——#34 断言的就是这份 updates。
  getInspectionById: jest.fn(async (id) => ({
    _id: id,
    title: '既有巡检',
    status: 'planned',
    assignedTo: [mockIds.peerA],
  })),
  updateInspection: jest.fn(async (inspection, updates) => ({ ...inspection, ...updates })),
}));

jest.mock('../../controllers/inspectionGuards', () => {
  const actual = jest.requireActual('../../controllers/inspectionGuards');
  return {
    normalizeInspectionRefLists: actual.normalizeInspectionRefLists,
    rejectOutOfScopeReferences: jest.fn(async () => false),
  };
});

/**
 * 第 7 组（PUT /api/roles/:id/permissions）用的服务层替身。
 * 查表纪律与 userService 那条完全一致：按驱动 cast 后的 12 字节（等价于小写 hex）命中，
 * 且 `{$in}` 只回去重后的文档——否则本组的大小写腿测的是替身的字典。
 */
jest.mock('../../services/roleService', () => {
  // 刻意写成 Array.from(new Set(...)) 而不是 userService 替身那种 [...new Set(...)]：
  // 两处文本必须不同，否则"仪器变异"的正则会在同一文件里命中 2 处而整体作废
  // （mut.js 要求命中恰好 1 处；文本撞车会让两个替身中只有一个被测到，另一个静默退化）。
  const pickByCast = (map, ids) =>
    Array.from(new Set((ids || []).map((id) => String(id).toLowerCase())))
      .map((id) => map[id])
      .filter(Boolean);

  return {
    findRoleForUpdate: jest.fn(async (id) => {
      const doc = mockStore.roles[String(id).toLowerCase()];
      return doc ? { ...doc } : null;
    }),
    findPermissionsByIds: jest.fn(async (ids) => pickByCast(mockStore.permDocs, ids)),
    getOperatorPermissions: jest.fn(async () => mockStore.perms[mockIds.operator] || []),
    // `role.permissions = uniquePermIds` 之后 save(role)：把控制器交下来的那一份原样存住。
    // #39 断言的就是它——"校验看 A、写入看 B"这种半修复只有在这里才现形。
    saveRole: jest.fn(async (role) => {
      mockStore.savedRole = { _id: role._id, permissions: role.permissions };
      return mockStore.savedRole;
    }),
    listUsersWithRole: jest.fn(async () => []),
    findPopulatedRole: jest.fn(async (id) => ({ _id: id })),
  };
});

const userController = require('../../controllers/userController');
const rolePermissionController = require('../../controllers/rolePermissionController');
const userService = require('../../services/userService');
const { invalidateUserCache } = require('../../middleware/auth');
const { uniqueIdStrings } = require('../../utils/helpers');
const { normalizeInspectionRefLists } = require('../../controllers/inspectionGuards');

const mockServiceNames = [
  'findUserForUpdate',
  'findRolesByIds',
  'findRolePermissionDocs',
  'findActiveRolePermissionDocs',
  'getPermissions',
  'updateRoles',
  'createUser',
  'getCreatedUser',
  'getUpdatedUser',
  'findDuplicateUsername',
  'findOneUser',
  'findBatchUsers',
  'deleteMany',
];

/** 响应替身：ApiResponse 只用到 res.status(...).json(...) */
const mockRes = () => {
  const res = {
    statusCode: null,
    body: null,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
  };
  return res;
};

const mockReq = (over = {}) => ({
  params: {},
  body: {},
  user: { userId: mockIds.operator, username: 'ops_admin', roleCodes: ['OPS_ADMIN'] },
  ip: '127.0.0.1',
  get: () => undefined,
  ...over,
});

const errorCodeOf = (res) => (res.body && res.body.errors && res.body.errors.errorCode) || null;

/** asyncHandler 出错时把原因交给 next：next 被调用即本闸的响铃，不能吞掉 */
const mockCall = async (handler, req) => {
  const res = mockRes();
  const next = jest.fn();
  await handler(req, res, next);
  expect(next.mock.calls.length).toBe(0);
  return res;
};

const assign = (roles, targetId = mockIds.target) =>
  mockCall(userController.assignRoles, mockReq({ params: { id: targetId }, body: { roles } }));

const create = (roles) =>
  mockCall(
    userController.createUser,
    mockReq({
      body: {
        username: 'c2_new_user',
        email: 'c2_new_user@example.com',
        password: 'Aa1!StrongPass',
        roles,
      },
    })
  );

const batch = (ids, operatorId = mockIds.operator) =>
  mockCall(
    userController.batchDeleteUsers,
    mockReq({
      body: { ids },
      user: { userId: operatorId, username: 'ops_admin', roleCodes: ['OPS_ADMIN'] },
    })
  );

/** 控制器交给写路径的那一份角色列表；没调用即 null */
const writtenRoles = () => {
  const calls = userService.updateRoles.mock.calls;
  return calls.length === 0 ? null : calls[calls.length - 1][1];
};

/**
 * 第 7 组用的调用形状：`app.get('wsService')` 返回 undefined ⇒ emitWebSocketEvent 早退，
 * 不把 socket 服务拖进本闸。targetUserId 不传 ⇒ 走"全局改写 role.permissions"那一支。
 */
const assignPerms = (permissions) =>
  mockCall(
    rolePermissionController.assignPermissions,
    mockReq({
      params: { id: mockIds.rolePermTarget },
      body: { permissions },
      app: { get: () => undefined },
    })
  );

/** saveRole 收到的那一份 permissions；没写即 null */
const savedPermissions = () => (mockStore.savedRole && mockStore.savedRole.permissions) || null;

const createdPayload = () => {
  const calls = userService.createUser.mock.calls;
  return calls.length === 0 ? null : calls[calls.length - 1][0];
};

const deletedIn = () => {
  const calls = userService.deleteMany.mock.calls;
  return calls.length === 0 ? null : calls[calls.length - 1][0]._id.$in;
};

beforeEach(() => {
  mockSeed();
  mockServiceNames.forEach((name) => userService[name].mockClear());
  invalidateUserCache.mockClear();
});

describe('第 0 组 · 替身自身的 $in 语义（本闸不空转的前提）', () => {
  test('findRolesByIds 对重复 id 只回一份文档（与 Role.find({_id:{$in}}) 同口径）', async () => {
    const docs = await userService.findRolesByIds([mockIds.roleGuest, mockIds.roleGuest]);
    expect(docs.length).toBe(1);
  });

  test('deleteMany 的 deletedCount 是「存在的去重文档数」，重复 id 不重复计数', async () => {
    const result = await userService.deleteMany({
      _id: { $in: [mockIds.peerA, mockIds.peerA, mockIds.peerB, mockIds.missing] },
    });
    expect(result.deletedCount).toBe(2);
  });

  test('缺陷前提成立：按原始列表比长度必然误判重复提交', async () => {
    // 替身去掉重 ⇒ 这条立刻红 ⇒ 说明上面的行为腿在空转（仪器自检，不是被测码）。
    const raw = [mockIds.roleGuest, mockIds.roleGuest];
    const docs = await userService.findRolesByIds(raw);
    expect(docs.length).not.toBe(raw.length);
    expect(uniqueIdStrings(raw).length).toBe(docs.length);
  });
});

describe('第 1 组 · uniqueIdStrings 的语义', () => {
  test('去重且保序', () => {
    expect(uniqueIdStrings(['b', 'a', 'b', 'c', 'a'])).toEqual(['b', 'a', 'c']);
  });

  test('逐项转字符串：ObjectId 实例与其 hex 串视为同一个 id', () => {
    const asObject = new mongoose.Types.ObjectId(mockIds.roleGuest);
    const out = uniqueIdStrings([asObject, mockIds.roleGuest, asObject]);
    expect(out).toEqual([mockIds.roleGuest]);
    expect(typeof out[0]).toBe('string');
  });

  test('非数组一律归一为空数组（不得抛、不得原样返回）', () => {
    [undefined, null, 'x', 1, {}, () => 1].forEach((input) => {
      expect(uniqueIdStrings(input)).toEqual([]);
    });
  });

  test('不改写入参（归一是派生值，不是原地操作）', () => {
    // 一腿一判据：这里只钉"不原地改"。第一版还顺手断言了 `toEqual(['a','b'])`，
    // 于是 dedup-helper-no-dedupe（不去重）也会把这条染红——颜色集里混进别人的判据，
    // 日后色差就很难读（实测：该变异的红腿集合多出一条 #7，与本腿真正要防的退化无关）。
    const input = ['a', 'a', 'b'];
    const out = uniqueIdStrings(input);
    expect(out).not.toBe(input);
    expect(input).toEqual(['a', 'a', 'b']);
  });
});

describe('第 2 组 · PUT /api/users/:id/roles 的重复角色', () => {
  test('重复提交同一合法角色必须放行，而不是 ROLE_ID_INVALID', async () => {
    const res = await assign([mockIds.roleGuest, mockIds.roleGuest]);
    expect(res.body && res.body.success).toBe(true);
    expect(errorCodeOf(res)).toBeNull();
  });

  test('写进 user.roles 的必须是去重后的那一份', async () => {
    await assign([mockIds.roleGuest, mockIds.roleGuest]);
    expect(writtenRoles()).toEqual([mockIds.roleGuest]);
    expect(mockStore.users[mockIds.target].roles.map(String)).toEqual([mockIds.roleGuest]);
  });

  test('混合 ObjectId 实例与字符串的同一角色：放行且只写一份', async () => {
    const res = await assign([
      new mongoose.Types.ObjectId(mockIds.roleGuest),
      mockIds.roleGuest,
      mockIds.roleOps,
    ]);
    expect(res.body && res.body.success).toBe(true);
    expect(writtenRoles()).toEqual([mockIds.roleGuest, mockIds.roleOps]);
  });

  test('去重不得吞掉真实缺失：重复 + 不存在仍然 ROLE_ID_INVALID', async () => {
    const res = await assign([mockIds.roleGuest, mockIds.roleGuest, mockIds.missing]);
    expect(errorCodeOf(res)).toBe('ROLE_ID_INVALID');
    expect(writtenRoles()).toBeNull();
  });

  test('去重不得削弱层级闸：重复提交高于自身的角色仍然拒绝', async () => {
    const res = await assign([mockIds.roleRich, mockIds.roleRich]);
    expect(errorCodeOf(res)).toBe('ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN');
    expect(writtenRoles()).toBeNull();
  });

  test('去重不得削弱同级归属闸（B-2）：未持有的同级角色重复提交照样拒绝', async () => {
    const res = await assign([mockIds.roleForeign, mockIds.roleForeign]);
    expect(errorCodeOf(res)).toBe('ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN');
    expect(writtenRoles()).toBeNull();
  });

  test('形状闸仍在归一之前：空数组与非数组都回 ROLE_LIST_INVALID 且不写库', async () => {
    expect(errorCodeOf(await assign([]))).toBe('ROLE_LIST_INVALID');
    expect(errorCodeOf(await assign('not-an-array'))).toBe('ROLE_LIST_INVALID');
    expect(userService.updateRoles.mock.calls.length).toBe(0);
  });
});

describe('第 3 组 · POST /api/users 的重复角色', () => {
  test('重复角色建号放行，且交给创建的是去重后的 roles', async () => {
    const res = await create([mockIds.roleGuest, mockIds.roleGuest]);
    expect(res.body && res.body.success).toBe(true);
    expect(res.statusCode).toBe(201);
    expect(createdPayload().roles).toEqual([mockIds.roleGuest]);
  });

  test('重复 + 不存在仍然 ROLE_NOT_FOUND_IN_LIST（存在性判据没被削弱）', async () => {
    const res = await create([mockIds.roleGuest, mockIds.roleGuest, mockIds.missing]);
    expect(errorCodeOf(res)).toBe('ROLE_NOT_FOUND_IN_LIST');
    expect(createdPayload()).toBeNull();
  });

  test('空角色数组走早退路径，归一不参与', async () => {
    const res = await create([]);
    expect(res.statusCode).toBe(201);
    expect(createdPayload().roles).toEqual([]);
  });
});

describe('第 4 组 · DELETE /api/users/batch 的重复 id', () => {
  test('重复 id 必须放行，而不是整批 USER_ID_NOT_FOUND_IN_LIST', async () => {
    const res = await batch([mockIds.peerA, mockIds.peerA, mockIds.peerB]);
    expect(res.body && res.body.success).toBe(true);
    expect(res.body.data.deleted).toBe(2);
  });

  test('传给 deleteMany 的 $in 是去重后的列表', async () => {
    await batch([mockIds.peerA, mockIds.peerB, mockIds.peerA]);
    expect(deletedIn()).toEqual([mockIds.peerA, mockIds.peerB]);
  });

  test('重复 + 不存在仍然整批拒绝', async () => {
    const res = await batch([mockIds.peerA, mockIds.peerA, mockIds.missing]);
    expect(errorCodeOf(res)).toBe('USER_ID_NOT_FOUND_IN_LIST');
    expect(deletedIn()).toBeNull();
  });

  test('归一发生在「不得删自己」之前：重复提交自己的 id 仍回 CANNOT_DELETE_SELF', async () => {
    const res = await batch([mockIds.operator, mockIds.operator]);
    expect(errorCodeOf(res)).toBe('CANNOT_DELETE_SELF');
    expect(deletedIn()).toBeNull();
  });

  test('缓存失效按去重后的 id 逐个执行（不随重复项放大）', async () => {
    await batch([mockIds.peerA, mockIds.peerA, mockIds.peerB]);
    expect(invalidateUserCache.mock.calls.map(([id]) => String(id))).toEqual([
      mockIds.peerA,
      mockIds.peerB,
    ]);
  });

  test('格式非法仍在归一之前拦住：非法片段不会因为去重被静默丢掉', async () => {
    const res = await batch([mockIds.peerA, 'not-hex', mockIds.peerA]);
    expect(errorCodeOf(res)).toBe('USER_ID_FORMAT_INVALID_IN_LIST');
    expect(userService.findBatchUsers.mock.calls.length).toBe(0);
  });
});

/**
 * 第 5 组 · 大小写这一维（同一缺陷的第二种触发方式，不是新增口味）
 *
 * 实测前提（不是推断）：
 *  - 路由格式闸放得过大写：validator 的 isMongoId 委托 isHexadecimal，
 *    其正则 /^(0x|0h)?[0-9A-F]+$/i 带 i 旗 ⇒ isMongoId('67EDBE599C964148975E43D5') === true。
 *  - 读回来恒为小写：bson 的 toHexString 用 byteToHex 查表（表项 n.toString(16).padStart(2,'0')），
 *    没有大写分支 ⇒ 任何 String(doc._id) 都比不上请求里大写的那一份。
 *  - $in 里两者却是同一个文档（cast 成 12 字节，大小写无关）。
 * 后果两条：`["67ED…","67ed…"]` 被算成"有一个 id 不存在"（合法写操作回 400），
 * 而"不许删自己"的 `requestedIds.includes(String(req.user.userId))` 被换个字母大小写绕过。
 *
 * 台账预测（先写后测，实测颜色记在文末）：
 *   #24 替身大小写不敏感 ⇒ 仪器前提，由本条守；case-stub-case-sensitive 让它红（#41 也红，见文末）
 *       #27 不吃这条仪器变异：控制器已归一，交给替身的列表里没有大写项 ⇒ 替身退化只能被前提腿看见
 *   #25 helper 合一 ⇒ case-helper-no-lowercase 应让它红
 *   #26 非 24 位十六进制原样 ⇒ case-helper-lowercase-all 应让它红（它是"别把归一做成通吃"的对照）
 *   #27 大写+重复放行且落库小写 ⇒ 无 lower 归一应让它红
 *   #28 大写自己的 id 仍 CANNOT_DELETE_SELF ⇒ 无 lower 归一应让它红
 */
describe('第 5 组 · 同一 id 的大小写两种写法', () => {
  test('替身按 ObjectId 解析大小写：大写与小写命中同一份文档（本组行为腿的前提）', async () => {
    const upper = mockIds.roleGuest.toUpperCase();
    // 只查大写的那一份也必须查到——这一句才是前提所在：
    // 替身若退回"按字符串相等查表"，它会**静默丢掉**大写项而不是报错，于是
    // "两个写法只回一份文档"这条断言照样成立（台账实测过：整条变异全绿存活）。
    const only = await userService.findRolesByIds([upper]);
    expect(only.length).toBe(1);
    expect(only[0].code).toBe('GUEST');
    const both = await userService.findRolesByIds([upper, mockIds.roleGuest]);
    expect(both.length).toBe(1);
    expect(both[0]._id).toBe(mockIds.roleGuest);
  });

  test('uniqueIdStrings 把 24 位十六进制转小写：两种写法归一成一个 id', () => {
    expect(uniqueIdStrings([mockIds.roleGuest.toUpperCase(), mockIds.roleGuest])).toEqual([
      mockIds.roleGuest,
    ]);
  });

  test('归一不越界：非 24 位十六进制的串保持原样（大小写不是这个入口该管的）', () => {
    expect(uniqueIdStrings(['USER:READ', 'user:read'])).toEqual(['USER:READ', 'user:read']);
    expect(uniqueIdStrings(['GGGGGGGGGGGGGGGGGGGGGGGG'])).toEqual(['GGGGGGGGGGGGGGGGGGGGGGGG']);
  });

  test('大写与重复同时提交合法角色：放行，且落库的是小写那一份', async () => {
    const upper = mockIds.roleGuest.toUpperCase();
    const res = await assign([upper, mockIds.roleGuest, upper]);
    expect(errorCodeOf(res)).toBeNull();
    expect(writtenRoles()).toEqual([mockIds.roleGuest]);
  });

  test('把自己的 id 写成大写也必须被「不得删自己」拦住（安全闸不吃大小写）', async () => {
    const res = await batch([mockIds.operator.toUpperCase(), mockIds.peerA]);
    expect(errorCodeOf(res)).toBe('CANNOT_DELETE_SELF');
    expect(deletedIn()).toBeNull();
  });
});

/**
 * 第 6 组 · 巡检写入侧：守卫校验的那份必须就是落库的那份
 *
 * 缺陷形状与前五组同族，但落点不同——巡检的两条范围闸**内部**已经 uniqueIdStrings 后比长度，
 * 控制器却把 `allowedFields` / `req.body` 原样交给服务层，而 `Inspection.create({...fields})`
 * 与 `$set` 都不去重（models/Inspection.js 的 assignedTo/devices 是裸 [ObjectId]，无 set 去重）。
 * 已核实的下游后果：reportStatsService.js:119-120 的 byAssignee 是
 * `$unwind: '$assignedTo'` + `$group count` ⇒ 同一人在一份计划里被计两次，还能把真人挤出 top10。
 *
 * 台账预测（先写后测；模式名与 tools/mut.js 一一对应；颜色为 42 腿基线的实测值）：
 *   insp-norm-dropped            两处归一都删掉        → 实测 红:#29,#33,#34,#35,#37
 *   insp-norm-force-assignedto   assignedTo 不看 isArray → 实测 红:#30,#31,#35
 *   insp-norm-force-devices      devices 同上           → 实测 红:#30,#31,#34
 *   insp-norm-findings-too       把 findings 也去重     → 实测 红:#32
 *   insp-norm-uncalled-create    控制器不调它（POST 臂） → 实测 红:#33,#37
 *   insp-norm-uncalled-update    控制器不调它（PUT 臂）  → 实测 红:#34,#35
 *   insp-put-inplace             PUT 退回原地改 req.body → 实测 红:#34,#35（取证保真：只追加链）
 *   insp-assignee-check-before-norm 可用性校验挪到归一前 → 实测 红:#33,#37
 * #33/#34/#35 是接线腿：#29 只证明"函数会归一"，证明不了"控制器调了它"，而 POST/PUT 是两条
 * 独立的调用点——只删一处时另一处必须仍然绿，否则两条腿其实共用一个判据。
 * 两条 force-* 的预测**不同**（#34 只看见 devices 侧、#35 只看见 assignedTo 侧）是刻意的：
 * 若两侧退化报同一组颜色，说明接线层只钉了一半的臂。
 * #37 与 #33 同色不是判据重叠：两条腿分别钉"先后顺序"与"有没有调用"，而 POST 那条腿提交的
 * 列表里恰好也带大写写法 ⇒ 任何一个让大写漏到可用性校验之前的退化都会同时现形于两处。
 *
 * 【实测记下的两条教训（先于颜色）】
 * ① "入参本来有几项"必须在**调用之后**读：第一版在调用前取快照，等于断言一个常量，恒绿、
 *    看不见任何退化。PUT 从"原地改 req.body"改成"归一一份副本"之后，这两条腿的调用后断言
 *    才第一次有了能红的东西（insp-put-inplace 让它红）——判据从"归一有没有发生"换成了
 *    "归一发生在哪一份上"。
 * ② 基线红的时候，四条变异的"实测红腿"会集体带上那条恒红的 #34，看起来像命中预测——
 *    先验基线，再看色差，顺序不能反。
 */
describe('第 6 组 · 巡检引用列表落库前归一', () => {
  test('assignedTo/devices 就地归一：重复与大写两种写法各合成一份小写', () => {
    const fields = {
      assignedTo: [mockIds.peerA.toUpperCase(), mockIds.peerA, mockIds.peerB],
      devices: [mockIds.missing.toUpperCase(), mockIds.missing],
    };
    normalizeInspectionRefLists(fields);
    expect(fields.assignedTo).toEqual([mockIds.peerA, mockIds.peerB]);
    expect(fields.devices).toEqual([mockIds.missing]);
  });

  test('没提交的列不凭空出现（PUT 是部分更新，归一成空数组等于替调用方清空指派）', () => {
    const fields = { title: '月度巡检' };
    normalizeInspectionRefLists(fields);
    expect(Object.prototype.hasOwnProperty.call(fields, 'assignedTo')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(fields, 'devices')).toBe(false);
  });

  test('非数组原样保留：这个入口不改变路由之外的既有行为', () => {
    const fields = { assignedTo: 'not-an-array', devices: null };
    normalizeInspectionRefLists(fields);
    expect(fields.assignedTo).toBe('not-an-array');
    expect(fields.devices).toBe(null);
  });

  test('findings 不动：它是记录列表不是集合，同一设备两条发现是合法数据', () => {
    const findings = [
      { deviceId: mockIds.missing, note: '灭火器压力不足' },
      { deviceId: mockIds.missing, note: '安全出口被占用' },
    ];
    const fields = { findings };
    normalizeInspectionRefLists(fields);
    expect(fields.findings).toBe(findings);
    expect(fields.findings.length).toBe(2);
  });

  test('接线：createInspection 交给服务层的就是归一后的那份', async () => {
    const inspectionService = require('../../services/InspectionService');
    const { createInspection } = require('../../controllers/inspectionController');
    inspectionService.createInspection.mockClear();
    const body = {
      title: '月度巡检',
      assignedTo: [mockIds.peerA.toUpperCase(), mockIds.peerA, mockIds.peerB],
      devices: [mockIds.missing.toUpperCase(), mockIds.missing],
    };
    const res = await mockCall(createInspection, mockReq({ body }));
    expect(errorCodeOf(res)).toBeNull();
    const sent = inspectionService.createInspection.mock.calls[0][0];
    expect(sent.assignedTo).toEqual([mockIds.peerA, mockIds.peerB]);
    expect(sent.devices).toEqual([mockIds.missing]);
    // 前提自证：入参本身仍是三项——若控制器根本没接线，上面拿到的是原样列表，必红。
    expect(body.assignedTo.length).toBe(3);
  });

  test('接线：updateInspection 交给服务层的 updates 也是归一后的那份（PUT 两条臂各钉一次）', async () => {
    const inspectionService = require('../../services/InspectionService');
    const { updateInspection } = require('../../controllers/inspectionController');
    inspectionService.updateInspection.mockClear();
    // 只提交 assignedTo：devices 这一列没提交，归一不许把它凭空造出来
    // （服务层按 `updates[field] !== undefined` 决定要不要 $set，多一列就是清空既有设备表）
    const body = { assignedTo: [mockIds.peerA.toUpperCase(), mockIds.peerA, mockIds.peerB] };
    const res = await mockCall(updateInspection, mockReq({ params: { id: 'insp1' }, body }));
    expect(errorCodeOf(res)).toBeNull();
    expect(inspectionService.updateInspection.mock.calls.length).toBe(1);
    const updates = inspectionService.updateInspection.mock.calls[0][1];
    expect(updates.assignedTo).toEqual([mockIds.peerA, mockIds.peerB]);
    expect(Object.prototype.hasOwnProperty.call(updates, 'devices')).toBe(false);
    // 归一的必须是**副本**：审计中间件在 setImmediate 回调时刻读 req.body 并把它哈希进
    // 只追加的审计链（middleware/security.js 的 persistAuditRecord，文档明确"勿提前快照"）。
    // 原地改写会把"客户端提交了三个指派"记成"一个"——取证记录与被审计的行为不再是同一件事。
    // 这一条必须在调用之后读 req.body：调用前取快照等于断言一个常量，恒绿、看不见退化
    // （第一版就是这么写的，实测踩过）。
    expect(updates).not.toBe(body);
    expect(body.assignedTo.length).toBe(3);
    expect(body.assignedTo[0]).toBe(mockIds.peerA.toUpperCase());
  });

  test('接线：PUT 只提交 devices 时不得凭空造出 assignedTo 列（与上一条对称补臂）', async () => {
    // 上一条提交的是 assignedTo，它只能看见 devices 那一侧的"无守卫归一"；
    // 这一条反过来只提交 devices，assignedTo 侧的退化才在**接线**层面有腿可红。
    // 缺了这条，"控制器有没有调它"这一层就只钉住一半的臂（实测色差见文末台账）。
    const inspectionService = require('../../services/InspectionService');
    const { updateInspection } = require('../../controllers/inspectionController');
    inspectionService.updateInspection.mockClear();
    const body = { devices: [mockIds.missing.toUpperCase(), mockIds.missing] };
    const res = await mockCall(updateInspection, mockReq({ params: { id: 'insp1' }, body }));
    expect(errorCodeOf(res)).toBeNull();
    const updates = inspectionService.updateInspection.mock.calls[0][1];
    expect(updates.devices).toEqual([mockIds.missing]);
    expect(Object.prototype.hasOwnProperty.call(updates, 'assignedTo')).toBe(false);
    // 与上一条同一判据的另一侧：devices 臂同样不许原地改 req.body（取证保真）
    expect(updates).not.toBe(body);
    expect(body.devices.length).toBe(2);
  });

  test('执行人存在性这一臂是活的：assignedTo 含库里没有的 id ⇒ VALIDATION_FAILED 且不落库', async () => {
    // 这条腿同时是 findActiveUserIds 替身的前提：桩一旦退回"把入参原样回显"（第 3 族，
    // 第一版本文件就是这么写的），本闸就只剩"接线对不对"而看不见整条写路径的可用性判定，
    // 而"接线绿 + 判定臂死"正是把一次局部修复合成一次安全结论的那种假绿。
    const inspectionService = require('../../services/InspectionService');
    const { createInspection } = require('../../controllers/inspectionController');
    inspectionService.createInspection.mockClear();
    const res = await mockCall(
      createInspection,
      mockReq({ body: { title: '月度巡检', assignedTo: [mockIds.peerA, mockIds.missing] } })
    );
    expect(errorCodeOf(res)).toBe('VALIDATION_FAILED');
    expect(inspectionService.createInspection.mock.calls.length).toBe(0);
  });

  test('大写写法的既有执行人不得被判成"不存在"：归一必须在可用性校验之前', async () => {
    // 驱动 findActiveUserIds 返回的是**库里**的小写 hex，而 findUnusableAssignees 拿裸值
    // `usable.has(String(id))` 比 ⇒ 接线顺序一退（先判可用性、后归一），一次合法的
    // `assignedTo:["67ED…"]` 就变成 400「指定的执行人不存在或已被停用」。
    // 这条腿钉的是两个调用点之间的**先后**，第 6 组其它腿只看得到"归一有没有发生"。
    const inspectionService = require('../../services/InspectionService');
    const { createInspection } = require('../../controllers/inspectionController');
    inspectionService.createInspection.mockClear();
    const res = await mockCall(
      createInspection,
      mockReq({ body: { title: '月度巡检', assignedTo: [mockIds.peerA.toUpperCase()] } })
    );
    expect(errorCodeOf(res)).toBeNull();
    expect(inspectionService.createInspection.mock.calls[0][0].assignedTo).toEqual([mockIds.peerA]);
  });
});

/* ============================== 第 7 组 ==============================
 * 六个 uniqueIdStrings 调用点里的最后一个：PUT /api/roles/:id/permissions
 * （rolePermissionController.validatePermissionTargets → `role.permissions = uniquePermIds`）
 *
 * 为什么单独补这一组：这一处**本来就**有去重（`[...new Set(map(String))]`），本轮只是把
 * 大小写规范化并进了同一个入口——"已经去重过"最容易让人以为无需再钉，而那两处权限 id
 * 站点（roleController.createRole / 本处）在新旧两种写法下颜色不变：把 uniqueIdStrings
 * 换回手写的 `new Set(map(String))`，全套旧腿照样绿。没有腿的修复等于没有修复。
 *
 * 台账预测（腿号按声明顺序；第 6 组补了 #36/#37 两条腿之后本组整体后移到 #38-#40）：
 *   #38 替身前提（roleService 侧的大小写查表，与 #24 分处两个替身，各钉各的）
 *   #39 放行 + 落库那份｜#40 真实缺失仍然拒
 *   perm-norm-dropped    归一退回"只过滤格式不去重不转小写" → 实测 红:#39
 *   perm-write-raw       比对用归一值、写入仍用裸值        → 实测 红:#39
 *   case-stub-perms-case-sensitive（仪器变异）              → 实测 红:#38
 * #39 之外都不该红是刻意的：#40 钉的是"归一不许吞掉真实缺失"，退化只会让判据更严不会更松，
 * 它跟着红就说明两条腿测的其实是同一件事；#38 不跟着红则说明行为腿没在替身退化时冒充前提。
 */
describe('第 7 组 · 角色权限改写路径的 id 列表', () => {
  test('替身按 ObjectId 解析权限 id：只查大写项也要命中，两种写法只回一份文档', async () => {
    const roleService = require('../../services/roleService');
    const upper = mockIds.permRead.toUpperCase();
    // 单独查大写项：丢弃型替身（按字符串相等查表 + filter(Boolean)）在这里必回 0 份，
    // 与 #24 同一写法——只断"数量"会让退化以另一种形状蒙混过关（本闸的偏差三教训）。
    const only = await roleService.findPermissionsByIds([upper], 'code');
    expect(only.length).toBe(1);
    expect(only[0].code).toBe('user:read');
    const both = await roleService.findPermissionsByIds([upper, mockIds.permRead], 'code');
    expect(both.length).toBe(1);
  });

  test('重复 + 大写两种权限 id：放行，且写进 role.permissions 的是归一后的小写去重列表', async () => {
    const res = await assignPerms([
      mockIds.permRead,
      mockIds.permRead.toUpperCase(),
      mockIds.permAssign,
    ]);
    expect(errorCodeOf(res)).toBeNull();
    expect(savedPermissions()).toEqual([mockIds.permRead, mockIds.permAssign]);
  });

  test('归一不得吞掉真实缺失：重复 + 不存在的权限 id 仍 PERMISSION_ID_INVALID 且不写库', async () => {
    const res = await assignPerms([mockIds.permRead, mockIds.permRead, '0000000000000000000000fe']);
    expect(errorCodeOf(res)).toBe('PERMISSION_ID_INVALID');
    expect(savedPermissions()).toBeNull();
  });
});

/* ============================== 第 8 组 ==============================
 * 单个 `:id` 入口的 cast 口径（第 28 轮补；假绿审计指出的仪器盲区）
 *
 * 前 7 组的大小写腿全部走**数组**入口（roles/ids/permissions），而替身只给列表查表补了
 * 小写归一，`findUserForUpdate`/`updateRoles`/`getUpdatedUser` 这些单个 `:id` 入口仍按
 * `String(id)` 取表——那是把本闸要杀的那类缺陷（"比较口径与驱动口径不一致"）复制进了仪器：
 * 驱动 `findById('67ED…')` 正常命中，替身却会 404。仪器比驱动**更严**时，退化藏得比更宽松
 * 更深：没有任何一条腿会因为"多拒了一个合法请求"而红，除非有人专门提交一次大写 :id。
 * 生产侧口径（已核实，读 src/services/userService.js 的 findById/findByIdAndUpdate）：
 * 24 位十六进制的大小写两种写法都是同一个文档，所以这两条腿断的是**应有的**行为。
 *
 * 台账（实测）：case-stub-case-sensitive（替身单值 castId 不再转小写）→ 红:#24,#41。
 * #42 在该变异下仍绿是刻意的：它断的是"大写且不存在的 id 仍然拒"，而"更严的替身"照样拒
 * ⇒ 这一条是**对照腿**（钉"单值查表不是通配"），不承担看见退化的职责。
 */
describe('第 8 组 · 大写 :id 走单个入口', () => {
  test('PUT /api/users/<大写 id>/roles 改的是同一个人：驱动 cast，替身也必须 cast', async () => {
    const res = await assign([mockIds.roleGuest], mockIds.target.toUpperCase());
    expect(errorCodeOf(res)).toBeNull();
    // 写下去的那一份仍是归一后的列表（大小写 :id 与重复项是两个维度，这里两个都要成立）
    expect(writtenRoles()).toEqual([mockIds.roleGuest]);
    // 落点必须是同一个用户：替身按 cast 后的 12 字节取表，大写 :id 命中的就是这份文档
    expect(mockStore.users[mockIds.target].roles).toEqual([mockIds.roleGuest]);
  });

  test('大写 :id 指向不存在的用户仍是 USER_NOT_FOUND（单值查表不是通配）', async () => {
    const res = await assign([mockIds.roleGuest], mockIds.missing.toUpperCase());
    expect(errorCodeOf(res)).toBe('USER_NOT_FOUND');
    expect(writtenRoles()).toBeNull();
  });
});
/* ============================== 变异台账（2026-10-04 第 28 轮全量重测）==============================
 * 施加方式：node tools/ledger.js <被测文件> 本门禁文件 <模式名>=<预测> …
 * 腿编号按文件里的声明顺序（42 腿）：
 *   #1-#3 第 0 组（替身自检）｜#4-#7 第 1 组（helper 语义）｜#8-#14 第 2 组（assignRoles）
 *   #15-#17 第 3 组（createUser）｜#18-#23 第 4 组（batchDeleteUsers）
 *   #24-#28 第 5 组（大小写这一维）｜#29-#32 第 6 组（归一函数本体四臂）
 *   #33-#35 第 6 组（控制器接线：POST 一处 + PUT 两臂）｜#36-#37 第 6 组（执行人可用性臂）
 *   #38-#40 第 7 组（角色权限改写）｜#41-#42 第 8 组（单个 :id 的 cast 口径）
 * 基线：42 采集 / 42 绿 / 0 红（六次开跑各带一次基线，六次同值）；六个被测文件
 * （userController / helpers / inspectionGuards / inspectionController / rolePermissionController /
 * 本门禁自己）22 条模式跑完，每条各自的恢复校验：逐字节相同 ✓
 *
 * 【为什么整套重测而不是只测新腿】仪器在本文件里改动过四次（替身查表方式、第 6 组接线腿与 #7
 * 判据收窄、第 7 组与 roleService 替身、本轮的第 6 组可用性两腿 + 第 8 组 + PUT 副本化）。
 * 改动仪器会让**所有**已发表的颜色失效：同一条变异的红腿集合会随仪器长大而变（见偏差八）。
 * 半套台账等于没有台账。本轮 22/22 与预测同色——但那份"准"是把前几轮的色差吸收进预测之后
 * 得到的，历史色差没有消失，全部留在下面的偏差条目里，一条都没删。
 *
 *   ── 被测 src/controllers/userController.js ──
 *   dedup-assign-compare-raw    预测 红:#8,#9,#10,#12,#13,#27   实测 同 ✓
 *   dedup-assign-write-raw      预测 红:#9,#10,#27              实测 同 ✓
 *   dedup-create-compare-raw    预测 红:#15                     实测 同 ✓
 *   dedup-batch-ids-raw         预测 红:#18,#19,#22,#28          实测 同 ✓
 *   ── 被测 src/utils/helpers.js ──
 *   dedup-helper-no-dedupe      预测 红:#3,#4,#5,#8,#9,#10,#12,#13,#15,#18,#19,#22,#25,#27,#29,
 *                                     #33,#34,#35,#39           实测 同（19 红）✓
 *   dedup-helper-nonarray-passthrough 预测 红:#6                实测 同 ✓
 *   case-helper-no-lowercase    预测 红:#25,#27,#28,#29,#33,#34,#35,#37,#39  实测 同 ✓
 *   case-helper-lowercase-everything 预测 红:#26                实测 同 ✓（"归一不许通吃"的对照）
 *   ── 被测 src/controllers/inspectionGuards.js（写入侧归一两臂 + 越界对照）──
 *   insp-norm-dropped           预测 红:#29,#33,#34,#35,#37      实测 同 ✓
 *   insp-norm-force-assignedto  预测 红:#30,#31,#35              实测 同 ✓
 *   insp-norm-force-devices     预测 红:#30,#31,#34              实测 同 ✓
 *   insp-norm-findings-too      预测 红:#32                      实测 同 ✓
 *   ── 被测 src/controllers/inspectionController.js（调用点、副本、先后顺序）──
 *   insp-norm-uncalled-create   预测 红:#33,#37                  实测 同 ✓（PUT 两腿不受影响）
 *   insp-norm-uncalled-update   预测 红:#34,#35                  实测 同 ✓（POST 腿不受影响）
 *   insp-put-inplace            预测 红:#34,#35                  实测 同 ✓（取证保真：只追加链）
 *   insp-assignee-check-before-norm 预测 红:#33,#37               实测 同 ✓
 *   ── 被测 src/controllers/rolePermissionController.js ──
 *   perm-norm-dropped           预测 红:#39                      实测 同 ✓（#40 仍然拒=只变严不变松）
 *   perm-write-raw              预测 红:#39                      实测 同 ✓
 *   ── 仪器变异（被测=本门禁文件自己）──
 *   dedup-stub-roles-nodedupe   预测 红:#1,#3,#24                实测 同 ✓
 *   case-stub-case-sensitive    预测 红:#24,#41                  实测 同 ✓（38 腿时实测只有 #24）
 *   assignee-stub-passthrough   预测 红:#36                      实测 同 ✓
 *   case-stub-perms-case-sensitive 预测 红:#38                   实测 同 ✓
 *
 * 【偏差一 · #12/#13 也跟着红，是我把"仍会拒"当成了"仍同码"】
 * 退回裸值后，重复提交的 `[roleRich, roleRich]` / `[roleForeign, roleForeign]` 仍然被拒，
 * 但拒它的是先撞上的存在性闸（ROLE_ID_INVALID），不再是层级闸/同级归属闸。
 * 这两条腿点名 errorCode ⇒ 换了闸门就换色。这正是点名断言要买的东西：
 * 只断 403/拒绝的话，这条"闸门被上层抢跑"的漂移会永久隐身。
 *
 * 【偏差二 · 去掉替身去重后，行为腿居然全绿——这不是漏洞，而是第 0 组存在的理由】
 * 控制器已经归一，`findRolesByIds(去重列表)` 在一个"不去重"的替身上同样一条 id 一个文档
 * ⇒ 比对照样相等 ⇒ 行为腿看不见替身的退化。替身形状的可信度**不是**由它们守的，
 * 而是由 #1/#3 守的（#3 断 `docs.length !== raw.length` 且 `uniqueIdStrings(raw).length ===
 * docs.length`）。教训：行为腿只依赖"裸值 vs 归一值"这一处分歧，替身能力退化要另设前提腿。
 *
 * 【偏差三 · 前提腿断言了"数量"而数量不是判据的来源 ⇒ 整条变异存活】
 * 第一版 #24 只断 `findRolesByIds([大写, 小写]).length === 1`。把替身退回"按字符串相等查表"
 * 之后它照样回 1 份——替身对查不到的 id 是 **filter(Boolean) 静默丢掉**，不是报错：
 * 大写项被丢弃、小写项命中，数量与"命中同一份文档"完全一样 ⇒ 断言成立而判据已经坏掉。
 * 现在 #24/#38 先单独查大写项，丢弃型替身在这里必然回 0 ⇒ 变异被测到。
 * **前提腿要断言"结果来自哪一条判据"，只断"结果的形状"会让退化以另一种形状蒙混过关。**
 *
 * 【偏差四 · #7 里混进了 #4 的判据，一条变异的红腿集合因此读不出来源】
 * dedup-helper-no-dedupe 把"不改写入参"那条也染红了：#7 除了断言入参没被原地改，还顺手
 * 断言 `toEqual(['a','b'])`（=去重结果），而"去重"已由 #4 单独钉。一腿一判据不是审美：
 * 判据重叠会让"哪些腿依赖哪个退化"这个问题没有答案。收窄后 #7 在该变异下转绿。
 *
 * 【偏差五 · 行为腿看不见替身的退化，只有前提腿看得见（发生在我自己的预测里）】
 * 我曾预测 case-stub-case-sensitive 让 #24 与 #27 一起红。当时实测只有 #24 红：控制器已经把
 * 大写转成小写，归一后的列表里根本没有大写项 ⇒ "大小写敏感的替身"与"cast 型替身"在 #27 上
 * 不可分辨。这不是漏测，而是分工——前提由 #24/#38 钉，行为由 #27/#39 钉。
 * 推论：任何"看起来依赖替身能力"的行为腿，都要问一句"退化后它真的会红吗"；答"不会"就得
 * 单独补前提腿（#38 给 roleService、#36 给 findActiveUserIds 都是这么来的）。
 *
 * 【偏差六 · 两个替身文本撞车会让仪器变异静默失效，而不是报错】
 * roleService 替身最初照抄了 userService 的 `[...new Set(...toLowerCase())]` 文本。本文件已有的
 * 仪器变异正则会命中 2 处——mut.js 的"必须恰好 1 处"纪律把它拦成 MUT-ABORT（好的失败方式）。
 * 已把新替身改成 `Array.from(new Set(...))`：两处文本各自可被单独打歪，#38/#24 分别有主。
 * **新增替身时要先看它的形状会不会与既有仪器变异撞车**，撞车的结果不是报错而是"其中一个
 * 退化永远绿"。
 *
 * 【偏差七 · 仪器比驱动更严时，盲区比"更宽松"更深（第 8 组的由来）】
 * 假绿专项指出：前 7 组的大小写腿全走**数组**入口，而替身只给列表查表补了小写归一，
 * `findUserForUpdate`/`updateRoles`/`getUpdatedUser` 这些单个 `:id` 入口仍按 `String(id)` 取表
 * ——那等于把本闸要杀的那类缺陷（"比较口径与驱动口径不一致"）复制进仪器。驱动
 * `findById('67ED…')` 正常命中，替身却 404。后果是**没有任何一条腿会因为"多拒了一个合法
 * 请求"而红**，除非有人专门提交一次大写 :id：仪器更宽松时退化会被放行腿抓到，仪器更严时
 * 只有"合法请求必须成功"的腿抓得到。补 #41/#42 后 case-stub-case-sensitive 才有 #41 可红。
 * 通用结论：**给替身补口径要按"驱动的两个方向"都补，并各留一条腿证明替身没比驱动更严。**
 *
 * 【偏差八 · 同一条变异的红腿集合会随仪器长大而变 ⇒ 旧颜色不可复用】
 * case-stub-case-sensitive：38 腿时实测 红:#24（当时 #41 不存在），42 腿时实测 红:#24,#41；
 * insp-norm-dropped 从 红:#29,#33,#34,#35 变成 +#37；insp-norm-uncalled-create 从 红:#33
 * 变成 红:#33,#37。三处都是"新腿真的吃这条退化"，不是色差。反过来也成立：删腿会让红腿集合
 * 缩小而没人报警。**任何仪器改动（补腿、改判据、改替身）之后，这套台账的全部颜色作废。**
 *
 * 【仍然存在的近似（本轮没闭合的，写清楚别让它隐身）】
 *  1. （本轮闭合）inspectionGuards 内部两条存在性比对 `docs.length !== ids.length`
 *     （rejectOutOfScopeAssignees/Devices 的 :33/:59）此前没有"重复/大小写两种写法仍算同一个"
 *     的腿。现在由 src/tests/controllers/inspectionGuardRefExistence.test.js（11 腿，无 DB）钉，
 *     该闸的被测面是守卫本体，模式为 guard-assignees-nodedupe/nocase、guard-devices-nodedupe/
 *     nocase/nofmtcheck 与仪器变异 guard-stub-case-sensitive。本闸第 6 组只钉"写入侧归一"。
 *  2. roleController.js:115 的权限 id 归一由 src/tests/controllers/
 *     roleCreatePermissionExistence.test.js 钉住"去重"，**没有大小写腿**——把 uniqueIdStrings
 *     换回 `new Set(map(String))` 那一套腿照样绿。该文件是并行 agent 的已提交用例，改动前需协调。
 *  3. 三处 service 侧 `findScopeFieldsByIds`（userService.js:219、DeviceService.js:127、
 *     AlarmService.js:181）的归一没有腿，且在当前接线下**造不出**能红的腿：调用方（守卫）
 *     已经先归一过一次，服务层这一句是幂等冗余 ⇒ 删掉它是等价变异。留着是纵深防御
 *     （新调用方不必重新想一遍口径），但要写清"这里没有腿，别把它当已覆盖"。
 *  4. permissionService.js:134（列表臂）与 permissionService.js:156（单值比对臂）由 src/tests/services/
 *     permissionParentIdCaseAndDedup.test.js（6 腿）钉。该闸台账里 parent-norm-dropped 是
 *     **已声明的等价变异**（本站点没有长度比较 ⇒ 预期存活），真正钉行为的是 parent-compare-raw
 *     （红:#2,#3,#5）。
 *  5. 路由层 isMongoId 放过大写十六进制这件事本身没改（改它会动 12 条路由的入参口径，
 *     且当前所有下游都按"12 字节"解析，不存在第二处判据分歧）；本闸的口径是
 *     "进门后一律按 cast 语义归一"，而不是"在门口拒绝大写"。
 *  6. userController.js 批量删除的 BATCH_DELETE_MAX 仍按**裸值长度**判（同一请求写 101 次
 *     同一个 id 会被判"超出批量上限"，而按归一长度应是 1）。本轮没动：改它会与并行 agent
 *     的用例口径打架，先记录不隐身。
 * ===================================================================== */
