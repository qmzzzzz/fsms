/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（第 28 轮 · 2026-10-04）
 *
 * 被测对象：inspectionGuards 的**两条存在性比较臂**（rejectOutOfScopeAssignees /
 *   rejectOutOfScopeDevices，含 findings 复用 devices 臂的那条）
 * 守护的不变式：C2 缺陷类——「请求侧归一后的清单长度」必须与「驱动 $in 返回的文档数」同口径
 * 可证伪性：文末变异台账
 * 不碰数据库：两个服务各留一个查表入口，$in 的 cast 语义由替身复刻
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 为什么单独一把闸：requestedIdListDeduped.test.js 的第 6 组把
 * `rejectOutOfScopeReferences` 整块桩成了"放行"（它要钉的是控制器有没有调归一入口），
 * 于是守卫**内部**那两处 `docs.length !== ids.length` 在该闸里一次都没执行过。
 * 那处归一（第 27 轮补的）当时是"有修复、无腿"的状态——本闸补的就是这一段。
 *
 * 与 src/tests/inspectionWriteScopeGates.test.js 的分工（那把闸跑真库、走 HTTP）：
 * 它钉"范围外必须拒"，本闸钉"重复/大小写的合法请求必须放行，且归一不许吞掉真缺失"。
 * 两边不重叠，也互不替代：本闸的替身把范围判定交给 `__outOfScope` 标记，
 * 真库那侧才有 populate/department 的完整语义。
 *
 * 缺陷形状（修复前）：`$in` 把每个元素 cast 成 ObjectId（12 字节）后**去重**返回文档，
 * 而请求清单是原样字符串 ⇒ 同一 id 写两遍（或写成两种大小写）时
 * `docs.length(1) !== ids.length(2)` ⇒ 一次合法的创建/更新被判「指定的执行人不存在」/
 * `DEVICE_NOT_FOUND`。大小写这一维由 `isMongoId` 委托十六进制判定放进门来。
 */

const mockIds = {
  operator: '0000000000000000000000a1',
  userIn: '0000000000000000000000b1',
  userMissing: '0000000000000000000000ff',
  deviceIn: '0000000000000000000000c1',
  deviceOut: '0000000000000000000000c2',
  deviceMissing: '0000000000000000000000fe',
};
const deviceIllegal = 'not-a-valid-object-id';

/**
 * 世界状态：用户/设备两张表按 cast 后的 12 字节（等价于小写 hex）建键，与 Mongo 一致。
 * `__outOfScope` 标记供范围臂使用：范围判定不写死常量，否则"归一之后守卫还读不读文档"
 * 这件事就没有腿能看见（第 4 族：一条腿同时断两件事时，两件事都看不见）。
 */
const mockStore = { users: {}, devices: {} };

const castLookup = (ids) => [...new Set((ids || []).map((id) => String(id).toLowerCase()))];

jest.mock('../../services/userService', () => ({
  findScopeFieldsByIds: jest.fn(async (ids) =>
    // 驱动 userService.findScopeFieldsByIds 的形状：uniqueIdStrings 后 $in 查投影字段。
    // 替身按 cast 语义回表——重复项与两种大小写写法只回一份文档。
    castLookup(ids)
      .map((id) => mockStore.users[id])
      .filter(Boolean)
      .map((u) => ({ _id: u._id, createdBy: u.createdBy, department: u.department }))
  ),
}));

jest.mock('../../services/DeviceService', () => ({
  findScopeFieldsByIds: jest.fn(async (ids) =>
    castLookup(ids)
      .map((id) => mockStore.devices[id])
      .filter(Boolean)
      .map((d) => ({
        _id: d._id,
        createdBy: d.createdBy,
        maintenanceRecord: d.maintenanceRecord,
        location: d.location,
        __outOfScope: d.__outOfScope === true,
      }))
  ),
}));

jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(async () => ({ type: 'department', departments: ['D1'] })),
  isRecordInScope: jest.fn((dataScope, doc) => !(doc && doc.__outOfScope)),
  isDepartmentValueAllowed: jest.fn(() => true),
}));

const {
  rejectOutOfScopeReferences,
  rejectOutOfScopeAssignees,
  rejectOutOfScopeDevices,
} = require('../../controllers/inspectionGuards');

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

const errorCodeOf = (res) => (res.body && res.body.errors && res.body.errors.errorCode) || null;
const messageOf = (res) => (res.body && res.body.message) || null;

const seed = () => {
  mockStore.users = {
    [mockIds.userIn]: { _id: mockIds.userIn, createdBy: mockIds.operator, department: 'D1' },
  };
  mockStore.devices = {
    [mockIds.deviceIn]: {
      _id: mockIds.deviceIn,
      createdBy: mockIds.operator,
      maintenanceRecord: { operator: mockIds.operator },
      location: { building: 'D1' },
    },
    [mockIds.deviceOut]: {
      _id: mockIds.deviceOut,
      createdBy: '0000000000000000000000d9',
      maintenanceRecord: { operator: '0000000000000000000000d9' },
      location: { building: 'D9' },
      __outOfScope: true,
    },
  };
};
seed();

const req = { user: { userId: mockIds.operator } };

/** 走控制器实际使用的那个入口 */
const guard = async (fields) => {
  const res = mockRes();
  const rejected = await rejectOutOfScopeReferences(req, res, fields);
  return { rejected, errorCode: errorCodeOf(res), message: messageOf(res) };
};

describe('巡检守卫内部的存在性比较', () => {
  test('替身前提：$in 按 12 字节解析——单独查大写项也要命中，两种写法只回一份文档', async () => {
    const userService = require('../../services/userService');
    const upper = mockIds.userIn.toUpperCase();
    const onlyUpper = await userService.findScopeFieldsByIds([upper]);
    // 数量与内容一起断：只断"数量 1"会放过命中了别的文档、以及丢弃型替身两种退化
    expect(onlyUpper.length).toBe(1);
    expect(String(onlyUpper[0]._id)).toBe(mockIds.userIn);
    const both = await userService.findScopeFieldsByIds([upper, mockIds.userIn]);
    expect(both.length).toBe(1);
  });

  test('assignedTo 同一用户写两遍：放行（存在性比较用的是归一后的清单）', async () => {
    const out = await guard({ assignedTo: [mockIds.userIn, mockIds.userIn] });
    expect(out.rejected).toBe(false);
    expect(out.errorCode).toBeNull();
  });

  test('assignedTo 同一用户的大小写两种写法：放行', async () => {
    const out = await guard({
      assignedTo: [mockIds.userIn.toUpperCase(), mockIds.userIn],
    });
    expect(out.rejected).toBe(false);
    expect(out.errorCode).toBeNull();
  });

  test('assignedTo 含真不存在的用户：仍拒且不进范围循环', async () => {
    // 归一不许把"真缺失"洗成"存在"：这一条与上面两条互为反向对照，
    // 缺了它，把比较改成 `docs.length === 0 ? 拒 : 放行` 一样能全绿。
    const out = await guard({ assignedTo: [mockIds.userIn, mockIds.userMissing] });
    expect(out.rejected).toBe(true);
    expect(out.errorCode).toBe('VALIDATION_FAILED');
    expect(out.message).toContain('执行人不存在');
  });

  test('devices 同一设备写两遍：放行', async () => {
    const out = await guard({ devices: [mockIds.deviceIn, mockIds.deviceIn] });
    expect(out.rejected).toBe(false);
    expect(out.errorCode).toBeNull();
  });

  test('devices 同一设备的大小写两种写法：放行', async () => {
    const out = await guard({
      devices: [mockIds.deviceIn, mockIds.deviceIn.toUpperCase()],
    });
    expect(out.rejected).toBe(false);
    expect(out.errorCode).toBeNull();
  });

  test('devices 含真不存在的设备：DEVICE_NOT_FOUND', async () => {
    const out = await guard({ devices: [mockIds.deviceIn, mockIds.deviceMissing] });
    expect(out.rejected).toBe(true);
    expect(out.errorCode).toBe('DEVICE_NOT_FOUND');
  });

  test('devices 里的范围外设备仍然拒：归一之后守卫确实在逐份文档判范围', async () => {
    const out = await guard({ devices: [mockIds.deviceOut] });
    expect(out.rejected).toBe(true);
    expect(out.errorCode).toBe('DEVICE_VIEW_FORBIDDEN');
  });

  test('findings 两条发现指向同一设备（大小写两种写法）：存在性放行', async () => {
    // findings 是**记录列表**：两条发现指向同一台设备是合法数据，写入侧不归一
    // （由 requestedIdListDeduped 第 6 组钉）；守卫侧比存在性时必须按集合去重，
    // 否则一次正常的结果提交会被判成"设备不存在"。
    const out = await guard({
      findings: [
        { deviceId: mockIds.deviceIn, note: '灭火器压力不足' },
        { deviceId: mockIds.deviceIn.toUpperCase(), note: '安全出口被占用' },
      ],
    });
    expect(out.rejected).toBe(false);
    expect(out.errorCode).toBeNull();
  });

  test('非法格式的设备 id：DEVICE_NOT_FOUND 且不查库（格式臂与归一口径同源）', async () => {
    const deviceService = require('../../services/DeviceService');
    deviceService.findScopeFieldsByIds.mockClear();
    const out = await guard({ devices: [deviceIllegal] });
    expect(out.rejected).toBe(true);
    expect(out.errorCode).toBe('DEVICE_NOT_FOUND');
    // 非法 id 一律不进 $in（否则会抛 CastError 变 500）：这一断言钉的是"先筛后查"的次序
    expect(deviceService.findScopeFieldsByIds.mock.calls.length).toBe(0);
  });

  test('两个臂各自可单独驱动（导出面不是摆设，守卫入口的分工是真的）', async () => {
    const res1 = mockRes();
    const res2 = mockRes();
    expect(await rejectOutOfScopeAssignees(res1, null, mockIds.operator, [])).toBe(false);
    expect(await rejectOutOfScopeDevices(res2, null, mockIds.operator, undefined)).toBe(false);
    expect(res1.body).toBeNull();
    expect(res2.body).toBeNull();
  });
});

/* ============================== 变异台账（先写预测，再实测）==============================
 * 施加方式：node tools/ledger.js src/controllers/inspectionGuards.js \
 *   src/tests/controllers/inspectionGuardRefExistence.test.js <模式>=<预测> …
 * 腿编号按声明顺序：#1 替身前提｜#2 assignedTo 重复｜#3 assignedTo 大小写
 *   #4 assignedTo 真缺失｜#5 devices 重复｜#6 devices 大小写｜#7 devices 真缺失
 *   #8 devices 范围外｜#9 findings 同一设备两种写法｜#10 非法格式｜#11 空数组短路
 *
 * 预测（写于实测之前）：
 *   guard-assignees-nodedupe（assignedTo 臂退回裸 map(String)，不去重不转小写）→ 红:#2,#3
 *   guard-assignees-nocase  （assignedTo 臂去重但不转小写）                    → 红:#3
 *   guard-devices-nodedupe （devices 臂退回裸 map(String)）                    → 红:#5,#6,#9
 *   guard-devices-nocase   （devices 臂去重但不转小写）                        → 红:#6,#9
 *   guard-stub-case-sensitive（仪器变异：替身查表不再转小写）                  → 红:#1
 *
 * 四条产品模式两两成对，是因为这一处修复本身就是"去重 + 大小写规范化"两件事：
 * 只钉其中一件的闸，在另一件退化时是哑的（本仓 C2 台账偏差五的教训）。
 * #4/#7/#8/#10 预测不跟着红也是刻意的：它们钉的是"归一不许削弱拒绝臂"，
 * 归一退化只会让判据更严，这些腿跟着红就说明它们测的是同一件事。
 *
 * 实测（2026-10-04）：见交付台账；与预测不一致的条目原样保留。
 */
