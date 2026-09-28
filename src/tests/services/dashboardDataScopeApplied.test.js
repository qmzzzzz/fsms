/**
 * 仪表盘的三条 $facet 聚合必须真的带上数据范围过滤
 *
 * 为什么单独一条用例守着：`/api/reports/dashboard` 的两条既有用例都看不见这个过滤条件——
 * `dataScope=none` 那条在 `getDashboardData` 里于 filters 算好之后、聚合之前就被
 * EMPTY_DASHBOARD 短路返回；另一条用超管 token，其 scope 过滤器本就是 `{}`。
 * 于是把 `collectDashboardFacets` 里任意一条 `{ $match: filters.x }` 换成 `{ $match: {} }`，
 * 部门主管的仪表盘会开始返回**全公司**的设备/报警/巡检计数，而没有任何用例会红。
 *
 * 判据形态：两个部门各自断言**精确计数**，且三档资源在两部门的数量互不相同——
 * 过滤器一旦被丢掉，两边都会退化成全库同一个数，等式立刻不成立。
 * 数量不能写成"全局计数"，因为内存库在同一个 jest worker 内被多个套件共享；
 * 楼栋名带唯一 stamp，因此"本部门的精确数量"不受同库其它种子的影响。
 * `type:'all'` 那一档只做下界断言，作用是自证种子真的落库且被聚合数到
 * （否则"精确计数为 0"可以来自过滤过度，而不是来自范围正确）。
 */

const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// 楼栋/编码片段：同一 worker 库内不与其它套件的种子相撞
const stamp = `ds${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const BUILDING_A = `BLD${stamp}A`;
const BUILDING_B = `BLD${stamp}B`;

// A 部门：设备 2 / 报警 3 / 巡检 1；B 部门：设备 3 / 报警 1 / 巡检 2
const SEED_COUNTS = {
  [BUILDING_A]: { devices: 2, alarms: 3, inspections: 1 },
  [BUILDING_B]: { devices: 3, alarms: 1, inspections: 2 },
};

// 设备类型在两部门互不重叠：byType 只断"条数等于 total"仍可能放行串部门，
// 再断一次"对面那类的名字根本不出现在我这侧"
const DEVICE_TYPES = {
  [BUILDING_A]: 'hydrant',
  [BUILDING_B]: 'smoke_detector',
};

describe('仪表盘聚合的数据范围过滤（写入口径 = 可见口径）', () => {
  let getDashboardData;
  let FireDevice;
  let FireAlarm;
  let Inspection;
  const createdUserIds = [];
  const createdRoleIds = [];
  const createdDocIds = [];
  let allUserId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    getDashboardData = require('../../services/reportDashboardService').getDashboardData;

    const now = new Date();
    for (const [building, counts] of Object.entries(SEED_COUNTS)) {
      // level 7 = 部门档（LEVEL_DEPARTMENT），取 user.department 作为范围值
      const role = await Role.create({
        name: `部门主管_${building}`,
        code: `DEPT_LEAD_${building}`,
        level: 7,
        isBuiltIn: false,
        permissions: [],
      });
      createdRoleIds.push(role._id);
      const lead = await User.create({
        username: `lead${building}`,
        email: `lead${building}@example.com`,
        password: randomPassword(),
        department: building,
        roles: [role._id],
      });
      createdUserIds.push(lead._id);

      for (let i = 0; i < counts.devices; i += 1) {
        const doc = await FireDevice.create({
          deviceName: `仪表盘设备_${building}_${i}`,
          deviceType: DEVICE_TYPES[building],
          status: 'normal',
          installDate: now,
          expiryDate: new Date(now.getTime() + 365 * 86400000),
          location: { building },
        });
        createdDocIds.push({ model: FireDevice, id: doc._id });
      }
      for (let i = 0; i < counts.alarms; i += 1) {
        const doc = await FireAlarm.create({
          alarmType: 'other',
          level: 'warning',
          description: `仪表盘报警_${building}_${i}`,
          status: 'resolved',
          location: { building },
          receivedAt: now,
          dispatchedAt: now,
          resolvedAt: now,
          reporter: { name: `rs${building}` },
          processLog: [{ time: now, action: 'alarm_received', remark: 'x' }],
        });
        createdDocIds.push({ model: FireAlarm, id: doc._id });
      }
      for (let i = 0; i < counts.inspections; i += 1) {
        const doc = await Inspection.create({
          inspectionType: 'daily',
          title: `仪表盘巡检_${building}_${i}`,
          locations: [{ building }],
          planStartTime: new Date(now.getTime() - 3600000),
          planEndTime: new Date(now.getTime() + 3600000),
          status: 'completed',
          checkItems: [{ name: '消火栓' }],
          executionLog: [{ userId: lead._id, action: 'completed', timestamp: now }],
        });
        createdDocIds.push({ model: Inspection, id: doc._id });
      }
    }

    // 超管（level 9 = LEVEL_ALL）：只用于证明种子确实可被数到
    const allRole = await Role.create({
      name: `超管_${stamp}`,
      code: `SUPER_DASH_${stamp}`,
      level: 9,
      isBuiltIn: false,
      permissions: [],
    });
    createdRoleIds.push(allRole._id);
    const allUser = await User.create({
      username: `dashall${stamp}`,
      email: `dashall${stamp}@example.com`,
      password: randomPassword(),
      department: BUILDING_A,
      roles: [allRole._id],
    });
    createdUserIds.push(allUser._id);
    allUserId = String(allUser._id);
  });

  afterAll(async () => {
    for (const { model, id } of createdDocIds) {
      await model.deleteOne({ _id: id }).catch(() => {});
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    for (const id of createdUserIds) {
      await User.deleteOne({ _id: id }).catch(() => {});
    }
    for (const id of createdRoleIds) {
      await Role.deleteOne({ _id: id }).catch(() => {});
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 取本部门的仪表盘（userId 需为字符串，getDataScope 按 id 查用户） */
  const dashboardForBuilding = async (building) => {
    const User = require('../../models/User');
    const lead = await User.findOne({ username: `lead${building}` }).lean();
    return getDashboardData(String(lead._id));
  };

  test('前提自证：种子确实落库，且超管档能数到它们', async () => {
    const sum = (key) => SEED_COUNTS[BUILDING_A][key] + SEED_COUNTS[BUILDING_B][key];
    const { data } = await getDashboardData(allUserId);
    expect(data.devices.total).toBeGreaterThanOrEqual(sum('devices'));
    expect(data.alarms.total).toBeGreaterThanOrEqual(sum('alarms'));
    expect(data.inspections.total).toBeGreaterThanOrEqual(sum('inspections'));
  });

  test.each(Object.entries(SEED_COUNTS))(
    '%s 档主管的三档计数只含本部门（丢掉任一 $match 即红）',
    async (building, counts) => {
      const { data } = await dashboardForBuilding(building);
      expect(data.devices.total).toBe(counts.devices);
      expect(data.alarms.total).toBe(counts.alarms);
      expect(data.inspections.total).toBe(counts.inspections);
    }
  );

  test('byType 分组同样只见本部门（分组臂不另开一次查询，必须同口径）', async () => {
    const a = await dashboardForBuilding(BUILDING_A);
    expect(a.data.devices.byType).toEqual([{ _id: DEVICE_TYPES[BUILDING_A], count: 2 }]);
    const b = await dashboardForBuilding(BUILDING_B);
    expect(b.data.devices.byType).toEqual([{ _id: DEVICE_TYPES[BUILDING_B], count: 3 }]);
    // 反向：对侧的类型名不得出现在这一侧
    expect(JSON.stringify(a.data.devices.byType)).not.toContain(DEVICE_TYPES[BUILDING_B]);
  });

  test('两个部门档主管的读数不得互相等价（否则"精确计数"可能来自恒零实现）', async () => {
    const a = await dashboardForBuilding(BUILDING_A);
    const b = await dashboardForBuilding(BUILDING_B);
    expect(a.data.devices.total).not.toBe(b.data.devices.total);
    expect(a.data.alarms.total).not.toBe(b.data.alarms.total);
    expect(a.data.inspections.total).not.toBe(b.data.inspections.total);
  });
});
