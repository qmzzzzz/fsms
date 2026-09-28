/**
 * 聚合口径归一化的共用实现 + 巡检/设备两处统计的同族回归
 *
 *
 * 范围说明：本仓所有「buildDataScopeFilter / applyDataScopeToQuery → aggregate」
 * 的路径都需要同一次 cast。已实测的分布：
 *   - reportExportService.scopeFilterFor：**早已自带私有 cast**（reportDashboard /
 *     reportStats 两个服务复用它，因此本来就是对的）
 *   - auditScopeFilter.applyAuditDataScope：显式 `new mongoose.Types.ObjectId(...)`，对
 *   - AlarmService / InspectionService / DeviceService：三处各自直接喂原始条件 ⇒ 本次改动修
 * 本文件覆盖后两者中的两个（alarm 在另一个文件），外加 cast 自身的单元测试——
 * 因为 scopeCast.js 是新生产代码，它的"不改入参""保留 Date/null"这些承诺
 * 不能靠调用方的绿来间接证明。
 */
const mongoose = require('mongoose');

const { castScopeObjectIds } = require('../utils/scopeCast');
const { buildDataScopeFilter } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');

const stamp = `zzcf${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);
const sumOf = (groups) => groups.reduce((acc, g) => acc + g.count, 0);

describe('castScopeObjectIds 自身语义', () => {
  const oid = new mongoose.Types.ObjectId();

  test('hex 字符串叶子转成 ObjectId 实例', () => {
    const out = castScopeObjectIds({ 'reporter.userId': oid.toString() });
    expect(out['reporter.userId']).toBeInstanceOf(mongoose.Types.ObjectId);
    expect(out['reporter.userId'].equals(oid)).toBe(true);
  });

  test('递归进 $or 数组（device 的 ownerField 就是这个形态）', () => {
    const out = castScopeObjectIds({
      $or: [{ createdBy: oid.toString() }, { 'maintenanceRecord.operator': oid.toString() }],
    });
    for (const arm of out.$or) {
      expect(Object.values(arm)[0]).toBeInstanceOf(mongoose.Types.ObjectId);
    }
  });

  test('$in 数组里的每个 hex 字符串都转', () => {
    const out = castScopeObjectIds({ userId: { $in: [oid.toString(), oid.toString()] } });
    expect(out.userId.$in.every((v) => v instanceof mongoose.Types.ObjectId)).toBe(true);
  });

  test('非 hex 字符串（部门名/楼栋名/枚举）与 null（deny 哨兵）原样保留', () => {
    const out = castScopeObjectIds({
      'location.building': 'A 座',
      status: 'pending',
      _id: null,
      occurredAt: { $gte: new Date('2026-01-01T00:00:00Z') },
    });
    expect(out['location.building']).toBe('A 座');
    expect(out.status).toBe('pending');
    expect(out._id).toBeNull();
    expect(out.occurredAt.$gte).toBeInstanceOf(Date);
    expect(out.occurredAt.$gte.getTime()).toBe(Date.UTC(2026, 0, 1));
  });

  test('已是 ObjectId / RegExp 的值不被重新包装（幂等，可安全叠层）', () => {
    const once = castScopeObjectIds({ userId: oid, ip: /^10\./ });
    const twice = castScopeObjectIds(once);
    expect(twice.userId).toBe(oid);
    expect(twice.ip).toBeInstanceOf(RegExp);
  });

  test('不修改入参（调用方还要把原条件用于别的用途）', () => {
    const input = { 'reporter.userId': oid.toString(), nested: { a: oid.toString() } };
    const snapshot = JSON.parse(JSON.stringify(input));
    castScopeObjectIds(input);
    expect(input).toEqual(snapshot);
  });

  test('已知取舍：24 位 hex 的普通字符串也会被转（与既有私有实现同判据）', () => {
    // 这不是缺陷而是刻意的形态判断：部门名/楼栋名理论上可以是 24 位十六进制串，
    // 但那种值本来就是为"看起来像 ObjectId 的 id 字段"服务的。此处钉住行为，
    // 使将来任何"改成只转已知字段名"的讨论有事实基线。
    const looksLikeHexButIsName = 'abcdef123456789012345678';
    const out = castScopeObjectIds({ 'location.building': looksLikeHexButIsName });
    expect(out['location.building']).toBeInstanceOf(mongoose.Types.ObjectId);
  });
});

describe('InspectionService.getInspectionStats：self 范围下分项与 total 同口径', () => {
  let Inspection;
  let service;
  let oid;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Inspection = require('../models/Inspection');
    service = require('../services/InspectionService');
    oid = new mongoose.Types.ObjectId();
    await Inspection.create([
      {
        title: `${stamp} 巡-自-1`,
        inspectionType: 'daily',
        assignedTo: [oid],
        status: 'completed',
        result: 'normal',
      },
      {
        title: `${stamp} 巡-自-2`,
        inspectionType: 'weekly',
        assignedTo: [oid],
        status: 'pending',
      },
      {
        title: `${stamp} 巡-别人`,
        inspectionType: 'daily',
        assignedTo: [new mongoose.Types.ObjectId()],
        status: 'pending',
      },
    ]);
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('JWT 字符串 userId：total 与三个分项维度全部自洽', async () => {
    const stats = await service.getInspectionStats(undefined, undefined, {
      type: 'self',
      userId: oid.toString(),
    });
    expect(stats.total).toBe(2);
    expect(sumOf(stats.byStatus)).toBe(2);
    expect(sumOf(stats.byType)).toBe(2);
    // byResult 那一臂走的是 {...scopedMatch, status:'completed'}，
    // 同样依赖 cast：夹具里只有 1 条是 completed
    expect(sumOf(stats.byResult)).toBe(1);
  });

  test('反向保护：显式 all 仍给全量', async () => {
    const all = await service.getInspectionStats(undefined, undefined, { type: 'all' });
    expect(all.total).toBeGreaterThanOrEqual(3);
    expect(sumOf(all.byStatus)).toBe(all.total);
  });
});

describe('DeviceService.getDeviceStats：$or 形态的 self 范围同样要 cast', () => {
  let FireDevice;
  let service;
  let oid;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../models/FireDevice');
    service = require('../services/DeviceService');
    oid = new mongoose.Types.ObjectId();
    await FireDevice.create([
      {
        deviceName: `${stamp} 备-自-建档`,
        deviceType: 'smoke_detector',
        installDate: new Date('2026-01-01'),
        createdBy: oid,
      },
      {
        deviceName: `${stamp} 备-自-维护`,
        deviceType: 'extinguisher',
        installDate: new Date('2026-01-01'),
        createdBy: new mongoose.Types.ObjectId(),
        maintenanceRecord: [{ operator: oid, content: `${stamp} 维护` }],
      },
      {
        deviceName: `${stamp} 备-别人`,
        deviceType: 'smoke_detector',
        installDate: new Date('2026-01-01'),
        createdBy: new mongoose.Types.ObjectId(),
      },
    ]);
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceName: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 复刻 deviceController 的喂法：buildDeviceScopeFilter(dataScope) 直接进 service */
  const scopeForSelf = (userId) =>
    buildDataScopeFilter(
      { type: 'self', userId },
      DATA_SCOPE_FIELDS.device.ownerField,
      DATA_SCOPE_FIELDS.device.departmentField
    );

  test('缺省条件是 $or 两臂、值为字符串（前提成立）', () => {
    const raw = scopeForSelf(oid.toString());
    expect(raw.$or).toHaveLength(2);
    expect(typeof raw.$or[0].createdBy).toBe('string');
    expect(typeof raw.$or[1]['maintenanceRecord.operator']).toBe('string');
  });

  test('建档 + 维护两条臂都命中：total 与 byType/byStatus 合计一致', async () => {
    const stats = await service.getDeviceStats(scopeForSelf(oid.toString()));
    expect(stats.total).toBe(2); // 不含别人那台
    expect(sumOf(stats.byType)).toBe(2);
    expect(sumOf(stats.byStatus)).toBe(2);
  });

  test('漏传 scopeFilter 只能得到零结果（缺省不得退化为全量）', async () => {
    const omitted = await service.getDeviceStats();
    expect(omitted).toEqual({
      total: 0,
      byType: [],
      byStatus: [],
      needMaintenance: 0,
      needSchedule: 0,
      expiringSoon: 0,
      expired: 0,
      expiryUnknown: 0,
    });
  });

  test('反向保护：all 的显式 {} 仍给全量（deny 只针对漏传）', async () => {
    const all = await service.getDeviceStats({});
    expect(all.total).toBeGreaterThanOrEqual(3);
    expect(sumOf(all.byType)).toBe(all.total);
  });
});

describe('DeviceService.getExpiringDevices：漏传范围必须是空清单而不是全表', () => {
  let FireDevice;
  let service;
  let oid;
  const expStamp = `${stamp}exp`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../models/FireDevice');
    service = require('../services/DeviceService');
    oid = new mongoose.Types.ObjectId();
    const inTenDays = new Date(Date.now() + 10 * 24 * 3600 * 1000);
    await FireDevice.create([
      {
        deviceName: `${expStamp} 自-到期`,
        deviceType: 'extinguisher',
        installDate: new Date('2026-01-01'),
        expiryDate: inTenDays,
        createdBy: oid,
      },
      {
        deviceName: `${expStamp} 别人-到期`,
        deviceType: 'hydrant',
        installDate: new Date('2026-01-01'),
        expiryDate: inTenDays,
        createdBy: new mongoose.Types.ObjectId(),
      },
    ]);
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceName: new RegExp(expStamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const selfScope = (userId) =>
    buildDataScopeFilter(
      { type: 'self', userId },
      DATA_SCOPE_FIELDS.device.ownerField,
      DATA_SCOPE_FIELDS.device.departmentField
    );

  test('夹具在窗口内（否则下面的"空"是空集假绿）', async () => {
    const all = await service.getExpiringDevices(30, {});
    expect(all.map((d) => d.deviceName)).toEqual(
      expect.arrayContaining([`${expStamp} 自-到期`, `${expStamp} 别人-到期`])
    );
  });

  test('漏传 scopeFilter → 0 条（原缺省 {} 会返回全组织到期设备清单）', async () => {
    expect(await service.getExpiringDevices(30)).toEqual([]);
  });

  test('显式 {} 仍是 all（窄化只针对漏传，不得做成永远为空）', async () => {
    const all = await service.getExpiringDevices(30, {});
    expect(all.length).toBeGreaterThanOrEqual(2);
  });

  test('self 范围只返回自己的设备，且 hex 字符串条件在 find 路径同样有效', async () => {
    const mine = await service.getExpiringDevices(30, selfScope(oid.toString()));
    expect(mine.map((d) => d.deviceName)).toEqual([`${expStamp} 自-到期`]);
  });
});
