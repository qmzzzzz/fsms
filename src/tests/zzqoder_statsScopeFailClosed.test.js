/**
 * 统计类接口的数据范围缺省必须是"拒绝"
 *
 * `getInspectionStats(startDate, endDate, dataScope = { type: 'all' })` 的默认值是
 * 最宽的那一档。今天所有调用方都显式传范围，所以这个默认值**不产生任何好处**，
 * 只会在将来某个调用方漏传时静默把全组织统计端出去——而且端出去的形式是
 * "看起来正常的一组数字"，没有任何报错。漏传的后果必须是零结果。
 *
 * 已核实的同族（轮 7 已全部按同判据收口，见技术文档 6-W/6-X/6-Y；
 * 判据与反向保护用例见 zzqoder_scopeCastFamily.test.js）：
 *   AlarmService.getAlarmStats: `if (dataScope && !apply(...))` ← 短路把 deny 分支整个跳过
 *   DeviceService.getDeviceStats / getExpiringDevices: `scopeFilter = {}` ← 空匹配即全表
 *
 * 反向保护同样重要：窄化只作用于**缺省**，显式 `{type:'all'}` 必须照旧给全量，
 * 否则这条修复会变成"统计接口永远返回 0"的假安全。
 */
const mongoose = require('mongoose');

describe('巡检统计：漏传数据范围只能得到零结果', () => {
  let Inspection;
  let service;
  const stamp = `zzqs${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Inspection = require('../models/Inspection');
    service = require('../services/InspectionService');
    require('../models/AuditLog');
    await Inspection.create({
      title: `${stamp} 统计夹具巡检`,
      inspectionType: 'daily',
      assignedTo: [],
    });
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('夹具确实存在（否则下面的"全零"是空集假绿）', async () => {
    expect(await Inspection.countDocuments({ title: new RegExp(stamp) })).toBe(1);
  });

  test('缺省（漏传 dataScope）→ total 与分组全部为零', async () => {
    const stats = await service.getInspectionStats(undefined, undefined);
    expect(stats.total).toBe(0);
    expect(stats.byStatus).toEqual([]);
    expect(stats.byType).toEqual([]);
    expect(stats.byResult).toEqual([]);
  });

  test('显式 type:none 与缺省同判据（deny 语义只有一份）', async () => {
    const denied = await service.getInspectionStats(undefined, undefined, { type: 'none' });
    const omitted = await service.getInspectionStats(undefined, undefined);
    expect(denied).toEqual(omitted);
  });

  test('反向保护：显式 all 仍给全量（缺省窄化不得变成永远为空）', async () => {
    const stats = await service.getInspectionStats(undefined, undefined, { type: 'all' });
    expect(stats.total).toBeGreaterThanOrEqual(1);
    expect(stats.byStatus.length).toBeGreaterThan(0);
  });
});
