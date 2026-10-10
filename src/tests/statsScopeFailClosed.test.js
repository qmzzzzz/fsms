/**
 * 统计类接口的数据范围缺省必须是"拒绝"
 *
 * 缺省值早已收窄成 `{ type: 'none' }`（拒绝）而不是最宽的那一档。今天所有调用方都
 * 显式传范围，所以 `all` 这个默认值**不产生任何好处**，只会在将来某个调用方漏传时
 * 静默把全组织统计端出去——而且端出去的形式是"看起来正常的一组数字"，没有任何报错。
 *
 * #12 之后漏传的后果不再是"零结果"，而是 **403 DATA_SCOPE_DENIED**：零结果让调用方
 * 分不清「这段时间没有巡检」与「这个账号没有可见范围」，而这两件事的后续动作相反
 * （一个继续等数据，一个去找管理员开权限）。
 *
 * 已核实的同族（轮 7 已全部按同判据收口，见技术文档 6-W/6-X/6-Y；
 * 判据与反向保护用例见 scopeCastFamily.test.js）：
 *   AlarmService.getAlarmStats: `if (dataScope && !apply(...))` ← 短路把 deny 分支整个跳过
 *   DeviceService.getDeviceStats / getExpiringDevices: `scopeFilter = {}` ← 空匹配即全表
 *
 * 反向保护同样重要：窄化只作用于**缺省**，显式 `{type:'all'}` 必须照旧给全量，
 * 否则这条修复会变成"统计接口永远返回 0"的假安全。
 */
const mongoose = require('mongoose');

describe('巡检统计：漏传数据范围必须 403', () => {
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

  test('缺省（漏传 dataScope）→ 403 DATA_SCOPE_DENIED', async () => {
    await expect(service.getInspectionStats(undefined, undefined)).rejects.toMatchObject({
      message: expect.stringMatching(/没有可用的数据范围/),
      statusCode: 403,
      code: 'DATA_SCOPE_DENIED',
    });
  });

  test('显式 type:none 与缺省同判据（deny 语义只有一份）', async () => {
    const denied = service.getInspectionStats(undefined, undefined, { type: 'none' });
    const omitted = service.getInspectionStats(undefined, undefined);
    await expect(denied).rejects.toMatchObject({ statusCode: 403, code: 'DATA_SCOPE_DENIED' });
    await expect(omitted).rejects.toMatchObject({ statusCode: 403, code: 'DATA_SCOPE_DENIED' });
  });

  test('反向保护：显式 all 仍给全量（缺省窄化不得变成永远为空）', async () => {
    const stats = await service.getInspectionStats(undefined, undefined, { type: 'all' });
    expect(stats.total).toBeGreaterThanOrEqual(1);
    expect(stats.byStatus.length).toBeGreaterThan(0);
  });
});
