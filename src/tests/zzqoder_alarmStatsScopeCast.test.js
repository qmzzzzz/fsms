/**
 * 统计聚合必须与列表同口径：self 范围下的 ObjectId 字符串不会在 aggregate 里被 cast
 *
 * 缺陷描述：`AlarmService.getAlarmStats` 把 `{'reporter.userId':'<24位hex字符串>'}`
 * 注入 `$match` 后送去 `aggregate`，而 userId 来自 JWT（字符串）。
 * `find()` 按 schema 自动 cast、`aggregate` 不 cast ⇒
 * **total（countDocuments，会 cast）> 0，而 byStatus/byLevel/byType 全空**。
 * 表现是看板"有 N 条报警，但一条都分类不出来"，且只对 self/department 级用户出现，
 * 管理员（type:'all'，无 userId 条件）永远正常——所以极难被发现。
 *
 * 本文件先钉住**平台事实**（不依赖任何业务代码），再钉住**服务结论**。
 * 平台事实那条如果哪天 Mongoose 改了行为，它会先红，提醒后面几条的前提已变。
 */
const mongoose = require('mongoose');

const stamp = `zzsc${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);

describe('平台事实：aggregate 的 $match 不做 schema cast，find/countDocuments 做', () => {
  let FireAlarm;
  let ownerOid;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../models/FireAlarm');
    ownerOid = new mongoose.Types.ObjectId();
    await FireAlarm.create([
      {
        alarmType: 'smoke',
        level: 'critical',
        description: `${stamp} 烟雾`,
        reporter: { userId: ownerOid },
      },
      {
        alarmType: 'temp_abnormal',
        level: 'warning',
        description: `${stamp} 温度`,
        reporter: { userId: ownerOid },
      },
      {
        alarmType: 'smoke',
        level: 'critical',
        description: `${stamp} 别人的`,
        reporter: { userId: new mongoose.Types.ObjectId() },
      },
    ]);
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('夹具落库 2 条属于 ownerOid、1 条属于别人（反空夹具）', async () => {
    expect(await FireAlarm.countDocuments({ 'reporter.userId': ownerOid })).toBe(2);
    expect(await FireAlarm.countDocuments({ description: new RegExp(stamp) })).toBe(3);
  });

  test('hex 字符串条件：find/countDocuments 命中，aggregate 命中 0 条', async () => {
    const asString = ownerOid.toString();
    // 会 cast 的两条路径
    expect(await FireAlarm.countDocuments({ 'reporter.userId': asString })).toBe(2);
    expect(await FireAlarm.find({ 'reporter.userId': asString })).toHaveLength(2);
    // 不 cast 的聚合路径——这正是 bug 的根因
    const grouped = await FireAlarm.aggregate([
      { $match: { 'reporter.userId': asString } },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]);
    expect(grouped).toEqual([]);
  });

  test('反向对照：同一个 id 以 ObjectId 形态进 aggregate 就正常（说明问题在值的形态）', async () => {
    const grouped = await FireAlarm.aggregate([
      { $match: { 'reporter.userId': ownerOid } },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].count).toBe(2);
  });
});

describe('AlarmService.getAlarmStats：self 范围下分项必须与 total 对得上', () => {
  let FireAlarm;
  let service;
  let ownerOid;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../models/FireAlarm');
    service = require('../services/AlarmService');
    ownerOid = new mongoose.Types.ObjectId();
    await FireAlarm.create([
      {
        alarmType: 'smoke',
        level: 'critical',
        status: 'pending',
        description: `${stamp} 自-1`,
        reporter: { userId: ownerOid },
      },
      {
        alarmType: 'patrol_find',
        level: 'warning',
        status: 'resolved',
        description: `${stamp} 自-2`,
        reporter: { userId: ownerOid },
      },
      {
        alarmType: 'smoke',
        level: 'critical',
        status: 'pending',
        description: `${stamp} 自-别人的`,
        reporter: { userId: new mongoose.Types.ObjectId() },
      },
    ]);
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const sumOf = (groups) => groups.reduce((acc, g) => acc + g.count, 0);

  test('JWT 形态的字符串 userId：total 与每个分项维度的合计一致（不为零）', async () => {
    const stats = await service.getAlarmStats(undefined, undefined, {
      type: 'self',
      userId: ownerOid.toString(),
    });
    expect(stats.total).toBe(2);
    expect(sumOf(stats.byStatus)).toBe(stats.total);
    expect(sumOf(stats.byLevel)).toBe(stats.total);
    expect(sumOf(stats.byType)).toBe(stats.total);
  });

  test('越界不得漏：self 范围统计里不含别人的报警', async () => {
    const stats = await service.getAlarmStats(undefined, undefined, {
      type: 'self',
      userId: ownerOid.toString(),
    });
    expect(stats.byStatus.find((g) => g._id === 'pending').count).toBe(1);
  });

  test('缺省（漏传 dataScope）只能得到零结果，不得退化为全量', async () => {
    const omitted = await service.getAlarmStats(undefined, undefined);
    expect(omitted.total).toBe(0);
    expect(omitted.byStatus).toEqual([]);
    expect(omitted.byLevel).toEqual([]);
    expect(omitted.byType).toEqual([]);
  });

  test('显式传 null 也必须 deny（漏传有默认值兜，null 没有）', async () => {
    // 这条不是重复上一条：参数默认值只在 **undefined** 时生效，
    // 传 null 会带着 null 进函数体。原实现的条件是 `if (dataScope && !apply(...))`，
    // null 为假 ⇒ 整个 deny 判断被跳过 ⇒ 统计退化为全组织。
    // （变异自检 SC-M5 首轮存活，就是靠这条把它杀掉的。）
    const asNull = await service.getAlarmStats(undefined, undefined, null);
    expect(asNull.total).toBe(0);
    expect(asNull.byStatus).toEqual([]);
  });

  test('反向保护：显式 all 仍给全量（缺省窄化不得变成永远为空）', async () => {
    const all = await service.getAlarmStats(undefined, undefined, { type: 'all' });
    expect(all.total).toBeGreaterThanOrEqual(3);
    // 同一口径的两条臂都必须自洽
    expect(sumOf(all.byStatus)).toBe(all.total);
    expect(sumOf(all.byLevel)).toBe(all.total);
  });
});
