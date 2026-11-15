/**
 * P2-08：FireAlarm.processLog 尾部封顶（200 条）+ processLogCount 计数留痕。
 *
 * 同型字段 FireDevice.maintenanceRecord / Inspection.executionLog 均为"尾部 200 条封顶
 * + 计数字段记总次数"。processLog 随详情接口整段返回并 populate，无上限的单文档迟早
 * 越过 16MB。三条判据：超 200 条截断、计数可数（count > length 即有留痕被截断）、
 * 旧数据兼容（无计数字段的存量文档照常读、追加后按新口径封顶计数）。
 */
const mongoose = require('mongoose');

describe('FireAlarm.processLog 尾部封顶与计数（P2-08）', () => {
  let FireAlarm;
  const stamp = `p08${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../../models/FireAlarm');
    require('../../models/User');
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const mkAlarm = (extra = {}) =>
    FireAlarm.create({
      description: `${stamp} 报警`,
      alarmType: 'smoke',
      level: 'warning',
      ...extra,
    });

  test('create 携带 250 条：截断为最新 200 条，计数记总次数 250', async () => {
    const entries = Array.from({ length: 250 }, (_, i) => ({ action: `step-${i}` }));
    const alarm = await mkAlarm({ processLog: entries });
    expect(alarm.processLog).toHaveLength(200);
    expect(alarm.processLog[0].action).toBe('step-50'); // 最早的 50 条被截掉
    expect(alarm.processLog[199].action).toBe('step-249');
    expect(alarm.processLogCount).toBe(250); // count > length ⇒ 截断可数
  });

  test('$push（findOneAndUpdate 路径）：尾部封顶且计数同步 +1', async () => {
    const alarm = await mkAlarm({
      processLog: Array.from({ length: 200 }, (_, i) => ({ action: `base-${i}` })),
    });
    const updated = await FireAlarm.findOneAndUpdate(
      { _id: alarm._id },
      { $push: { processLog: { action: 'extra-1' } } },
      { new: true }
    );
    expect(updated.processLog).toHaveLength(200); // 不增长
    expect(updated.processLog[199].action).toBe('extra-1'); // 留最新
    expect(updated.processLog[0].action).toBe('base-1'); // 最早的 base-0 被挤掉
    expect(updated.processLogCount).toBe(201);
  });

  test('$push（updateMany 路径）：多条命中各自封顶计数', async () => {
    const a = await mkAlarm({ processLog: Array.from({ length: 200 }, () => ({ action: 'x' })) });
    const b = await mkAlarm({ processLog: Array.from({ length: 199 }, () => ({ action: 'y' })) });
    await FireAlarm.updateMany(
      { _id: { $in: [a._id, b._id] } },
      { $push: { processLog: { action: 'released' } } }
    );
    const [afterA, afterB] = await Promise.all([
      FireAlarm.findById(a._id),
      FireAlarm.findById(b._id),
    ]);
    expect(afterA.processLog).toHaveLength(200);
    expect(afterA.processLogCount).toBe(201);
    expect(afterB.processLog).toHaveLength(200); // 199+1 未触顶
    expect(afterB.processLogCount).toBe(200);
  });

  test('旧数据兼容：无计数字段的存量文档照常读，追加后按新口径封顶计数', async () => {
    const legacy = Array.from({ length: 250 }, (_, i) => ({
      time: new Date(Date.now() - i * 60000),
      action: `legacy-${i}`,
    }));
    const raw = {
      alarmCode: `${stamp}-LEGACY`,
      description: `${stamp} 存量报警`,
      alarmType: 'smoke',
      level: 'warning',
      status: 'pending',
      processLog: legacy,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await FireAlarm.collection.insertOne(raw);
    const before = await FireAlarm.findById(raw._id);
    expect(before.processLog).toHaveLength(250); // 读路径不截存量：兼容旧数据
    const updated = await FireAlarm.findOneAndUpdate(
      { _id: raw._id },
      { $push: { processLog: { action: 'new-entry' } } },
      { new: true }
    );
    expect(updated.processLog).toHaveLength(200); // 追加后按新口径封顶
    expect(updated.processLog[199].action).toBe('new-entry');
    expect(updated.processLogCount).toBe(1); // 计数从新写入起算
  });
});
