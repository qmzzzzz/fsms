/**
 * L-22 回归：删除级联的三条查询必须有索引覆盖（`explain` 级别锁定）
 *
 * 背景：设备删除的三条级联 `updateMany`（FireAlarm.deviceId、Inspection.devices、
 * Inspection.findings.deviceId）此前均无索引覆盖 → COLLSCAN。
 * 12 万规模实测 204.54ms，补索引后 1.07ms（191.2x）。
 *
 * 为何不能只断言「schema 里有这条索引声明」：
 *   schema.index() 只是**声明**，实际集合上的索引要经过 syncIndexes/ensureIndexes
 *   才存在；且改写成等价但用不上的形态（例如把 $eq 写成 $in、或加一层 $or）
 *   会让计划退回 COLLSCAN，而 schema 声明依旧完好。
 *   故本套件用 `explain` 断言**执行计划实际选择了 IXSCAN**——这才是退化会显形的层面。
 *
 * 规模说明：本测试只造极小数据（explain 不执行数据量级判断，
 * 计划选择在空集合上也已确定）。**性能数字本身**不在本测试断言范围，
 * 那是 deliverables/性能实测基线-2026-09-16.json 的职责。
 */

const mongoose = require('mongoose');

describe('L-22 删除级联索引覆盖（explain 级锁定）', () => {
  let FireAlarm;
  let Inspection;
  const deviceId = new mongoose.Types.ObjectId();
  const collNames = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ({ FireAlarm, Inspection } = require('../../models'));
    // 索引声明 → 实际集合：确保待测索引真实存在（CI 冷启动时集合是空的）
    await FireAlarm.syncIndexes();
    await Inspection.syncIndexes();
    collNames.push(FireAlarm.collection.name, Inspection.collection.name);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 取 explain 中所有 stage 名，用于断言「走了索引而非全表扫描」 */
  const stagesOf = (explain) => {
    const names = [];
    const walk = (node) => {
      if (!node || typeof node !== 'object') return;
      if (typeof node.stage === 'string') names.push(node.stage);
      for (const v of Object.values(node)) walk(v);
    };
    walk(explain);
    return names;
  };

  const explainFilter = async (Model, filter) => {
    const res = await Model.collection
      .find(filter)
      .explain('queryPlanner')
      .catch(() => null);
    if (!res) throw new Error('explain 失败：无法读取执行计划');
    return stagesOf(res);
  };

  test('FireAlarm.updateMany({deviceId}) 走 IXSCAN，非 COLLSCAN', async () => {
    const stages = await explainFilter(FireAlarm, { deviceId });
    expect(stages).toContain('IXSCAN');
    expect(stages).not.toContain('COLLSCAN');
  });

  test('Inspection.updateMany({devices: id}) 走 IXSCAN（数组元素匹配）', async () => {
    const stages = await explainFilter(Inspection, { devices: deviceId });
    expect(stages).toContain('IXSCAN');
    expect(stages).not.toContain('COLLSCAN');
  });

  test('Inspection.updateMany({findings.deviceId}) 走 IXSCAN（嵌套数组字段）', async () => {
    const stages = await explainFilter(Inspection, { 'findings.deviceId': deviceId });
    expect(stages).toContain('IXSCAN');
    expect(stages).not.toContain('COLLSCAN');
  });

  /**
   * 【本轮改造：源码 grep → 真实调用捕获】
   *
   * 原用例对 DeviceService.js 做正则 grep，断言源码里「出现过」三个 filter 字面量。
   * 它拦不住真正的回归：上面三条 explain 用的是**本测试自己写的 filter**，
   * 与实现实际传的 filter 是两份互不约束的数据。把实现里的 'findings.deviceId'
   * 改成任意别的字段，explain 依旧全绿（它查的还是自己那份字面量），
   * 而 grep 只要源码里**还有一处**该模式就通过——注释掉的代码、字符串字面量、
   * 死分支都算命中。于是「索引覆盖」的结论与「实现真的用这个字段查」之间是断开的。
   *
   * 现改为：spy 住三个 Model 的 updateMany，真跑 DeviceService.deleteDevice()，
   * 取出实现**实际传入**的 filter 对象，再拿它去 explain。
   * 这样「字段名漂移」会直接反映到执行计划上——索引建在 'findings.deviceId'，
   * 实现改用别的字段就会查不到索引、退回 COLLSCAN，本用例随即转红。
   *
   * 注意：此处断言的是「实现传的 filter 能走索引」，而非「实现传的 filter 等于
   * 某个写死的对象」——后者仍是对字面量的断言，前者才是对行为的断言。
   */
  test('deleteDevice 实际传入的 filter 均走 IXSCAN（捕获真实调用，非比对字面量）', async () => {
    const { FireDevice } = require('../../models');
    const deviceService = require('../../services/DeviceService');

    // 造一台真实设备，让 deleteDevice 走到级联清理（否则提前 return 会捕获不到调用）
    const device = await FireDevice.create({
      deviceCode: `L22-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      deviceName: 'L-22 级联捕获用设备',
      deviceType: 'extinguisher',
      installDate: new Date('2026-01-01'),
    });

    const captured = [];
    const spies = [FireAlarm, Inspection].map((Model) =>
      jest.spyOn(Model, 'updateMany').mockImplementation((filter) => {
        captured.push({ model: Model.modelName, filter });
        return Promise.resolve({ acknowledged: true, modifiedCount: 0 });
      })
    );
    // findByIdAndDelete 也要拦下，避免真删（本用例只关心三条级联 filter）
    const deleteSpy = jest
      .spyOn(FireDevice, 'findByIdAndDelete')
      .mockResolvedValue(device);

    try {
      await deviceService.deleteDevice(device);
    } finally {
      spies.forEach((sp) => sp.mockRestore());
      deleteSpy.mockRestore();
      await FireDevice.deleteMany({ _id: device._id });
    }

    // 捕获到的必须是**恰好三条**：少一条说明级联被删掉（悬空引用回归），
    // 多一条说明新增了未纳入本用例索引覆盖的查询
    expect(captured).toHaveLength(3);

    // 每条都用实现实际传入的 filter 去 explain，断言真走索引
    for (const { model, filter } of captured) {
      const Model = model === 'FireAlarm' ? FireAlarm : Inspection;
      const stages = await explainFilter(Model, filter);
      expect({ model, filter, stages }).toMatchObject({
        model,
        filter,
        stages: expect.arrayContaining(['IXSCAN']),
      });
      expect(stages).not.toContain('COLLSCAN');
    }
  });
});
