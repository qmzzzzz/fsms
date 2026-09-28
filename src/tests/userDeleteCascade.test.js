/**
 * 删除用户必须释放"进行中的指派"
 *
 * `userService.deleteById` 原先就是一行 `User.findByIdAndDelete`。删掉一个正在处理报警
 * 或正在执行巡检的账户，会把业务砖化且没有任何出口：
 *   FireAlarm 的四个收口条件分别是
 *     arrive/resolve : {status:'processing', handler: 操作者}
 *     false_alarm/cancel : handler ∈ {操作者, null, 不存在}
 *   悬空 ObjectId 四个条件全不匹配 → 这条报警**永远关不掉**，超管也救不回来
 *   （数据范围判定能过，但 handler 永远不会等于任何现存操作者）。
 *   Inspection 的 start 要求 assignedTo 含操作者或 `assignedTo.0` 不存在，
 *   单元素幽灵数组两者都不满足 → 计划永远执行不了， 但仍计入 pending 并拖住 completionRate。
 *
 * 报警侧只把 handler 置空是不够的：processing + handler:null 仍然只剩误报一条出路
 * （dispatch/cancel 的前置条件是 status:'pending'，arrive/resolve 要求 handler===操作者）。
 * 真实出警的工单被强制登记成"误报"，等于把一起真事故从合规统计里抹掉。
 * 级联因此连同 status 退回 pending（本系统"无人认领"的既有语义），并追加一条
 * handler_released 过程记录。下面第一条用例用**真实服务函数**走完
 * dispatch → arriveAtScene → resolveAlarm 来验收，而不是照抄过滤条件——
 * 照抄过一次就错过一次（旧版本用例写的 `status:'processing' + handler:null`
 * 看起来可达，实际的 cancelAlarm 只认 pending）。
 *
 * 修复只清"进行中的指派"。历史取证字段（reporter.userId、processLog[].operator、
 * reviewedBy、executionLog[].userId、createdBy）与**已终结**记录的指派一律保留——
 * "谁当时做了什么"必须留住，哪怕那个人已经不存在。这正是下面两条反向保护要钉的。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('删除用户的级联：解除开放指派，保留历史归属', () => {
  const PASSWORD = randomPassword();
  const stamp = `zzuc${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);

  let User;
  let FireAlarm;
  let Inspection;
  let userService;
  let AlarmService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    FireAlarm = require('../models/FireAlarm');
    Inspection = require('../models/Inspection');
    require('../models/AuditLog');
    // InspectionService 的开工/提交返回体带 populate(devices → FireDevice)，缺这份模型
    // 会在查询里抛 MissingSchemaError（与本用例要验的级联无关，纯属夹具装配）
    require('../models/FireDevice');
    userService = require('../services/userService');
    AlarmService = require('../services/AlarmService');
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const mkUser = (tag) =>
    User.create({
      username: `${stamp}${tag}`.slice(0, 30),
      email: `${stamp}${tag}@example.com`,
      password: PASSWORD,
    });

  const mkAlarm = (fields) =>
    FireAlarm.create({
      description: `${stamp} 报警`,
      alarmType: 'smoke',
      level: 'warning',
      ...fields,
    });

  const mkInspection = (fields) =>
    Inspection.create({
      title: `${stamp} 巡检`,
      inspectionType: 'daily',
      ...fields,
    });

  test('处理中的报警：删除处理人后退回待指派池，完整生命周期恢复', async () => {
    const handler = await mkUser('h1');
    const reporter = await mkUser('r1');
    const other = await mkUser('o1');
    const alarm = await mkAlarm({
      status: 'processing',
      handler: handler._id,
      dispatchedAt: new Date(),
      arrivedAt: new Date(),
      processLog: [
        {
          time: new Date(),
          action: 'dispatched',
          operator: handler._id,
          remark: '已指派处理人',
        },
      ],
      reporter: { userId: reporter._id, username: reporter.username },
    });

    // 前提自证（砖化的真实形态）：删之前
    //   派单/取消的准入 `{status:'pending'}` 不匹配（它是 processing）
    //   到场/结单的准入 `{status:'processing', handler:操作者}` 也不匹配（handler 已不存在）
    // ⇒ 四个出口只剩误报
    expect(await FireAlarm.countDocuments({ _id: alarm._id, status: 'pending' })).toBe(0);
    expect(
      await FireAlarm.countDocuments({
        _id: alarm._id,
        status: 'processing',
        handler: other._id,
      })
    ).toBe(0);

    const deleted = await userService.deleteById(handler._id);
    expect(deleted).not.toBeNull(); // 既有契约：返回被删文档（控制器用它的 username 记审计）

    const after = await FireAlarm.findById(alarm._id);
    expect(after.handler).toBeNull();
    expect(after.status).toBe('pending');
    // "本次派单"的时间戳随 status 一起重置：报表用它算响应时长
    // （dispatchedAt - receivedAt），留着会把已删账户的派单时间算进新一次处置
    expect(after.dispatchedAt).toBeNull();
    expect(after.arrivedAt).toBeNull();
    // 重置的是标量，不是历史：原派单记录留住，退回动作另起一条追加
    expect(after.processLog.map((e) => e.action)).toEqual(['dispatched', 'handler_released']);
    expect(String(after.processLog[0].operator)).toBe(String(handler._id));
    expect(after.processLog[1].operator).toBeNull();
    // 归属人（取证字段）必须留住，哪怕已经是个悬空引用
    expect(String(after.reporter.userId)).toBe(String(reporter._id));

    // 真正的验收：换个人能把它走完，而不是只能登记成误报
    const dispatched = await AlarmService.dispatchAlarm(alarm._id, other._id, other._id, {
      dataScope: { type: 'all' },
    });
    expect(dispatched.status).toBe('processing');
    const arrived = await AlarmService.arriveAtScene(alarm._id, other._id);
    expect(arrived.arrivedAt).toBeInstanceOf(Date);
    const resolved = await AlarmService.resolveAlarm(
      alarm._id,
      { handleResult: '现场确认并处置', cause: 'fire' },
      other._id
    );
    expect(resolved.status).toBe('resolved');
  });

  test('已终结的报警保留历史处理人（级联不得改写取证记录）', async () => {
    const handler = await mkUser('h2');
    const alarm = await mkAlarm({
      status: 'resolved',
      handler: handler._id,
      reporter: { userId: handler._id, username: handler.username },
    });

    await userService.deleteById(handler._id);

    const after = await FireAlarm.findById(alarm._id);
    expect(String(after.handler)).toBe(String(handler._id));
  });

  test('进行中/待执行的巡检：从 assignedTo 里摘掉被删者，其余成员不受影响', async () => {
    const gone = await mkUser('g1');
    const peer = await mkUser('p1');
    const plan = await mkInspection({ status: 'pending', assignedTo: [gone._id, peer._id] });

    await userService.deleteById(gone._id);

    const after = await Inspection.findById(plan._id);
    const ids = after.assignedTo.map(String);
    expect(ids).not.toContain(String(gone._id));
    expect(ids).toContain(String(peer._id));
  });

  /**
   * F-151：`overdue` 必须一起释放。
   * 级联原先只摘 `['pending', 'in_progress']`，而调度器（deviceReminder.markOverdueInspections）
   * 恰恰会把超期的 pending/in_progress 改写成 `overdue` ⇒ 越紧急的计划越容易漏在闸门外面。
   * 漏掉之后开工/提交的准入是「assignedTo 含操作者」或「assignedTo.0 不存在」，
   * 单元素幽灵数组两者都不满足 ⇒ 这条巡检再也干不了，而 `cancelInspection` 不卡执行人，
   * 于是唯一出路是把一条可能真做过的消防巡检登记成"已取消"。
   * 本用例的验收是"换个人能把它干完"，不是"字段被清了"——清字段只是手段。
   */
  test('超期(overdue)的巡检：删掉唯一执行人后别人仍能开工并提交', async () => {
    const InspectionService = require('../services/InspectionService');
    const gone = await mkUser('g3');
    const other = await mkUser('o3');
    const plan = await mkInspection({
      status: 'overdue',
      assignedTo: [gone._id],
      planEndTime: new Date(Date.now() - 60 * 1000),
    });

    const conflict = async (fn) => {
      try {
        await fn();
        return null;
      } catch (e) {
        return e.statusCode;
      }
    };
    // 前提自证：删除**之前**这条计划谁都干不了（409），否则下面"删完就能干"证明不了级联
    expect(await conflict(() => InspectionService.startInspection(plan, other._id))).toBe(409);

    await userService.deleteById(gone._id);

    const released = await Inspection.findById(plan._id);
    expect(released.assignedTo.map(String)).not.toContain(String(gone._id));
    // 状态不被级联改写：overdue 是调度器打的时间标记，级联只解指派
    expect(released.status).toBe('overdue');

    // 真正的验收：同范围他人现在能把它干完（开工 → 提交结果落库）
    const started = await InspectionService.startInspection(released, other._id);
    expect(started.status).toBe('in_progress');
    const done = await InspectionService.completeInspection(
      started,
      { result: 'normal', findings: [] },
      other._id
    );
    expect(done.status).toBe('completed');
    expect(done.result).toBe('normal');
  });

  test('已完成的巡检保留完整执行人名单（历史归责依据）', async () => {
    const gone = await mkUser('g2');
    const plan = await mkInspection({ status: 'completed', assignedTo: [gone._id] });

    await userService.deleteById(gone._id);

    const after = await Inspection.findById(plan._id);
    expect(after.assignedTo.map(String)).toContain(String(gone._id));
  });

  test('批量删除同样级联（每个被删者的开放指派都要释放）', async () => {
    const a = await mkUser('b1');
    const b = await mkUser('b2');
    const keep = await mkUser('b3');
    const alarmA = await mkAlarm({ status: 'processing', handler: a._id });
    const alarmB = await mkAlarm({ status: 'processing', handler: b._id });
    const alarmKeep = await mkAlarm({ status: 'processing', handler: keep._id });

    const result = await userService.deleteMany({ _id: { $in: [a._id, b._id] } });
    expect(result.deletedCount).toBe(2);

    expect((await FireAlarm.findById(alarmA._id)).handler).toBeNull();
    expect((await FireAlarm.findById(alarmB._id)).handler).toBeNull();
    // 反向保护：没被删的处理人不能被顺手清掉，其工单也不能被退回待指派池
    // （退回是按 handler 命中的，写成"所有 processing 都重置"会波及全库在途工单）
    const kept = await FireAlarm.findById(alarmKeep._id);
    expect(String(kept.handler)).toBe(String(keep._id));
    expect(kept.status).toBe('processing');
  });

  test('无任何指派的用户删除路径保持原样（级联不得引入新失败）', async () => {
    const lonely = await mkUser('al1');
    const deleted = await userService.deleteById(lonely._id);
    expect(deleted.username).toBe(lonely.username);
    expect(await User.findById(lonely._id)).toBeNull();
  });
});
