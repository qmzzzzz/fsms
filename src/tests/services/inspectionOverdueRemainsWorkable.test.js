/**
 * overdue 不得成为巡检的沉态（调度器改写 ≠ 工作流终态）
 *
 * 缺陷形态（实测确认，不是推测）：
 *   deviceReminder.markOverdueInspections 把 planEndTime 已过的 **pending 与 in_progress**
 *   一并改写成 'overdue'；而 startInspection 只认 'pending'、completeInspection 只认
 *   'in_progress'。于是：
 *     - 迟开工的巡检：被标 overdue 后永远点不了"开始"，唯一出路是 cancel；
 *     - 干到一半超时：作业人员手里的 in_progress 被后台改成 overdue，提交结果直接 409，
 *       result / findings 再也进不了库——一个安全系统里"确实做过的巡检"没有留痕，
 *       完成率还会把这条算成未完成。
 *   与 InspectionService 自己的注释（P2-19 引入 overdue 是为了让筛选有事实来源）相矛盾：
 *   引入了一个没有出边的状态。
 *
 * 本文件钉的是"改完还能干完"，而不是"会被改"（既有用例
 * businessStateConsistencyInvariants.test.js:280 已经钉了后者）。
 *
 * 可证伪性：把任一 `$in: [..., 'overdue']` 改回单值 ⇒ 对应用例红；
 * 把条件放宽成"任何状态都能开始/提交" ⇒ 第 3、4 条负向用例红。
 */

'use strict';

const mongoose = require('mongoose');
const Inspection = require('../../models/Inspection');
const InspectionService = require('../../services/InspectionService');
const { markOverdueInspections } = require('../../services/deviceReminder');
const {
  INSPECTION_STATUSES,
  INSPECTION_OPEN_STATUSES,
  INSPECTION_TERMINAL_STATUSES,
} = require('../../constants/inspection');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const TAG = `ovd${Date.now().toString(36)}`;
const OWNER = new mongoose.Types.ObjectId();
const OTHER = new mongoose.Types.ObjectId();
const createdUsers = [];

const makeInspection = (over = {}) =>
  Inspection.create({
    inspectionType: 'daily',
    title: `${TAG}-${Math.random().toString(36).slice(2, 8)}`,
    assignedTo: [OWNER],
    planStartTime: new Date(Date.now() - 7200_000),
    planEndTime: new Date(Date.now() - 3600_000), // 已过计划结束时间
    status: 'pending',
    ...over,
  });

const rejectsWith = (fn) =>
  fn().then(
    () => ({ threw: false }),
    (err) => ({ threw: true, status: err.statusCode || err.status, message: err.message })
  );

describe('overdue 巡检仍可开工与提交', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // executionLog.userId 会被 populate 成用户文档；OWNER 若是个"没有用户的 id"，
    // populate 直接给出 null（本仓实测：数组路径上的 populate 丢弃未命中项/置 null），
    // 断言就会拿到 "null" 而不是被测的指派人。所以必须造真用户。
    const User = require('../../models/User');
    await User.create({
      _id: OWNER,
      username: `${TAG}owner`,
      email: `${TAG}owner@example.com`,
      password: randomPassword(),
      roles: [],
    });
    createdUsers.push(OWNER);
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(`^${TAG}`) });
    if (createdUsers.length)
      await require('../../models/User').deleteMany({ _id: { $in: createdUsers } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('调度器确实会把 pending 与 in_progress 改成 overdue（前提自证，不是我在演一个到不了的状态）', async () => {
    const pending = await makeInspection();
    const running = await makeInspection({ status: 'in_progress', actualStartTime: new Date() });
    const marked = await markOverdueInspections();
    expect(marked).toBeGreaterThanOrEqual(2);
    expect((await Inspection.findById(pending._id)).status).toBe('overdue');
    expect((await Inspection.findById(running._id)).status).toBe('overdue');
  });

  test('overdue 可以被开始（迟开工的巡检不再只有 cancel 一条路）', async () => {
    const doc = await makeInspection({ status: 'overdue' });
    const started = await InspectionService.startInspection(doc, OWNER);
    expect(started.status).toBe('in_progress');
    expect(started.actualStartTime).toBeInstanceOf(Date);
    const logged = started.executionLog.at(-1);
    // executionLog.userId 被 populate 成用户文档（select username/realName）——
    // 直接 String(它) 得到 "[object Object]"，比对必须先取回 _id（本仓同类坑已踩多次）
    expect({ action: logged.action, userId: String(logged.userId?._id ?? logged.userId) }).toEqual({
      action: 'started',
      userId: String(OWNER),
    });
  });

  test('overdue 可以直接提交结果：result 与 findings 真的落库（原子性未放宽）', async () => {
    const doc = await makeInspection({ status: 'overdue' });
    const deviceId = new mongoose.Types.ObjectId();
    const completed = await InspectionService.completeInspection(
      doc,
      {
        result: 'abnormal',
        findings: [{ deviceId: deviceId, issue: `${TAG}-消火栓无水`, severity: 'high' }],
        remark: '超时后补交',
      },
      OWNER
    );
    expect(completed.status).toBe('completed');
    const fresh = await Inspection.findById(doc._id);
    expect(fresh.result).toBe('abnormal');
    expect(fresh.findings).toHaveLength(1);
    expect(fresh.findings[0].issue).toBe(`${TAG}-消火栓无水`);
    expect(fresh.findings[0].severity).toBe('high');

    // 重复提交仍被拒：允许 overdue 提交不等于打开并发重复提交的口子
    const again = await rejectsWith(() =>
      InspectionService.completeInspection(fresh, { result: 'normal' }, OWNER)
    );
    expect(again.threw).toBe(true);
  });

  test('负向：终态不得被"开始/提交"，非指派人也不得（放宽只针对 overdue 一格）', async () => {
    const done = await makeInspection({ status: 'completed', actualEndTime: new Date() });
    const cancelled = await makeInspection({ status: 'cancelled' });

    for (const [label, doc] of [
      ['completed', done],
      ['cancelled', cancelled],
    ]) {
      const start = await rejectsWith(() => InspectionService.startInspection(doc, OWNER));
      const complete = await rejectsWith(() =>
        InspectionService.completeInspection(doc, { result: 'normal' }, OWNER)
      );
      expect({ label, startThrew: start.threw, completeThrew: complete.threw }).toEqual({
        label,
        startThrew: true,
        completeThrew: true,
      });
    }

    // 迟到的 overdue 仍然只认被指派人：换个人开始必须失败
    const overdue = await makeInspection({ status: 'overdue' });
    const foreign = await rejectsWith(() => InspectionService.startInspection(overdue, OTHER));
    expect(foreign.threw).toBe(true);
    expect((await Inspection.findById(overdue._id)).status).toBe('overdue');
  });

  test('反复开始不得改写"实际开始"：首次开工时刻是取证事实，不是最后一次点按的时间', async () => {
    // 真实链条：迟开工的巡检先被开始一次（记 actualStartTime + 一条 started）→
    // 计划结束时间已过，调度器把 in_progress 打回 overdue → 作业人员回来又点一次"开始"。
    // 修复前 $set 无条件写 now ⇒ 首次时刻被抹掉，报表的"今日开始数"
    // （reportDashboardService 按 actualStartTime:$gte 统计）把这条算成刚开工，
    // 导出的"实际开始"列也不再可取证。
    const doc = await makeInspection(); // pending + 已过 planEndTime
    await markOverdueInspections();
    const first = await InspectionService.startInspection(
      await Inspection.findById(doc._id),
      OWNER
    );
    expect(first.actualStartTime).toBeInstanceOf(Date);

    // 换成一小时前的哨兵值：真实场景里首次开工与"再次点开始"必然差很久，
    // 若直接与 now 比对，毫秒级抖动能让变异体假绿。
    const T0 = new Date(Date.now() - 3600_000);
    await Inspection.findByIdAndUpdate(doc._id, { actualStartTime: T0 });

    await markOverdueInspections(); // 执行中再次被打回 overdue
    expect((await Inspection.findById(doc._id)).status).toBe('overdue');

    const restarted = await InspectionService.startInspection(
      await Inspection.findById(doc._id),
      OWNER
    );
    expect(restarted.status).toBe('in_progress');
    expect(restarted.actualStartTime).toEqual(T0);
    // 但每次开工仍必须留痕——保留首值不等于拒绝记录重复开始
    expect(restarted.executionLog.map((e) => e.action)).toEqual(['started', 'started']);
  });

  test('端到端：pending 被调度器改写后，仍能开工并完成（真实链条而非拼状态）', async () => {
    const doc = await makeInspection(); // pending + 已过 planEndTime
    await markOverdueInspections();
    const flipped = await Inspection.findById(doc._id);
    expect(flipped.status).toBe('overdue');

    const started = await InspectionService.startInspection(flipped, OWNER);
    // 开工后如果又被扫描成 overdue（另一轮周期），提交仍须成功
    await markOverdueInspections();
    expect((await Inspection.findById(doc._id)).status).toBe('overdue');
    const completed = await InspectionService.completeInspection(
      started,
      { result: 'normal', findings: [] },
      OWNER
    );
    expect(completed.status).toBe('completed');
    expect((await Inspection.findById(doc._id)).result).toBe('normal');
  });

  /**
   * 取消的准入档位逐档跑真实服务。给 F-151 那次改写（`$nin: ['completed','cancelled']`
   * → `$in: INSPECTION_OPEN_STATUSES`）兜底：改之前只有 pending 被覆盖过取消
   * （inspectionExecutionLogCap.test.js 的 cancelled 那一行），而"超期计划唯一的出路是
   * 取消"恰是本文件开头那条缺陷叙述里的兜底出口。方向从"排除终态"翻成"只放开放档位"之后，
   * 万一开放档位少一档，这里当场红，而不是等运维在页面上点不动。
   */
  test('取消的准入 = 开放档位：三档开放态可取消，两档终态 409', async () => {
    // 前提自证：两份清单铺满全集，否则"逐档"会因清单被削短而漏跑
    expect([...INSPECTION_OPEN_STATUSES, ...INSPECTION_TERMINAL_STATUSES].sort()).toEqual(
      [...INSPECTION_STATUSES].sort()
    );

    for (const st of INSPECTION_OPEN_STATUSES) {
      const doc = await makeInspection({ status: st });
      const cancelled = await InspectionService.cancelInspection(doc, `门禁取消 ${st}`, OWNER);
      expect({ st, after: cancelled.status }).toEqual({ st, after: 'cancelled' });
    }

    for (const st of INSPECTION_TERMINAL_STATUSES) {
      const doc = await makeInspection({ status: st });
      const r = await rejectsWith(() => InspectionService.cancelInspection(doc, '不该取消', OWNER));
      expect({ st, threw: r.threw, status: r.status }).toEqual({
        st,
        threw: true,
        status: 409,
      });
      expect(await Inspection.countDocuments({ _id: doc._id, status: st })).toBe(1);
    }
  });
});
