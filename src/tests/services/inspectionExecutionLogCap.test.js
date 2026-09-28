'use strict';

/**
 * executionLog 的尾部封顶与"截断可数"声明
 *
 * 缺陷机制（实测，不是推测）：`overdue` 只是调度器打的时间标记、不是工作流阶段 ——
 * `markOverdueInspections` 每轮把 `planEndTime` 已过的 `in_progress` 打回 `overdue`
 * （deviceReminder.js:151-158），而 `startInspection` 的条件是 `status: {$in:['pending','overdue']}`
 * ⇒ 一条过期计划可以被**反复开始**，每次开始都往 `executionLog` 追加一条留痕，
 * 数组无上限增长；它还会随详情接口整段返回并 populate executionLog.userId。
 *
 * 修法口径：`$slice` 保尾部 N 条 + `executionLogCount` 记总次数 ⇒
 * `count > length` 就是"有留痕被截断"的载体（与 xlsx 导出的 X-Export-Truncated 同一原则：
 * 截断可以发生，但不许静默）。本文件把四条写入路径各自的封顶都钉住，
 * 并区分"保尾"与"保头"这两种 `$slice` 写法（第 3 条用例是唯一的杀手）。
 */

process.env.INSPECTION_EXECUTION_LOG_CAP = '3'; // 必须早于 require：服务在模块加载期读它

const mongoose = require('mongoose');
const Inspection = require('../../models/Inspection');
// 服务在四个写入点后都链式 populate findings.deviceId ⇒ 不注册 FireDevice 会在
// populate 规划期就抛 MissingSchemaError（与被测判据无关，但会挡死用例）
require('../../models/FireDevice');
require('../../models/User');
const InspectionService = require('../../services/InspectionService');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const CAP = 3;
const TAG = `elc${Date.now().toString(36)}`;
const OWNER = new mongoose.Types.ObjectId();
const REVIEWER = new mongoose.Types.ObjectId();
const PAST = new Date(Date.now() - 3600_000);

/** 造 n 条带 remark 标记的历史留痕，用来区分"保尾"还是"保头" */
const seeds = (n) =>
  Array.from({ length: n }, (_, i) => ({
    userId: OWNER,
    action: 'seed',
    timestamp: new Date(PAST.getTime() + i * 1000),
    remark: `seed-${i + 1}`,
  }));

const makeInspection = (over = {}) =>
  Inspection.create({
    inspectionType: 'daily',
    title: `${TAG}-${Math.random().toString(36).slice(2, 8)}`,
    assignedTo: [OWNER],
    planStartTime: PAST,
    planEndTime: PAST,
    status: 'pending',
    ...over,
  });

describe('executionLog 封顶：保尾、可数、四条路径都带上', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    await User.create([
      {
        _id: OWNER,
        username: `${TAG}owner`,
        email: `${TAG}owner@example.com`,
        password: randomPassword(),
        roles: [],
      },
      {
        _id: REVIEWER,
        username: `${TAG}rev`,
        email: `${TAG}rev@example.com`,
        password: randomPassword(),
        roles: [],
      },
    ]);
  });

  afterAll(async () => {
    const User = require('../../models/User');
    await Inspection.deleteMany({ title: new RegExp(`^${TAG}`) }).catch(() => {});
    await User.deleteMany({ _id: { $in: [OWNER, REVIEWER] } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('新建的巡检计数从 0 起（字段默认值，不是 undefined）', async () => {
    const doc = await makeInspection();
    expect(doc.executionLogCount).toBe(0);
    expect(doc.executionLog).toHaveLength(0);
  });

  test('反复开始同一条过期计划：数组封顶在 CAP 条，而总次数照实累加', async () => {
    let doc = await makeInspection({ status: 'overdue' });
    for (let i = 0; i < CAP * 2; i++) {
      await InspectionService.startInspection(doc, OWNER);
      // 模拟调度器的下一轮：in_progress 又被打回 overdue（这正是可反复开始的来源）
      await Inspection.findByIdAndUpdate(doc._id, { status: 'overdue' });
      doc = await Inspection.findById(doc._id);
    }
    expect(doc.executionLog).toHaveLength(CAP);
    expect(doc.executionLogCount).toBe(CAP * 2);
    // count - length 就是"被截掉了多少条"，这个事实必须留在文档里
    expect(doc.executionLogCount - doc.executionLog.length).toBe(CAP);
  });

  test('$slice 保的是尾部：旧留痕被丢弃，而不是新写入被丢弃', async () => {
    const doc = await makeInspection({ status: 'overdue', executionLog: seeds(CAP + 1) });
    expect(doc.executionLog).toHaveLength(CAP + 1); // 前提：种进去的确实比上限多一条

    await InspectionService.startInspection(doc, OWNER);
    const after = await Inspection.findById(doc._id);
    expect(after.executionLog).toHaveLength(CAP);
    const remarks = after.executionLog.map((e) => e.remark).filter(Boolean);
    // 种 4 条 + 本次 1 条 = 5 条，保尾 3 条 ⇒ 留下的必须是最后这三条：
    // [seed-3, seed-4, started]。写成 `$slice: CAP`（保头）会留下 seed-1..3、
    // 把本次写入丢掉 ⇒ 两条断言同时红。
    expect(remarks).toEqual(['seed-3', 'seed-4']);
    expect(after.executionLog.at(-1).action).toBe('started');
  });

  test.each([
    ['started', 'overdue', (doc) => InspectionService.startInspection(doc, OWNER)],
    [
      'completed',
      'in_progress',
      (doc) => InspectionService.completeInspection(doc, { result: 'normal', findings: [] }, OWNER),
    ],
    [
      'review_approved',
      'completed',
      (doc) => InspectionService.reviewInspection(doc, { reviewResult: 'approved' }, REVIEWER),
    ],
    ['cancelled', 'pending', (doc) => InspectionService.cancelInspection(doc, '测试取消', OWNER)],
  ])('写入路径 %s 也必须封顶（同一判据不得只装在一处）', async (action, status, run) => {
    const doc = await makeInspection({
      status,
      executionLog: seeds(CAP + 1),
      ...(status === 'completed' ? { actualEndTime: new Date() } : {}),
    });
    await run(doc);
    const after = await Inspection.findById(doc._id);
    expect(after.executionLog).toHaveLength(CAP);
    expect(after.executionLog.at(-1).action).toBe(action);
    expect(after.executionLogCount).toBe(1);
  });
});
