/**
 * updateInspection 的「已开始的巡检不能修改」必须是原子判定
 *
 * 缺陷形态（InspectionService.js:173-199 实测确认）：整条 update 路径是
 * 「读 → 内存里判 status → save()」三段式。控制器先 getInspectionById 取文档，
 * 服务再用**内存中**的 status 把门，最后 `inspection.save()` 按 _id 写回。
 * 中间任何一次并发改写状态都不参与判定：
 *   A: 打开编辑页（读到 pending）
 *   B: 同时点「开始执行」→ startInspection 原子地把库改成 in_progress
 *   A: 保存 → 内存里仍是 pending ⇒ 放行 ⇒ save() 把标题/时间窗/设备/执行人
 *      写进一条**已经在执行**的巡检
 * 于是"已开始的计划不可改"这条业务不变量只在"没人同时操作"时成立，
 * 而已经写进数据库的越权修改还会静默覆盖执行者正在用的计划。
 * 本类其余四个写操作（start/complete/review/cancel）都已经是
 * findOneAndUpdate + 状态前置条件，唯独 update 仍是读改写——不是权衡，是漏改。
 *
 * 判据分工：
 *   1. 竞态泄漏判据（核心）：交错发生后必须拒绝，且**库里字段不变**
 *   2. 前提自证：证明交错真的发生了（内存 pending vs 库 in_progress），
 *      否则第 1 条可能在演一个到不了的状态
 *   3. 反向对照：正常 pending 更新必须成功且逐字段落库 ⇒ "一律拒绝"不能让 1 变绿
 *   4. 白名单：body 里的 status/result/executionLog 不得绕过白名单写入
 *   5. 终态无并发也必须被拒（钉住原语义，不是我改出来的新语义）
 *   6. 返回体形状保持 populate（防止原子化把响应降级成裸 ObjectId）
 *   7. 记录被并发删除时不得报成功，也不得复活
 *   8. runValidators 保持开启：原子写不比 save() 松
 *
 * 可证伪性：把 findOneAndUpdate 的状态前置条件摘掉（或退回内存判定）⇒ 第 1 条红
 * （修复前实测 `threw: false`，字段真的写进了 in_progress 的巡检）；
 * 把 updatableFields 白名单删空 ⇒ 第 3 条红；把白名单换成 `Object.assign` ⇒ 第 4 条红。
 * 其余各条修复前后同样绿，是"原子化没把别的语义带走"的对照，不是缺陷证据。
 */

'use strict';

const mongoose = require('mongoose');
const Inspection = require('../../models/Inspection');
// Inspection 的 populate 路径引用 FireDevice/User；模型按 require 注册，
// 不显式引入会在 findOneAndUpdate 的 populate 阶段抛 MissingSchemaError
require('../../models/FireDevice');
const InspectionService = require('../../services/InspectionService');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const TAG = `zzatm${Date.now().toString(36)}`;
const OWNER = new mongoose.Types.ObjectId();

const makeInspection = (over = {}) =>
  Inspection.create({
    inspectionType: 'daily',
    title: `${TAG}-${Math.random().toString(36).slice(2, 8)}`,
    assignedTo: [OWNER],
    planStartTime: new Date(Date.now() + 3600_000),
    planEndTime: new Date(Date.now() + 7200_000),
    status: 'pending',
    ...over,
  });

const rejectsWith = (fn) =>
  fn().then(
    () => ({ threw: false }),
    (err) => ({ threw: true, status: err.statusCode || err.status, message: err.message })
  );

describe('updateInspection 的状态前置条件必须原子', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    // startInspection 会把 executionLog.userId populate 成用户文档；
    // 指派人若是"没有用户的 id"，populate 结果为 null，与本文件无关的断言会失真
    const User = require('../../models/User');
    await User.create({
      _id: OWNER,
      username: `${TAG}owner`,
      email: `${TAG}owner@example.com`,
      password: randomPassword(),
      roles: [],
    });
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(`^${TAG}`) });
    await require('../../models/User').deleteMany({ _id: OWNER });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('前提自证：读改写之间确实能插进一次原子改状态（不是在演到不了的状态）', async () => {
    const created = await makeInspection();
    const staleView = await Inspection.findById(created._id); // A 的内存视图
    const liveView = await Inspection.findById(created._id); // B 拿去开工

    const started = await InspectionService.startInspection(liveView, OWNER);
    expect(started.status).toBe('in_progress');
    // 两条必须同时成立才叫竞态：库里已变、A 手里还是旧值
    expect((await Inspection.findById(created._id)).status).toBe('in_progress');
    expect(staleView.status).toBe('pending');
  });

  test('竞态下不得把修改写进已在执行的巡检（核心判据）', async () => {
    const created = await makeInspection();
    const staleView = await Inspection.findById(created._id);
    await InspectionService.startInspection(await Inspection.findById(created._id), OWNER);

    const racingTitle = `${TAG}RACE-WRITTEN`;
    const r = await rejectsWith(() =>
      InspectionService.updateInspection(staleView, {
        title: racingTitle,
        description: '竞态写入的描述',
        planStartTime: new Date(Date.now() + 999 * 3600_000),
        assignedTo: [],
      })
    );
    expect({ threw: r.threw, statusCode: r.status }).toEqual({ threw: true, statusCode: 400 });

    // 拒绝之外还必须"什么都没写进去"：只断抛错会放过"先落库再抛错"的实现
    const db = await Inspection.findById(created._id).lean();
    expect(db.title).not.toBe(racingTitle);
    expect(db.description).toBeUndefined();
    expect(String(db.planStartTime)).not.toBe(String(new Date(Date.now() + 999 * 3600_000)));
    expect(db.assignedTo.map(String)).toEqual([String(OWNER)]);
    expect(db.status).toBe('in_progress');
  });

  test('反向对照：正常 pending 更新必须成功并逐字段落库（"一律拒绝"不能让上面两条绿）', async () => {
    const created = await makeInspection();
    const loaded = await InspectionService.getInspectionById(created._id);
    const newStart = new Date(Date.now() + 10 * 3600_000);
    const newEnd = new Date(Date.now() + 11 * 3600_000);

    const updated = await InspectionService.updateInspection(loaded, {
      title: `${TAG}ok-title`,
      description: `${TAG}ok-desc`,
      remark: `${TAG}ok-remark`,
      priority: 'high',
      planStartTime: newStart,
      planEndTime: newEnd,
      checkItems: [{ name: '消火栓水压', standard: '≥0.35MPa', required: true }],
    });
    expect(updated).toBeTruthy();
    expect(updated.title).toBe(`${TAG}ok-title`);

    const db = await Inspection.findById(created._id);
    expect({
      title: db.title,
      description: db.description,
      remark: db.remark,
      priority: db.priority,
      checkItems: db.checkItems.map((c) => `${c.name}|${c.standard}|${c.required}`),
      status: db.status,
    }).toEqual({
      title: `${TAG}ok-title`,
      description: `${TAG}ok-desc`,
      remark: `${TAG}ok-remark`,
      priority: 'high',
      checkItems: ['消火栓水压|≥0.35MPa|true'],
      status: 'pending',
    });
    expect(String(db.planStartTime)).toBe(String(newStart));
  });

  test('返回体仍是 populate 过的形状（原子化不得把响应降级成裸 ObjectId）', async () => {
    const created = await makeInspection();
    const loaded = await InspectionService.getInspectionById(created._id);
    const updated = await InspectionService.updateInspection(loaded, {
      title: `${TAG}shape`,
    });
    const assignee = updated.assignedTo[0];
    // 裸 ObjectId 时 String(它) 直接是 24 位 hex；populate 后才有 username
    expect(assignee._id && String(assignee._id)).toBe(String(OWNER));
    expect(assignee.username).toBe(`${TAG}owner`);
  });

  test('白名单：body 夹带 status/result/executionLog 不得绕过', async () => {
    const created = await makeInspection();
    const loaded = await InspectionService.getInspectionById(created._id);
    await InspectionService.updateInspection(loaded, {
      title: `${TAG}wl`,
      status: 'completed',
      result: 'abnormal',
      actualEndTime: new Date(),
      executionLog: [{ userId: OWNER, action: 'hacked', timestamp: new Date() }],
    });
    const db = await Inspection.findById(created._id);
    expect(db.status).toBe('pending');
    expect(db.result).toBeUndefined();
    expect(db.actualEndTime).toBeUndefined();
    expect(db.executionLog.length).toBe(0);
  });

  test('无并发的终态同样不可修改（原语义保持，不是只修竞态）', async () => {
    for (const status of ['in_progress', 'completed', 'cancelled', 'overdue']) {
      const created = await makeInspection({
        status,
        actualStartTime: status === 'pending' ? undefined : new Date(),
      });
      const loaded = await InspectionService.getInspectionById(created._id);
      const r = await rejectsWith(() =>
        InspectionService.updateInspection(loaded, { title: `${TAG}should-not-stick-${status}` })
      );
      // 400 不是笔误：本仓口径「状态不允许」=400、「状态转移冲突」=409
      // （start/complete/review 抛 conflict，update 的状态闸抛 badRequest）。
      // 原子化只把判定时机从内存挪进查询条件，对外契约不变。
      expect({ status, threw: r.threw, code: r.status }).toEqual({
        status,
        threw: true,
        code: 400,
      });
      expect((await Inspection.findById(created._id)).title).not.toBe(
        `${TAG}should-not-stick-${status}`
      );
    }
  });

  test('服务层校验未被原子化带走：runValidators 仍生效（绕过路由直连服务）', async () => {
    // save() 天然跑 schema 校验；换成 findOneAndUpdate 后必须显式 runValidators，
    // 否则"路由漏校验/内部调用方绕过路由"时超长字段能直接落库（路由确有 title≤200，
    // 但那是另一层的闸，本条钉的是服务层不比自己变松）。
    const created = await makeInspection();
    const loaded = await InspectionService.getInspectionById(created._id);
    const r = await rejectsWith(() =>
      InspectionService.updateInspection(loaded, { title: 'x'.repeat(201) })
    );
    expect(r.threw).toBe(true);
    expect((await Inspection.findById(created._id)).title).toBe(created.title);
  });

  test('记录被并发删除时不得报成功，也不得复活', async () => {
    const created = await makeInspection();
    const staleView = await Inspection.findById(created._id);
    await Inspection.deleteOne({ _id: created._id });

    const r = await rejectsWith(() =>
      InspectionService.updateInspection(staleView, { title: `${TAG}ghost` })
    );
    expect(r.threw).toBe(true);
    expect(await Inspection.countDocuments({ _id: created._id })).toBe(0);
  });
});
