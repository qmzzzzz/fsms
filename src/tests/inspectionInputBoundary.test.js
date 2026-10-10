/**
 * 巡检写路径的输入边界（枚举 / 长度 / 类型）
 *
 * 起因：第 8 轮审计代理报「InspectionService 的四个 findOneAndUpdate 都没传
 * runValidators，而 :224 那条有」，据此建议补 flag。逐条核到源码后**不采纳**，
 * 理由是可执行的那道闸在路由层，不在模型层：
 *   - `start` 写的是常量与服务端时刻，没有用户可控值；
 *   - `complete`/`review`/`cancel` 写的每个用户字段，路由都先过
 *     `completeValidation`/`reviewValidation`/`cancelValidation`
 *     （routes/inspectionRoutes.js:336/366/405 已挂载，非只登记不接线），
 *     而四个处理器的 `validationResult` 判空都在 `getInspectionById` **之前**，
 *     所以被拒的请求连文档都不会被读到，更谈不上写；
 *   - `services/InspectionService.js` 里 `cancelValidation` 的注释（:371-384）
 *     明确记录了"取消走 findOneAndUpdate，默认不跑校验器，所以 schema 的
 *     maxlength 在这条路上是装饰"——这是**已知并被主动选择**的收口位置，
 *     再补 runValidators 等于把同一判据写两遍，还把 Mongoose 的英文
 *     ValidationError 重新变成客户端可见错误（P3-16 当初消掉的就是它）。
 *
 * 但核查中发现真缺口：**这条边界零用例覆盖**——全仓没有任何用例断言过
 * '无效的巡检结果'/'无效的审核结果'/超长备注/超长取消原因被拒。
 * `constants/inspectionEnumSingleSource.test.js` 只钉"枚举同源"（静态），
 * 不钉"越界的值进不了库"（行为）。也就是说删掉任一校验器，现有 501 个套件仍全绿，
 * 而 schema 的 enum/maxlength 在查询级写入上根本不执行 ⇒ 越界值直接落库：
 *   - 无效 `status`/`result` 会绕开所有状态档位判断（`$in` 闸门对未知档位一律不放行，
 *     于是那条记录既开始不了也提交不了，成僵尸）；
 *   - 超长 `executionLog[].remark` 正是 :371-384 记的 16MB 卡死路径。
 *
 * 因此本套件的判据是"边界拒绝 **且** 未写入"成对出现，并各配一条反向对照，
 * 防止把闸做成"一律拒绝"。
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const {
  INSPECTION_RESULTS,
  INSPECTION_FINDING_SEVERITIES,
  INSPECTION_REVIEW_RESULTS,
} = require('../constants/inspection');

const DEPT = 'ZZIB-A';
const stamp = `zzib${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('巡检 complete/review/cancel 的输入边界必须拒绝且不落库', () => {
  let app;
  let Inspection;
  let User;
  let Role;
  let Permission;
  let token;
  let operator;

  const sign = (u) =>
    jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    Inspection = require('../models/Inspection');
    require('../models/AuditLog');
    require('../models/TokenBlacklist');

    // 权限轴与数据范围轴两条独立轴：*:* 过 checkPermission，范围由 level 决定
    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `${stamp} 边界`,
      code: `${stamp}_scope`,
      level: 7,
      permissions: [wildcard._id],
    });
    operator = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: randomPassword(),
      department: DEPT,
      roles: [role._id],
    });
    token = sign(operator);

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await Role.deleteMany({ name: new RegExp(`^${stamp} `) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  /** 建一条 pending 巡检；可选直接开工（complete/review 需要 in_progress/completed） */
  const mk = async (tag, { started = false, done = false } = {}) => {
    const created = await request(app)
      .post('/api/inspections')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: `${stamp}-${tag}`,
        inspectionType: 'daily',
        planStartTime: '2026-09-20T08:00:00.000Z',
        planEndTime: '2026-09-20T10:00:00.000Z',
        checkItems: [{ name: `${stamp} 检查项` }],
        // 数据范围闸按 departmentField 判：inspection 的部门维度就是 locations.building
        //（见 inspectionWriteScopeGates.test.js 的同类前提），不填这条则 level 7 也进不去
        locations: [{ building: DEPT }],
      });
    expect(created.status).toBe(201);
    const id = created.body.data._id;
    if (started || done) {
      const start = await request(app)
        .put(`/api/inspections/${id}/start`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(start.status).toBe(200);
    }
    if (done) {
      const comp = await request(app)
        .put(`/api/inspections/${id}/complete`)
        .set('Authorization', `Bearer ${token}`)
        .send({ result: INSPECTION_RESULTS[0] });
      expect(comp.status).toBe(200);
    }
    return id;
  };

  const raw = (id) => Inspection.findById(id).lean();

  const put = (path, body) =>
    request(app).put(path).set('Authorization', `Bearer ${token}`).send(body);

  // 前提自证：本套件赖以成立的两件事——执行点确实挂在路由上，且模型层在查询级
  // 写入上不会兜住越界值（否则"路由是唯一闸"这个判据就站不住，本套件也就在钉一个假命题）
  test('前提自证：路由里三组校验器都已挂载（只登记不接线就等于没有）', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '../routes/inspectionRoutes.js'), 'utf8');
    // 钉「路径 ↔ 校验器」的配对，而不是"某个 router.put 里出现过这个名字"：
    // 后者会把 completeValidation 挂到 /start 上也算通过。
    const PAIRS = [
      ['/complete', 'completeValidation'],
      ['/review', 'reviewValidation'],
      ['/cancel', 'cancelValidation'],
    ];
    for (const [seg, name] of PAIRS) {
      expect(src).toMatch(new RegExp(`const ${name} = \\[`));
      expect(src).toMatch(new RegExp(`'/:id${seg}',[\\s\\S]{0,200}?${name},`));
    }
  });

  test('前提自证：findOneAndUpdate 不跑校验器（越界值真能进库 ⇒ 只能靠路由挡）', async () => {
    const id = (await mk('probe')).toString();
    const bad = `${stamp}-${'x'.repeat(600)}`;
    // 绕过 HTTP，直接按服务层的写法落一条超长 remark：
    // 若模型层真会拒绝，说明"路由是唯一执行点"这个前提被高估，本套件的定位就要重写。
    const updated = await Inspection.findOneAndUpdate(
      { _id: id },
      { $set: { remark: bad } },
      { new: true }
    );
    expect(updated.remark.length).toBeGreaterThan(500);
    // 对照组：同一值走 save() 必须被 schema 拦下（证明差异在写入形态，不在值本身）
    await expect(
      (async () => {
        const doc = await Inspection.findById(id);
        doc.remark = bad;
        await doc.save();
      })()
    ).rejects.toThrow(/最多 500|maximum size/);
  });

  test('complete：result 越界 → 400，且状态与结果都没被写进去', async () => {
    const id = await mk('c-result', { started: true });
    const before = await raw(id);
    const res = await put(`/api/inspections/${id}/complete`, { result: 'garbage' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    const after = await raw(id);
    expect(after.status).toBe(before.status);
    expect(after.status).toBe('in_progress');
    expect(after.actualEndTime).toBeUndefined();
  });

  test('complete：findings[].severity 越界 → 400，findings 不落库', async () => {
    const id = await mk('c-sev', { started: true });
    const res = await put(`/api/inspections/${id}/complete`, {
      result: INSPECTION_RESULTS[1],
      findings: [{ issue: `${stamp} 灭火器失压`, severity: 'catastrophic' }],
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    const after = await raw(id);
    expect(after.findings ?? []).toHaveLength(0);
    expect(after.status).toBe('in_progress');
  });

  test('complete：remark 超长 → 400（schema 的 maxlength 在这条路上不执行）', async () => {
    const id = await mk('c-len', { started: true });
    const res = await put(`/api/inspections/${id}/complete`, {
      result: INSPECTION_RESULTS[0],
      remark: 'x'.repeat(501),
    });
    expect(res.status).toBe(400);
    expect((await raw(id)).remark ?? '').toBe('');
  });

  test('complete：remark 传对象 → 400，不得被 stringify 成 "[object Object]" 入库', async () => {
    // 钉 utils/validationRules 的 mustBeString：express-validator 的 trim/isLength
    // 会把值 stringify 后**写回 req.body**，缺 isString 前置时对象能一路通过长度校验，
    // 落库的却是字面量 '[object Object]'（审计/导出侧读起来像一条正常备注）。
    const id = await mk('c-type', { started: true });
    const res = await put(`/api/inspections/${id}/complete`, {
      result: INSPECTION_RESULTS[0],
      remark: { a: 1 },
    });
    expect(res.status).toBe(400);
    expect((await raw(id)).remark).not.toBe('[object Object]');
  });

  test('review：reviewComment 超长 → 400，审核结论不写', async () => {
    const id = await mk('r-len', { started: true, done: true });
    const res = await put(`/api/inspections/${id}/review`, {
      reviewResult: INSPECTION_REVIEW_RESULTS[0],
      reviewComment: 'y'.repeat(501),
    });
    expect(res.status).toBe(400);
    const after = await raw(id);
    expect(after.reviewResult).toBeUndefined();
    expect(after.reviewedBy).toBeUndefined();
  });

  test('review：reviewResult 越界 → 400（路由与服务层两处判据同值）', async () => {
    const id = await mk('r-enum', { started: true, done: true });
    const res = await put(`/api/inspections/${id}/review`, { reviewResult: 'maybe' });
    expect(res.status).toBe(400);
    expect((await raw(id)).reviewResult).toBeUndefined();
  });

  test('cancel：reason 超长 → 400，executionLog 一条都不多', async () => {
    // 这条正是 routes/inspectionRoutes.js:371-384 记录的 16MB 卡死路径：
    // $slice 只裁条数不裁长度，MB 级 remark 能把文档顶过上限后连保存都做不了。
    const id = await mk('x-len', {});
    const before = (await raw(id)).executionLog ?? [];
    const res = await put(`/api/inspections/${id}/cancel`, { reason: 'z'.repeat(501) });
    expect(res.status).toBe(400);
    const after = await raw(id);
    expect(after.executionLog ?? []).toHaveLength(before.length);
    expect(after.status).toBe('pending');
  });

  test('cancel：reason 传对象 → 400（不得落成 "[object Object]"）', async () => {
    const id = await mk('x-type', {});
    const res = await put(`/api/inspections/${id}/cancel`, { reason: { a: 1 } });
    expect(res.status).toBe(400);
    const log = (await raw(id)).executionLog ?? [];
    expect(log.some((e) => String(e.remark).includes('[object Object]'))).toBe(false);
  });

  // ===== 反向对照：闸不是"一律拒绝" =====
  test('对照：合法值一路走通 pending→in_progress→completed→审核', async () => {
    const id = await mk('ok', {});
    expect((await put(`/api/inspections/${id}/start`, {})).status).toBe(200);
    const comp = await put(`/api/inspections/${id}/complete`, {
      result: INSPECTION_RESULTS[1],
      findings: [{ issue: `${stamp} 消火箱被遮挡`, severity: INSPECTION_FINDING_SEVERITIES[2] }],
      location: `${stamp} 三楼`,
      remark: 'x'.repeat(500), // 恰好到上限：边界值必须放行
    });
    expect(comp.status).toBe(200);
    const done = await raw(id);
    expect(done.status).toBe('completed');
    expect(done.findings).toHaveLength(1);
    expect(done.remark.length).toBe(500);

    const rev = await put(`/api/inspections/${id}/review`, {
      reviewResult: INSPECTION_REVIEW_RESULTS[0],
      reviewComment: 'y'.repeat(500),
    });
    expect(rev.status).toBe(200);
    expect((await raw(id)).reviewResult).toBe(INSPECTION_REVIEW_RESULTS[0]);
  });

  test('对照：合法 reason 取消成功，executionLog 里确实留下取消原因', async () => {
    const id = await mk('ok-cancel', {});
    const res = await put(`/api/inspections/${id}/cancel`, { reason: '现场装修暂停' });
    expect(res.status).toBe(200);
    const after = await raw(id);
    expect(after.status).toBe('cancelled');
    expect(after.executionLog.at(-1).remark).toBe('现场装修暂停');
  });
});
