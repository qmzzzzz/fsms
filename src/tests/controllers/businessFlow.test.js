/**
 * 业务闭环端到端覆盖（冲 100%：device/alarm/inspection 控制器与服务层）
 *
 * 三大业务此前覆盖率极低（InspectionService 7.5% / alarmController 13.2% /
 * inspectionController 14.9% / deviceController 19.1% / AlarmService 35.6%）。
 * 本文件经 HTTP 层驱动全生命周期：创建 → 列表/详情 → 状态迁移（含非法迁移拒绝）
 * → 统计 → 删除保护。报警按 M-1 指派给操作者本人以走通到场/处置全流程。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('业务闭环：设备 / 报警 / 巡检（冲 100%）', () => {
  let app;
  let FireDevice;
  let FireAlarm;
  let Inspection;
  let adminToken;
  let selfUserId;
  const stamp = `bf${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

  // 设备 ID 为设备类用例的自包含前置：每个用例自行创建设备后经此传递，
  // 不再依赖「设备：创建」用例先行（--randomize 下该用例可能最后执行，
  // 导致其余设备用例拿到 undefined，URL 变成 /api/devices/undefined/...）
  const createFixtureDevice = async (test) => {
    const createRes = await authed()
      .post('/api/devices')
      .send({
        deviceCode: `BF-${stamp}-${test}`,
        deviceName: `烟感_业务闭环_${test}`,
        deviceType: 'smoke_detector',
        installDate: new Date().toISOString(),
        location: { building: 'A栋', floor: '3F', detail: `走廊${test}` },
      });
    expect(createRes.status).toBe(201);
    return String(createRes.body.data._id || createRes.body.data.id);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_业务闭环',
      code: `SUPER_ADMIN_BF_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `bfadmin${stamp}`,
      email: `bfadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    selfUserId = String(admin._id);

    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^BF-${stamp}`) }).catch(() => {});
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `bfadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_BF_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  // 与仓库既有测试同口径：动词先行再 .set（request(app).set 直调在该 supertest
  // 版本下返回对象没有 set，必须先 get/post/put/delete 产生 Test 请求对象）
  const authed = () => ({
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`),
    post: (url) => request(app).post(url).set('Authorization', `Bearer ${adminToken}`),
    put: (url) => request(app).put(url).set('Authorization', `Bearer ${adminToken}`),
    delete: (url) => request(app).delete(url).set('Authorization', `Bearer ${adminToken}`),
  });

  // ================= 设备 =================

  test('设备：创建 → 列表 → 详情 → 更新 → 统计 → 到期查询', async () => {
    const createRes = await authed()
      .post('/api/devices')
      .send({
        deviceCode: `BF-${stamp}-001`,
        deviceName: '烟感_业务闭环',
        deviceType: 'smoke_detector',
        installDate: new Date().toISOString(),
        location: { building: 'A栋', floor: '3F', detail: '走廊东侧' },
      });
    expect(createRes.status).toBe(201);
    const deviceId = String(createRes.body.data._id || createRes.body.data.id);

    const list = await authed().get('/api/devices?page=1&limit=10');
    expect(list.status).toBe(200);
    expect(list.body.data.length).toBeGreaterThan(0);

    const detail = await authed().get(`/api/devices/${deviceId}`);
    expect(detail.status).toBe(200);
    // deviceCode 模型层 uppercase:true，比对前统一大写
    expect(detail.body.data.deviceCode.toUpperCase()).toBe(`BF-${stamp}-001`.toUpperCase());

    const update = await authed().put(`/api/devices/${deviceId}`).send({ deviceName: '烟感_更名' });
    expect(update.status).toBe(200);
    // status 不在可更新白名单（P2-16）：显式拒绝
    const statusViaUpdate = await authed()
      .put(`/api/devices/${deviceId}`)
      .send({ status: 'in_use' });
    expect(statusViaUpdate.status).toBe(400);

    const stats = await authed().get('/api/devices/stats');
    expect(stats.status).toBe(200);

    const expiring = await authed().get('/api/devices/expiring?days=30');
    expect(expiring.status).toBe(200);
  });

  test('设备：状态迁移 normal → warning → fault → maintenance → normal；维护记录推进', async () => {
    const deviceId = await createFixtureDevice('-901');
    // status 枚举：normal/warning/fault/offline/maintenance/scrapped（DEVICE_STATUS）
    const toWarn = await authed()
      .put(`/api/devices/${deviceId}/status`)
      .send({ status: 'warning' });
    expect(toWarn.status).toBe(200);
    expect(toWarn.body.data.status).toBe('warning');

    const toFault = await authed().put(`/api/devices/${deviceId}/status`).send({ status: 'fault' });
    expect(toFault.status).toBe(200);

    const toMaint = await authed()
      .put(`/api/devices/${deviceId}/status`)
      .send({ status: 'maintenance' });
    expect(toMaint.status).toBe(200);

    const back = await authed().put(`/api/devices/${deviceId}/status`).send({ status: 'normal' });
    expect(back.status).toBe(200);

    // 非法枚举值被路由校验拒绝
    const badStatus = await authed()
      .put(`/api/devices/${deviceId}/status`)
      .send({ status: 'in_use' });
    expect(badStatus.status).toBe(400);

    // 维护记录：routine 类推进检查周期
    const maint = await authed()
      .post(`/api/devices/${deviceId}/maintenance`)
      .send({
        type: 'routine',
        content: `例行维护_${stamp}`,
      });
    // 实测 200（维护记录接口固定 200，从未返回过 201）
    expect(maint.status).toBe(200);
  });

  test('设备：维护记录校验被真正消费——非法 type/超长 content 返回 400（此前校验器是死代码）', async () => {
    const deviceId = await createFixtureDevice('-903');
    // deviceRoutes.js maintenanceValidation：type ∈ [routine,repair,replacement,inspection]、content 1-500。
    // 修复前控制器不读 validationResult → 非法 type 冲模型 enum 抛 ValidationError=500；
    // content 无 schema 上限 → 超长被静默入库。现两者都应被路由校验挡下返回 400。
    const badType = await authed()
      .post(`/api/devices/${deviceId}/maintenance`)
      .send({ type: 'not_a_real_type', content: `x_${stamp}` });
    expect(badType.status).toBe(400);
    expect(badType.status).not.toBe(500);

    const tooLong = await authed()
      .post(`/api/devices/${deviceId}/maintenance`)
      .send({ type: 'repair', content: 'a'.repeat(501) });
    expect(tooLong.status).toBe(400);

    // 合法维护记录仍正常入库（守卫没把正路一起堵死）
    const ok = await authed()
      .post(`/api/devices/${deviceId}/maintenance`)
      .send({ type: 'repair', content: `ok_${stamp}` });
    expect(ok.status).toBe(200);
  });

  test('设备：报废 → 重复报废拒绝 → 报废后状态变更拒绝 → 删除', async () => {
    const deviceId = await createFixtureDevice('-902');
    const scrap = await authed()
      .put(`/api/devices/${deviceId}/scrap`)
      .send({ scrapReason: `测试报废_${stamp}` });
    expect(scrap.status).toBe(200);

    const dupScrap = await authed()
      .put(`/api/devices/${deviceId}/scrap`)
      .send({ scrapReason: 'again' });
    expect(dupScrap.status).toBe(400);

    const afterScrap = await authed()
      .put(`/api/devices/${deviceId}/status`)
      .send({ status: 'normal' });
    expect(afterScrap.status).toBe(400);

    const del = await authed().delete(`/api/devices/${deviceId}`);
    // 实测 200（删除接口固定 200，从未返回过 204）
    expect(del.status).toBe(200);
  });

  // ================= 报警 =================

  test('报警：上报 → 列表/详情/统计 → 指派 → 到场 → 处置完成', async () => {
    const report = await authed()
      .post('/api/alarms/report')
      .send({
        alarmType: 'other',
        description: `火警闭环_${stamp}`,
        level: 'warning',
        location: { building: 'B栋', floor: '2F' },
      });
    expect(report.status).toBe(201);
    const alarmId = String(report.body.data._id || report.body.data.id);

    const list = await authed().get('/api/alarms?page=1&limit=10');
    expect(list.status).toBe(200);

    const detail = await authed().get(`/api/alarms/${alarmId}`);
    expect(detail.status).toBe(200);

    const stats = await authed().get('/api/alarms/stats');
    expect(stats.status).toBe(200);

    // M-1：到场/处置仅限被指派处理人本人 → 指派给自己走通全流程
    const dispatch = await authed()
      .put(`/api/alarms/${alarmId}/dispatch`)
      .send({ handlerId: selfUserId });
    expect(dispatch.status).toBe(200);

    const arrive = await authed().put(`/api/alarms/${alarmId}/arrive`);
    expect(arrive.status).toBe(200);

    const resolve = await authed()
      .put(`/api/alarms/${alarmId}/resolve`)
      .send({
        handleResult: `已扑灭_${stamp}`,
        cause: 'fire',
      });
    expect(resolve.status).toBe(200);
    // 处置完成的终态必须真的落到 resolved 且带上处理结果：
    // 只断 200 时，状态机回滚或结果未写入都看不出来
    expect(resolve.body.data.status).toBe('resolved');
    expect(resolve.body.data.handleResult).toContain('已扑灭');
  });

  test('报警：指派不存在处理人被拒；误报与取消分支', async () => {
    const a1 = await authed()
      .post('/api/alarms/report')
      .send({
        alarmType: 'patrol_find',
        description: `误报闭环_${stamp}`,
        level: 'info',
      });
    expect(a1.status).toBe(201);
    // 上报后必须落到 pending 且已带初始处理日志：只断 201 时，
    // 「先建单再补日志」的两步写或状态初值写错都看不出来
    expect(a1.body.data.status).toBe('pending');
    expect(a1.body.data.processLog.map((l) => l.action)).toEqual(['alarm_received']);
    const falseId = String(a1.body.data._id || a1.body.data.id);

    const badHandler = await authed()
      .put(`/api/alarms/${falseId}/dispatch`)
      .send({
        handlerId: String(new mongoose.Types.ObjectId()),
      });
    expect(badHandler.status).toBe(400);
    // 400 必须点名「处理人不存在」：指派路径还有「账户被禁用」「越权指派」等拒绝理由，
    // 不点名就分不清是哪道闸挡下的（更无法发现闸门被换掉）
    expect(badHandler.body.message).toBe('指定的处理人不存在');
    // 且拒绝不等于「先写后报错」：报警必须仍是 pending 且未被写入 handler
    const afterBad = await authed().get(`/api/alarms/${falseId}`);
    expect(afterBad.body.data.status).toBe('pending');
    expect(afterBad.body.data.handler).toBeFalsy();

    const falseAlarm = await authed()
      .put(`/api/alarms/${falseId}/false-alarm`)
      .send({
        reason: `演练触发_${stamp}`,
      });
    expect(falseAlarm.status).toBe(200);
    // 误报是终态：状态机必须真的落到 false_alarm 且带处理结果与原因，
    // 只断 200 时，状态没改/原因未落库都看不出来
    expect(falseAlarm.body.data.status).toBe('false_alarm');
    expect(falseAlarm.body.data.cause).toBe('false_alarm');
    expect(falseAlarm.body.data.handleResult).toContain('演练触发');
    expect(falseAlarm.body.data.resolvedAt).toBeTruthy();
    expect(falseAlarm.body.data.processLog.at(-1).action).toBe('marked_false_alarm');

    const a2 = await authed()
      .post('/api/alarms/report')
      .send({
        alarmType: 'phone_report',
        description: `取消闭环_${stamp}`,
        level: 'info',
      });
    const cancelId = String(a2.body.data._id || a2.body.data.id);
    const cancel = await authed()
      .put(`/api/alarms/${cancelId}/cancel`)
      .send({ reason: `重复上报_${stamp}` });
    expect(cancel.status).toBe(200);
    // 取消同样是终态 + 留痕：状态必须为 cancelled，取消原因进处理日志
    expect(cancel.body.data.status).toBe('cancelled');
    const cancelLog = cancel.body.data.processLog.at(-1);
    expect(cancelLog.action).toBe('cancelled');
    expect(cancelLog.remark).toContain('重复上报');
  });

  // ================= 巡检 =================

  test('巡检：创建 → 更新 → 开始 → 取消 → 删除；统计与非法日期过滤', async () => {
    const create = await authed()
      .post('/api/inspections')
      .send({
        title: `巡检闭环_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        planEndTime: new Date(Date.now() + 7200 * 1000).toISOString(),
        locations: [{ building: 'C栋' }],
        checkItems: [{ name: '灭火器压力', standard: '指针位于绿区' }],
        description: '覆盖用巡检计划',
      });
    expect(create.status).toBe(201);
    // 状态机起点：新建计划必须是 pending
    expect(create.body.data.status).toBe('pending');
    const inspId = String(create.body.data._id || create.body.data.id);

    const update = await authed().put(`/api/inspections/${inspId}`).send({
      description: '更名后的巡检计划',
      priority: 'high',
    });
    expect(update.status).toBe(200);

    const list = await authed().get('/api/inspections?page=1&limit=10');
    expect(list.status).toBe(200);

    const badDate = await authed().get('/api/inspections?startDate=not-a-date');
    expect(badDate.status).toBe(400);

    const start = await authed().put(`/api/inspections/${inspId}/start`);
    expect(start.status).toBe(200);
    expect(start.body.data.status).toBe('in_progress');

    // 时间窗倒置（P2-19 关联）：planEndTime < planStartTime 被路由校验拒绝
    const inverted = await authed()
      .post('/api/inspections')
      .send({
        title: `倒置_${stamp}`,
        inspectionType: 'daily',
        planStartTime: new Date(Date.now() + 7200 * 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: '应急灯' }],
      });
    expect(inverted.status).toBe(400);

    const cancel = await authed()
      .put(`/api/inspections/${inspId}/cancel`)
      .send({ reason: '计划变更' });
    expect(cancel.status).toBe(200);
    expect(cancel.body.data.status).toBe('cancelled');

    const stats = await authed().get('/api/inspections/stats');
    expect(stats.status).toBe(200);

    const del = await authed().delete(`/api/inspections/${inspId}`);
    expect(del.status).toBe(200);
    // 删除的判据是记录真的没了：200 也可能是「已取消故无需删除」的空操作
    expect(await require('../../models/Inspection').findById(inspId)).toBeNull();
  });

  test('巡检：执行完成 → 自审被拒（M-2 分离）；未指派记录可审通过', async () => {
    // 场景一：执行人是自己 → 自审自批被禁止
    const ownCreate = await authed()
      .post('/api/inspections')
      .send({
        title: `自审禁止_${stamp}`,
        inspectionType: 'weekly',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: '疏散通道' }],
        assignedTo: [selfUserId],
      });
    expect(ownCreate.status).toBe(201);
    const ownId = String(ownCreate.body.data._id || ownCreate.body.data.id);

    const start = await authed().put(`/api/inspections/${ownId}/start`);
    expect(start.status).toBe(200);
    const complete = await authed()
      .put(`/api/inspections/${ownId}/complete`)
      .send({
        result: 'normal',
        findings: [{ issue: '通道畅通', severity: 'low' }],
        location: 'C栋大厅',
      });
    expect(complete.status).toBe(200);
    // 执行完成的终态：只断 200 时，状态机停在 in_progress 也不会红
    expect(complete.body.data.status).toBe('completed');

    const selfReview = await authed().put(`/api/inspections/${ownId}/review`).send({
      result: 'approved',
      reviewComment: '通过',
    });
    // 自审自批禁止（M-2）：服务层条件更新不命中 → ApiError 400
    expect(selfReview.status).toBe(400);
    // 自审被拒后记录必须仍停在已完成、未被写坏（拒了但没改 vs 改了才报错）
    const afterSelfReview = await require('../../models/Inspection').findById(ownId).lean();
    expect(afterSelfReview.status).toBe('completed');
    expect(afterSelfReview.reviewResult ?? null).toBeNull();

    // 场景二：未指派记录由管理员审核 → 通过；重复审核被拒
    const otherCreate = await authed()
      .post('/api/inspections')
      .send({
        title: `他审通过_${stamp}`,
        inspectionType: 'weekly',
        planStartTime: new Date(Date.now() + 1000).toISOString(),
        planEndTime: new Date(Date.now() + 3600 * 1000).toISOString(),
        checkItems: [{ name: '喷淋头' }],
      });
    const otherId = String(otherCreate.body.data._id || otherCreate.body.data.id);
    await authed().put(`/api/inspections/${otherId}/start`);
    await authed().put(`/api/inspections/${otherId}/complete`).send({ result: 'normal' });

    const review = await authed().put(`/api/inspections/${otherId}/review`).send({
      // 接口口径：路由校验器验 result，控制器消费 reviewResult（两字段需同时携带）
      result: 'approved',
      reviewResult: 'approved',
      reviewComment: '复核无误',
    });
    expect(review.status).toBe(200);
    // 审核通过的判据是结果真的落库
    const reviewed = await require('../../models/Inspection').findById(otherId).lean();
    expect(reviewed.reviewResult).toBe('approved');

    const reReview = await authed().put(`/api/inspections/${otherId}/review`).send({
      result: 'rejected',
      reviewResult: 'rejected',
    });
    // 已审核记录不可再审（服务层 conflict 409）
    expect(reReview.status).toBe(409);
    // 重复审核不得覆盖首次结果（409 之后结果仍是 approved）
    const stillApproved = await require('../../models/Inspection').findById(otherId).lean();
    expect(stillApproved.reviewResult).toBe('approved');

    await authed()
      .delete(`/api/inspections/${ownId}`)
      .catch(() => {});
    await authed()
      .delete(`/api/inspections/${otherId}`)
      .catch(() => {});
  });
});
