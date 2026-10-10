/**
 * 被指派处理报警的人必须能操作那条报警
 *
 * rbac.js 的 self 档注释写着"仅自己创建/**负责**的数据"，但
 * `DATA_SCOPE_FIELDS.alarm.ownerField` 只有 `reporter.userId` —— 实现比它自己的
 * 文档少了一半。后果不是"看不见列表"这种体验问题，而是**流程砖化**：
 *   报岗人 R 上报 → 值班主管派给消防员 F（dispatch 允许，只校验部门）
 *   → 报警变 processing、handler=F
 *   → F arrive/resolve：控制器的 isAlarmInScope 只看 reporter/building → 403
 *   → R 也收不了口：resolve 要求 handler==操作者、false_alarm 要求 handler ∈ {me,null,缺}、
 *     cancel 要求 status=pending、再派要求 status=pending
 *   → 这条报警谁也关不掉，只能留在 processing。
 *
 * 修法（也是本文件的判据）：**指派即授予对该条记录的操作权**，而不是扩大列表可见范围。
 * 因此这里同时钉住反方向：与这条报警毫无关系的人（既非报岗人也非处理人）必须仍然 403，
 * 以及"已终结的报警"不能因为我是 handler 就能再改（状态机不被绕过）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('./helpers/buildLoginEnvelope');

describe('被指派的处理人对单条报警有操作权', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let FireAlarm;
  const stamp = `ah${Date.now()}`.replace(/\d/g, (d) => 'wxyzabbcde'[Number(d)]);
  const PASSWORD = randomPassword();
  const tokenOf = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: user.tokenVersion || 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  const ensurePerm = async (code) => {
    const module = code.split(':')[0];
    return Permission.findOneAndUpdate(
      { code },
      { $setOnInsert: { name: `权限_${code}`, code, type: 'api', module } },
      { upsert: true, new: true }
    );
  };

  let reporter;
  let handler;
  let bystander;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    FireAlarm = require('../models/FireAlarm');
    require('../models/TokenBlacklist');

    const handlePerms = await Promise.all([
      ensurePerm('alarm:read'),
      ensurePerm('alarm:handle'),
      ensurePerm('alarm:create'),
    ]);
    const selfRole = await Role.create({
      name: `消防员_${stamp}`,
      code: `FIREFIGHTER_${stamp}`,
      level: 4, // self 档：只看自己创建/负责的
      permissions: handlePerms.map((p) => p._id),
    });
    const make = async (tag) =>
      User.create({
        username: `${stamp}${tag}`,
        email: `${stamp}${tag}@example.com`,
        password: PASSWORD,
        department: '东塔',
        roles: [selfRole._id],
      });
    [reporter, handler, bystander] = await Promise.all([make('rpt'), make('hnd'), make('bye')]);

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ 'reporter.userId': reporter._id }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 造一条"已派给 handler、处理中"的报警（等价于 dispatch 成功后的落库形态） */
  const openAlarm = async (fields = {}) =>
    FireAlarm.create({
      description: `${stamp} 烟雾报警`,
      alarmType: 'smoke',
      level: 'warning',
      status: 'processing',
      location: { building: '东塔' },
      reporter: { userId: reporter._id, username: reporter.username },
      handler: handler._id,
      ...fields,
    });

  test('前提已翻转：报警派给 F 后，F 的 self 读范围现在查得到这一条', async () => {
    // 本用例原本是"前提自证"——钉住旧砖化状态（handler 的读范围查不到被派的单），
    // 用来证明 canOperateAlarm 那条修复针对的现象确实存在。
    // 轮 7 把属主声明本身也补齐了（DATA_SCOPE_FIELDS.alarm.ownerField 增加 handler 一臂，
    // 使列表/统计与详情/操作同口径），旧前提不再成立，于是这里改成钉住**新的一对不变量**：
    //   ① handler 看得见；② 无关的人仍然看不见（窄化不能顺手放宽到全组织）。
    const alarm = await openAlarm();
    const { getDataScope, buildDataScopeFilter } = require('../middleware/rbac');
    const scope = await getDataScope(String(handler._id));
    expect(scope.type).toBe('self');
    const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
    // 注意签名：buildDataScopeFilter(dataScope, ownerField, departmentField)。
    // 传整个字段对象会得到 {[object Object]: id} 这种假条件（首轮实跑即暴露）。
    const { ownerField, departmentField } = DATA_SCOPE_FIELDS.alarm;
    expect(ownerField).toEqual(['reporter.userId', 'handler']);
    const filter = buildDataScopeFilter(scope, ownerField, departmentField);

    // 数组属主 ⇒ 范围条件占用 $or。这个形状同时是 search 分支的雷区，
    // 由 alarmHandlerListVisibility.test.js 守（LV-M2 变异专门杀它）。
    expect(Object.keys(filter)).toEqual(['$or']);
    // 真库直接验证：处理人自己的范围现在命中这一条
    expect(await FireAlarm.countDocuments({ _id: alarm._id, ...filter })).toBe(1);
    // 对照一：报岗人同样能查到（两条臂都有效）
    const reporterScope = await getDataScope(String(reporter._id));
    const reporterFilter = buildDataScopeFilter(reporterScope, ownerField, departmentField);
    expect(await FireAlarm.countDocuments({ _id: alarm._id, ...reporterFilter })).toBe(1);
    // 对照二（关键的负控）：局外人两条臂都不命中——补齐 handler 不等于放开范围
    const bystanderScope = await getDataScope(String(bystander._id));
    const bystanderFilter = buildDataScopeFilter(bystanderScope, ownerField, departmentField);
    expect(await FireAlarm.countDocuments({ _id: alarm._id, ...bystanderFilter })).toBe(0);
  });

  test('处理人到场：arrive 必须成功', async () => {
    const alarm = await openAlarm();
    const res = await request(app)
      .put(`/api/alarms/${alarm._id}/arrive`)
      .set('Authorization', `Bearer ${tokenOf(handler)}`)
      .send({});
    expect(res.status).toBe(200);
    const after = await FireAlarm.findById(alarm._id);
    expect(after.arrivedAt).toBeTruthy();
  });

  test('处理人结单：resolve 必须成功并落库处理结果', async () => {
    const alarm = await openAlarm();
    const res = await request(app)
      .put(`/api/alarms/${alarm._id}/resolve`)
      .set('Authorization', `Bearer ${tokenOf(handler)}`)
      .send({ handleResult: `${stamp} 现场确认并处置`, cause: 'equipment_fault' });
    expect(res.status).toBe(200);
    const after = await FireAlarm.findById(alarm._id);
    expect(after.status).toBe('resolved');
  });

  test('处理人能看到被派给自己的那条详情（列表范围不变，仅这一条可看）', async () => {
    const alarm = await openAlarm();
    const res = await request(app)
      .get(`/api/alarms/${alarm._id}`)
      .set('Authorization', `Bearer ${tokenOf(handler)}`);
    expect(res.status).toBe(200);
  });

  test('反向保护：与这条报警毫无关系的人仍然 403（不得把"操作权"做成绕过范围）', async () => {
    const alarm = await openAlarm();
    const res = await request(app)
      .put(`/api/alarms/${alarm._id}/arrive`)
      .set('Authorization', `Bearer ${tokenOf(bystander)}`)
      .send({});
    expect(res.status).toBe(403);
  });

  test('反向保护：已终结的报警不能因为"我是处理人"再被改（状态机不被绕过）', async () => {
    const alarm = await openAlarm({
      status: 'resolved',
      handleResult: '已处置',
      resolvedAt: new Date(),
    });
    const res = await request(app)
      .put(`/api/alarms/${alarm._id}/arrive`)
      .set('Authorization', `Bearer ${tokenOf(handler)}`)
      .send({});
    expect(res.status).toBe(409);
  });
});
