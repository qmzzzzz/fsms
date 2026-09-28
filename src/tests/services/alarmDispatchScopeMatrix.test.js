'use strict';

/**
 * P2-17 的第二半：`dispatchAlarm` 的被指派人范围必须按 dataScope 档位**穷尽判定**
 *
 * 缺陷（台账 §4.1 / §7-3）：`AlarmService.dispatchAlarm` 只对
 * `dataScope.type === 'department'` 做跨部门拦截，其余档位一律放行——
 * `self` 档（"仅自己的数据"）可以把报警派给**任意在册用户**（连同部门都不需要），
 * `none` 档与"调用方根本没传 dataScope"同样放行。
 * 后果不是"数据看得见"而是**内容进他人列表 + 他人被迫接单**：
 * `handleAlarm`/`arriveAtScene` 的经办人守卫读的就是这个 `handler` 字段。
 *
 * 本套件的价值在于它是**矩阵**而不是单点：四个档位 + 一个缺失态各自的判定都必须写明，
 * 少一个分支就红一条（这正是"新增档位时忘记处理"的防呆）。
 * 与 `businessStateConsistencyInvariants.test.js` 的 P2-17 用例不重复：
 * 那套钉的是"存在性/在职/跨部门/空部门"，本套钉的是 self/none/未传参 三条线。
 */

const mongoose = require('mongoose');

const AlarmService = require('../../services/AlarmService');
const User = require('../../models/User');
const FireAlarm = require('../../models/FireAlarm');

const PWD = 'Qz7#Lm42vTx9';

describe('dispatchAlarm 数据范围矩阵（self/none/未传参 都必须拒绝跨人指派）', () => {
  let opSelf; // 仅有 self 档语义的操作者（本人属 A 栋）
  let mateInDept; // A 栋另一位在职人员
  let farDept; // B 栋在职人员

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const mk = (username, department) =>
      User.create({ username, email: `${username}@example.com`, password: PWD, department });
    opSelf = await mk('dsx_op', 'A栋');
    mateInDept = await mk('dsx_mate', 'A栋');
    farDept = await mk('dsx_far', 'B栋');
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: 'dsx-测试报警' }).catch(() => {});
    await User.deleteMany({ username: /^dsx_/ }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      // 与其它套件共用内存 Mongo：只有本套件建立的连接才关
    }
  });

  const makeAlarm = () =>
    AlarmService.reportAlarm({
      alarmType: 'smoke',
      level: 'critical',
      location: { building: 'A栋' },
      description: 'dsx-测试报警',
      reporterName: '张三',
      reporterPhone: '13800000000',
    });

  test('未传 dataScope（调用方没给授权上下文）不得放行跨人指派', async () => {
    // 修复前的真实行为：`if (dataScope && ...)` 让"没传"直接跳过全部校验，
    // 跨部门派单成功——本用例现在应当是红的，修完转绿。
    const alarm = await makeAlarm();
    await expect(
      AlarmService.dispatchAlarm(alarm._id, farDept._id, opSelf._id)
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  test('self 档不得把活派给别人（同部门也不行）', async () => {
    const alarm = await makeAlarm();
    await expect(
      AlarmService.dispatchAlarm(alarm._id, mateInDept._id, opSelf._id, {
        dataScope: { type: 'self', userId: opSelf._id },
      })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  test('self 档正对照：派给自己（接单/自办）必须仍然可用', async () => {
    const alarm = await makeAlarm();
    const updated = await AlarmService.dispatchAlarm(alarm._id, opSelf._id, opSelf._id, {
      dataScope: { type: 'self', userId: opSelf._id },
    });
    expect(updated.status).toBe('processing');
    expect(String(updated.handler)).toBe(String(opSelf._id));
  });

  test('none 档一律拒绝（纵深防御：HTTP 侧已被 isAlarmInScope 挡住，Service 侧不得放行）', async () => {
    const alarm = await makeAlarm();
    await expect(
      AlarmService.dispatchAlarm(alarm._id, mateInDept._id, opSelf._id, {
        dataScope: { type: 'none' },
      })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  test('department 档正对照：同部门可派、跨部门仍拒（确保没被改过头）', async () => {
    const okAlarm = await makeAlarm();
    const ok = await AlarmService.dispatchAlarm(okAlarm._id, mateInDept._id, opSelf._id, {
      dataScope: { type: 'department', department: 'A栋' },
    });
    expect(String(ok.handler)).toBe(String(mateInDept._id));

    const badAlarm = await makeAlarm();
    await expect(
      AlarmService.dispatchAlarm(badAlarm._id, farDept._id, opSelf._id, {
        dataScope: { type: 'department', department: 'A栋' },
      })
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  test('all 档不受部门限制（否则修 self 会把超管一起锁死）', async () => {
    const alarm = await makeAlarm();
    const updated = await AlarmService.dispatchAlarm(alarm._id, farDept._id, opSelf._id, {
      dataScope: { type: 'all' },
    });
    expect(String(updated.handler)).toBe(String(farDept._id));
  });

  test('未知档位按拒绝处理（新增 scope 类型时不许静默放行）', async () => {
    const alarm = await makeAlarm();
    await expect(
      AlarmService.dispatchAlarm(alarm._id, farDept._id, opSelf._id, {
        dataScope: { type: 'region' },
      })
    ).rejects.toMatchObject({ statusCode: 403 });
  });
});
