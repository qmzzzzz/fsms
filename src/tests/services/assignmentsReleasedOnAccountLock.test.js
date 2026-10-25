/**
 * 锁定账户必须释放进行中的指派
 *
 * 锁定态下 arrive/resolve/start 都以"操作者 === 处理人/被指派人"为条件，
 * 而锁定账户无法登录 ⇒ 工单没有出口。释放必须发生在 save 之后：先写状态再清
 * 指派，写入失败时不得提前把指派清掉（重试同一请求仍会走到释放）。
 */

const mongoose = require('mongoose');

describe('锁定账户释放开放指派', () => {
  let User;
  let Role;
  let FireAlarm;
  let Inspection;
  let authService;
  const stamp = `lk${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).slice(0, 10);
  const PASSWORD = 'Test@1234567';
  let operator;
  let target;
  let alarm;
  let inspection;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    require('../../models/FireDevice');
    require('../../models/AuditLog');
    authService = require('../../services/authService');

    const highRole = await Role.create({ name: 't-high', code: `${stamp}_HIGH`, level: 8 });
    const lowRole = await Role.create({ name: 't-low', code: `${stamp}_LOW`, level: 1 });
    operator = await User.create({
      username: `${stamp}op`,
      email: `${stamp}op@example.com`,
      password: PASSWORD,
      roles: [highRole._id],
    });
    target = await User.create({
      username: `${stamp}tg`,
      email: `${stamp}tg@example.com`,
      password: PASSWORD,
      roles: [lowRole._id],
    });
    alarm = await FireAlarm.create({
      description: `${stamp} 报警`,
      alarmType: 'smoke',
      level: 'warning',
      status: 'processing',
      handler: target._id,
      dispatchedAt: new Date(),
    });
    inspection = await Inspection.create({
      title: `${stamp} 巡检`,
      inspectionType: 'daily',
      status: 'pending',
      assignedTo: [target._id],
    });
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('锁定成功后：processing 报警退回 pending，未完成巡检摘掉该成员并留痕', async () => {
    const result = await authService.setUserLockStatus(
      target._id,
      { locked: true, reason: '回归用例' },
      {
        operatorId: operator._id,
        operatorUsername: operator.username,
        ip: '127.0.0.1',
        userAgent: 'jest',
      }
    );
    expect(result.outcome).toBe('OK');

    const alarmAfter = await FireAlarm.findById(alarm._id);
    expect(String(alarmAfter.handler || '')).toBe('');
    expect(alarmAfter.status).toBe('pending');
    const releaseLog = alarmAfter.processLog.find((entry) => entry.action === 'handler_released');
    expect(releaseLog).toBeTruthy();
    expect(releaseLog.remark).toContain('锁定');

    const inspectionAfter = await Inspection.findById(inspection._id);
    expect(inspectionAfter.assignedTo).toHaveLength(0);

    const targetAfter = await User.findById(target._id).select('status');
    expect(targetAfter.status).toBe('locked');
  });
});
