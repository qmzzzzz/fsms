'use strict';

/**
 * 报警/设备状态迁移 → 实时推送的接线测试
 *
 * 缺陷前提（审计 P1①）：`emitNotification` 在生产代码里零调用方，且 `alarm` /
 * `device-alert` 房间没有订阅者。仅测 notifier 门面本身不足以防回归——
 * 有人把 service 里的调用**删掉**，门面测试照样全绿（没有调用就没有错误）。
 * 因此本套件从真实的 service 入口出发，钉住：
 *
 *  1. 六个报警状态迁移、三条设备状态迁移（更新/维护态迁移/报废）都必须推一次；
 *  2. 推送事件名按迁移命名（前端/值班员据此判断发生了什么）；
 *  3. 推送载荷里的 status 必须是**落库后的新状态**（推送先于落库 = 订阅方刷新拿到旧值）；
 *  4. 写操作未命中（幂等/条件不满足，更新结果为 null）时不得推送
 *     ——否则会通知一次「状态变了」，而库里什么都没变。
 */

const mongoose = require('mongoose');

const AlarmService = require('../../services/AlarmService');
const DeviceService = require('../../services/DeviceService');
const realtimeNotifier = require('../../services/realtimeNotifier');
const FireAlarm = require('../../models/FireAlarm');
const FireDevice = require('../../models/FireDevice');
const User = require('../../models/User');

const PWD = 'Qz7#Lm42vTx9';
const TAG = 'rte-接线测试';

describe('状态迁移的实时推送接线', () => {
  let operator;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    operator = await User.create({
      username: 'rte_operator',
      email: 'rte_operator@example.com',
      password: PWD,
      department: 'A栋',
    });
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(TAG) }).catch(() => {});
    await FireDevice.deleteMany({ deviceCode: /^RTE-/ }).catch(() => {});
    await User.deleteMany({ username: /^rte_/ }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  let alarmSpy;
  let deviceSpy;

  beforeEach(() => {
    alarmSpy = jest.spyOn(realtimeNotifier, 'notifyAlarm');
    deviceSpy = jest.spyOn(realtimeNotifier, 'notifyDeviceStatusChanged');
  });

  afterEach(() => {
    jest.restoreAllMocks();
    realtimeNotifier.setWebSocketService(null);
  });

  const makeAlarm = () =>
    AlarmService.reportAlarm({
      alarmType: 'smoke',
      level: 'critical',
      location: { building: 'A栋', floor: '3层', room: '配电室' },
      description: `${TAG}-报警`,
      reporterName: '张三',
      reporterPhone: '13800000000',
    });

  /** 最近一次报警推送的 [type, payload.status] */
  const lastAlarmPush = () => {
    const call = alarmSpy.mock.calls[alarmSpy.mock.calls.length - 1];
    return [call[0], call[1]?.status];
  };

  test('上报：落库即推 alarm_created，载荷状态为库内新状态', async () => {
    const alarm = await makeAlarm();
    expect(alarmSpy).toHaveBeenCalledTimes(1);
    expect(lastAlarmPush()).toEqual(['alarm_created', 'pending']);
    const inDb = await FireAlarm.findById(alarm._id).lean();
    expect(inDb.status).toBe('pending');
    expect(alarmSpy.mock.calls[0][1].alarmCode).toBe(inDb.alarmCode);
  });

  test('派单 / 到达 / 结单：三个节点各推一次，状态取自更新后的文档', async () => {
    const alarm = await makeAlarm();
    alarmSpy.mockClear();

    const dispatched = await AlarmService.dispatchAlarm(alarm._id, operator._id, operator._id, {
      dataScope: { type: 'all' },
    });
    expect(lastAlarmPush()).toEqual(['alarm_dispatched', 'processing']);
    expect(String(dispatched.handler)).toBe(String(operator._id));

    await AlarmService.arriveAtScene(alarm._id, operator._id);
    expect(lastAlarmPush()).toEqual(['alarm_arrived', 'processing']);

    await AlarmService.resolveAlarm(
      alarm._id,
      { handleResult: '已扑灭', cause: '电气故障' },
      operator._id
    );
    expect(lastAlarmPush()).toEqual(['alarm_resolved', 'resolved']);
    expect(alarmSpy).toHaveBeenCalledTimes(3);

    const inDb = await FireAlarm.findById(alarm._id).lean();
    expect(inDb.status).toBe('resolved');
  });

  test('标记误报推 alarm_false_alarm，载荷状态与库内一致', async () => {
    const alarm = await makeAlarm();
    alarmSpy.mockClear();
    await AlarmService.markAsFalseAlarm(alarm._id, '误触', operator._id);
    expect(lastAlarmPush()).toEqual(['alarm_false_alarm', 'false_alarm']);
    expect((await FireAlarm.findById(alarm._id).lean()).status).toBe('false_alarm');
  });

  test('取消推 alarm_cancelled，载荷状态与库内一致', async () => {
    const alarm = await makeAlarm();
    alarmSpy.mockClear();
    await AlarmService.cancelAlarm(alarm._id, '重复上报', operator._id);
    expect(lastAlarmPush()).toEqual(['alarm_cancelled', 'cancelled']);
    expect((await FireAlarm.findById(alarm._id).lean()).status).toBe('cancelled');
  });

  test('条件写未命中（对已结单报警再派单）不得推送：库里没有任何变化', async () => {
    // 绑定一个可观测的假 WS：判据是「真的没有消息发出」，而不是「notifyAlarm 没被调用」——
    // 后者会逼实现恢复成每处手写 `if (updated)`，把 null 守卫散落回六个调用点。
    const sent = [];
    realtimeNotifier.setWebSocketService({
      emitNotification: (...args) => {
        sent.push(args);
        return true;
      },
    });

    const alarm = await makeAlarm();
    await AlarmService.dispatchAlarm(alarm._id, operator._id, operator._id, {
      dataScope: { type: 'all' },
    });
    await AlarmService.resolveAlarm(
      alarm._id,
      { handleResult: '已扑灭', cause: '电气故障' },
      operator._id
    );
    sent.length = 0; // 清掉前面三个节点已投递的消息，只看本次失败写入

    const result = await AlarmService.dispatchAlarm(alarm._id, operator._id, operator._id, {
      dataScope: { type: 'all' },
    });
    expect(result).toBeNull();
    expect(sent).toEqual([]);
  });

  /** 建一台在用设备（与生产数据形态一致：installed → in_use） */
  const makeDevice = async (code) => {
    const device = await FireDevice.create({
      deviceCode: code,
      deviceName: `${TAG}设备`,
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
    });
    await device.transitionTo('in_use');
    return device;
  };

  test('设备状态更新推 device_status_changed，携带前后状态', async () => {
    const device = await makeDevice('RTE-STATUS');
    await DeviceService.updateDeviceStatus(device, 'fault');
    expect(deviceSpy).toHaveBeenCalledTimes(1);
    const [updated, previousStatus] = deviceSpy.mock.calls[0];
    expect(updated.status).toBe('fault');
    expect(previousStatus).toBe('normal');
    expect((await FireDevice.findById(device._id).lean()).status).toBe('fault');
  });

  test('进入维护态走状态机迁移路径：只推一次（transitionTo 提前保存后不得重复推）', async () => {
    const device = await makeDevice('RTE-MAINT');
    await DeviceService.updateDeviceStatus(device, 'maintenance');
    expect(deviceSpy).toHaveBeenCalledTimes(1);
    expect(deviceSpy.mock.calls[0][0].status).toBe('maintenance');
    expect(deviceSpy.mock.calls[0][1]).toBe('normal');
    expect((await FireDevice.findById(device._id).lean()).lifecycleStage).toBe('maintenance');
  });

  test('报废推 device_status_changed，previousStatus 为报废前状态', async () => {
    const device = await makeDevice('RTE-SCRAP');
    await DeviceService.updateDeviceStatus(device, 'fault');
    deviceSpy.mockClear();

    await DeviceService.scrapDevice(device, '到期报废');
    expect(deviceSpy).toHaveBeenCalledTimes(1);
    expect(deviceSpy.mock.calls[0][0].status).toBe('scrapped');
    expect(deviceSpy.mock.calls[0][1]).toBe('fault');
    const inDb = await FireDevice.findById(device._id).lean();
    expect(inDb.status).toBe('scrapped');
    expect(inDb.lifecycleStage).toBe('scrapped');
  });
});
