'use strict';

/**
 * 业务事件实时推送门面（realtimeNotifier）契约测试
 *
 * 背景：`emitNotification` 此前**没有任何生产调用方**——报警/设备状态在 service 层
 * 落库后无人推送，`alarm` / `device-alert` 房间也没有前端订阅，实时刷新形同虚设。
 * 现在由本门面承接 service → WS 的接线，本套件锁定四条契约：
 *
 *  1. 未绑定 WS（单测/启动早期/关闭后）必须安全空转，不得抛错——业务写入已完成，
 *     推送失败不能把成功请求变成 500；
 *  2. 绑定后投递的房间与事件名固定（alarm / device-alert），名字错 = 订阅方收不到；
 *  3. 载荷**只含标识与状态**：房间对所有已认证用户开放，描述/位置/手机号等
 *     业务内容不得成为旁路读取面；
 *  4. 门面吞掉投递异常（返回 false + warn），异常不得冒泡到业务事务；
 *  5. 绑定生命周期由 WebSocketService 自己持有（构造即绑定、dispose 即解绑）——
 *     只在 index.js 里手工接线的话，任何绕过启动流程的构造路径都会静默丢推送。
 */

const http = require('http');
const logger = require('../../utils/logger');
const realtimeNotifier = require('../../services/realtimeNotifier');

describe('realtimeNotifier：service 层推送门面', () => {
  afterEach(() => {
    realtimeNotifier.setWebSocketService(null);
    jest.restoreAllMocks();
  });

  test('未绑定 WS：报警/设备推送都返回 false 且不抛（启动早期与关闭后安全空转）', () => {
    expect(realtimeNotifier.notifyAlarm('alarm_created', { alarmCode: 'A-1' })).toBe(false);
    expect(
      realtimeNotifier.notifyDeviceStatusChanged({ deviceCode: 'D-1', status: 'fault' }, 'normal')
    ).toBe(false);
  });

  test('解绑（setWebSocketService(null)）后不再投递', () => {
    const svc = { emitNotification: jest.fn(() => true) };
    realtimeNotifier.setWebSocketService(svc);
    expect(realtimeNotifier.notifyAlarm('alarm_created', { alarmCode: 'A-1' })).toBe(true);
    realtimeNotifier.setWebSocketService(null);
    expect(realtimeNotifier.notifyAlarm('alarm_created', { alarmCode: 'A-2' })).toBe(false);
    expect(svc.emitNotification).toHaveBeenCalledTimes(1);
  });

  test('报警推送：固定发往 alarm 房间，载荷只含标识/状态/等级/类型（不含描述与位置）', () => {
    const svc = { emitNotification: jest.fn(() => true) };
    realtimeNotifier.setWebSocketService(svc);
    const alarm = {
      alarmCode: 'ALM-20261102-001',
      status: 'pending',
      level: 'critical',
      alarmType: 'smoke',
      // 以下均属业务内容，房间对所有已认证用户开放，不得随推送外泄
      description: '三楼配电室冒烟',
      location: { building: 'A栋', floor: '3层', room: '配电室' },
      reporterName: '张三',
      reporterPhone: '13800000000',
    };

    expect(realtimeNotifier.notifyAlarm('alarm_created', alarm)).toBe(true);
    expect(svc.emitNotification).toHaveBeenCalledTimes(1);
    const [room, type, payload] = svc.emitNotification.mock.calls[0];
    expect(room).toBe('alarm');
    expect(type).toBe('alarm_created');
    expect(payload).toEqual({
      alarmCode: 'ALM-20261102-001',
      status: 'pending',
      level: 'critical',
      alarmType: 'smoke',
    });
    // 显式反向断言：实现若改成 { ...alarm }，上面 toEqual 仍可能过（多出的键），这里钉死
    expect(Object.keys(payload).sort()).toEqual(['alarmCode', 'alarmType', 'level', 'status']);
  });

  test('设备状态推送：固定发往 device-alert 房间，携带前后状态（前端据此判断迁移方向）', () => {
    const svc = { emitNotification: jest.fn(() => true) };
    realtimeNotifier.setWebSocketService(svc);
    const device = {
      deviceCode: 'SMK-001',
      deviceName: '一层烟感',
      status: 'fault',
      location: { building: 'A栋' },
      // 内部备注与巡检记录同样不属于推送载荷
      remark: '维保中',
      maintenanceRecords: [{ content: '更换探头' }],
    };

    expect(realtimeNotifier.notifyDeviceStatusChanged(device, 'normal')).toBe(true);
    const [room, type, payload] = svc.emitNotification.mock.calls[0];
    expect(room).toBe('device-alert');
    expect(type).toBe('device_status_changed');
    expect(payload).toEqual({
      deviceCode: 'SMK-001',
      deviceName: '一层烟感',
      previousStatus: 'normal',
      status: 'fault',
    });
    expect(Object.keys(payload).sort()).toEqual(
      ['deviceCode', 'deviceName', 'previousStatus', 'status'].sort()
    );
  });

  test('投递抛错：返回 false 并告警，异常不得冒泡到业务事务', () => {
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    realtimeNotifier.setWebSocketService({
      emitNotification: () => {
        throw new Error('socket closed');
      },
    });

    expect(() =>
      realtimeNotifier.notifyAlarm('alarm_resolved', { alarmCode: 'A-9' })
    ).not.toThrow();
    expect(realtimeNotifier.notifyAlarm('alarm_resolved', { alarmCode: 'A-9' })).toBe(false);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls[0][0]).toContain('alarm/alarm_resolved');
    expect(warn.mock.calls[0][0]).toContain('socket closed');
  });

  test('空对象不投递：避免把 undefined 标识推给订阅方', () => {
    const svc = { emitNotification: jest.fn(() => true) };
    realtimeNotifier.setWebSocketService(svc);
    expect(realtimeNotifier.notifyAlarm('alarm_created', null)).toBe(false);
    expect(realtimeNotifier.notifyDeviceStatusChanged(null, 'normal')).toBe(false);
    expect(svc.emitNotification).not.toHaveBeenCalled();
  });
});

describe('WebSocketService 与推送门面的生命周期绑定', () => {
  test('构造即绑定：实例一存在，service 层推送就能到达它；dispose 即解绑', () => {
    const WebSocketService = require('../../services/websocketService');
    const server = http.createServer();
    let svc;
    let disposed = false;
    try {
      svc = new WebSocketService(server);
      const emit = jest.spyOn(svc, 'emitNotification').mockReturnValue(true);

      expect(realtimeNotifier.notifyAlarm('alarm_created', { alarmCode: 'A-LIFE' })).toBe(true);
      const [room, type, payload] = emit.mock.calls[0];
      expect({ room, type, alarmCode: payload.alarmCode }).toEqual({
        room: 'alarm',
        type: 'alarm_created',
        alarmCode: 'A-LIFE',
      });

      svc.dispose();
      disposed = true;
      expect(realtimeNotifier.notifyAlarm('alarm_created', { alarmCode: 'A-LIFE-2' })).toBe(false);
    } finally {
      // 断言失败发生在 dispose 之前时兜底关闭，避免定时器/监听器泄漏到其它套件
      if (svc && !disposed) {
        try {
          svc.dispose();
        } catch (_) {
          /* 已销毁 */
        }
      }
      server.close();
    }
  });
});
