/**
 * 业务事件实时推送（WS 门面的服务层入口）
 *
 * WebSocketService 在 listen 后才构造，service 层直接 require 门面会让不起 server 的单测
 * 撞上未初始化实例；这里用一次性绑定解耦（构造时绑定、dispose 解绑）。
 * 推送尽力而为：业务已成功，通知失败只留 warn，不影响请求。
 *
 * 载荷只放标识与状态——房间对所有已认证用户开放，消息体不得成为旁路读取面。
 */

const logger = require('../utils/logger');

let wsService = null;

const setWebSocketService = (service) => {
  wsService = service || null;
};

/** 投递到房间；room/type 白名单由 WebSocketService 校验，载荷禁止放敏感字段 */
const emit = (room, notificationType, message) => {
  if (!wsService) return false;
  try {
    return wsService.emitNotification(room, notificationType, message);
  } catch (err) {
    logger.warn(`实时推送失败（${room}/${notificationType}）：${err?.message ?? err}`);
    return false;
  }
};

/** 报警状态迁移：房间 'alarm'，载荷仅标识/状态/等级/类型 */
const notifyAlarm = (notificationType, alarm) => {
  if (!alarm) return false;
  return emit('alarm', notificationType, {
    alarmCode: alarm.alarmCode,
    status: alarm.status,
    level: alarm.level,
    alarmType: alarm.alarmType,
  });
};

/** 设备状态迁移：房间 'device-alert'，载荷仅标识与前后状态 */
const notifyDeviceStatusChanged = (device, previousStatus) => {
  if (!device) return false;
  return emit('device-alert', 'device_status_changed', {
    deviceCode: device.deviceCode,
    deviceName: device.deviceName,
    previousStatus,
    status: device.status,
  });
};

module.exports = { setWebSocketService, notifyAlarm, notifyDeviceStatusChanged };
