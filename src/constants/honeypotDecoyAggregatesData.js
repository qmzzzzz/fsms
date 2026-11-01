'use strict';

const approval = (by, name, atOffsetMin) => Object.freeze({ by, name, atOffsetMin });

const DECOY_TEMP_GRANTS = Object.freeze([
  Object.freeze({
    _id: 'hp-g1',
    userId: 'hp-u3',
    username: 'wangfang',
    permissionCodes: Object.freeze(['user:update', 'role:update']),
    reason: '权限矩阵核对期间需要临时修改值班员账号与角色',
    requestedBy: 'hp-u2',
    requestedByName: '李强',
    requestedAtOffsetMin: 55,
    approvals: Object.freeze([approval('hp-u1', '张伟', 48)]),
    durationHours: 8,
    status: 'pending',
    createdAtOffsetMin: 40,
    grantedAtOffsetMin: null,
    expiresAtOffsetMin: null,
    decisionReason: '',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
  Object.freeze({
    _id: 'hp-g2',
    userId: 'hp-u4',
    username: 'chenlei',
    permissionCodes: Object.freeze(['device:read']),
    reason: 'A1 厂房夜间巡检需临时查看设备台账',
    requestedBy: 'hp-u2',
    requestedByName: '李强',
    requestedAtOffsetMin: 380,
    approvals: Object.freeze([approval('hp-u1', '张伟', 320)]),
    durationHours: 8,
    status: 'active',
    createdAtOffsetMin: 360,
    grantedAtOffsetMin: 300,
    expiresAtOffsetMin: -180,
    decisionReason: '',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
  Object.freeze({
    _id: 'hp-g3',
    userId: 'hp-u5',
    username: 'zhaomin',
    permissionCodes: Object.freeze(['permission:update']),
    reason: '批量修正设备类权限的接口路径，需临时改权限表',
    requestedBy: 'hp-u1',
    requestedByName: '张伟',
    requestedAtOffsetMin: 1300,
    approvals: Object.freeze([approval('hp-u1', '张伟', 1230), approval('hp-u2', '李强', 1215)]),
    durationHours: 24,
    status: 'active',
    createdAtOffsetMin: 1260,
    grantedAtOffsetMin: 1200,
    expiresAtOffsetMin: -240,
    decisionReason: '',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
  Object.freeze({
    _id: 'hp-g4',
    userId: 'hp-u2',
    username: 'liqiang',
    permissionCodes: Object.freeze(['report:read']),
    reason: '季度消防报表自查，需临时读取报表数据',
    requestedBy: 'hp-u1',
    requestedByName: '张伟',
    requestedAtOffsetMin: 200,
    approvals: Object.freeze([approval('hp-u1', '张伟', 150)]),
    durationHours: 48,
    status: 'active',
    createdAtOffsetMin: 180,
    grantedAtOffsetMin: 120,
    expiresAtOffsetMin: -2760,
    decisionReason: '',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
  Object.freeze({
    _id: 'hp-g5',
    userId: 'hp-u3',
    username: 'wangfang',
    permissionCodes: Object.freeze(['inspection:read']),
    reason: '想看一下别的班组的巡检记录',
    requestedBy: 'hp-u3',
    requestedByName: '王芳',
    requestedAtOffsetMin: 1600,
    approvals: Object.freeze([]),
    durationHours: 4,
    status: 'rejected',
    createdAtOffsetMin: 1560,
    grantedAtOffsetMin: null,
    expiresAtOffsetMin: null,
    decisionReason: '事由不具体且跨班组，请先由值班长确认必要性后重报',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
  Object.freeze({
    _id: 'hp-g6',
    userId: 'hp-u4',
    username: 'chenlei',
    permissionCodes: Object.freeze(['alarm:handle']),
    reason: 'B2 罐区报警集中处置，需临时具备处置权限',
    requestedBy: 'hp-u2',
    requestedByName: '李强',
    requestedAtOffsetMin: 4830,
    approvals: Object.freeze([approval('hp-u1', '张伟', 4500)]),
    durationHours: 24,
    status: 'revoked',
    createdAtOffsetMin: 4800,
    grantedAtOffsetMin: 4200,
    expiresAtOffsetMin: -2760,
    decisionReason: '',
    revokeReason: '处置任务提前结束，主动回收',
    revokedAtOffsetMin: 2400,
    revokedByName: '张伟',
  }),
  Object.freeze({
    _id: 'hp-g7',
    userId: 'hp-u5',
    username: 'zhaomin',
    permissionCodes: Object.freeze(['report:export']),
    reason: '上报消防季度报表，需临时导出一次',
    requestedBy: 'hp-u2',
    requestedByName: '李强',
    requestedAtOffsetMin: 187230,
    approvals: Object.freeze([approval('hp-u1', '张伟', 187100)]),
    durationHours: 4,
    status: 'expired',
    createdAtOffsetMin: 187200,
    grantedAtOffsetMin: 187000,
    expiresAtOffsetMin: 186760,
    decisionReason: '',
    revokeReason: '',
    revokedAtOffsetMin: null,
    revokedByName: '',
  }),
]);

const EXPIRING_MESSAGE = '获取即将到期设备成功';

const endpoint = (id, path, envelope, message) =>
  Object.freeze({ id, path, method: 'GET', envelope, message });

const AGGREGATE_ENDPOINTS = Object.freeze([
  endpoint('user-stats', '/api/users/stats', 'success', '获取用户统计成功'),
  endpoint('role-options', '/api/roles/all', 'success', '获取成功'),
  endpoint('permission-tree', '/api/roles/permissions/tree', 'success', '获取权限树成功'),
  endpoint('grant-list', '/api/permissions/grants', 'paginated', '获取临时授权列表成功'),
  endpoint('grant-review', '/api/permissions/grants/review', 'success', '获取权限复核汇总成功'),
  endpoint('device-stats', '/api/devices/stats', 'success', '获取统计信息成功'),
  endpoint('device-expiring', '/api/devices/expiring', 'paginated', EXPIRING_MESSAGE),
  endpoint('device-reminders', '/api/devices/reminders', 'success', '获取设备提醒成功'),
  endpoint('alarm-stats', '/api/alarms/stats', 'success', '获取统计信息成功'),
  endpoint('inspection-stats', '/api/inspections/stats', 'success', '获取统计信息成功'),
]);

const MODULE_NAMES = Object.freeze({
  system: '系统管理',
  user: '用户管理',
  role: '角色管理',
  permission: '权限管理',
  device: '设备管理',
  alarm: '报警管理',
  inspection: '巡检管理',
  report: '报表统计',
  security: '安全管理',
});

const DEVICE_EXPIRY_FIELDS = Object.freeze([
  'deviceCode',
  'deviceName',
  'deviceType',
  'location',
  'expiryDate',
  'status',
]);
const DEVICE_MAINTENANCE_FIELDS = Object.freeze([
  'deviceCode',
  'deviceName',
  'deviceType',
  'location',
  'nextCheckDate',
  'status',
]);
const DEVICE_SCHEDULE_FIELDS = Object.freeze([
  'deviceCode',
  'deviceName',
  'deviceType',
  'location',
  'installDate',
  'checkCycle',
  'status',
]);

const bucket = (key, sort, fields) => Object.freeze({ key, sort, fields });

const REMINDER_BUCKETS = Object.freeze([
  bucket('expired', 'expiryDate', DEVICE_EXPIRY_FIELDS),
  bucket('expiringSoon', 'expiryDate', DEVICE_EXPIRY_FIELDS),
  bucket('needMaintenance', 'nextCheckDate', DEVICE_MAINTENANCE_FIELDS),
  bucket('needSchedule', 'installDate', DEVICE_SCHEDULE_FIELDS),
]);

const nonDerivable = (endpoint, field, why) => Object.freeze({ endpoint, field, why });

const NON_DERIVABLE = Object.freeze([
  nonDerivable(
    '/api/users/stats',
    'byRole[].roleId',
    '真实链是 24 位 ObjectId，合成世界只有 hp-r* 命名空间'
  ),
  nonDerivable(
    '/api/users/stats',
    '全部计数',
    '真实链按调用者数据范围收窄，合成世界只有一份组织级数据 ⇒ 任何身份拿到同一组数'
  ),
  nonDerivable(
    '/api/users/stats',
    'byDepartment[]/byRole[] 并列项次序',
    '真实链 $sort{count:-1} 无次序键，同数并列由引擎定序；这里按合成表出现序'
  ),
  nonDerivable(
    '/api/roles/all',
    '行序',
    '真实链 sort{level:1} 而 level 不在合成表里（真实种子 10/8/9/6/4/1）；这里按合成表定义序'
  ),
  nonDerivable(
    '/api/roles/permissions/tree',
    '节点 _id/id',
    '真实链是 24 位 ObjectId；模块节点是 module-<module> 拼接串，叶子是 hp-p* 合成号'
  ),
  nonDerivable(
    '/api/permissions/grants',
    '_id/userId/requestedBy/approvals[].by',
    '真实链是 24 位 ObjectId，合成世界用 hp-* 命名空间（与 /api/users 的 _id 同源）'
  ),
  nonDerivable(
    '/api/permissions/grants',
    'createdAt 排序键',
    '真实链 sort{createdAt:-1} 只用它排序、不进投影；合成行用 createdAtOffsetMin 承担同一职责'
  ),
  nonDerivable(
    '/api/permissions/grants/review',
    'asOf',
    '请求时刻（真实链 new Date()）⇒ 每次响应都不同，不可能由合成数据预置'
  ),
  nonDerivable(
    '/api/permissions/grants/review',
    'overdue/overdueGrants 恒为 0/[]',
    'REVIEW_OVERDUE_DAYS=90 而 MAX_GRANT_HOURS=168（7 天）：active 且未过期就不可能早于 90 天前授予，任意合法数据集都是 0'
  ),
  nonDerivable(
    '/api/devices/stats',
    'byType[]/byStatus[] 并列项次序',
    '真实链 $sort{count:-1} 无次序键，并列由引擎定序；这里按合成表出现序'
  ),
  nonDerivable(
    '/api/devices/expiring',
    'location 的可选子键',
    '真实 FireDevice.location 还有 detail/coordinates 两个可选子键（合成行只采 building/floor/room）；属缺键方向，三键与 /api/devices 列表同形'
  ),
  nonDerivable(
    '/api/devices/reminders',
    'scannedAt',
    '请求时刻（真实链 new Date().toISOString()）⇒ 无法预置'
  ),
  nonDerivable(
    '/api/alarms/stats',
    'byStatus[]._id/byLevel[]._id 的覆盖度',
    '第三刀后数据面与真实链同为 ALARM_STATUSES/ALARM_LEVELS 英文档，但合成表只有 5 行采样 ⇒ 只覆盖出现过的档（pending/processing/resolved/false_alarm、info/warning/critical），未采样的枚举值不产桶（真实库有存量行就会产）'
  ),
  nonDerivable(
    '/api/alarms/stats',
    '各桶次序',
    '真实链 $group 后没有 $sort，桶的先后由引擎决定；这里按合成表出现序'
  ),
  nonDerivable(
    '/api/inspections/stats',
    '各桶次序',
    '真实链 $group 后没有 $sort，桶的先后由引擎决定；这里按合成表出现序'
  ),
]);

module.exports = {
  AGGREGATE_ENDPOINTS,
  DECOY_TEMP_GRANTS,
  DEVICE_EXPIRY_FIELDS,
  EXPIRING_MESSAGE,
  MODULE_NAMES,
  NON_DERIVABLE,
  REMINDER_BUCKETS,
};
