'use strict'; // 批次 D：六个列表端点的信封/校验/排序单一来源（纯声明；零 model/service/mongoose 依赖）

const { DEVICE_TYPE, USER_STATUS } = require('../utils/constants');
const { ALARM_LEVELS, ALARM_STATUSES, ALARM_TYPES } = require('./alarm');
const { DEVICE_STATUS_VALUES } = require('./deviceStatus');
const { INSPECTION_STATUSES, INSPECTION_TYPES } = require('./inspection');
const { PERMISSION_TYPES, RESOURCE_STATUSES } = require('./permission');

/*
 * "未终结档"集合：口径出处是 AlarmService.js:372 的 `status: { $in: ['pending', 'processing'] }`
 * （列表侧唯一在用的未终结集合）。第三刀起数据面直接用真实英文枚举（honeypotDecoyEvents.js），
 * 这张表只剩"把源码里的集合写成常量"一件事，同源性由 honeypotListShapeParity.test.js 从该
 * 源码文本抽取比对——不是"再抄一份"就算数。
 */
const OPEN_ALARM_STATUSES = Object.freeze(['pending', 'processing']);
const ALARM_OPEN_STATUSES = Object.freeze(
  ALARM_STATUSES.filter((code) => OPEN_ALARM_STATUSES.includes(code))
);

// 校验规则描述符：kind/参数/文案逐条对应真实路由的 listQueryValidation 数组（数组顺序=错误顺序）。
// optional:'falsy' ≡ optional({values:'falsy'})（跳过 undefined/null/''/false/0）；
// optional:'undefined' ≡ optional()（只跳过 undefined——`?page=` 这种空串照样 400）。
const enumRule = (field, values, msg) =>
  Object.freeze({ field, kind: 'in', values, msg, optional: 'falsy' });
const lengthRule = (field, max, msg) =>
  Object.freeze({ field, kind: 'length', max, trim: true, msg, optional: 'undefined' });
const mongoIdRule = (field, msg) =>
  Object.freeze({ field, kind: 'mongoId', msg, optional: 'falsy' });
const isoRule = (field, msg) => Object.freeze({ field, kind: 'iso8601', msg, optional: 'falsy' });
const PAGE_RULE = Object.freeze({
  field: 'page',
  kind: 'int',
  min: 1,
  msg: '页码无效',
  optional: 'undefined',
});
const LIMIT_RULE = Object.freeze({
  field: 'limit',
  kind: 'int',
  min: 1,
  max: 100,
  msg: '每页数量应在 1-100',
  optional: 'undefined',
});
const DATES = Object.freeze(['startDate', 'endDate']);
const sortOf = (...pairs) =>
  Object.freeze(pairs.map(([field, dir]) => Object.freeze({ field, dir })));
const searchOf = (...pairs) =>
  Object.freeze(pairs.map(([field, kind]) => Object.freeze({ field, kind })));

const LIST_ENDPOINTS = Object.freeze([
  Object.freeze({
    key: 'users',
    path: '/api/users',
    message: '获取用户列表成功',
    defaultLimit: 10,
    maxLimit: 500, // 控制器没传第三个实参 ⇒ normalizePagination 的 500 上限；路由把 limit 卡在 100，这档到不了，值只是与真实调用逐字对齐
    nextCursor: false,
    filters: Object.freeze(['status', 'department', 'role']),
    sort: sortOf(['createdAt', -1]), // controllers/userController/read.js:24-36 的 validateSort 白名单缺省值
    search: searchOf(['username', 'prefix'], ['realName', 'substring']),
    rules: Object.freeze([
      enumRule('status', Object.values(USER_STATUS), '无效的用户状态'),
      PAGE_RULE,
      LIMIT_RULE,
      lengthRule('department', 100, '部门名称不能超过 100 个字符'),
      lengthRule('role', 50, '角色编码不能超过 50 个字符'),
    ]),
  }),
  Object.freeze({
    key: 'roles',
    path: '/api/roles',
    message: '获取角色列表成功',
    defaultLimit: 10,
    maxLimit: 500,
    nextCursor: false,
    filters: Object.freeze(['status']),
    sort: sortOf(['level', 1], ['createdAt', -1]),
    search: searchOf(['name', 'substring'], ['code', 'codePrefix']),
    rules: Object.freeze([
      enumRule('status', RESOURCE_STATUSES, '无效的状态值'),
      PAGE_RULE,
      LIMIT_RULE,
    ]),
  }),
  Object.freeze({
    key: 'permissions',
    path: '/api/permissions',
    message: '获取权限列表成功',
    defaultLimit: 50, // controllers/permissionController.js:22-45 的 limit = 50
    maxLimit: 500,
    nextCursor: false,
    filters: Object.freeze(['type', 'status', 'module']),
    sort: sortOf(['module', 1], ['sort', 1], ['createdAt', -1]),
    search: null, // listPermissions 不读 search：这里给 null 而不是空表，免得日后被当成"漏了"
    rules: Object.freeze([
      enumRule('type', PERMISSION_TYPES, '无效的权限类型'),
      enumRule('status', RESOURCE_STATUSES, '无效的状态值'),
      lengthRule('module', 50, '模块名不能超过 50 个字符'),
      PAGE_RULE,
      LIMIT_RULE,
    ]),
  }),
  Object.freeze({
    key: 'devices',
    path: '/api/devices',
    message: '获取设备列表成功',
    defaultLimit: 10,
    maxLimit: 100,
    nextCursor: true, // DeviceService offset 分支也下发 nextCursor（无下一页时是 null，不是缺键）
    filters: Object.freeze(['status', 'deviceType', 'building', 'floor']),
    sort: sortOf(['deviceCode', 1]),
    search: searchOf(['name', 'substring'], ['code', 'codePrefix']),
    rules: Object.freeze([
      enumRule('status', DEVICE_STATUS_VALUES, '无效的设备状态'),
      enumRule('deviceType', Object.values(DEVICE_TYPE), '无效的设备类型'),
      PAGE_RULE,
      LIMIT_RULE,
      lengthRule('building', 100, '楼栋不能超过 100 个字符'),
      lengthRule('floor', 100, '楼层不能超过 100 个字符'),
    ]),
  }),
  Object.freeze({
    key: 'alarms',
    path: '/api/alarms',
    message: '获取报警列表成功',
    defaultLimit: 10,
    maxLimit: 100,
    nextCursor: true,
    filters: Object.freeze(['status', 'level', 'alarmType']),
    dates: DATES,
    sort: sortOf(['occurredAt', -1], ['_id', -1]),
    search: searchOf(['code', 'prefix'], ['description', 'substring'], ['location', 'substring']),
    rules: Object.freeze([
      enumRule('status', ALARM_STATUSES, '无效的报警状态'),
      enumRule('level', ALARM_LEVELS, '无效的报警级别'),
      enumRule('alarmType', ALARM_TYPES, '无效的报警类型'),
      PAGE_RULE,
      LIMIT_RULE,
      isoRule('startDate', '开始日期格式无效'),
      isoRule('endDate', '结束日期格式无效'),
    ]),
  }),
  Object.freeze({
    key: 'inspections',
    path: '/api/inspections',
    message: '获取巡检列表成功',
    defaultLimit: 10,
    maxLimit: 100,
    nextCursor: true,
    filters: Object.freeze(['status', 'inspectionType', 'assignedTo']),
    dates: DATES,
    sort: sortOf(['planStartTime', -1], ['_id', -1]),
    search: searchOf(['code', 'substring'], ['area', 'substring']),
    rules: Object.freeze([
      enumRule('status', INSPECTION_STATUSES, '无效的巡检状态'),
      enumRule('inspectionType', INSPECTION_TYPES, '无效的巡检类型'),
      mongoIdRule('assignedTo', '执行人 ID 格式无效'),
      PAGE_RULE,
      LIMIT_RULE,
      isoRule('startDate', '开始日期格式无效'),
      isoRule('endDate', '结束日期格式无效'),
    ]),
  }),
]);

const LIST_ENDPOINTS_BY_KEY = Object.freeze(
  Object.fromEntries(LIST_ENDPOINTS.map((endpoint) => [endpoint.key, endpoint]))
);

module.exports = {
  ALARM_OPEN_STATUSES,
  LIST_ENDPOINTS,
  LIST_ENDPOINTS_BY_KEY,
  OPEN_ALARM_STATUSES,
};
