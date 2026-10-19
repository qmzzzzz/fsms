/**
 * 系统初始化数据服务 · 业务模块权限目录（设备/报警/巡检/报表/超级权限）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const businessPermissions = [
  // ================= 消防设备管理模块 =================
  { name: '设备管理菜单', code: 'device:*', type: 'menu', module: 'device', path: '/devices' },
  {
    name: '查看设备列表',
    code: 'device:read',
    type: 'api',
    module: 'device',
    path: '/api/devices',
    method: 'GET',
    parent: null,
  },
  {
    name: '创建设备',
    code: 'device:create',
    type: 'api',
    module: 'device',
    path: '/api/devices',
    method: 'POST',
    parent: null,
  },
  {
    name: '编辑设备',
    code: 'device:update',
    type: 'api',
    module: 'device',
    path: '/api/devices/:id',
    method: 'PUT',
    parent: null,
  },
  {
    name: '删除设备',
    code: 'device:delete',
    type: 'api',
    module: 'device',
    path: '/api/devices/:id',
    method: 'DELETE',
    parent: null,
  },
  {
    name: '设备维护按钮',
    code: 'device:maintain',
    type: 'button',
    module: 'device',
    path: '/devices',
  },
  {
    name: '设备报废按钮',
    code: 'device:scrap',
    type: 'button',
    module: 'device',
    path: '/devices',
  },
  {
    name: '设备统计',
    code: 'device:stats',
    type: 'api',
    module: 'device',
    path: '/api/devices/stats',
    method: 'GET',
    parent: null,
  },

  // ================= 火警报警管理模块 =================
  { name: '报警管理菜单', code: 'alarm:*', type: 'menu', module: 'alarm', path: '/alarms' },
  {
    name: '查看报警列表',
    code: 'alarm:read',
    type: 'api',
    module: 'alarm',
    path: '/api/alarms',
    method: 'GET',
    parent: null,
  },
  {
    name: '上报报警',
    code: 'alarm:create',
    type: 'api',
    module: 'alarm',
    path: '/api/alarms/report',
    method: 'POST',
    parent: null,
  },
  {
    name: '指派处理按钮',
    code: 'alarm:dispatch',
    type: 'button',
    module: 'alarm',
    path: '/alarms',
  },
  { name: '处置报警按钮', code: 'alarm:handle', type: 'button', module: 'alarm', path: '/alarms' },
  {
    name: '报警统计',
    code: 'alarm:stats',
    type: 'api',
    module: 'alarm',
    path: '/api/alarms/stats',
    method: 'GET',
    parent: null,
  },

  // ================= 巡检管理模块 =================
  {
    name: '巡检管理菜单',
    code: 'inspection:*',
    type: 'menu',
    module: 'inspection',
    path: '/inspections',
  },
  {
    name: '查看巡检列表',
    code: 'inspection:read',
    type: 'api',
    module: 'inspection',
    path: '/api/inspections',
    method: 'GET',
    parent: null,
  },
  {
    name: '创建巡检计划',
    code: 'inspection:create',
    type: 'api',
    module: 'inspection',
    path: '/api/inspections',
    method: 'POST',
    parent: null,
  },
  {
    name: '执行巡检按钮',
    code: 'inspection:execute',
    type: 'button',
    module: 'inspection',
    path: '/inspections',
  },
  {
    name: '审核巡检按钮',
    code: 'inspection:review',
    type: 'button',
    module: 'inspection',
    path: '/inspections',
  },
  {
    name: '删除巡检',
    code: 'inspection:delete',
    type: 'api',
    module: 'inspection',
    path: '/api/inspections/:id',
    method: 'DELETE',
    parent: null,
  },

  // ================= 报表统计模块 =================
  { name: '报表统计菜单', code: 'report:*', type: 'menu', module: 'report', path: '/reports' },
  {
    name: '查看报表',
    code: 'report:read',
    type: 'api',
    module: 'report',
    path: '/api/reports',
    method: 'GET',
    parent: null,
  },
  {
    name: '导出报表按钮',
    code: 'report:export',
    type: 'button',
    module: 'report',
    path: '/reports',
  },

  // ================= 超级权限 =================
  { name: '全部权限', code: '*:*', type: 'api', module: 'system', parent: null },
];

module.exports = { businessPermissions };
