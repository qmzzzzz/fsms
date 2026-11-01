/**
 * 诱饵会话「本人自助面」的合成身份与轨迹（P2）与 honeypotDecoyData.js 的分工：那张表是"业务集合"的合成行，本文件只回答 "这个会话是谁"——权限目录、本人资料、登录与操作轨迹。权限行与真实目录逐字对齐（值取自 services/initData/permissionsSystem.js 与 permissionsBusiness.js）。装扮里出现一个真实系统里查不到的权限码，等于把陷阱写在脸上；这条同值关系由 src/tests/ci/honeypotSelfShapeParity.test.js 盯着。
 * 刻意排除四条（理由见 ADR-013 边界表"本人自助面"一节）：星号通配符（如 `system:*`）是超管语义，而装扮自称的是业务管理员；security:audit 与两条 pii 权限的缺席正是 P1c "审计导出 403、未脱敏导出要二次验证"两条回答自洽的前提——声称有权限却被拒。
 */

const DECOY_SELF_EMAIL_DOMAIN = 'ljxfw.cn';

const DECOY_SELF_PROFILE = Object.freeze({
  phone: '13800001001',
  department: '中控室',
  avatar: null,
  createdAtOffsetMin: 60 * 24 * 512,
});

const DECOY_SELF_TRAIL_IP = '10.20.31.44';
const DECOY_SELF_TRAIL_SID = '8f4c1c60-77a2-4a19-9c5e-1d0e7b3a2f55';
const DECOY_SELF_TRAIL_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// 目录行构造器：只为让下面 52 行读起来像目录，字段集合与真实 Permission 文档一致
const perm = (code, type, module, name, path, method) =>
  Object.freeze({ code, type, module, name, path, ...(method ? { method } : {}) });

const DECOY_PERMISSION_CATALOG = Object.freeze([
  perm('system:*', 'menu', 'system', '系统管理', '/system'),
  perm('system:read', 'api', 'system', '查看敏感信息', '/api/security/view-sensitive', 'POST'),
  perm('user:*', 'menu', 'system', '用户管理菜单', '/system/users'),
  perm('user:read', 'api', 'system', '查看用户列表', '/api/users', 'GET'),
  perm('user:create', 'api', 'system', '创建用户', '/api/users', 'POST'),
  perm('user:update', 'api', 'system', '编辑用户', '/api/users/:id', 'PUT'),
  perm('user:delete', 'api', 'system', '删除用户', '/api/users/:id', 'DELETE'),
  perm('user:assign_role', 'button', 'system', '分配角色按钮', '/system/users'),
  perm('user:lock', 'button', 'system', '锁定/解锁用户', '/system/users'),
  perm('user:reset_password', 'button', 'system', '重置用户密码', '/system/users'),
  perm('role:*', 'menu', 'system', '角色管理菜单', '/system/roles'),
  perm('role:read', 'api', 'system', '查看角色', '/api/roles', 'GET'),
  perm('role:create', 'api', 'system', '创建角色', '/api/roles', 'POST'),
  perm('role:update', 'api', 'system', '编辑角色', '/api/roles/:id', 'PUT'),
  perm('role:delete', 'api', 'system', '删除角色', '/api/roles/:id', 'DELETE'),
  perm('role:assign', 'button', 'system', '分配权限按钮', '/system/roles'),
  perm('permission:*', 'menu', 'system', '权限管理菜单', '/system/permissions'),
  perm('permission:read', 'api', 'system', '查看权限', '/api/permissions', 'GET'),
  perm('permission:tree', 'api', 'system', '获取权限树', '/api/roles/permissions/tree', 'GET'),
  perm('permission:create', 'api', 'system', '创建权限', '/api/permissions', 'POST'),
  perm('permission:update', 'api', 'system', '更新权限', '/api/permissions/:id', 'PUT'),
  perm('permission:delete', 'api', 'system', '删除权限', '/api/permissions/:id', 'DELETE'),
  perm('security:*', 'menu', 'system', '安全管理菜单', '/system/security'),
  perm('security:stats', 'api', 'system', '查看安全统计', '/api/security/stats', 'GET'),
  perm('security:config', 'api', 'system', '安全配置管理', '/api/security/config', 'PUT'),
  perm('privilege:*', 'menu', 'system', '临时权限授予菜单', '/system/privilege-grants'),
  perm('privilege:read', 'api', 'system', '查看临时授权', '/api/permissions/grants', 'GET'),
  perm('privilege:grant', 'api', 'system', '申请临时授权', '/api/permissions/grants', 'POST'),
  perm(
    'privilege:approve',
    'api',
    'system',
    '审批临时授权',
    '/api/permissions/grants/{id}/approve',
    'POST'
  ),
  perm('device:*', 'menu', 'device', '设备管理菜单', '/devices'),
  perm('device:read', 'api', 'device', '查看设备列表', '/api/devices', 'GET'),
  perm('device:create', 'api', 'device', '创建设备', '/api/devices', 'POST'),
  perm('device:update', 'api', 'device', '编辑设备', '/api/devices/:id', 'PUT'),
  perm('device:delete', 'api', 'device', '删除设备', '/api/devices/:id', 'DELETE'),
  perm('device:maintain', 'button', 'device', '设备维护按钮', '/devices'),
  perm('device:scrap', 'button', 'device', '设备报废按钮', '/devices'),
  perm('device:stats', 'api', 'device', '设备统计', '/api/devices/stats', 'GET'),
  perm('alarm:*', 'menu', 'alarm', '报警管理菜单', '/alarms'),
  perm('alarm:read', 'api', 'alarm', '查看报警列表', '/api/alarms', 'GET'),
  perm('alarm:create', 'api', 'alarm', '上报报警', '/api/alarms/report', 'POST'),
  perm('alarm:dispatch', 'button', 'alarm', '指派处理按钮', '/alarms'),
  perm('alarm:handle', 'button', 'alarm', '处置报警按钮', '/alarms'),
  perm('alarm:stats', 'api', 'alarm', '报警统计', '/api/alarms/stats', 'GET'),
  perm('inspection:*', 'menu', 'inspection', '巡检管理菜单', '/inspections'),
  perm('inspection:read', 'api', 'inspection', '查看巡检列表', '/api/inspections', 'GET'),
  perm('inspection:create', 'api', 'inspection', '创建巡检计划', '/api/inspections', 'POST'),
  perm('inspection:execute', 'button', 'inspection', '执行巡检按钮', '/inspections'),
  perm('inspection:review', 'button', 'inspection', '审核巡检按钮', '/inspections'),
  perm('inspection:delete', 'api', 'inspection', '删除巡检', '/api/inspections/:id', 'DELETE'),
  perm('report:*', 'menu', 'report', '报表统计菜单', '/reports'),
  perm('report:read', 'api', 'report', '查看报表', '/api/reports', 'GET'),
  perm('report:export', 'button', 'report', '导出报表按钮', '/reports'),
]);

// 轨迹行构造器：字段是 AuditLog 的 lean 文档形状（服务层再补 _id、时间戳与会话身份）
const trail = (offsetMin, action, category, method, path, success, riskLevel, extra) =>
  Object.freeze({ offsetMin, action, category, method, path, success, riskLevel, ...extra });

const DECOY_SELF_LOGS = Object.freeze([
  trail(12, 'security_my-logs', 'security', 'GET', '/api/security/my-logs', true, 'low', {
    session: 'current',
    description: '查看本人操作日志',
  }),
  trail(30, 'auth_sessions', 'auth', 'GET', '/api/auth/sessions', true, 'low', {
    session: 'current',
    description: '查看本人登录设备',
  }),
  trail(71, 'device_view', 'device', 'GET', '/api/devices/68c1a4e07f3b2d0e9a5b7c31', true, 'low', {
    session: 'current',
  }),
  trail(92, 'auth_me', 'auth', 'GET', '/api/auth/me', true, 'low', { session: 'current' }),
  trail(95, 'login_success', 'auth', 'POST', '/api/auth/login', true, 'low', {
    session: 'current',
    description: '登录成功',
  }),
  trail(97, 'login_failed', 'auth', 'POST', '/api/auth/login', false, 'medium', {
    session: 'current',
    errorMessage: '用户名或密码错误',
  }),
  trail(1490, 'report_export', 'report', 'GET', '/api/reports/export', true, 'low', {
    session: 'previous',
  }),
]);

module.exports = {
  DECOY_PERMISSION_CATALOG,
  DECOY_SELF_EMAIL_DOMAIN,
  DECOY_SELF_LOGS,
  DECOY_SELF_PROFILE,
  DECOY_SELF_TRAIL_IP,
  DECOY_SELF_TRAIL_SID,
  DECOY_SELF_TRAIL_UA,
};
