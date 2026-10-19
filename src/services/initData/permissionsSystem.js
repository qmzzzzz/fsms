/**
 * 系统初始化数据服务 · 系统管理模块权限目录（seed 数据）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

/**
 * 系统预设权限列表
 * 按模块组织，覆盖消防管理系统的所有功能
 * 权限分级：
 *   - menu   : 菜单权限（前端路由可见性，path = 路由路径）
 *   - button : 按钮权限（页面内操作按钮可见性，path = 关联菜单路由）
 *   - api    : 接口权限（后端 API 访问控制，path = 接口路径，method = HTTP 方法）
 *   - dataScope 本次以 menu/button/api 三级落地，数据范围由角色 level 决定
 */
const systemPermissions = [
  // ================= 系统管理模块 =================
  { name: '系统管理', code: 'system:*', type: 'menu', module: 'system', path: '/system' },
  {
    // #9：查看他人敏感信息（手机号/邮箱全文）所需权限。本人查看免鉴权
    // （/api/security/view-sensitive 路由层 checkViewSensitivePermission 已按
    //  targetUserId 分派）；本权限授予 SECURITY_ADMIN 等需跨用户查看的角色。
    name: '查看敏感信息',
    code: 'system:read',
    type: 'api',
    module: 'system',
    path: '/api/security/view-sensitive',
    method: 'POST',
    parent: null,
  },

  // 用户管理
  { name: '用户管理菜单', code: 'user:*', type: 'menu', module: 'system', path: '/system/users' },
  {
    name: '查看用户列表',
    code: 'user:read',
    type: 'api',
    module: 'system',
    path: '/api/users',
    method: 'GET',
    parent: null,
  },
  {
    name: '创建用户',
    code: 'user:create',
    type: 'api',
    module: 'system',
    path: '/api/users',
    method: 'POST',
    parent: null,
  },
  {
    name: '编辑用户',
    code: 'user:update',
    type: 'api',
    module: 'system',
    path: '/api/users/:id',
    method: 'PUT',
    parent: null,
  },
  {
    name: '删除用户',
    code: 'user:delete',
    type: 'api',
    module: 'system',
    path: '/api/users/:id',
    method: 'DELETE',
    parent: null,
  },
  {
    name: '分配角色按钮',
    code: 'user:assign_role',
    type: 'button',
    module: 'system',
    path: '/system/users',
  },
  {
    name: '锁定/解锁用户',
    code: 'user:lock',
    type: 'button',
    module: 'system',
    path: '/system/users',
  },
  {
    name: '重置用户密码',
    code: 'user:reset_password',
    type: 'button',
    module: 'system',
    path: '/system/users',
  },

  // 角色管理
  { name: '角色管理菜单', code: 'role:*', type: 'menu', module: 'system', path: '/system/roles' },
  {
    name: '查看角色',
    code: 'role:read',
    type: 'api',
    module: 'system',
    path: '/api/roles',
    method: 'GET',
    parent: null,
  },
  {
    name: '创建角色',
    code: 'role:create',
    type: 'api',
    module: 'system',
    path: '/api/roles',
    method: 'POST',
    parent: null,
  },
  {
    name: '编辑角色',
    code: 'role:update',
    type: 'api',
    module: 'system',
    path: '/api/roles/:id',
    method: 'PUT',
    parent: null,
  },
  {
    name: '删除角色',
    code: 'role:delete',
    type: 'api',
    module: 'system',
    path: '/api/roles/:id',
    method: 'DELETE',
    parent: null,
  },
  {
    name: '分配权限按钮',
    code: 'role:assign',
    type: 'button',
    module: 'system',
    path: '/system/roles',
  },

  // 权限管理
  {
    name: '权限管理菜单',
    code: 'permission:*',
    type: 'menu',
    module: 'system',
    path: '/system/permissions',
  },
  {
    name: '查看权限',
    code: 'permission:read',
    type: 'api',
    module: 'system',
    path: '/api/permissions',
    method: 'GET',
    parent: null,
  },
  {
    name: '获取权限树',
    code: 'permission:tree',
    type: 'api',
    module: 'system',
    path: '/api/roles/permissions/tree',
    method: 'GET',
    parent: null,
  },
  // 这三条不是"顺手补的"：路由侧一直用 checkPermission('permission:create|update|delete')
  // 把关，而目录里没有这三个码 —— 权限文档是角色编辑页唯一的可勾选项来源，
  // 勾不出来的码就永远无法被授予任何人。结果是"管理权限定义"这件事
  // 只能在 *:* 超级管理员下发生，且没有任何运维路径能修正它（403 看起来像配置漏了，
  // 实际是目录里根本没有这个可授予项）。
  // 这里补齐的是**可授予性**本身：不改变任何既有角色的授权范围，需要授给谁仍由人工决定。
  {
    name: '创建权限',
    code: 'permission:create',
    type: 'api',
    module: 'system',
    path: '/api/permissions',
    method: 'POST',
    parent: null,
  },
  {
    name: '更新权限',
    code: 'permission:update',
    type: 'api',
    module: 'system',
    path: '/api/permissions/:id',
    method: 'PUT',
    parent: null,
  },
  {
    name: '删除权限',
    code: 'permission:delete',
    type: 'api',
    module: 'system',
    path: '/api/permissions/:id',
    method: 'DELETE',
    parent: null,
  },

  // 安全管理
  {
    name: '安全管理菜单',
    code: 'security:*',
    type: 'menu',
    module: 'system',
    path: '/system/security',
  },
  {
    name: '查看安全统计',
    code: 'security:stats',
    type: 'api',
    module: 'system',
    path: '/api/security/stats',
    method: 'GET',
    parent: null,
  },
  {
    name: '查看审计日志',
    code: 'security:audit',
    type: 'api',
    module: 'system',
    path: '/api/security/audit-logs',
    method: 'GET',
    parent: null,
  },
  {
    name: '安全配置管理',
    code: 'security:config',
    type: 'api',
    module: 'system',
    path: '/api/security/config',
    method: 'PUT',
    parent: null,
  },
];

module.exports = { systemPermissions };
