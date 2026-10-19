/**
 * 系统初始化数据服务 · 内置角色目录与角色-权限映射（seed 数据）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

/**
 * 系统预设角色
 */
const defaultRoles = [
  {
    name: '超级管理员',
    code: 'SUPER_ADMIN',
    description: '拥有系统全部权限',
    level: 10,
    isBuiltIn: true,
  },
  {
    name: '安全管理员',
    code: 'SECURITY_ADMIN',
    description: '负责用户管理和权限分配',
    level: 8,
    isBuiltIn: true,
  },
  {
    // A6（2026-10-16）职责分离：把「查看审计」从「执行敏感操作」的角色里拆出来。
    //
    // 背景：SECURITY_ADMIN 同时持有 user:delete 与 security:audit —— 一个角色既能做
    // 敏感操作、又能查看这些操作的审计记录。主篡改向量（改/删审计记录）已被审计链
    // （utils/auditChain.js + scripts/verify-audit-chain.js，append-only + hash chain）覆盖，
    // 剩下的是合规口味问题：执行者与监督者不应是同一人。
    //
    // 权限集**只有两条只读**（security:audit + security:stats），没有任何写权限：
    // 这正是本角色的存在意义——它拿到审计读权限的同时不可能改变任何数据。
    //
    // level 取 9（不是 8）是刻意的：数据范围由 level 决定（middleware/rbac.js:169，
    // ≥9 全部 / ≥7 本部门 / ≥5 仅自己）。外部审计与上级监督要看的正是**全量**审计视图，
    // 与 SECURITY_ADMIN 同档（8 ⇒ 本部门）会让这个角色看不到本部门之外的记录、
    // 从而失去拆分的意义。level 只影响数据范围，不授予任何权限——权限一律来自
    // 下面的 rolePermissionMap，故 level 9 不会让它多拿到任何一条操作权
    // （isGlobalAdmin 判据是 `*:*` 权限而不是 level，见 controllers/roleGuards.js:122）。
    name: '审计监督员',
    code: 'AUDIT_VIEWER',
    description: '只读审计日志与安全统计，供外部审计/上级监督使用（无任何写权限）',
    level: 9,
    isBuiltIn: true,
  },
  {
    name: '消防主管',
    code: 'FIRE_SUPERVISOR',
    description: '负责报警处理和巡检审核',
    level: 6,
    isBuiltIn: true,
  },
  {
    name: '普通消防员',
    code: 'FIREFIGHTER',
    description: '执行巡检和设备查看',
    level: 4,
    isBuiltIn: true,
  },
  {
    name: '访客',
    code: 'GUEST',
    description: '只读基础信息',
    level: 1,
    isBuiltIn: true,
  },
];

/**
 * 角色 - 权限映射关系（精细化，遵循最小权限原则）
 * level 决定数据范围：≥9 全部 / ≥7 本部门 / ≥5 仅自己 / 其余无
 *
 * 注意：此处使用具体权限编码而非 module:* 通配符，
 * 避免角色获得超出其职责的删除/修改权限。
 * 菜单可见性由 getMenuTree 的「模块内任一权限」逻辑保证，无需通配符。
 */
const rolePermissionMap = {
  // 超级管理员：全部权限
  SUPER_ADMIN: ['*:*'],

  // 安全管理员（level 8）：用户管理 + 角色管理 + 权限查看 + 安全审计 + 业务只读监督
  SECURITY_ADMIN: [
    // — 用户管理 —
    'user:read',
    'user:create',
    'user:update',
    'user:delete',
    'user:lock',
    'user:reset_password',
    'user:assign_role',
    // — 角色管理 —
    'role:read',
    'role:create',
    'role:update',
    'role:delete',
    'role:assign',
    // — 权限查看（只读，不修改权限定义）—
    'permission:read',
    'permission:tree',
    // — 安全管理 —
    'security:stats',
    'security:audit',
    // #9：查看他人敏感信息（手机号/邮箱全文）需 system:read；本人查看免鉴权
    'system:read',
    // — 业务数据只读（监督用）—
    'device:read',
    'device:stats',
    'alarm:read',
    'alarm:stats',
    'inspection:read',
    'report:read',
    'report:export',
  ],

  // 审计监督员（level 9）：**只读**审计与安全统计，无任何写权限（A6 职责分离）
  //
  // 与 SECURITY_ADMIN 的差别只有一处、且是有意的一处：不持 user:delete / role:assign
  // 等任何敏感操作权限。于是"执行敏感操作"与"查看这些操作的审计"落在两个角色上。
  // 刻意**不**给 report:export：审计导出（security_audit-logs_export）是 security:audit
  // 下的独立出口，业务报表导出与审计监督无关，多给一条只会扩大数据外发面。
  AUDIT_VIEWER: ['security:stats', 'security:audit'],

  // 消防主管（level 6）：报警处理 + 巡检审核 + 设备维护 + 报表
  FIRE_SUPERVISOR: [
    // — 设备管理（查看/维护/报废，不直接删除）—
    'device:read',
    'device:maintain',
    'device:scrap',
    'device:stats',
    // — 报警管理（完整处理流程）—
    'alarm:read',
    'alarm:create',
    'alarm:dispatch',
    'alarm:handle',
    'alarm:stats',
    // — 巡检管理（创建/审核）—
    'inspection:read',
    'inspection:create',
    'inspection:review',
    // — 报表 —
    'report:read',
    'report:export',
  ],

  // 普通消防员（level 4）：执行巡检 + 报警上报/处置 + 设备查看
  FIREFIGHTER: [
    // — 设备只读 —
    'device:read',
    // — 报警（上报 + 处置）—
    'alarm:read',
    'alarm:create',
    'alarm:handle',
    // — 巡检（执行）—
    'inspection:read',
    'inspection:execute',
  ],

  // 访客（level 1）：只读基础信息
  GUEST: ['device:read', 'alarm:read', 'inspection:read', 'report:read'],
};

module.exports = { defaultRoles, rolePermissionMap };
