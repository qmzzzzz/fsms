/**
 * 系统初始化数据服务
 * 创建默认的权限、角色等基础数据
 */

const crypto = require('crypto');
const mongoose = require('mongoose');
const Permission = require('../models/Permission');
const Role = require('../models/Role');
const User = require('../models/User');
const logger = require('../utils/logger');
const { SUPER_ADMIN_ROLE_CODE, getSuperAdminUsername } = require('../utils/superAdmin');

/**
 * 系统预设权限列表
 * 按模块组织，覆盖消防管理系统的所有功能
 * 权限分级：
 *   - menu   : 菜单权限（前端路由可见性，path = 路由路径）
 *   - button : 按钮权限（页面内操作按钮可见性，path = 关联菜单路由）
 *   - api    : 接口权限（后端 API 访问控制，path = 接口路径，method = HTTP 方法）
 *   - dataScope 本次以 menu/button/api 三级落地，数据范围由角色 level 决定
 */
const defaultPermissions = [
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

/**
 * 初始化权限数据
 */
const initPermissions = async () => {
  logger.info('开始初始化权限数据...');

  try {
    // 查询已存在的权限 code
    const existingCodes = (await Permission.find({}).select('code').lean()).map((p) => p.code);
    const toInsert = defaultPermissions
      .filter((p) => !existingCodes.includes(p.code))
      .map((p) => ({ ...p, parent: null })); // 先全部置为 null，后续统一关联

    if (toInsert.length === 0) {
      logger.info('权限数据已全部存在，跳过初始化');
      return { created: 0, skipped: defaultPermissions.length };
    }

    // 先全部插入（不带 parent），确保所有文档已落库
    let inserted = [];
    let hadConflict = false;
    try {
      inserted = await Permission.insertMany(toInsert, { ordered: false });
    } catch (err) {
      // 多实例并发部署时忽略唯一索引冲突；ordered:false 下可能已有部分文档落库，
      // 此时拿不到返回数组，下方 created 改用回查数据库统计真实创建数
      if (err.code !== 11000) throw err;
      hadConflict = true;
      logger.warn('权限初始化遇到并发冲突，继续关联 parent');
    }

    // 修复：构建 code -> _id 映射时查询全部 defaultPermissions 的 code（含已存在的父权限），
    // 否则已存在的模块通配符权限（如 user:*）不在映射中，新插入子权限的 parent 永远无法关联
    const allPermCodes = defaultPermissions.map((p) => p.code);
    const allPermissions = await Permission.find({
      code: { $in: allPermCodes },
    })
      .select('code')
      .lean();
    const codeToId = new Map(allPermissions.map((p) => [p.code, p._id]));

    // 批量更新 parent 关联
    const bulkOps = [];
    for (const permData of toInsert) {
      if (permData.code.includes(':')) {
        const moduleCode = permData.code.split(':')[0];
        const parentCode = `${moduleCode}:*`;
        const parentId = codeToId.get(parentCode);
        const permId = codeToId.get(permData.code);
        if (parentId && permId) {
          bulkOps.push({
            updateOne: {
              filter: { _id: permId },
              update: { $set: { parent: parentId } },
            },
          });
        }
      }
    }

    if (bulkOps.length > 0) {
      await Permission.bulkWrite(bulkOps);
    }

    // created 以 insertMany 实际返回数组长度为准；并发冲突导致返回值丢失时回查数据库兜底，
    // 避免 toInsert.length 把因唯一键冲突未插入成功的文档也虚报为已创建
    const created = hadConflict
      ? await Permission.countDocuments({ code: { $in: toInsert.map((p) => p.code) } })
      : inserted.length;
    const skipped = defaultPermissions.length - created;
    logger.info(
      `权限初始化完成：创建 ${created} 个，关联 ${bulkOps.length} 个 parent，跳过 ${skipped} 个`
    );
    return { created, skipped };
  } catch (error) {
    logger.error(`权限初始化失败：${error.message}`);
    throw error;
  }
};

/**
 * 初始化角色数据
 * 注意：内置角色（isBuiltIn）每次启动都会与 rolePermissionMap 对账，
 * 防止数据库残留过宽权限（如 GUEST 曾拥有 device:* 通配符）无法被收回。
 *
 * P3-21 消除 N+1：原实现对每个角色各发一次 findOne + 一次 Permission.find
 * （5 个角色 ≥ 10 次串行往返），且 SECURITY_ADMIN/FIRE_SUPERVISOR 的权限集
 * 高度重叠却各自重复拉取。现在改为「两次批量查询 + 内存内映射」：
 * 一次取回全部角色，一次取回全部涉及的权限，之后纯内存比对。
 */
const initRoles = async () => {
  logger.info('开始初始化角色数据...');

  let created = 0;
  let skipped = 0;
  let reconciled = 0;

  // ===== 批量预取（替代逐角色查询） =====
  const allRoleCodes = defaultRoles.map((r) => r.code);
  const existingRoles = await Role.find({ code: { $in: allRoleCodes } });
  const existingByCode = new Map(existingRoles.map((r) => [r.code, r]));

  // 所有角色涉及的权限码取并集后一次查完（重叠权限只查一次）
  const allPermCodes = [...new Set(defaultRoles.flatMap((r) => rolePermissionMap[r.code] || []))];
  const permDocs =
    allPermCodes.length > 0
      ? await Permission.find({ code: { $in: allPermCodes } })
          .select('_id code')
          .lean()
      : [];
  const permIdByCode = new Map(permDocs.map((p) => [p.code, p._id]));

  /** 取某角色预定义权限对应的 ObjectId 列表（缺失的权限码自动跳过） */
  const permIdsFor = (roleCode) =>
    (rolePermissionMap[roleCode] || []).map((code) => permIdByCode.get(code)).filter(Boolean);

  // 先收集所有需要创建的 role + 权限，再批量操作，减少中间失败导致的脏数据
  const rolesToCreate = [];
  const rolePermissionsMap = new Map(); // roleCode -> [permIds]
  // 内置角色权限对账的批量更新操作
  const reconcileOps = [];

  for (const roleData of defaultRoles) {
    const existing = existingByCode.get(roleData.code);
    if (existing) {
      skipped++;
      // 内置角色：与 rolePermissionMap 对账，强制收敛到预定义权限集
      if (roleData.isBuiltIn) {
        const expectedIds = permIdsFor(roleData.code).map((id) => id.toString());
        const currentIds = (existing.permissions || []).map((p) => p.toString());
        const needsUpdate =
          expectedIds.length !== currentIds.length ||
          !expectedIds.every((id) => currentIds.includes(id));
        if (needsUpdate) {
          reconcileOps.push({
            updateOne: {
              filter: { _id: existing._id },
              update: { $set: { permissions: expectedIds } },
            },
          });
          reconciled++;
          logger.warn(`内置角色 ${roleData.code} 权限已对账收敛`);
        }
      }
      continue;
    }
    rolesToCreate.push(roleData);

    const permIds = permIdsFor(roleData.code);
    if (permIds.length > 0) {
      rolePermissionsMap.set(roleData.code, permIds);
    }
  }

  // 对账更新一次性提交（原实现逐个 existing.save()）
  if (reconcileOps.length > 0) {
    await Role.bulkWrite(reconcileOps);
  }

  // 批量创建角色
  if (rolesToCreate.length > 0) {
    const createdRoles = await Role.insertMany(rolesToCreate, { ordered: false });

    // 批量更新权限关联
    const bulkOps = [];
    for (const role of createdRoles) {
      const permIds = rolePermissionsMap.get(role.code);
      if (permIds && permIds.length > 0) {
        bulkOps.push({
          updateOne: {
            filter: { _id: role._id },
            update: { $set: { permissions: permIds } },
          },
        });
      }
    }
    if (bulkOps.length > 0) {
      await Role.bulkWrite(bulkOps);
    }
    created = createdRoles.length;
  }

  logger.info(`角色初始化完成：创建 ${created} 个，对账 ${reconciled} 个，跳过 ${skipped} 个`);
  return { created, reconciled, skipped };
};

/**
 * 创建默认管理员账户
 */
const createDefaultAdmin = async () => {
  logger.info('检查默认管理员账户...');

  const adminRole = await Role.findOne({ code: SUPER_ADMIN_ROLE_CODE });
  if (!adminRole) {
    logger.warn('未找到超级管理员角色，跳过管理员创建');
    return null;
  }

  const existingAdmin = await User.findByUsername(getSuperAdminUsername());
  if (existingAdmin) {
    logger.info('默认管理员账户已存在');
    return existingAdmin;
  }

  // 默认管理员密码：优先从环境变量读取，未配置时生成随机强密码
  const adminPassword =
    process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(16).toString('hex');

  // 邮箱可配置（P2-22）：原先硬编码 'admin@example.com'，而 email 有唯一索引，
  // 且 createDefaultAdmin 只按 username 判重。若在公开注册开启期间有人抢注该邮箱，
  // 后续全新环境启动时 User.create 抛 E11000 → initializeSystem rethrow → 进程退出，
  // 形成可远程触发的开机 DoS。
  // 两层防护：① 允许用 ADMIN_INITIAL_EMAIL 覆盖；② 撞唯一键时自动降级为唯一后备邮箱。
  const desiredEmail = (process.env.ADMIN_INITIAL_EMAIL || '').trim() || 'admin@example.com';
  const username = getSuperAdminUsername();

  /** 用指定邮箱创建管理员 */
  const createWith = (email) =>
    User.create({
      username,
      email,
      password: adminPassword,
      realName: '系统管理员',
      status: 'active',
      roles: [adminRole._id],
    });

  // 创建时一并写入 roles，单次落库：原先「create 后再 save 绑定角色」的两步写
  // 在两步之间进程中断会留下无角色的 admin 账户（登录后权限为空）
  let admin;
  try {
    admin = await createWith(desiredEmail);
  } catch (err) {
    // 仅对 email 唯一键冲突降级；其他错误（含 username 冲突）照常抛出
    const conflictKey = err?.code === 11000 ? Object.keys(err.keyPattern || {})[0] : null;
    if (conflictKey !== 'email') throw err;

    const fallbackEmail = `admin+${Date.now().toString(36)}@localhost.invalid`;
    logger.warn(
      `默认管理员邮箱 ${desiredEmail} 已被占用（可能被外部注册抢占），` +
        `降级使用 ${fallbackEmail} 以避免启动失败；请登录后修改为真实邮箱`
    );
    admin = await createWith(fallbackEmail);
  }

  logger.info('默认管理员账户已创建', { username: getSuperAdminUsername() });
  if (!process.env.ADMIN_INITIAL_PASSWORD) {
    // 密码不写入日志文件，写入受保护的初始密码文件（权限 600）
    // 避免被日志收集系统（ELK/CloudWatch）持久化
    try {
      const fs = require('fs');
      const path = require('path');
      const pwdFile = path.join(process.cwd(), '.admin-initial-password');
      fs.writeFileSync(
        pwdFile,
        `username: ${getSuperAdminUsername()}\npassword: ${adminPassword}\n`,
        { mode: 0o600 }
      );
      // Windows 局限：NTFS 不支持 POSIX 权限位，writeFileSync 的 mode 参数在 Windows 上被忽略，
      // chmodSync 也只能粗粒度切换只读属性。此处 best-effort 再收紧一次：
      // 类 Unix 平台确保 0600；Windows 平台失败仅告警不阻断（文件位于进程工作目录内）
      try {
        fs.chmodSync(pwdFile, 0o600);
      } catch (chmodErr) {
        logger.warn(`初始密码文件权限收紧失败（Windows 下 mode 参数无效）：${chmodErr.message}`);
      }
      logger.info(`管理员初始密码已写入 ${pwdFile}（权限 600），请尽快登录后修改`);
    } catch (e) {
      // M-02 修复：文件写入失败时绝不将密码明文输出到 stdout/日志
      // （容器环境 stdout 会被日志驱动持久化，等同密码泄露）。
      // 只提示可操作的恢复途径；密码仅存在于内存，进程退出即丢失，
      // 此时应通过 ADMIN_INITIAL_PASSWORD 显式指定后重启。
      logger.error(
        `初始密码文件写入失败（${e.message}）。请停止服务，通过环境变量 ADMIN_INITIAL_PASSWORD ` +
          '显式指定管理员初始密码后重新启动；切勿从日志中查找密码（密码未被记录）。'
      );
    }
  } else {
    logger.warn('*** 请及时修改默认管理员密码！***');
  }

  return admin;
};

/**
 * 超级管理员归属对账
 *
 * 唯一超管是系统不变量，且**只在此处**被写入——所有 HTTP 接口一律拒绝
 * 变更超管归属（见 utils/superAdmin.js 的设计说明）。因此这里是唯一的
 * 修复入口：无论归属如何丢失（误操作、直连数据库改动、迁移遗漏），
 * 重启一次即自愈。
 *
 * 三类情形：
 * 1. 指定账户缺少超管角色 → 补回（覆盖「0 持有者」的不可恢复状态）
 * 2. 其他账户多持有超管角色 → 剥离并记 error 日志（唯一性收敛）
 * 3. 指定账户不存在 → 只告警不创建：账户创建有独立流程
 *    （createDefaultAdmin），此处凭空造号会绕开密码策略与审计
 *
 * @returns {Promise<void>}
 */
const reconcileSuperAdmin = async () => {
  const username = getSuperAdminUsername();
  logger.info('超级管理员归属对账', { username });

  const superRole = await Role.findOne({ code: SUPER_ADMIN_ROLE_CODE });
  if (!superRole) {
    logger.error('未找到 SUPER_ADMIN 角色，超管对账跳过（initRoles 应已播种该角色）');
    return;
  }
  if (!superRole.isBuiltIn) {
    // isBuiltIn 是所有超管保护判断的前置条件（isSuperAdminRole 要求二者同时成立），
    // 一旦为 false，全部 SUPER_ADMIN 保护逻辑静默失效
    logger.warn('SUPER_ADMIN 角色的 isBuiltIn 为 false，已强制修正为 true');
    await Role.updateOne({ _id: superRole._id }, { $set: { isBuiltIn: true } });
  }

  const target = await User.findByUsername(username);
  if (!target) {
    logger.warn(
      `超管目标账户 ${username} 不存在，归属对账跳过。` +
        '如需指定其他账户，请设置环境变量 SUPER_ADMIN_USERNAME'
    );
    return;
  }

  // 1) 目标账户补齐超管角色（$addToSet 幂等，不会重复push）
  const targetHas = (target.roles || []).some((r) => String(r) === String(superRole._id));
  if (!targetHas) {
    await User.updateOne({ _id: target._id }, { $addToSet: { roles: superRole._id } });
    logger.warn('已为账户补回 SUPER_ADMIN 角色（此前缺失，最高权限不可用）', { username });
    // 角色变化必须失效认证缓存，否则该账户已签发的会话仍按旧角色鉴权
    try {
      const { invalidateUserCache } = require('../middleware/auth');
      invalidateUserCache(target._id);
    } catch (e) {
      logger.debug(`超管对账缓存失效跳过：${e.message}`);
    }
  }

  // 2) 其他账户剥离超管角色（唯一性收敛）
  const extras = await User.find({
    _id: { $ne: target._id },
    roles: superRole._id,
  }).select('username');

  if (extras.length > 0) {
    await User.updateMany(
      { _id: { $ne: target._id }, roles: superRole._id },
      { $pull: { roles: superRole._id } }
    );
    logger.error(
      `检测到 ${extras.length} 个非授权账户持有 SUPER_ADMIN 角色，已剥离：` +
        extras.map((u) => u.username).join('、')
    );
    try {
      const { invalidateUserCache } = require('../middleware/auth');
      extras.forEach((u) => invalidateUserCache(u._id));
    } catch (e) {
      logger.debug(`超管对账缓存失效跳过：${e.message}`);
    }
  }

  logger.info('超级管理员归属已对齐', { username });
};

/**
 * 清理 tokenblacklists 集合的遗留唯一索引
 *
 * 背景：早期 schema 用明文 `token` 字段存黑名单，后改为 `tokenHash`（SHA-256）。
 * 字段改名了，但 MongoDB 里的 `token_1` 唯一索引不会随 schema 变更自动删除。
 * 于是新写入的文档 token 字段全为 undefined → 索引键均为 null →
 * **第二条起插入必然 E11000**。
 *
 * 后果（实测）：consumeToken 把这个 E11000 当作「refresh token 重放」，
 * 每次刷新都触发 invalidateUserTokens 递增 tokenVersion，用户会话被永久吊销，
 * 且因为同时写了 passwordChangedAt，前端收到「密码已修改，请重新登录」的
 * 误导性提示。表现为「注册用户的 refresh_token 永久失效」。
 *
 * 这里在启动期做幂等清理：只删 `token` 单键索引，不动 tokenHash/expiresAt/userId。
 * @returns {Promise<void>}
 */
const reconcileTokenBlacklistIndexes = async () => {
  try {
    const coll = mongoose.connection.collection('tokenblacklists');
    const indexes = await coll.indexes();

    // 精确匹配「仅含 token 单键」的索引；避免误删复合索引
    const legacy = indexes.filter((idx) => {
      const keys = Object.keys(idx.key || {});
      return keys.length === 1 && keys[0] === 'token';
    });

    if (legacy.length === 0) return;

    for (const idx of legacy) {
      await coll.dropIndex(idx.name);
      logger.warn(
        `已删除 tokenblacklists 的遗留索引 ${idx.name}（旧 schema 的明文 token 字段）：` +
          '该索引会让所有新文档因 token=null 撞唯一键，导致 refresh 轮换被误判为重放'
      );
    }
  } catch (e) {
    // 集合不存在（全新部署）属正常情况，其余异常只告警不阻断启动
    if (e.codeName === 'NamespaceNotFound' || /ns does not exist/i.test(e.message || '')) return;
    logger.warn(`tokenblacklists 索引对账跳过：${e.message}`);
  }
};

/**
 * 初始化系统配置（注册开关等）
 */
const initSystemConfig = async () => {
  const { SystemConfig } = require('../models');

  // 注册开关：默认关闭公开注册（生产环境安全）
  // 仅在配置不存在时按环境变量播种（$setOnInsert），此后由
  // PUT /api/security/config/allowPublicRegistration 独占管理。
  //
  // 必须用 $setOnInsert 而非无条件 set：若每次启动都按 env 覆写，
  // 管理员在运行时关闭注册后，一次重启就会按 ALLOW_PUBLIC_REGISTRATION=true
  // 悄悄重新开放公网注册——安全属性静默倒退，且反向的「临时开放后关闭」
  // 同样无法持久。与紧邻的 loginCaptchaEnabled 保持同一口径。
  await SystemConfig.updateOne(
    { key: 'allowPublicRegistration' },
    {
      $setOnInsert: {
        key: 'allowPublicRegistration',
        value: process.env.ALLOW_PUBLIC_REGISTRATION === 'true',
        valueType: 'boolean',
        description: '公开注册开关',
      },
    },
    { upsert: true }
  );

  // 登录验证码开关：默认关闭；仅在配置不存在时播种（$setOnInsert），
  // 管理员通过 API 修改后的状态不会被服务重启覆盖
  await SystemConfig.updateOne(
    { key: 'loginCaptchaEnabled' },
    {
      $setOnInsert: {
        key: 'loginCaptchaEnabled',
        value: false,
        valueType: 'boolean',
        description: '登录图形验证码开关',
      },
    },
    { upsert: true }
  );

  // updateOne 绕过了 SystemConfig.set 内置的缓存失效，此处显式清理：
  // 测试/嵌入场景可能在同进程内先读过开关（写入负缓存），播种后需让其重读
  SystemConfig.invalidateRegistrationCache();
  SystemConfig.invalidateLoginCaptchaCache();

  logger.info('系统配置初始化完成');
};

/**
 * 对账 users 集合的 username 索引（P3-30）
 *
 * schema 从「字段级 unique」改为「显式 collation 唯一索引 username_ci」后，
 * MongoDB 里既有的 `username_1`（默认 collation，大小写敏感）不会自动消失。
 * 两个索引并存时 username_1 仍然放行 Admin/admin 共存，修复等于没生效。
 *
 * 关键顺序问题：不能先删旧索引再建新索引——若库中已存在大小写冲突的账号，
 * 新的唯一索引会创建失败，而旧索引已被删掉，结果是**两个约束都没有**。
 * 因此流程为：① 先检测冲突组；② 有冲突则保留旧索引并告警，等人工处置；
 * ③ 无冲突才删除 username_1（新索引由 mongoose autoIndex 建立）。
 *
 * @returns {Promise<void>}
 */
const reconcileUserIndexes = async () => {
  try {
    const coll = mongoose.connection.collection('users');
    const indexes = await coll.indexes();
    const legacy = indexes.find((idx) => idx.name === 'username_1');
    if (!legacy) return;

    // 大小写归一化后分组，找出视觉等同却并存的账号
    const conflicts = await coll
      .aggregate([
        {
          $group: {
            _id: { $toLower: '$username' },
            count: { $sum: 1 },
            names: { $addToSet: '$username' },
          },
        },
        { $match: { count: { $gt: 1 } } },
      ])
      .toArray();

    if (conflicts.length > 0) {
      const detail = conflicts.map((c) => c.names.join('/')).join('；');
      logger.error(
        '检测到大小写冲突的用户名，无法启用大小写不敏感唯一索引：' +
          `${detail}。旧索引 username_1 已保留（约束不会中断），` +
          '请人工合并或重命名冲突账号后重启服务完成索引升级'
      );
      return;
    }

    await coll.dropIndex('username_1');
    logger.warn(
      '已删除 users 的遗留索引 username_1（大小写敏感）：' +
        '该索引允许 Admin/admin 并存，构成操作者身份仿冒面；' +
        '大小写不敏感的 username_ci 唯一索引由 schema 定义接管'
    );
  } catch (e) {
    if (e.codeName === 'NamespaceNotFound' || /ns does not exist/i.test(e.message || '')) return;
    logger.warn(`users 索引对账跳过：${e.message}`);
  }
};

const initializeSystem = async () => {
  try {
    await initPermissions();
    await initRoles();
    // 用户名索引对账须在任何写入 users 之前：createDefaultAdmin 依赖
    // findByUsername 的 collation 判重，索引缺失时该查询会退化为全表扫描
    await reconcileUserIndexes();
    await createDefaultAdmin();
    // 超管对账须在 createDefaultAdmin 之后：首次启动时 admin 账户此刻才存在
    await reconcileSuperAdmin();
    // 索引对账：清掉旧 schema 残留的唯一索引，否则 refresh 轮换会被误判为重放
    await reconcileTokenBlacklistIndexes();
    await initSystemConfig();
    logger.info('=== 系统初始化完成 ===');
  } catch (error) {
    logger.error(`系统初始化失败：${error.message}`);
    throw error;
  }
};

module.exports = {
  initializeSystem,
  initPermissions,
  initRoles,
  createDefaultAdmin,
  reconcileSuperAdmin,
  reconcileUserIndexes,
  reconcileTokenBlacklistIndexes,
  initSystemConfig,
  defaultPermissions,
  defaultRoles,
};
