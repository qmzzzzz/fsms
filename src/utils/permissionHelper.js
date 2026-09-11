/**
 * 权限辅助工具
 * 提供权限相关的通用工具方法
 */

const User = require('../models/User');
const Permission = require('../models/Permission');
const logger = require('../utils/logger');

/**
 * 获取用户的完整权限信息（包含菜单、按钮、API 权限）
 * @param {string} userId - 用户 ID
 * @returns {Promise<Object>} 权限信息对象
 */
const getUserPermissions = async (userId) => {
  try {
    const user = await User.findById(userId)
      .populate({
        path: 'roles',
        // 仅生效角色参与授权：管理员停用（inactive）角色后，
        // 该角色的全部权限不得继续通过 hasPermission/菜单树生效
        match: { status: 'active' },
        populate: {
          path: 'permissions',
          // 同理：停用的权限项不参与授权
          match: { status: 'active' },
          select: 'code name type module path method',
        },
      })
      .select('username realName email phone department avatar lastLoginAt roles createdAt');

    if (!user) {
      return null;
    }

    const permissions = new Set();
    const menuPermissions = [];
    const buttonPermissions = [];
    const apiPermissions = [];

    // match 过滤后 roles 数组中可能残留 null 占位（引用未命中），需跳过
    user.roles.filter(Boolean).forEach((role) => {
      (role.permissions || []).filter(Boolean).forEach((perm) => {
        permissions.add(perm.code);

        // 按类型分类
        switch (perm.type) {
          case 'menu':
            menuPermissions.push({
              code: perm.code,
              name: perm.name,
              path: perm.path,
              module: perm.module,
            });
            break;
          case 'button':
            buttonPermissions.push({
              code: perm.code,
              name: perm.name,
              path: perm.path,
            });
            break;
          case 'api':
            apiPermissions.push({
              code: perm.code,
              name: perm.name,
              path: perm.path,
              method: perm.method,
            });
            break;
        }
      });
    });

    return {
      user: {
        id: user._id,
        username: user.username,
        realName: user.realName,
        // email/phone 不做脱敏：getUserPermissions 的 user 对象仅被 /auth/me 消费
        // （getMenuTree/getUserPermissionSet 只读 permissions），返回的是用户本人
        // 经自身令牌认证后的数据，且该响应直接回填个人资料编辑表单——
        // 若返回脱敏值（如 q***z@x.com / 138****5678），保存时会把脱敏串写回
        // 数据库造成数据损坏，或因手机号格式校验失败而阻断全部保存。
        // 展示他人数据的接口（管理员列表等）不经过本函数，不受影响。
        email: user.email,
        phone: user.phone,
        department: user.department,
        avatar: user.avatar,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        roles: user.roles.map((r) => ({ name: r.name, code: r.code })),
      },
      permissions: Array.from(permissions),
      menuPermissions,
      buttonPermissions,
      apiPermissions,
    };
  } catch (error) {
    logger.error(`获取用户权限失败：${error.message}`);
    throw error;
  }
};

/**
 * 获取动态菜单树（根据用户权限过滤）
 * @param {string} userId - 用户 ID
 * @returns {Promise<Array>} 菜单树
 */
const getMenuTree = async (userId) => {
  try {
    const userPerms = await getUserPermissions(userId);
    if (!userPerms) return [];

    const permCodes = new Set(userPerms.permissions);

    // 单次查出全部生效权限，内存内按类型复用（原先对 Permission 集合做了两次全量查询）
    const allPerms = await Permission.find({ status: 'active' })
      .select('code name path module type')
      .sort({ module: 1, sort: 1 })
      .lean();

    // 菜单类权限
    const menus = allPerms.filter((p) => p.type === 'menu');

    // 按模块分组（用于判断用户是否拥有某模块的任意权限）
    const moduleHasPerm = new Set();
    allPerms.forEach((p) => {
      if (permCodes.has(p.code) || permCodes.has('*:*') || permCodes.has(`${p.module}:*`)) {
        moduleHasPerm.add(p.module);
      }
    });

    // 过滤有权限的菜单：拥有模块通配符、模块内任意权限、或超级权限
    const allowedMenus = menus.filter(
      (m) =>
        permCodes.has(m.code) ||
        permCodes.has('*:*') ||
        permCodes.has(`${m.module}:*`) ||
        moduleHasPerm.has(m.module)
    );

    // 构建菜单树
    const tree = [];
    const moduleMap = new Map();

    // 先创建模块节点
    const modules = [...new Set(allowedMenus.map((m) => m.module))];
    modules.forEach((mod) => {
      const modulePerm = menus.find((m) => m.code === `${mod}:*`);
      moduleMap.set(mod, {
        id: mod,
        name: modulePerm?.name || mod,
        children: [],
      });
    });

    // 挂载菜单到模块
    allowedMenus.forEach((menu) => {
      const moduleNode = moduleMap.get(menu.module);
      if (moduleNode) {
        moduleNode.children.push({
          id: menu.code,
          name: menu.name,
          path: menu.path,
          code: menu.code,
        });
      }
    });

    // 转换为主菜单结构
    moduleMap.forEach((node) => {
      if (node.children.length > 0) {
        tree.push(node);
      }
    });

    return tree;
  } catch (error) {
    logger.error(`获取菜单树失败：${error.message}`);
    return [];
  }
};

/**
 * 权限码匹配：精确 / 全局通配 / 模块通配
 */
const matchesPermission = (permCodeSet, permissionCode) => {
  if (permCodeSet.has(permissionCode)) return true;
  if (permCodeSet.has('*:*')) return true;
  const [module] = permissionCode.split(':');
  return permCodeSet.has(`${module}:*`);
};

/**
 * 权限码匹配的数组形态（O-3：授予守卫三处内联 hasPerm 闭包的唯一实现）。
 * 语义与 matchesPermission 完全一致：精确 / `*:*` 全局通配 / `module:*` 模块通配；
 * 入参为权限码数组（User.getPermissions 的返回形态），容忍非字符串码。
 * @param {string[]} permCodes 操作者持有的权限码
 * @param {string} permissionCode 待判定的权限码
 * @returns {boolean}
 */
const matchesPermissionCodes = (permCodes, permissionCode) => {
  const code = String(permissionCode);
  if (permCodes.includes(code)) return true;
  if (permCodes.includes('*:*')) return true;
  const [module] = code.split(':');
  return permCodes.includes(`${module}:*`);
};

/**
 * 取用户权限集（单次查询），供批量判定复用，避免 N+1 查询
 */
const getUserPermissionSet = async (userId) => {
  const userPerms = await getUserPermissions(userId);
  return new Set(userPerms ? userPerms.permissions : []);
};

/**
 * 检查用户是否有指定权限
 * @param {string} userId - 用户 ID
 * @param {string} permissionCode - 权限编码
 * @returns {Promise<boolean>}
 */
const hasPermission = async (userId, permissionCode) => {
  try {
    const permCodeSet = await getUserPermissionSet(userId);
    return matchesPermission(permCodeSet, permissionCode);
  } catch (error) {
    logger.error(`权限检查失败：${error.message}`);
    return false;
  }
};

/**
 * 检查用户是否有任一权限（一次取权限集后本地判定，原先每个权限码各查一次库）
 * @param {string} userId - 用户 ID
 * @param {string[]} permissionCodes - 权限编码列表
 * @returns {Promise<boolean>}
 */
const hasAnyPermission = async (userId, permissionCodes) => {
  try {
    const permCodeSet = await getUserPermissionSet(userId);
    return (permissionCodes || []).some((code) => matchesPermission(permCodeSet, code));
  } catch (error) {
    logger.error(`批量权限检查失败：${error.message}`);
    return false;
  }
};

/**
 * 检查用户是否有所有权限（同上，单次取集）
 * @param {string} userId - 用户 ID
 * @param {string[]} permissionCodes - 权限编码列表
 * @returns {Promise<boolean>}
 */
const hasAllPermissions = async (userId, permissionCodes) => {
  try {
    const permCodeSet = await getUserPermissionSet(userId);
    return (permissionCodes || []).every((code) => matchesPermission(permCodeSet, code));
  } catch (error) {
    logger.error(`批量权限检查失败：${error.message}`);
    return false;
  }
};

/**
 * 检查用户是否有指定角色
 * @param {string} userId - 用户 ID
 * @param {string|string[]} roleCodes - 角色编码（支持多个）
 * @returns {Promise<boolean>}
 */
const hasRole = async (userId, roleCodes) => {
  try {
    const user = await User.findById(userId).populate({
      path: 'roles',
      // P3-8：与 getUserPermissions 同口径——仅 active 角色参与判定。
      // 原实现不过滤 status，管理员停用角色后 hasRole 仍返回 true，
      // 而 hasPermission 已按停用口径拒绝，同一用户两处判定互相矛盾。
      match: { status: 'active' },
    });
    if (!user) return false;

    const codes = Array.isArray(roleCodes) ? roleCodes : [roleCodes];
    const userRoleCodes = user.roles.map((r) => r.code);

    return codes.some((code) => userRoleCodes.includes(code));
  } catch (error) {
    logger.error(`角色检查失败：${error.message}`);
    return false;
  }
};

/**
 * 获取用户的角色列表
 * @param {string} userId - 用户 ID
 * @returns {Promise<Array>} 角色列表
 */
const getUserRoles = async (userId) => {
  try {
    const user = await User.findById(userId).populate({
      path: 'roles',
      select: 'name code description level',
    });

    if (!user) return [];

    return user.roles.map((r) => ({
      id: r._id,
      name: r.name,
      code: r.code,
      description: r.description,
      level: r.level,
    }));
  } catch (error) {
    logger.error(`获取用户角色失败：${error.message}`);
    return [];
  }
};

/**
 * 获取用户的数据范围
 * @param {string} userId - 用户 ID
 * @returns {Promise<Object>} 数据范围
 */
const getDataScope = async (userId) => {
  const { getDataScope: getScope } = require('../middleware/rbac');
  return getScope(userId);
};

/**
 * 计算角色集合的最高层级（报告 O-13：层级校验口径的单一事实来源）
 *
 * 语义必须与历史实现逐字对齐（roleController/userController/securityController
 * 原 10 处内联展开）：roles 为 undefined/null 时视为 0；**空数组返回 -Infinity**——
 * 无角色操作者对任何层级都判「低于自身」，与「无角色不得变更任何用户」的
 * fail-closed 语义一致，改写为 0 会放行空角色用户执行层级操作，属安全回归。
 *
 * @param {Array<{level?: number}|object>} roles 已 populate 的角色列表
 * @returns {number} 最高层级；空集合 -Infinity；入参缺失 0
 */
const maxRoleLevel = (roles) =>
  Math.max(...(Array.isArray(roles) ? roles.map((r) => r.level || 0) : [0]));

/**
 * 查询操作者当前的最高角色层级（层级校验统一入口）
 *
 * 替代各 controller 内联的「findById + populate('roles','level') + Math.max」
 * 重复展开，防止口径漂移。调用方无需再自行加载 operator——
 * 历史上 10 处调用点的 operator 变量均只服务于该计算。
 *
 * @param {string} userId 操作者 ID
 * @returns {Promise<number>} 最高层级（语义见 maxRoleLevel）
 */
const getOperatorMaxLevel = async (userId) => {
  const operator = await User.findById(userId).populate('roles', 'level').lean();
  return maxRoleLevel(operator?.roles);
};

module.exports = {
  getUserPermissions,
  getMenuTree,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  hasRole,
  getUserRoles,
  getDataScope,
  matchesPermissionCodes,
  maxRoleLevel,
  getOperatorMaxLevel,
};
