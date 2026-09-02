/**
 * RBAC 权限控制中间件
 * 基于角色的访问控制核心实现
 * 支持菜单权限、按钮权限、API 权限、数据范围权限的多层级控制
 */

const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const logger = require('../utils/logger');

/**
 * 权限检查中间件工厂
 * @param {string|string[]} requiredPermissions - 需要的权限编码，支持多个
 * @param {string} logic - 多个权限时的逻辑：'AND' 或 'OR'
 */
const checkPermission = (requiredPermissions, logic = 'OR') => {
  return async (req, res, next) => {
    try {
      const userId = req.user.userId;
      const permissions = Array.isArray(requiredPermissions)
        ? requiredPermissions
        : [requiredPermissions];

      logger.debug('检查用户是否拥有权限', {
        userId,
        requiredPermissions: permissions,
      });

      // 同一请求内复用权限结果，避免 N+1 查询
      if (!req.userPermissions) {
        req.userPermissions = await User.getPermissions(userId);
      }
      const userPermissions = req.userPermissions;
      logger.debug(`用户权限列表：${JSON.stringify(userPermissions)}`);

      // 检查是否拥有超级管理员权限
      if (userPermissions.includes('*:*')) {
        logger.debug('用户拥有超级管理员权限，通过检查');
        return next();
      }

      let hasAccess = false;

      // 检查用户是否有某个权限（支持通配符匹配）
      const userHasPermission = (requiredPerm) => {
        // 精确匹配
        if (userPermissions.includes(requiredPerm)) return true;
        // 超级管理员通配符
        if (userPermissions.includes('*:*')) return true;

        // 模块通配符匹配：如 user:* 匹配 user:create, user:read 等
        const [reqModule] = requiredPerm.split(':');
        const moduleWildcard = `${reqModule}:*`;
        if (userPermissions.includes(moduleWildcard)) return true;

        return false;
      };

      if (logic === 'AND') {
        // 需要所有权限
        hasAccess = permissions.every((perm) => userHasPermission(perm));
      } else {
        // 只需要任一权限
        hasAccess = permissions.some((perm) => userHasPermission(perm));
      }

      if (hasAccess) {
        logger.debug(`权限检查通过`);
        next();
      } else {
        logger.warn('用户缺少权限', { userId, requiredPermissions: permissions });
        return ApiResponse.forbidden(res, '您没有执行此操作的权限');
      }
    } catch (error) {
      logger.error(`权限检查失败：${error.message}`);
      return ApiResponse.serverError(res, '权限验证过程出错');
    }
  };
};

/**
 * 角色检查中间件
 * @param {string|string[]} requiredRoles - 需要的角色编码
 */
const checkRole = (requiredRoles) => {
  return async (req, res, next) => {
    try {
      const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

      // 优化：优先使用 authenticate 中间件已加载的实时角色（req.user.roleCodes），
      // 避免重复查库；仅在未提供时回退到带请求级缓存的数据库查询
      let userRoles;
      if (req.user && req.user.roleCodes && req.user.roleCodes.length > 0) {
        userRoles = req.user.roleCodes;
      } else {
        // 同一请求内复用角色查询结果，避免 N+1
        if (!req.userRoles) {
          const user = await User.findById(req.user.userId).populate('roles', 'code').lean();
          req.userRoles = user?.roles?.map((r) => r.code) || [];
        }
        userRoles = req.userRoles;
      }

      logger.debug(`检查用户角色是否包含：${roles.join(', ')}`, { userRoles });

      const hasRole = roles.some((role) => userRoles.includes(role));

      if (hasRole) {
        next();
      } else {
        logger.warn(`用户角色不匹配，需要：${roles.join(', ')}`);
        return ApiResponse.forbidden(res, '您的角色无权执行此操作');
      }
    } catch (error) {
      logger.error(`角色检查失败：${error.message}`);
      return ApiResponse.serverError(res, '角色验证过程出错');
    }
  };
};

/**
 * 数据范围权限检查
 * 根据用户角色层级限制可访问的数据范围
 * 返回的数据范围可用于 Controller 中的查询过滤
 *
 * 数据范围类型：
 * - all: 全部数据（角色 level >= 9）
 * - department: 本部门/本区域数据（角色 level >= 7）
 * - self: 仅自己创建/负责的数据（角色 level >= 5）
 * - none: 无数据权限
 *
 * @param {string} userId - 用户 ID
 * @returns {Promise<Object>} 数据范围配置
 */
const getDataScope = async (userId) => {
  const user = await User.findById(userId).populate({
    path: 'roles',
    select: 'level name code',
  });

  if (!user) return { type: 'none' };

  // 处理 roles 为空的情况
  if (!user.roles || user.roles.length === 0) {
    return { type: 'none' };
  }

  const levels = user.roles.map((r) => r.level || 1);
  const maxLevel = Math.max(...levels);

  // 数据范围层级常量（与 initData.js 中 role level 10/8/6/4/1 对应）
  // L1 修正：种子角色 FIREFIGHTER=4 / GUEST=1，原先 LEVEL_SELF=5 导致消防员
  // （level 4）落入 none 档，"仅自己数据"的既定语义被静默降级为无数据
  const LEVEL_ALL = 9; // 超级管理员：全部数据
  const LEVEL_DEPARTMENT = 7; // 安全管理员/部门主管：本部门数据
  const LEVEL_SELF = 4; // 普通消防员：仅自己创建/负责的数据

  // 根据角色层级返回数据范围
  if (maxLevel >= LEVEL_ALL) {
    return { type: 'all' };
  } else if (maxLevel >= LEVEL_DEPARTMENT) {
    return { type: 'department', department: user.department };
  } else if (maxLevel >= LEVEL_SELF) {
    return { type: 'self', userId };
  } else {
    // 访客/低级别：无数据权限
    return { type: 'none' };
  }
};

/**
 * 数据范围查询过滤器工厂
 * 根据数据范围自动生成 Mongoose 查询条件
 * @param {Object} dataScope - 数据范围配置
 * @param {string|string[]} ownerField - 所有者字段名（用于 self 范围）；
 *        传数组表示「任一字段命中即在范围内」（如设备的 createdBy 与维护操作者，
 *        见 constants/dataScopeFields.js 的口径说明）
 * @param {string} departmentField - 部门字段路径（用于 department 范围）
 * @returns {Object} Mongoose 查询条件
 */
const buildDataScopeFilter = (
  dataScope,
  ownerField = 'createdBy',
  departmentField = 'location.building'
) => {
  if (!dataScope || dataScope.type === 'all') {
    return {};
  }

  /** 属主条件：多字段用 $or 取并集，单字段直接等值 */
  const ownerCondition = (value) => {
    if (Array.isArray(ownerField)) {
      return { $or: ownerField.map((f) => ({ [f]: value })) };
    }
    return { [ownerField]: value };
  };

  switch (dataScope.type) {
    case 'department':
      if (!dataScope.department) {
        return ownerCondition(null);
      }
      // 精确匹配而非 RegExp，防止正则注入绕过数据隔离
      return { [departmentField]: dataScope.department };

    case 'self':
      return ownerCondition(dataScope.userId);

    case 'none':
    default:
      return { _id: null }; // 返回永远不匹配的条件
  }
};

/**
 * 判断单条记录是否落在用户的数据范围内（用于按 ID 的详情接口，防止横向越权）
 * 与列表接口的 buildDataScopeFilter 口径保持一致
 * @param {Object} dataScope - getDataScope 的返回值
 * @param {Object} doc - 数据库文档（Mongoose Document 或 lean 对象）
 * @param {Object} fields - { ownerField, departmentField, userId }
 * @returns {boolean}
 */
const isRecordInScope = (dataScope, doc, { ownerField, departmentField, userId }) => {
  if (!dataScope || dataScope.type === 'all') return true;
  if (!doc) return false;

  // 路径取值需感知数组：如 locations.building / maintenanceRecord.operator，
  // 中间层为数组时收集每个元素的字段值（否则 array.field 取值为 undefined，范围校验恒失败）
  const getPath = (obj, path) =>
    path.split('.').reduce((acc, k) => {
      if (acc == null) return undefined;
      if (Array.isArray(acc)) return acc.flatMap((o) => (o == null ? [] : [o[k]]));
      return acc[k];
    }, obj);

  // 字段值可能是标量、ObjectId、数组或 populate 后的完整文档对象（此时取 _id 比较）
  const collectValues = (value, out) => {
    if (value === undefined || value === null) return;
    if (Array.isArray(value)) {
      value.forEach((v) => collectValues(v, out));
      return;
    }
    if (typeof value === 'object') {
      if (value._bsontype) {
        out.push(value.toString());
      } else if (value._id != null) {
        out.push(value._id.toString());
      }
      return;
    }
    out.push(String(value));
  };
  const matchesField = (value, expected) => {
    const values = [];
    collectValues(value, values);
    return values.some((v) => v === String(expected));
  };

  switch (dataScope.type) {
    case 'department':
      return dataScope.department
        ? matchesField(getPath(doc, departmentField), dataScope.department)
        : false;
    case 'self':
      // ownerField 支持数组（任一命中即在范围内），与 buildDataScopeFilter 同口径
      if (Array.isArray(ownerField)) {
        return ownerField.some((f) => matchesField(getPath(doc, f), userId));
      }
      return matchesField(getPath(doc, ownerField), userId);
    case 'none':
    default:
      return false;
  }
};

/**
 * 便捷方法：加载数据范围并校验单条记录是否在范围内
 * 封装了 getDataScope + isRecordInScope 的重复模式，减少控制器样板代码
 *
 * @param {Object} req - Express 请求对象（需已通过 authenticate）
 * @param {Object} doc - 数据库文档
 * @param {string} ownerField - 属主字段路径（如 'createdBy'、'assignedTo'）
 * @param {string} departmentField - 部门字段路径（如 'location.building'）
 * @returns {Promise<{allowed: boolean, dataScope: Object}>}
 */
const assertRecordInScope = async (req, doc, ownerField, departmentField) => {
  const dataScope = await getDataScope(req.user.userId);
  const allowed = isRecordInScope(dataScope, doc, {
    ownerField,
    departmentField,
    userId: req.user.userId,
  });
  return { allowed, dataScope };
};

/**
 * 把数据范围约束合并进已有的 Mongoose 查询对象（Service 层列表/统计通用）
 *
 * 存在必要性（P1-3 修复）：三个 Service（Alarm/Device/Inspection）各自手写了
 * `if (type==='department' && dataScope.department) {...} else if (type==='self')
 * {...} else if (type==='none') {return 空}` 的副本。当 type==='department'
 * 但 department 为空串/null（用户未填部门，业务常见）时，三个分支全不命中 →
 * **零过滤返回全组织数据**。而 buildDataScopeFilter 对该情形兜底
 * `{[ownerField]: null}`（返回空集），同模块两套口径互相矛盾：
 * 列表看到全公司、统计为 0。
 *
 * 本函数是唯一收敛点：deny 语义显式返回 false，字段冲突用 $and 取交集
 * （不能让任一方覆盖另一方——覆盖会越权放大可见集或泄露跨部门数据）。
 *
 * @param {Object} query 待就地修改的查询对象
 * @param {Object} dataScope getDataScope 的返回值
 * @param {Object} fields { ownerField, departmentField }
 * @returns {boolean} true=已应用约束可继续查询；false=范围为空，调用方应直接返回空结果
 */
const applyDataScopeToQuery = (query, dataScope, { ownerField, departmentField }) => {
  // 显式 deny 判定（不依赖 buildDataScopeFilter 的兜底形态）：
  // - 无范围信息 / 未知 type / type='none' → 拒绝
  // - type='department' 但 department 为空 → 拒绝（这正是曾经零过滤越权的入口）
  // 之所以在此显式判断而非复用 buildDataScopeFilter 的返回值：后者对
  // 「department 为空」返回的是 { [ownerField]: null }，一个语义含糊的
  // 「匹配属主为空的记录」条件——它恰好使结果集接近空，但并不表达 deny，
  // 且会让调用方误以为查询有效。这里把 deny 变成明确的布尔信号。
  if (!dataScope) return false;
  if (dataScope.type === 'all') return true;
  if (dataScope.type === 'none') return false;
  if (dataScope.type === 'department' && !dataScope.department) return false;
  if (dataScope.type === 'self' && !dataScope.userId) return false;
  if (!['department', 'self'].includes(dataScope.type)) return false;

  const scopeFilter = buildDataScopeFilter(dataScope, ownerField, departmentField);

  for (const [field, value] of Object.entries(scopeFilter)) {
    if (Object.prototype.hasOwnProperty.call(query, field)) {
      // 同字段冲突（用户显式筛选 vs 范围限定）：$and 取交集
      query.$and = [...(query.$and || []), { [field]: query[field] }, { [field]: value }];
      delete query[field];
    } else {
      query[field] = value;
    }
  }
  return true;
};

module.exports = {
  checkPermission,
  checkRole,
  getDataScope,
  buildDataScopeFilter,
  applyDataScopeToQuery,
  isRecordInScope,
  assertRecordInScope,
};
