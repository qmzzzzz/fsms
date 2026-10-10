/**
 * RBAC 权限控制中间件
 * 基于角色的访问控制核心实现
 * 支持菜单权限、按钮权限、API 权限、数据范围权限的多层级控制
 */

const User = require('../models/User');
const ApiResponse = require('../utils/apiResponse');
const ApiError = require('../utils/ApiError');
const { ERROR_CODES } = require('../utils/errorCodes');
const logger = require('../utils/logger');
const { resolvePunishableIp } = require('../utils/ipUtils');

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
        // B-L6 接线：权限滥用频控检测（此前 checkPermissionAbuse 为死代码）——
        // 信号取全局审计中间件落库的 403 记录，fire-and-forget 不阻塞拒绝路径。
        // 2026-10-01：传 resolvePunishableIp(req) 的裁定结果而非裸 req.ip——
        // 惩罚目标不能取自请求方可写的 XFF（同网段伪造 XFF 定点踢人/换桶逃避）
        try {
          void require('../services/securityAlert')
            .checkPermissionAbuse(userId, resolvePunishableIp(req))
            .catch(() => {});
        } catch (_) {
          /* 检测失败不影响拒绝主流程 */
        }
        return ApiResponse.codeError(res, 'PERMISSION_DENIED');
      }
    } catch (error) {
      logger.error(`权限检查失败：${error.message}`);
      return ApiResponse.codeError(res, 'PERMISSION_CHECK_FAILED');
    }
  };
};

/**
 * 查看他人敏感信息需 system:read；查看本人敏感信息则免鉴权（#9）
 *
 * 背景（评价报告 #9）：/api/security/view-sensitive 原实现一律要求
 * system:read，但控制器查询的是调用者本人数据（securityController.js:239
 * `User.findById(req.user.userId)`），普通角色（消防员/访客）查看本人
 * 手机号/邮箱也拿不到该权限 → 403。正确口径是：
 *   - 本人查看 → 放行（数据范围即本人，二次验证已由 requireReAuthentication 兜底）
 *   - 查看他人（请求体带 targetUserId）→ 需要 system:read
 * 注意：超管持有 *:* 恒通过（上方 checkPermission 顶层已处理），不受影响。
 */
const checkViewSensitivePermission = async (req, res, next) => {
  try {
    const { targetUserId } = req.body || {};
    if (targetUserId && String(targetUserId) !== String(req.user.userId)) {
      return checkPermission('system:read')(req, res, next);
    }
    return next();
  } catch (error) {
    logger.error('查看敏感信息权限检查出错', { error: error.message });
    return next(error);
  }
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
          // 与 auth.js buildAuthContext / getDataScope 同口径：只认生效角色，
          // 否则停用角色的 code 会在此回退路径复活、绕过 checkRole（filter(Boolean) 为防御可能的 null 洞，实测 8.24.1 不留）。
          const user = await User.findById(req.user.userId)
            .populate({ path: 'roles', select: 'code', match: { status: 'active' } })
            .lean();
          req.userRoles = (user?.roles || []).filter(Boolean).map((r) => r.code);
        }
        userRoles = req.userRoles;
      }

      logger.debug(`检查用户角色是否包含：${roles.join(', ')}`, { userRoles });

      const hasRole = roles.some((role) => userRoles.includes(role));

      if (hasRole) {
        next();
      } else {
        logger.warn(`用户角色不匹配，需要：${roles.join(', ')}`);
        return ApiResponse.codeError(res, 'ROLE_NOT_ALLOWED');
      }
    } catch (error) {
      logger.error(`角色检查失败：${error.message}`);
      return ApiResponse.codeError(res, 'ROLE_CHECK_FAILED');
    }
  };
};

/**
 * 数据范围权限检查
 * 根据用户角色层级限制可访问的数据范围
 * 返回的数据范围可用于 Controller 中的查询过滤
 *
 * 数据范围类型（阈值与下方 LEVEL_* 常量同源，不要只改注释）：
 * - all: 全部数据（角色 level >= 9）
 * - department: 本部门/本区域数据（角色 level >= 7）
 * - self: 仅自己创建/负责的数据（角色 level >= 4）
 * - none: 无数据权限（level < 4）
 *
 * @param {string} userId - 用户 ID
 * @returns {Promise<Object>} 数据范围配置
 */
const getDataScope = async (userId) => {
  const user = await User.findById(userId).populate({
    path: 'roles',
    select: 'level name code',
    // 与权限轴（userPermissionService/permissionHelper 的 match:{status:'active'}）同口径：
    // 管理员停用角色必须让「数据范围」也立即失效。否则停用 SUPER_ADMIN 角色后，
    // getDataScope 仍按其 level 返回 {type:'all'}，10+ 处列表/统计/报表调用方照常全量放行。
    // populate 过滤后若 roles 全被剔除 → 下方 length===0 分支返回 {type:'none'}（deny），fail-closed。
    match: { status: 'active' },
  });

  if (!user) return { type: 'none' };

  // 防御性 filter(Boolean)：实测 mongoose 8.24.1 对 populate+match 未命中的引用是**丢弃元素**
  // （不留 null），故今天它不改变结果；保留它是防未来版本改为留 null 洞 —— 形状由
  // src/tests/populateMatchShape.test.js 钉住（升级会先红），届时 `r.level` 才可能抛错。
  // 过滤后若 roles 全被剔除 → {type:'none'}（deny），fail-closed。
  const activeRoles = (user.roles || []).filter(Boolean);

  // 处理 roles 为空的情况
  if (activeRoles.length === 0) {
    return { type: 'none' };
  }

  const levels = activeRoles.map((r) => r.level || 1);
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
  // 缺失判据一律 deny（与同模块 isRecordInScope / applyDataScopeToQuery 同向）。
  // 原实现把 `!dataScope` 与 `type==='all'` 并成一臂 `return {}`，而 `{}` 是**空条件 =
  // 全量放行**：三个兄弟函数里只有这一个在"没有范围信息"时 fail-open。
  // isRecordInScope 已因同样的理由改成 deny（见其注释「一旦有调用方把 undefined 传进来
  // （重构、缓存未命中、种子数据缺字段），就变成无条件放行」）——本函数是**漏掉的那一处**。
  // 今日调用方都传 `await getDataScope(...)`（该函数永不返回 null），所以这是防御性收紧，
  // 不改变任何现存路径的行为。
  if (!dataScope) return { _id: null };
  if (dataScope.type === 'all') {
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
      // department 为空（用户未填部门，业务常见）必须 deny，不能落到 ownerCondition(null)。
      // 对设备 ownerCondition(null) = {$or:[{createdBy:null},{'maintenanceRecord.operator':null}]}：
      // 泄漏臂是 {createdBy:null}——按 Mongo 的 null 语义它会匹配"字段缺失"的文档，
      // 于是所有未建档设备（播种/导入、createdBy 为空）跨部门全部命中 = 按部门范围却返回全组织数据。
      // （注：{'maintenanceRecord.operator':null} 对 maintenanceRecord 默认空数组 [] 并不命中。）
      // 与 applyDataScopeToQuery 的显式 deny 同口径（后者早已拦此情形，这里补齐直接调用方）。
      if (!dataScope.department) {
        return { _id: null };
      }
      // 精确匹配而非 RegExp，防止正则注入绕过数据隔离
      return { [departmentField]: dataScope.department };

    case 'self':
      // 同理：self 缺 userId 时 ownerCondition(undefined) 语义含糊，显式 deny。
      if (!dataScope.userId) {
        return { _id: null };
      }
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
  // 缺失判据一律 deny（与同模块 applyDataScopeToQuery 的 `if (!dataScope) return false` 同向）。
  // 原先写成 return true 是 fail-open：两个兄弟函数对没有范围信息给出相反答案，
  // 一旦有调用方把 undefined 传进来（重构、缓存未命中、种子数据缺字段），就变成无条件放行。
  if (!dataScope) return false;
  if (dataScope.type === 'all') return true;
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

  // 自己的记录永远在自己范围内（唯一例外是 type:'none'）。
  // createdBy 与 department 都是可选字段：播种账户、以及范围闸上线之前创建的存量账户很可能是 null，
  // 只比这两个字段会让"改自己的资料""自己被锁定"被自己的范围闸拒掉（self/department 档实测均如此）。
  // 'none'（GUEST）必须在短路之前排除：不能因为"是自己的记录"就拿到任何数据权限。
  if (dataScope.type !== 'none' && matchesField(getPath(doc, '_id'), userId)) return true;

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
 * @returns {boolean} true=已应用约束可继续查询
 * @throws {ApiError} 403 DATA_SCOPE_DENIED——范围不可用（无范围信息 / 未知 type /
 *   type='none' / department 缺值 / self 缺 userId）。调用方无需也无法"返回空结果"，
 *   异常会一路冒到 errorHandler 变成 403。
 */
/**
 * 数据范围不可用 ⇒ 403（DATA_SCOPE_DENIED）。
 *
 * 走 ApiError 而非直接 res.status：本函数被 Service 层调用（那里没有 res），
 * 由全局 errorHandler 统一映射成 403 响应——与 ApiError 类的既定用途一致。
 */
const deniedDataScope = () =>
  new ApiError(
    ERROR_CODES.DATA_SCOPE_DENIED.message,
    ERROR_CODES.DATA_SCOPE_DENIED.status,
    undefined,
    'DATA_SCOPE_DENIED'
  );

/**
 * 数据范围是否不可用——**唯一一份判据**。
 *
 * 为什么必须单点：这份判据原先只活在 applyDataScopeToQuery 开头的几行里，
 * 而 auditScopeFilter / reportExportService 各自还有一份"deny 就回空集"的私有实现。
 * #12 要求这三处统一改成 403，判据抄三遍必然漂移，漂移的方向一定是"某一条忘了拒"。
 *
 * @param {Object} dataScope getDataScope 的返回值
 * @returns {boolean} true=不可用（调用方应 403）
 */
const isDataScopeDenied = (dataScope) =>
  !dataScope ||
  dataScope.type === 'none' ||
  (dataScope.type === 'department' && !dataScope.department) ||
  (dataScope.type === 'self' && !dataScope.userId) ||
  // 白名单必须含 'all'：它是**可用**范围（最宽的那一档），漏掉就会把超管一律拒掉。
  // 这个漏子第一次跑 edgeCases 的「all：原样放行」就炸了——记在这里免得再犯。
  !['all', 'department', 'self'].includes(dataScope.type);

const applyDataScopeToQuery = (query, dataScope, { ownerField, departmentField }) => {
  // 显式 deny 判定（不依赖 buildDataScopeFilter 的兜底形态）：
  // - 无范围信息 / 未知 type / type='none' → 拒绝
  // - type='department' 但 department 为空 → 拒绝（这正是曾经零过滤越权的入口）
  // 之所以在此显式判断而非复用 buildDataScopeFilter 的返回值：
  //  ① dataScope 为假时它返回 **{}**（与 type='all' 同一分支）＝不加任何过滤＝全量数据，
  //     这是"看起来像 deny 的兜底对象"里最危险的一种形态，绝不能被当成拒绝；
  //  ② department 缺值 / self 缺 userId / type='none' 或未知 type 时它返回 { _id: null }，
  //     "匹配不到文档"只在**该条件真的被 AND 进最终查询**时才成立——它是个查询片段而不是
  //     拒绝信号：调用方同名字段覆盖、或把"拿到对象"当成"范围有效"来分支时 deny 静默失效。
  // 不可用即**抛 403**（#12 选项①），不再返回 false 让调用方各自回空集：
  // 空集让调用方分不清「没有数据」与「没有可见范围」，而这两者的后续动作相反。
  // 抛而不是返回布尔，还顺带封掉"调用方忘了判返回值"这条退化路径——
  // 旧的 false 返回值没有任何机制保证 6 个调用点都检查它。
  // deny 判定必须排在读 dataScope.type 之前：调用方显式传 null 时（参数默认值
  // 只在 undefined 时生效，null 会原样进函数体），先读 .type 会抛 TypeError ⇒ 500，
  // 而"没有范围信息"本该是 403。isDataScopeDenied 的第一条就是 !dataScope。
  // （src/tests/alarmStatsScopeCast.test.js 的"显式传 null 也必须 403"钉住这一条。）
  if (isDataScopeDenied(dataScope)) throw deniedDataScope();
  if (dataScope.type === 'all') return true;

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

/**
 * 部门维度的**单值**判定：某个字符串（楼栋名/部门名）是否落在操作者的数据范围内。
 *
 * 存在必要性：`isRecordInScope` 判的是"一条已存在的文档"，而写路径要在**入库之前**
 * 判断"用户填进来的这个值能不能写"（设备的 `location.building`、巡检的
 * `locations[].building`，两者都是各自的 departmentField）。这条规则原先在巡检守卫里
 * 内联一份，设备侧则完全没有——同一规则两处口径不同正是本仓反复出现的漂移形状。
 *
 * 档位语义与 `isRecordInScope` 保持一致：
 *  · all ⇒ 不限；
 *  · department ⇒ 必须等于本人部门，未配置部门一律 deny（空部门曾经导致"零过滤放行"）；
 *  · self ⇒ 该维度恒允许：self 档的可见性由属主臂决定，楼栋对它不是范围维度，
 *    把它判死会让消防员无法给自己维护的设备填位置（过度收紧）；
 *  · none / 未识别的档位 ⇒ 一律 deny（新增档位不得静默变成全量授权）。
 *
 * @param {Object} dataScope getDataScope 的返回值
 * @param {string} value 待写入的部门维度值
 */
const isDepartmentValueAllowed = (dataScope, value) => {
  if (!dataScope) return false;
  switch (dataScope.type) {
    case 'all':
      return true;
    case 'department':
      return Boolean(dataScope.department) && value === dataScope.department;
    case 'self':
      return true;
    case 'none':
    default:
      return false;
  }
};

module.exports = {
  checkPermission,
  checkViewSensitivePermission,
  checkRole,
  getDataScope,
  buildDataScopeFilter,
  applyDataScopeToQuery,
  isDataScopeDenied,
  deniedDataScope,
  isRecordInScope,
  assertRecordInScope,
  isDepartmentValueAllowed,
};
