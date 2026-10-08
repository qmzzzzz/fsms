/**
 * 用户管理控制器
 * 处理用户的 CRUD 操作
 */

const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../utils/validationRules');
const ApiResponse = require('../utils/apiResponse');
const {
  getOperatorMaxLevel,
  maxRoleLevel,
  matchesPermissionCodes,
} = require('../utils/permissionHelper');
const { syncPermissionsToUsers } = require('../utils/permissionSync');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');
const { getDataScope, buildDataScopeFilter, assertRecordInScope } = require('../middleware/rbac');
const { castScopeObjectIds } = require('../utils/scopeCast');
// 数据范围字段名只有一份（constants/dataScopeFields.js）。此前 getUserStats 里私抄了
// 'createdBy'/'department'：改常量会让列表按新字段过滤、统计仍按旧字段聚合，
// 同一用户在"我的列表"与"我的统计"上看到互相矛盾的口径——正是这个常量当初要消灭的 P2-20。
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const {
  validateSort,
  normalizePagination,
  isValidAvatar,
  validatePasswordStrength,
  uniqueIdStrings,
} = require('../utils/helpers');
const { validateRules } = require('../utils/ipRange');
const { decryptLoginCredential } = require('../utils/loginCipher');
const { checkSuperAdminMembership, isSuperAdminRole } = require('../utils/superAdmin');
const { normalizeEmailKey } = require('../utils/emailKey');
const statsCache = require('../services/statsCache');
const { invalidateUserCache } = require('../middleware/auth');
const { businessMonthStart } = require('../constants/timezone');
const userService = require('../services/userService');

/**
 * user 资源的属主/部门字段只有一份（constants/dataScopeFields.js）。
 * 此前本文件 5 处数据范围闸手写 'createdBy'/'department'，而同文件的统计接口引用常量——
 * 常量一改就会出现"列表/详情/写路径按新字段、统计按旧字段"的口径分叉（P2-20 的原始教训）。
 */
const { ownerField: USER_OWNER_FIELD, departmentField: USER_DEPT_FIELD } = DATA_SCOPE_FIELDS.user;

/**
 * 获取用户列表（支持分页、搜索、过滤）
 * GET /api/users
 */
const getUsers = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, status, department, role, sort = '-createdAt' } = req.query;

  // 校验并规范化排序参数
  const safeSort = validateSort(sort, {
    allowedFields: [
      'username',
      'email',
      'realName',
      'status',
      'department',
      'createdAt',
      'updatedAt',
      'lastLoginAt',
    ],
    defaultSort: '-createdAt',
  });

  const dataScope = await getDataScope(req.user.userId);
  const { roleFound, scopeAllowed, query } = await userService.buildListQuery(
    { search, status, department, role },
    dataScope
  );

  if (!roleFound || !scopeAllowed) {
    return ApiResponse.paginated(
      res,
      [],
      {
        page: parseInt(page),
        limit: parseInt(limit),
        total: 0,
        totalPages: 0,
      },
      '获取用户列表成功'
    );
  }

  // 规范化分页参数（统一限界）
  const { page: pageNum, limit: limitNum } = normalizePagination(page, limit);

  // 执行查询
  const { users, count } = await userService.listUsers(query, safeSort, pageNum, limitNum);

  return ApiResponse.paginated(
    res,
    users,
    {
      page: pageNum,
      limit: limitNum,
      total: count,
      totalPages: Math.ceil(count / limitNum),
    },
    '获取用户列表成功'
  );
});

/**
 * 获取单个用户详情
 * GET /api/users/:id
 */
const getUserById = asyncHandler(async (req, res) => {
  const user = await userService.getUserDetail(req.params.id);

  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围校验：与列表接口口径一致，防止按 ID 横向越权
  // （本接口在路由上已有 user:read 权限门槛，这里补齐数据范围一致性）
  const { allowed } = await assertRecordInScope(req, user, USER_OWNER_FIELD, USER_DEPT_FIELD);
  if (!allowed) {
    return ApiResponse.codeError(res, 'USER_VIEW_FORBIDDEN');
  }

  return ApiResponse.success(res, user, '获取成功');
});

/**
 * P0-1 建号数据范围闸（与 updateUser 的 department 分支同源）。
 * department 是「数据范围决定字段」：新建账户落入该部门后按自身部门可见数据。
 * 若允许 department/self 域操作者把新账号建到其可见域之外（例：东区管理员建 总部
 * 账号并持其口令），等价于在域外安插一个可读该域数据的账号——与 updateUser 明令
 * 禁止的「把用户移出自己的域」是同一件事的两个入口，此前只有 update 有闸。
 * self/none（opDept=null）拒任何非空 department；all（超管）与本部门放行。
 * @returns {Promise<boolean>} true 表示已写出 403 拒绝响应，调用方应立即 return。
 */
async function guardCreateUserScope(req, res, department, username) {
  if (department === undefined || department === '') return false;
  const opScope = await getDataScope(req.user.userId);
  if (opScope.type === 'all') return false;
  const opDept = opScope.type === 'department' ? opScope.department : null;
  if (department === opDept) return false;
  logger.warn('拒绝在操作者数据范围外创建用户', {
    operator: operatorTag(req),
    operatorScope: opScope.type,
    operatorDept: opDept || null,
    requestedUsername: username,
    requestedDept: department,
  });
  ApiResponse.codeError(res, 'USER_SCOPE_FIELD_FORBIDDEN');
  return true;
}

/** 角色文档集合 → 其携带的权限码集合（纯投影，不含任何授权判定语义） */
const permissionCodesOfRoles = (roleDocs) => {
  const codes = new Set();
  for (const r of roleDocs) {
    for (const p of r.permissions || []) {
      if (p?.code) codes.add(p.code);
    }
  }
  return codes;
};

/**
 * 权限子集校验的唯一实现：本次要授予的权限里、操作者自身不具备的那些即越权。
 *
 * 建号与角色分配此前各写一份同样的"双重循环取码 + 过滤"，注释里互相声明
 * "与对方完全同口径"——口径靠注释维持就是漂移的开始（层级闸与子集闸的先后、
 * 排除集是否参与，两处都必须一致）。
 *
 * currentRoleDocs 传目标已持有的角色：收权时目标的权限可能多于操作者，
 * 那些权限不是本次授予行为，必须排除，否则操作者连"给下级收权"都做不到。
 * @returns {string[]} 操作者无权授予的权限码；空数组即放行
 */
const findUnoperableGrantCodes = (operatorPermCodes, grantRoleDocs, currentRoleDocs) => {
  const granting = permissionCodesOfRoles(grantRoleDocs);
  if (currentRoleDocs) {
    for (const code of permissionCodesOfRoles(currentRoleDocs)) granting.delete(code);
  }
  return [...granting].filter((code) => !matchesPermissionCodes(operatorPermCodes, code));
};

/**
 * IP 访问范围规则的语法闸（建号与更新共用）：非法片段逐条回报，
 * 否则入库后规则静默失效——比报错更糟的是"以为限了"。
 * @returns {boolean} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectInvalidIpRules = (res, allowedIPs) => {
  if (allowedIPs === undefined || allowedIPs === '') return false;
  const check = validateRules(allowedIPs);
  if (check.valid) return false;
  ApiResponse.codeError(res, 'IP_RULES_FORMAT_INVALID', {
    message: `IP 范围规则格式有误：${check.invalid.join('、')}`,
    params: { rules: check.invalid.join('、') },
  });
  return true;
};

/**
 * 角色列表形状闸：必须是非空数组（元素是否指向真实角色由后续存在性校验负责）。
 * @returns {boolean} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectInvalidRoleList = (res, roles) => {
  if (roles && Array.isArray(roles) && roles.length > 0) return false;
  ApiResponse.codeError(res, 'ROLE_LIST_INVALID');
  return true;
};

/** 日志与告警里指代操作者的统一写法（用户名缺失时退回 id，不出现 undefined） */
const operatorTag = (req) => req.user.username || req.user.userId;

/**
 * 同级角色的归属校验（纵深防御）：与操作者同 level 的角色，必须是操作者自己持有的那些。
 *
 * 只对**与操作者同级**的角色生效：高于操作者的已被层级校验拒绝，低于的由权限子集
 * 校验兜住，只有"恰好同级"这一档需要额外要求归属——两名同级、分管不同模块的
 * 管理员互挂对方角色，即可各自集齐双方全部权限且不触发任何层级告警。
 *
 * 不能写成"想授予某角色就必须自己持有它"：那会封死"把 GUEST 授予新人"这类
 * 最常见的合法操作（操作者本人当然不持有 GUEST），反而逼管理员囤积角色，
 * 本身就是权限膨胀的反模式。
 * @returns {string[]} 同级且非操作者自身持有的角色编码
 */
const findForeignPeerRoles = (operatorRoleCodes, validRoles, operatorMaxLevel) =>
  validRoles
    .filter((r) => (r.level || 0) === operatorMaxLevel)
    .map((r) => r.code)
    .filter((code) => !operatorRoleCodes.has(code));

/**
 * 同级角色归属闸的执行体（B-2）：两条授权轨共用同一实现——改角色（assignRoles）
 * 与建号（createUser）。
 *
 * 建号轨原本漏了这一道，而漏掉它不是"当场提权"（上一层的权限子集闸已保证新账户
 * 权限 ⊆ 操作者自身权限），真实后果是**角色继承型扩权**：新账户成了那个同级角色的
 * 合法持有者，日后该角色被补上任何权限，新账户——以及掌握其口令的操作者——自动获得，
 * 而这条增量从未触过任何授权判定。附带同样重要的归因面：动作记在别人名下。
 * 与 assignRoles 保持同一尺子是必要的：两条轨口径不一致时，运营者会自然流向松的那条。
 *
 * `req.user.roleCodes` 由 auth 中间件在请求期实时刷新（freshRoleCodes），
 * 非签发时快照，作为角色归属比对的事实来源。
 * @param {string} subjectTag 日志里指代被授权主体的写法（`target=xxx` / `newUser=xxx`）
 * @returns {boolean} true 表示已写出 403 拒绝响应，调用方应立即返回
 */
const rejectForeignPeerRoles = (res, req, grantRoles, operatorMaxLevel, subjectTag) => {
  const foreignRoles = findForeignPeerRoles(
    new Set(req.user.roleCodes || []),
    grantRoles,
    operatorMaxLevel
  );
  if (foreignRoles.length === 0) return false;
  logger.warn(
    `角色分配越权被拒（同级角色归属）：operator=${operatorTag(req)} ${subjectTag} ` +
      `非自身持有的同级角色=${foreignRoles.join(',')}`
  );
  ApiResponse.codeError(res, 'ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN', {
    message: `无权分配自身未持有的同级角色：${foreignRoles.join('、')}`,
    params: { foreignRoles: foreignRoles.join('、') },
  });
  return true;
};

/**
 * 建号角色前置校验：
 *  1) 角色必须全部存在（数量对不上即有 id 不存在）；
 *  2) 新建账户一律不得携带超管角色——层级闸拦不住这条路径：超管本人的
 *     operatorMaxLevel 也是 10，`targetMaxLevel > operatorMaxLevel` 为 false 会放行，
 *     等于凭空造出第二位超管；
 *  3) 不得授予高于自身层级的角色；
 *  4) 不得授予自身不持有的权限——层级闸只拦「高于自己」，同级/低级角色完全可能
 *     携带操作者没有的权限（只持 user:* 的账号管理员挂一个含 security:config 的
 *     同级角色即绕道提权）。判定与 assignRoles 共用同一实现。
 *  5) 不得授予自身未持有的**同级**角色（B-2，判据见 rejectForeignPeerRoles）。
 *     这一道原先只有 assignRoles 有：同一个人改别人角色会被拦、建个新账户挂同一个
 *     角色则放行，两条轨口径不一致 ⇒ 松的那条就是实际口径。
 * @returns {Promise<{roles: Array, rejected: boolean}>}
 */
const validateRolesForCreate = async (req, res, roles) => {
  if (!roles || roles.length === 0) return { roles: [], rejected: false };
  // 归一后的这一份既参与"是否都存在"的比较，也是最终写进新文档的 roles：
  // 重复项不去掉的话，比较会把合法请求判成 400，去掉了却不复用，重复项就落库。
  const requestedRoles = uniqueIdStrings(roles);

  const targetRoles = await userService.findRolesByIds(requestedRoles, 'level code isBuiltIn', {
    lean: true,
  });
  if (targetRoles.length !== requestedRoles.length) {
    ApiResponse.codeError(res, 'ROLE_NOT_FOUND_IN_LIST');
    return { rejected: true };
  }
  if (targetRoles.some(isSuperAdminRole)) {
    logger.warn('创建用户时携带超管角色被拒', { operator: operatorTag(req) });
    ApiResponse.codeError(res, 'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE');
    return { rejected: true };
  }

  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetMaxLevel = maxRoleLevel(targetRoles);
  if (targetMaxLevel > operatorMaxLevel) {
    ApiResponse.codeError(res, 'ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN');
    return { rejected: true };
  }

  const operatorPermCodes = await userService.getPermissions(req.user.userId);
  if (!operatorPermCodes.includes('*:*')) {
    const grantRoleDocs = await userService.findRolePermissionDocs(requestedRoles);
    const lacking = findUnoperableGrantCodes(operatorPermCodes, grantRoleDocs);
    if (lacking.length > 0) {
      logger.warn(
        `建号越权授予权限被拒：operator=${operatorTag(req)} ` + `缺少权限=${lacking.join(',')}`
      );
      ApiResponse.codeError(res, 'PERMISSION_GRANT_FORBIDDEN', {
        message: `无权授予以下权限：${lacking.join('、')}`,
        params: { permissions: lacking.join('、') },
      });
      return { rejected: true };
    }
    if (
      rejectForeignPeerRoles(
        res,
        req,
        targetRoles,
        operatorMaxLevel,
        `newUser=${req.body.username}`
      )
    ) {
      return { rejected: true };
    }
  }
  return { roles: requestedRoles, rejected: false };
};

/**
 * 建号口令取值（FE-M3 双轨）：密文轨 encPassword 与管理员代设明文轨并存。
 * 密文解密失败统一回 400（不区分原因，免得给探测者回话），解密成功后
 * 必须补做与注册同口径的强度校验——走密文轨的口令绕过了前端校验，
 * 不能假定它合格。
 * @returns {Promise<{password?: string, rejected: boolean}>} rejected=true 表示已写出响应
 */
const resolveAdminSetPassword = async (req, res, username) => {
  if (typeof req.body.encPassword !== 'string' || !req.body.encPassword) {
    return { password: req.body.password, rejected: false };
  }
  let password;
  try {
    password = await decryptLoginCredential(req.body.encPassword);
  } catch (err) {
    logger.warn(`管理员建号口令密文无效：${username}（${err.code || err.message}）`);
    ApiResponse.codeError(res, 'AUTH_ENCRYPTED_CREDENTIAL_INVALID');
    return { rejected: true };
  }
  const strengthErr = validatePasswordStrength(password);
  if (strengthErr) {
    ApiResponse.error(res, strengthErr, 400);
    return { rejected: true };
  }
  return { password, rejected: false };
};

/**
 * 创建用户
 * POST /api/users
 */
const createUser = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { username, email, realName, phone, department, roles, allowedIPs } = req.body;

  // FE-M3：管理员建号口令密文轨（encPassword，与代设明文双轨）
  const { password, rejected } = await resolveAdminSetPassword(req, res, username);
  if (rejected) return;

  // IP 访问范围规则格式校验：非法片段直接回报，避免入库后规则静默失效
  if (rejectInvalidIpRules(res, allowedIPs)) return;

  // 检查用户名是否已存在
  // P3-30：username 判重走 collation（大小写不敏感），与唯一索引 username_ci 同口径；
  // 邮箱保持默认 collation 以命中 email_1 索引，故不能合并为一次 $or 查询
  const [dupName, dupEmail] = await Promise.all([
    userService.findDuplicateUsername(username),
    userService.findOneUser({ email }),
  ]);
  if (dupName || dupEmail) {
    return ApiResponse.error(res, dupName ? '用户名已存在' : '邮箱已被使用', 400);
  }

  // 先校验角色，再创建用户，避免角色校验失败后留下孤儿用户
  const roleCheck = await validateRolesForCreate(req, res, roles);
  if (roleCheck.rejected) return;
  const validatedRoles = roleCheck.roles;

  // P0-1（建号口径补齐，与 updateUser 的 department 闸同源）：详见 guardCreateUserScope。
  if (await guardCreateUserScope(req, res, department, username)) return;

  // 创建用户（带角色）
  const user = await userService.createUser({
    username,
    email,
    password,
    realName,
    phone,
    department,
    createdBy: req.user.userId,
    roles: validatedRoles,
    allowedIPs: allowedIPs || '',
  });

  logger.info('管理员创建用户', { operator: req.user.username, username });

  // 用户数据变更，失效操作者数据范围下的统计缓存
  statsCache.invalidateByUserId(req.user.userId);

  const createdUser = await userService.getCreatedUser(user._id);

  return ApiResponse.success(res, createdUser, '用户创建成功', 201);
});

/**
 * status 变更的三道闸门（顺序即判定顺序，不可调整）：
 *  1) 不得把超级管理员置为非 active——且**不带 isSelf 例外**：超管把自己锁死后
 *     无人能解锁（层级校验会拦下所有针对 level=10 的操作），属自锁死路径；
 *  2) 不得变更自身 status（改完即失去登录能力，且同样无人能修回）；
 *  3) 变更他人 status 须持 user:lock——否则仅持 user:update 的账号就能绕过专用
 *     锁定接口（PUT /api/security/users/:userId/lock）的权限门；*:* 通配视为持有全部权限。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectForbiddenStatusChange = async (req, res, { user, status, isSelf, targetRoles }) => {
  const isBuiltInSuperAdmin = targetRoles.some(isSuperAdminRole);
  if (status && status !== 'active' && isBuiltInSuperAdmin) {
    ApiResponse.codeError(res, 'CANNOT_DISABLE_SUPER_ADMIN');
    return true;
  }
  const changesOwnStatus = isSelf && status !== undefined && String(status) !== String(user.status);
  if (changesOwnStatus) {
    ApiResponse.codeError(res, 'CANNOT_CHANGE_OWN_STATUS');
    return true;
  }
  const changesOthersStatus =
    !isSelf && status !== undefined && String(status) !== String(user.status);
  if (changesOthersStatus) {
    const operatorPermCodes = await userService.getPermissions(req.user.userId);
    if (!operatorPermCodes.includes('user:lock') && !operatorPermCodes.includes('*:*')) {
      ApiResponse.codeError(res, 'USER_STATUS_CHANGE_FORBIDDEN');
      return true;
    }
  }
  return false;
};

/**
 * 字段格式闸：头像白名单（与个人资料接口同口径，防存储恶意 URL/data URI）、
 * IP 范围规则语法（非法片段必须回报，否则入库后规则静默失效）。
 * @returns {boolean} true 表示已写出拒绝响应
 */
const rejectInvalidFieldFormats = (res, { avatar, allowedIPs }) => {
  if (avatar !== undefined && avatar !== '' && !isValidAvatar(avatar)) {
    ApiResponse.codeError(res, 'AVATAR_INVALID');
    return true;
  }
  return rejectInvalidIpRules(res, allowedIPs);
};

/**
 * 层级保护：禁止修改等于或高于自身层级的用户（与删除/锁定/角色分配逻辑保持一致），
 * 防止低层级管理员篡改或禁用高层级账户（含 status 变更）；修改自身资料除外。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const rejectPeerOrHigherTarget = async (req, res, { targetRoles, isSelf }) => {
  if (isSelf) return false;
  const targetMaxLevel = maxRoleLevel(targetRoles);
  // 按操作者 ID 重新查询角色层级（req.user.roles 存的是角色编码，不能直接用于 _id 查询）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  if (targetMaxLevel >= operatorMaxLevel) {
    ApiResponse.codeError(res, 'USER_UPDATE_PEER_OR_HIGHER_FORBIDDEN');
    return true;
  }
  return false;
};

/**
 * 数据范围闸（P0-1）：department 与 allowedIPs 都是「决定谁能看见什么/从哪能访问」的
 * 归属字段，不得由可见域之外的操作者改写。
 *
 * 背景（已端到端复现的跨部门越权链）：本接口此前只有层级校验（isSelf 例外 +
 * targetMaxLevel >= operatorMaxLevel），于是 dept=东区的部门管理员执行
 *   PUT /api/users/<自己> { department: '总部' }
 * → 200 → 随后 GET /api/devices 以「总部」口径返回全量设备 → 越权读取。
 *
 * 口径（与 assertRecordInScope / applyDataScopeToQuery 的 deny 语义一致）：
 *   - all        → 不受限（超级管理员）
 *   - department → 仅允许本部门内变更：目标用户当前须在本部门，新值也须是本部门
 *   - self/none  → 拒绝这两个字段的任何变更
 * isSelf 不构成豁免：攻击链正是「改自己」。层级校验管「能不能碰这个人」，
 * 数据范围校验管「能不能把他的归属改到我的可见域之外」——两者正交，都要有。
 * @returns {Promise<boolean>} true 表示已写出拒绝响应
 */
const rejectOutOfScopeFieldChange = async (req, res, { user, department, allowedIPs }) => {
  const touchesScopeField =
    (department !== undefined && department !== user.department) ||
    (allowedIPs !== undefined && allowedIPs !== user.allowedIPs);
  if (!touchesScopeField) return false;

  const opScope = await getDataScope(req.user.userId);
  if (opScope.type === 'all') return false;

  const opDept = opScope.type === 'department' ? opScope.department : null;
  const targetInScopeDept = Boolean(opDept) && user.department === opDept;
  const newDeptInScopeDept = department === undefined || department === opDept;
  if (targetInScopeDept && newDeptInScopeDept) return false;

  logger.warn('拒绝范围外的数据范围字段变更', {
    operator: operatorTag(req),
    operatorScope: opScope.type,
    operatorDept: opDept || null,
    targetUsername: user.username,
    targetDept: user.department || null,
    requestedDept: department,
    requestedAllowedIPs: allowedIPs !== undefined,
  });
  ApiResponse.codeError(res, 'USER_SCOPE_FIELD_FORBIDDEN');
  return true;
};

/**
 * 待写入的用户字段（此前 email 被静默丢弃——前端编辑表单确实提交该字段；
 * 唯一性冲突处理与创建接口口径一致）
 * @returns {Promise<boolean>} true 表示邮箱已被他人占用，调用方应立即 return
 */
const emailTakenBySomeoneElse = async (email, user) => {
  // 查重本身不会漏：Mongoose 把 schema 的 lowercase setter 同时作用于查询条件。
  // 这里显式取规范形态是为了两件事：① 与 user.email 的比较是普通 JS 比较，没有 setter；
  // ② 不把正确性押在"query setter"这一条 Mongoose 隐式行为上（历史上变过）。见 utils/emailKey.js。
  const emailKey = normalizeEmailKey(email);
  if (emailKey === undefined || emailKey === normalizeEmailKey(user.email)) return false;
  const existing = await userService.findOneUser({
    email: emailKey,
    _id: { $ne: user._id },
  });
  return Boolean(existing);
};

/** 按「字段是否出现」逐个赋值：undefined 表示本次不改，不得写成 false/null */
const applyProfileFields = (
  user,
  { realName, email, phone, department, avatar, status, allowedIPs }
) => {
  // 必须在逐个赋值**之前**读旧 status：restoringAccess 判的是"这次写入是否把账户从
  // 不可登录状态恢复回来"，赋值之后旧值就没了。
  const restoringAccess = status === 'active' && user.status !== 'active';
  if (realName !== undefined) user.realName = realName;
  if (email !== undefined) user.email = email;
  if (phone !== undefined) user.phone = phone;
  if (department !== undefined) user.department = department;
  if (avatar !== undefined) user.avatar = avatar;
  if (status !== undefined) user.status = status;
  if (allowedIPs !== undefined) user.allowedIPs = allowedIPs;
  // 恢复可登录状态时必须连**临时锁定**一起清掉，与专用解锁接口同口径
  // （services/authService 的 lockUser）。两套锁定是分开的：status 由管理员改，
  // lockUntil 由登录爆破阈值写；而 authenticate 与 loginUser 都只看 lockUntil 就拒登录。
  // 于是"先被爆破锁定、再被管理员锁定"的账户，本处原先只改 status ⇒
  // 接口 200「用户信息更新成功」、缓存也失效了，用户依然登不进来，运维只会去怀疑密码。
  // 判据取「由非 active 变回 active」而不是「status 字段被写过」：
  // active→active 的普通编辑不得顺手重置爆破计数（那等于给攻击者一个免费清零入口）。
  if (restoringAccess) {
    user.lockUntil = null;
    user.failedLoginCount = 0;
  }
};

/**
 * 更新用户信息
 * PUT /api/users/:id
 */
const updateUser = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { realName, email, phone, department, avatar, status, allowedIPs } = req.body;

  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围闸（与 getUserById 读路径同一判据）：层级校验管"能不能碰这个人"，
  // 范围校验管"这个人是否在你的可见域内"——两者正交。此前仅读路径有闸，
  // 部门域管理员可对自己根本看不到（GET 403）的跨部门用户执行写操作。
  const { allowed: updateTargetInScope } = await assertRecordInScope(
    req,
    user,
    USER_OWNER_FIELD,
    USER_DEPT_FIELD
  );
  if (!updateTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  // 以下逐步调用与原实现同序；每步自己决定是否要查库，调用方只管"被拒即 return"
  const targetRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const isSelf = String(user._id) === String(req.user.userId);

  if (await rejectPeerOrHigherTarget(req, res, { targetRoles, isSelf })) return;

  if (await rejectForbiddenStatusChange(req, res, { user, status, isSelf, targetRoles })) return;

  if (rejectInvalidFieldFormats(res, { avatar, allowedIPs })) return;

  if (await rejectOutOfScopeFieldChange(req, res, { user, department, allowedIPs })) return;

  if (await emailTakenBySomeoneElse(email, user)) {
    return ApiResponse.codeError(res, 'EMAIL_TAKEN_SHORT');
  }

  applyProfileFields(user, { realName, email, phone, department, avatar, status, allowedIPs });

  await userService.saveUser(user);

  // 用户状态变更时失效缓存（P3-3：解锁同样必须失效——
  // 原实现只对「变为非 active」失效，锁定/禁用解除后 authenticate 的
  // 60s 缓存仍持有旧的 status，合法用户最长 1 分钟仍被拒）
  if (status !== undefined) {
    // 统计缓存：状态变更影响统计口径，目标用户与操作者（统计视角）均需失效
    statsCache.invalidateByUserId(user._id);
    statsCache.invalidateByUserId(req.user.userId);
    invalidateUserCache(user._id);
  }

  // IP 范围规则变更需立即生效：authenticate 的用户缓存持有旧 allowedIPs，
  // 不失效会让新规则最长延迟 30 秒（存在越权访问窗口）
  if (allowedIPs !== undefined) {
    invalidateUserCache(user._id);
  }

  const updatedUser = await userService.getUpdatedUser(user._id);

  logger.info('用户信息已更新', { username: user.username });

  return ApiResponse.success(res, updatedUser, '用户信息更新成功');
});

/**
 * 分配角色给用户
 * PUT /api/users/:id/roles
 */
const assignRoles = asyncHandler(async (req, res) => {
  // 路由层 assignRolesValidation 的校验结果必须显式消费：
  // 只声明校验器不消费 = 校验链形同虚设（与其他接口口径统一，报告 O-3）
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { roles } = req.body;

  if (rejectInvalidRoleList(res, roles)) return;
  // 归一必须在比较之前：$in 只回**去重后**的文档，`validRoles.length !== roles.length`
  // 于是会把"重复提交同一个角色"判成"角色不存在"（判据与理由见 utils/helpers 的 uniqueIdStrings）。
  // 归一后的这一份还要参与最终写入，否则去重的意义只剩一半。
  const requestedRoles = uniqueIdStrings(roles);

  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围闸：与 updateUser/deleteUser 同判据（派角色同样是对象级写操作）
  const { allowed: assignTargetInScope } = await assertRecordInScope(
    req,
    user,
    USER_OWNER_FIELD,
    USER_DEPT_FIELD
  );
  if (!assignTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  // 此前仅校验"被分配角色"的层级，未校验"目标用户"的层级，
  // 导致低层级管理员可剥离同级/更高级用户（含内置超管）的角色
  // M-01 修复：目标用户层级保护（口径对齐 updateUser/deleteUser/toggleUserLock）
  const targetUserRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetUserMaxLevel = maxRoleLevel(targetUserRoles);

  // 验证新角色是否存在（同时取出 permissions 供权限子集校验）
  const validRoles = await userService.findRolesByIds(requestedRoles, 'level code permissions', {
    populate: { path: 'permissions', select: 'code' },
  });
  if (validRoles.length !== requestedRoles.length) {
    return ApiResponse.codeError(res, 'ROLE_ID_INVALID');
  }

  // 权限层级校验：禁止分配高于操作者自身层级的角色
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetMaxLevel = maxRoleLevel(validRoles);
  if (targetMaxLevel > operatorMaxLevel) {
    return ApiResponse.codeError(res, 'ROLE_ASSIGN_HIGHER_LEVEL_FORBIDDEN');
  }

  // 目标用户层级保护：禁止变更等于或高于自身层级的用户（修改自身除外）
  const isSelf = String(user._id) === String(req.user.userId);
  if (!isSelf && targetUserMaxLevel >= operatorMaxLevel) {
    return ApiResponse.codeError(res, 'USER_ROLE_ASSIGN_PEER_OR_HIGHER_FORBIDDEN');
  }

  // ===== P2-8 修复：权限子集校验 =====
  // 仅比 level 是不够的。createRole 的"授予权限必须自身持有"落在
  // src/controllers/roleController.js:147-150，assignPermissions 的同一条校验落在
  // src/controllers/rolePermissionController.js:106（由 src/controllers/rolePermissionController.js:215 调用）——
  // 都强制「授予的权限必须自身持有」，唯独 assignRoles 只看层级——
  // 于是两名同级（level 相同）但分管不同模块的管理员互挂对方角色，
  // 即可各自集齐双方全部权限，横向扩权且不触发任何层级告警。
  // isSelf 同样必须校验：给自己挂一个同级富权限角色是最直接的自我提权路径，
  // 而层级保护恰好对 isSelf 放行。
  const operatorPermCodes = await userService.getPermissions(req.user.userId);
  if (!operatorPermCodes.includes('*:*')) {
    // 只校验「新增的」权限：目标用户已持有的权限不属于本次授予行为，
    // 否则操作者无法对权限比自己多的用户做任何角色调整（含收权）。
    // 判定本身与建号路径共用同一个实现（findUnoperableGrantCodes），
    // 精确匹配与模块通配的语义则来自 utils/permissionHelper 的唯一实现。
    const currentRoleDocs = await userService.findActiveRolePermissionDocs(user.roles);
    const lacking = findUnoperableGrantCodes(operatorPermCodes, validRoles, currentRoleDocs);
    if (lacking.length > 0) {
      logger.warn(
        `角色分配越权被拒：operator=${operatorTag(req)} ` +
          `target=${user.username} 缺少权限=${lacking.join(',')}`
      );
      return ApiResponse.codeError(res, 'PERMISSION_GRANT_FORBIDDEN', {
        message: `无权授予以下权限：${lacking.join('、')}`,
        params: { permissions: lacking.join('、') },
      });
    }
  }

  // ===== 后端复审 B-2：同级角色归属包含校验（判据与理由见 rejectForeignPeerRoles）=====
  // 建号轨（validateRolesForCreate 第 5 道）调用的是同一个实现，两条轨不会再各走各的尺子。
  if (
    !operatorPermCodes.includes('*:*') &&
    rejectForeignPeerRoles(res, req, validRoles, operatorMaxLevel, `target=${user.username}`)
  ) {
    return;
  }

  // 超管归属不可变更（含操作者本人）：剥离会造成不可恢复的自锁死
  // （超管是唯一 *:* 来源，剥离后无任何接口能修回），授予会破坏唯一性。
  // 归属只由启动期 reconcileSuperAdmin 决定，详见 utils/superAdmin.js
  const nextRoleDocs = await userService.findRolesByIds(requestedRoles, 'code isBuiltIn', {
    lean: true,
  });
  const membershipError = checkSuperAdminMembership(targetUserRoles, nextRoleDocs);
  if (membershipError) {
    logger.warn(
      `超管归属变更被拒：operator=${operatorTag(req)} ` + `target=${user.username} isSelf=${isSelf}`
    );
    return ApiResponse.codeError(res, membershipError.code, { message: membershipError.message });
  }

  // 原子更新替代读-改-save：user.save() 会把整个文档回写，并发窗口内的
  // 其他字段修改（如 status）会被本次内存快照覆盖；findByIdAndUpdate+$set 只写 roles
  await userService.updateRoles(user._id, requestedRoles);

  // 角色变更后失效缓存

  invalidateUserCache(user._id);
  // 统计缓存：目标用户与操作者（统计视角）均需失效
  statsCache.invalidateByUserId(user._id);
  statsCache.invalidateByUserId(req.user.userId);

  const updatedUser = await userService.getUpdatedUser(user._id);

  logger.info('用户角色已更新', { username: user.username });

  // 角色变更直接改变该用户的有效权限：定向推送新权限集，无需重新登录。
  // 必须在 invalidateUserCache 之后执行，否则重算会命中变更前的缓存
  await syncPermissionsToUsers(req, [user._id], {
    action: 'roles-assigned',
  });

  return ApiResponse.success(res, updatedUser, '角色分配成功');
});

/**
 * 删除用户
 * DELETE /api/users/:id
 */
const deleteUser = asyncHandler(async (req, res) => {
  const user = await userService.findUserForUpdate(req.params.id);
  if (!user) {
    return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
  }

  // 数据范围闸：与 updateUser/getUserById 同判据（层级之外的正交一闸）
  const { allowed: deleteTargetInScope } = await assertRecordInScope(
    req,
    user,
    USER_OWNER_FIELD,
    USER_DEPT_FIELD
  );
  if (!deleteTargetInScope) {
    return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN');
  }

  // 不允许删除自己
  if (user._id.toString() === req.user.userId) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：禁止删除等于或高于自身层级的用户（与锁定/角色分配逻辑保持一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targetRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetMaxLevel = maxRoleLevel(targetRoles);
  if (targetMaxLevel >= operatorMaxLevel) {
    return ApiResponse.codeError(res, 'USER_DELETE_PEER_OR_HIGHER_FORBIDDEN');
  }

  // 超管账户不可删除：删账户等于让超管归属归零。
  // 上面的层级校验在当前数据下已能拦住（level=10 是上限），此处是显式兜底——
  // 若 SUPER_ADMIN 的 level 被下调，层级校验会失效而本判断仍然生效
  if (targetRoles.some(isSuperAdminRole)) {
    logger.warn('删除超管账户被拒', {
      operator: operatorTag(req),
      target: user.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN');
  }

  const userId = user._id;
  await userService.deleteById(req.params.id);

  // 失效缓存

  invalidateUserCache(userId);
  // 统计缓存：目标用户与操作者（统计视角）均需失效
  statsCache.invalidateByUserId(userId);
  statsCache.invalidateByUserId(req.user.userId);

  logger.info('用户已删除', { username: user.username });

  return ApiResponse.success(res, null, '用户删除成功');
});

/**
 * 批量删除用户
 * DELETE /api/users/batch
 */
const batchDeleteUsers = asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
  }

  const { ids } = req.body;
  const BATCH_DELETE_MAX = 100; // 单次批量删除上限

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return ApiResponse.codeError(res, 'USER_ID_LIST_INVALID');
  }

  if (ids.length > BATCH_DELETE_MAX) {
    return ApiResponse.codeError(res, 'BATCH_DELETE_LIMIT_EXCEEDED', {
      message: `单次批量删除最多 ${BATCH_DELETE_MAX} 个用户`,
      params: { max: BATCH_DELETE_MAX },
    });
  }

  // 校验所有 ID 是否为合法 ObjectId
  const mongoose = require('mongoose');
  const invalidIds = ids.filter((id) => !mongoose.Types.ObjectId.isValid(id));
  if (invalidIds.length > 0) {
    return ApiResponse.codeError(res, 'USER_ID_FORMAT_INVALID_IN_LIST', {
      message: `包含非法的用户 ID 格式: ${invalidIds.slice(0, 5).join(', ')}`,
      params: { invalidIds: invalidIds.slice(0, 5).join(', ') },
    });
  }

  // 归一必须在比较之前（与 assignRoles 同一条理由：$in 只回**去重后**的文档，
  // 重复 id 会被 `targets.length !== ids.length` 判成"这个用户不存在"而整批拒绝）
  const requestedIds = uniqueIdStrings(ids);

  // 检查是否包含自己（统一转为字符串比较，避免 ObjectId 类型不一致）
  if (requestedIds.includes(String(req.user.userId))) {
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SELF');
  }

  // 层级保护：批量目标中包含同级或更高级别用户时整体拒绝（与单个删除口径一致）
  const operatorMaxLevel = await getOperatorMaxLevel(req.user.userId);
  const targets = await userService.findBatchUsers(requestedIds);
  if (targets.length !== requestedIds.length) {
    return ApiResponse.codeError(res, 'USER_ID_NOT_FOUND_IN_LIST');
  }
  const oversized = targets.find((t) => maxRoleLevel(t.roles) >= operatorMaxLevel);

  // 数据范围闸：任一目标越出可见域即整批拒绝（批量接口不得成为单对象保护的绕过路径）
  for (const target of targets) {
    const { allowed: batchTargetInScope } = await assertRecordInScope(
      req,
      target,
      USER_OWNER_FIELD,
      USER_DEPT_FIELD
    );
    if (!batchTargetInScope) {
      return ApiResponse.codeError(res, 'USER_SCOPE_FORBIDDEN', {
        message: `无权操作用户：${target.username}（超出您的数据范围）`,
        params: { username: target.username },
      });
    }
  }

  if (oversized) {
    return ApiResponse.codeError(res, 'BATCH_DELETE_PEER_OR_HIGHER_FORBIDDEN', {
      message: `无权删除同级或更高级别的用户：${oversized.username}`,
      params: { username: oversized.username },
    });
  }

  // 超管账户不可删除（与单个删除口径一致）：任一目标是超管则整批拒绝，
  // 避免"批量接口成为单个接口保护的绕过路径"
  const superTarget = targets.find((t) => (t.roles || []).some(isSuperAdminRole));
  if (superTarget) {
    logger.warn('批量删除含超管账户被拒', {
      operator: operatorTag(req),
      target: superTarget.username,
    });
    return ApiResponse.codeError(res, 'CANNOT_DELETE_SUPER_ADMIN', {
      message: `不能删除超级管理员账户：${superTarget.username}（系统必须保留唯一的最高权限账户）`,
    });
  }

  const result = await userService.deleteMany({ _id: { $in: requestedIds } });

  // 批量失效缓存

  requestedIds.forEach(invalidateUserCache);
  requestedIds.forEach((id) => statsCache.invalidateByUserId(id));
  // 统计缓存：操作者（统计视角）也需要同步失效
  statsCache.invalidateByUserId(req.user.userId);

  logger.info(`批量删除用户：${result.deletedCount} 个`);

  return ApiResponse.success(res, { deleted: result.deletedCount }, '批量删除成功');
});

/**
 * $facet 结果 → 面板形状。任何一臂缺失都落到 0 / 空集，
 * 不让 undefined 流到前端（面板按数值直接参与算式）。
 */
const facetArmCount = (rows) => rows?.[0]?.count || 0;

const mapUserStatsFacet = (facetResult) => ({
  total: facetArmCount(facetResult?.total),
  active: facetArmCount(facetResult?.active),
  inactive: facetArmCount(facetResult?.inactive),
  thisMonth: facetArmCount(facetResult?.thisMonth),
  byDepartment: facetResult?.byDepartment || [],
  byRole: facetResult?.byRole || [],
});

/**
 * 获取用户统计信息
 * GET /api/users/stats
 */
const getUserStats = asyncHandler(async (req, res) => {
  // 数据范围控制：与列表/详情接口口径一致，防止越权看到全组织统计
  const dataScope = await getDataScope(req.user.userId);
  const scopeFilter = buildDataScopeFilter(
    dataScope,
    DATA_SCOPE_FIELDS.user.ownerField,
    DATA_SCOPE_FIELDS.user.departmentField
  );

  // 统计缓存：缓存键由用户 ID + 数据范围稳定摘要组成，保证按用户+数据范围隔离
  const crypto = require('crypto');
  const scopeFingerprint = crypto
    .createHash('sha1')
    .update(JSON.stringify(scopeFilter))
    .digest('hex')
    .slice(0, 12);
  const cacheKey = `stats:${req.user.userId}:${scopeFingerprint}`;

  // 命中缓存直接返回，避免数据库往返
  const cached = statsCache.get(cacheKey);
  if (cached.hit) {
    return ApiResponse.success(res, cached.data, '获取用户统计成功');
  }

  // 本月起始时间：取业务时区当月 1 日零点（与全站「今日」窗口同源）。
  // 原 setDate(1)+setHours(0,0,0,0) 是服务器本地时区——容器裸跑 UTC 时，
  // 业务时区每月 1 日前 8 小时新建的账号被算进上月，与同接口的其它计数、
  // 仪表盘「今日」口径互相矛盾。
  const startOfMonth = businessMonthStart();

  // $facet 单次聚合：冷缓存时 6 次串行 DB 往返合并为 1 次，降低冷启动/并发抖动
  const [facetResult] = await userService.aggregateStats([
    // Model.aggregate 不做 schema cast：self 范围下 scopeFilter.createdBy 是 JWT 里的
    // 字符串，直接进 $match 对 ObjectId 字段零匹配 → 统计恒 0（列表走 find() 会 cast，
    // 于是"列表有数据、看板全 0"）。与 AlarmService.getAlarmStats 同用 castScopeObjectIds 归一。
    { $match: castScopeObjectIds(scopeFilter) },
    {
      $facet: {
        // 总用户数
        total: [{ $count: 'count' }],
        // 活跃用户数（状态为 active）
        active: [{ $match: { status: 'active' } }, { $count: 'count' }],
        // 禁用用户数
        inactive: [{ $match: { status: 'inactive' } }, { $count: 'count' }],
        // 本月新增用户
        thisMonth: [{ $match: { createdAt: { $gte: startOfMonth } } }, { $count: 'count' }],
        // 按部门统计
        byDepartment: [
          { $match: { status: 'active' } },
          { $group: { _id: '$department', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        // 按角色统计（口径对齐 byDepartment：仅统计 active 用户，
        // 此前 byDepartment 只算 active 而 byRole 算全部，两个维度基数不一致）
        byRole: [
          { $match: { status: 'active' } },
          { $unwind: '$roles' },
          { $group: { _id: '$roles', count: { $sum: 1 } } },
          { $lookup: { from: 'roles', localField: '_id', foreignField: '_id', as: 'role' } },
          { $unwind: '$role' },
          {
            $project: {
              _id: 0,
              roleId: '$_id',
              roleName: '$role.name',
              roleCode: '$role.code',
              count: 1,
            },
          },
          { $sort: { count: -1 } },
        ],
      },
    },
  ]);

  const data = mapUserStatsFacet(facetResult);

  // 写入缓存（TTL 使用配置默认值），便于后续请求直接命中
  statsCache.set(cacheKey, data);

  return ApiResponse.success(res, data, '获取用户统计成功');
});

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  assignRoles,
  deleteUser,
  batchDeleteUsers,
  getUserStats,
};
