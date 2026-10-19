/**
 * userController 建号路径：createUser 及其前置校验（口令/角色/IP 规则/数据范围）。
 */
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { getDataScope } = require('../../middleware/rbac');
const { validatePasswordStrength, uniqueIdStrings } = require('../../utils/helpers');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const { isSuperAdminRole } = require('../../utils/superAdmin');
// A3：email 已 at-rest 加密 ⇒ 查重改走 HMAC 检索键（明文列随机 IV，相等性不成立）
const { piiSearchKey } = require('../../utils/piiCrypto');
const statsCache = require('../../services/statsCache');
const userService = require('../../services/userService');
const canaryWatch = require('../../services/canaryWatch');
const {
  findUnoperableGrantCodes,
  rejectForeignPeerRoles,
  operatorTag,
  rejectInvalidIpRules,
} = require('./shared');

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
    password = await decryptLoginCredential(req.body.encPassword, 'USER_CREATE');
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

  // 哨兵用户名（canary）闸：系统保留名不经管理面进入用户集合（幽灵名一旦被
  // 真实占用，对应哨兵在登录面无从触发——启动期 canaryWatch.init() 会做遮蔽
  // 对账，但防线前移到这里）。与下方判重同为 400 文案响应（管理面可明示
  // "保留"；注册面保持模糊，见 authService/session.js）。
  if (canaryWatch.matchCanaryName(username)) {
    logger.warn('建号被拒 - 用户名为安全哨兵保留名', {
      operator: operatorTag(req),
      username,
    });
    return ApiResponse.error(res, '该用户名为系统保留名，不能使用', 400);
  }

  // FE-M3：管理员建号口令密文轨（encPassword，与代设明文双轨）
  const { password, rejected } = await resolveAdminSetPassword(req, res, username);
  if (rejected) return;

  // IP 访问范围规则格式校验：非法片段直接回报，避免入库后规则静默失效
  if (rejectInvalidIpRules(res, allowedIPs)) return;

  // 检查用户名是否已存在
  // P3-30：username 判重走 collation（大小写不敏感），与唯一索引 username_ci 同口径；
  // A3（2026-10-16）：邮箱分支改查 **emailKey**（HMAC 检索键，唯一索引）。
  // 原先查的是明文 `email_1`，而 email 列已加密——继续查明文列会恒不命中，
  // 表现为「建号时撞他人邮箱不再报 400」。两次查询仍不能合并为一次 $or：
  // 带 collation 的 username 分支与不带 collation 的 emailKey 分支索引不同。
  const [dupName, dupEmail] = await Promise.all([
    userService.findDuplicateUsername(username),
    userService.findOneUser({ emailKey: piiSearchKey(email) }),
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

module.exports = { createUser };
