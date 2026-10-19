/**
 * userController 资料变更路径：updateUser 及其守卫（层级/status/字段格式/范围/邮箱查重）。
 */
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { getDataScope, assertRecordInScope } = require('../../middleware/rbac');
const { isValidAvatar } = require('../../utils/helpers');
const { normalizeEmailKey } = require('../../utils/emailKey');
// A3：email 已 at-rest 加密 ⇒ 查重改走 HMAC 检索键（明文列随机 IV，相等性不成立）
const { piiSearchKey } = require('../../utils/piiCrypto');
const { isSuperAdminRole } = require('../../utils/superAdmin');
const statsCache = require('../../services/statsCache');
const { invalidateUserCache } = require('../../middleware/auth');
const userService = require('../../services/userService');
const {
  USER_OWNER_FIELD,
  USER_DEPT_FIELD,
  operatorTag,
  rejectInvalidIpRules,
} = require('./shared');

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
  // A3（2026-10-16）：查重改走 **emailKey**（HMAC 检索键）——email 列已加密，
  // 明文相等性在随机 IV 的密文列上不成立，继续查 `{ email }` 会恒不命中，
  // 表现为「管理员改他人邮箱撞车不再报 EMAIL_TAKEN_SHORT」。
  // 局部变量刻意叫 `normalizedEmail` 而**不叫** `emailKey`：后者现在是 schema 上的
  // HMAC 字段名，同名不同义极易写出 `user.emailKey = <小写明文>`（旧代码正是这个名字）。
  // 归一化（lowercase）仍要显式取一次：与 user.email 的比较是普通 JS 比较，没有 setter。
  const normalizedEmail = normalizeEmailKey(email);
  if (normalizedEmail === undefined || normalizedEmail === normalizeEmailKey(user.email)) {
    return false;
  }
  const existing = await userService.findOneUser({
    emailKey: piiSearchKey(normalizedEmail),
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

module.exports = { updateUser };
