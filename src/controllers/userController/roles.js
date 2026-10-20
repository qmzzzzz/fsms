/**
 * userController 角色授予路径：assignRoles。
 */
const { validationResult } = require('express-validator');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const { syncPermissionsToUsers } = require('../../utils/permissionSync');
const logger = require('../../utils/logger');
const { asyncHandler } = require('../../middleware/errorHandler');
const { assertRecordInScope } = require('../../middleware/rbac');
const { uniqueIdStrings } = require('../../utils/helpers');
const { checkSuperAdminMembership } = require('../../utils/superAdmin');
const statsCache = require('../../services/statsCache');
const { invalidateUserCache } = require('../../middleware/auth');
const userService = require('../../services/userService');
const {
  USER_OWNER_FIELD,
  USER_DEPT_FIELD,
  findUnoperableGrantCodes,
  rejectForeignPeerRoles,
  operatorTag,
} = require('./shared');

/**
 * 角色列表形状闸：必须是非空数组（元素是否指向真实角色由后续存在性校验负责）。
 * @returns {boolean} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectInvalidRoleList = (res, roles) => {
  if (roles && Array.isArray(roles) && roles.length > 0) return false;
  ApiResponse.codeError(res, 'ROLE_LIST_INVALID');
  return true;
};

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
  // 修复：目标用户层级保护（口径对齐 updateUser/deleteUser/toggleUserLock）
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

  // ===== 修复：权限子集校验 =====
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
  // 统计缓存：角色分布影响所有查看者的聚合口径，必须全量失效（A-1）
  statsCache.invalidateAll('user-roles');

  const updatedUser = await userService.getUpdatedUser(user._id);

  logger.info('用户角色已更新', { username: user.username });

  // 角色变更直接改变该用户的有效权限：定向推送新权限集，无需重新登录。
  // 必须在 invalidateUserCache 之后执行，否则重算会命中变更前的缓存
  await syncPermissionsToUsers(req, [user._id], {
    action: 'roles-assigned',
  });

  return ApiResponse.success(res, updatedUser, '角色分配成功');
});

module.exports = { assignRoles };
