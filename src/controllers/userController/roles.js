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
  findGrantViolationAfterWrite,
  rejectForeignPeerRoles,
  operatorTag,
} = require('./shared');

/**
 * 入参请求闸：express-validator 结果必须显式消费（与其他接口口径统一，报告 O-3），
 * 角色列表必须是非空数组（元素是否指向真实角色由后续存在性校验负责）。
 * @returns {boolean} true 表示已写出拒绝响应，调用方应立即 return
 */
const rejectInvalidRoleRequest = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    ApiResponse.codeError(res, 'VALIDATION_FAILED', {
      fieldErrors: safeFieldErrors(errors),
    });
    return true;
  }
  const { roles } = req.body;
  if (roles && Array.isArray(roles) && roles.length > 0) return false;
  ApiResponse.codeError(res, 'ROLE_LIST_INVALID');
  return true;
};

/**
 * ===== 修复：权限子集校验 =====
 * 仅比 level 是不够的。createRole 的"授予权限必须自身持有"落在
 * src/controllers/roleController.js:147-150，assignPermissions 的同一条校验落在
 * src/controllers/rolePermissionController.js:106（由 src/controllers/rolePermissionController.js:215 调用）——
 * 都强制「授予的权限必须自身持有」，唯独 assignRoles 只看层级——
 * 于是两名同级（level 相同）但分管不同模块的管理员互挂对方角色，
 * 即可各自集齐双方全部权限，横向扩权且不触发任何层级告警。
 * isSelf 同样必须校验：给自己挂一个同级富权限角色是最直接的自我提权路径，
 * 而层级保护恰好对 isSelf 放行。
 * @returns {boolean} true 表示已写出拒绝响应
 */
const rejectUnoperableGrants = async (res, req, operatorPermCodes, validRoles, user) => {
  if (operatorPermCodes.includes('*:*')) return false;
  // 只校验「新增的」权限：目标用户已持有的权限不属于本次授予行为，
  // 否则操作者无法对权限比自己多的用户做任何角色调整（含收权）。
  // 判定本身与建号路径共用同一个实现（findUnoperableGrantCodes），
  // 精确匹配与模块通配的语义则来自 utils/permissionHelper 的唯一实现。
  const currentRoleDocs = await userService.findActiveRolePermissionDocs(user.roles);
  const lacking = findUnoperableGrantCodes(operatorPermCodes, validRoles, currentRoleDocs);
  if (lacking.length === 0) return false;
  logger.warn(
    `角色分配越权被拒：operator=${operatorTag(req)} ` +
      `target=${user.username} 缺少权限=${lacking.join(',')}`
  );
  ApiResponse.codeError(res, 'PERMISSION_GRANT_FORBIDDEN', {
    message: `无权授予以下权限：${lacking.join('、')}`,
    params: { permissions: lacking.join('、') },
  });
  return true;
};

/**
 * 超管归属不可变更（含操作者本人）：剥离会造成不可恢复的自锁死
 * （超管是唯一 *:* 来源，剥离后无任何接口能修回），授予会破坏唯一性。
 * 归属只由启动期 reconcileSuperAdmin 决定，详见 utils/superAdmin.js
 * @returns {boolean} true 表示已写出拒绝响应
 */
const rejectMembershipChange = (res, req, targetUserRoles, nextRoleDocs, user, isSelf) => {
  const membershipError = checkSuperAdminMembership(targetUserRoles, nextRoleDocs);
  if (!membershipError) return false;
  logger.warn(
    `超管归属变更被拒：operator=${operatorTag(req)} ` + `target=${user.username} isSelf=${isSelf}`
  );
  ApiResponse.codeError(res, membershipError.code, { message: membershipError.message });
  return true;
};

/**
 * 写后复验 + 回滚（角色分配轨）。
 *
 * 覆盖两类窗口：
 *  1) L-03：角色在校验后、落库前被停用/删除（activeOnly 之后取回的数量对不上）；
 *  2) TOCTOU：updateRole 抬高 level / assignPermissions 扩张权限发生在校验之后，
 *     本次授予超出操作者实际权限。
 * 复验不通过时把目标用户的角色集写回 `user.roles`（载入时的快照）。
 * 回滚本身先走 CAS；若连回滚都因并发写 miss，则无条件写回快照——本次授予
 * 已被判定越权，不能因为"回滚时又有人改了角色"就把它留在库里。极端并发下
 * 可能覆盖另一次合法调整，但那可以在审计日志（warn）里定位并重做；
 * 留下一个越权角色没有可观测的出口。
 *
 * @returns {Promise<boolean>} true 表示已回滚并写出拒绝响应
 */
const revalidateGrantAfterWrite = async (
  res,
  { user, requestedRoles, operatorMaxLevel, operatorPermCodes }
) => {
  const [freshRoleDocs, currentRoleDocs] = await Promise.all([
    userService.findRolesByIds(requestedRoles, 'level code permissions', {
      activeOnly: true,
      populate: { path: 'permissions', select: 'code' },
    }),
    userService.findActiveRolePermissionDocs(user.roles),
  ]);
  const violation = findGrantViolationAfterWrite({
    operatorPermCodes,
    operatorMaxLevel,
    grantRoleDocs: freshRoleDocs,
    currentRoleDocs,
    expectedCount: requestedRoles.length,
  });
  if (!violation) return false;

  const rolledBack = await userService.updateRoles(user._id, user.roles || [], requestedRoles);
  if (!rolledBack) {
    logger.warn('角色分配写后复验失败，CAS 回滚 miss，改为无条件写回快照', {
      target: user.username,
      code: violation.code,
    });
    await userService.updateRoles(user._id, user.roles || []);
  }
  logger.warn(
    `角色分配写后复验失败：target=${user.username} code=${violation.code}` +
      (violation.lacking ? ` 缺少权限=${violation.lacking.join(',')}` : '')
  );
  ApiResponse.codeError(
    res,
    violation.code,
    violation.lacking
      ? {
          message: `无权授予以下权限：${violation.lacking.join('、')}`,
          params: { permissions: violation.lacking.join('、') },
        }
      : undefined
  );
  return true;
};

/**
 * 分配角色给用户
 * PUT /api/users/:id/roles
 */
const assignRoles = asyncHandler(async (req, res) => {
  if (rejectInvalidRoleRequest(req, res)) return;

  const { roles } = req.body;
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

  // 目标用户层级必须一并校验：否则低层级管理员可剥离同级/更高级用户（含内置超管）的角色，
  // 口径对齐 updateUser/deleteUser/toggleUserLock。
  const targetUserRoles = await userService.findRolesByIds(user.roles, 'level code isBuiltIn');
  const targetUserMaxLevel = maxRoleLevel(targetUserRoles);

  // 验证新角色是否存在（同时取出 permissions 供权限子集校验）
  // L-05：只接受生效角色。停用角色挂到用户身上不立即生效，但角色一旦恢复启用，
  // 这次"当时无害"的授予会静默变成真实权限——授予动作必须按生效口径校验。
  const validRoles = await userService.findRolesByIds(requestedRoles, 'level code permissions', {
    populate: { path: 'permissions', select: 'code' },
    activeOnly: true,
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

  const operatorPermCodes = await userService.getPermissions(req.user.userId);
  if (await rejectUnoperableGrants(res, req, operatorPermCodes, validRoles, user)) return;

  // ===== 后端复审 B-2：同级角色归属包含校验（判据与理由见 rejectForeignPeerRoles）=====
  // 建号轨（validateRolesForCreate 第 5 道）调用的是同一个实现，两条轨不会再各走各的尺子。
  if (
    !operatorPermCodes.includes('*:*') &&
    rejectForeignPeerRoles(res, req, validRoles, operatorMaxLevel, `target=${user.username}`)
  ) {
    return;
  }

  const nextRoleDocs = await userService.findRolesByIds(requestedRoles, 'code isBuiltIn', {
    lean: true,
  });
  if (rejectMembershipChange(res, req, targetUserRoles, nextRoleDocs, user, isSelf)) return;

  // 原子更新替代读-改-save：user.save() 会把整个文档回写，并发窗口内的
  // 其他字段修改（如 status）会被本次内存快照覆盖；findByIdAndUpdate+$set 只写 roles。
  // L-06：再带上载入时的 roles 快照——否则并发窗口里被改过的角色集会按本次
  // 内存快照覆盖（lost update），而本次授予/回收是按旧角色集校验的。
  const updated = await userService.updateRoles(user._id, requestedRoles, user.roles || []);
  if (!updated) {
    return ApiResponse.codeError(res, 'USER_STATE_CONFLICT');
  }

  // 写后复验：角色可能已停用/删除（L-03），也可能在这次判定之后被抬高层级或
  // 扩张权限（TOCTOU）。两种情况都回滚到授予前的角色集。
  const revalidated = await revalidateGrantAfterWrite(res, {
    user,
    requestedRoles,
    operatorMaxLevel,
    operatorPermCodes,
  });
  if (revalidated) return;

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
