/**
 * 角色写路径的授权守卫（roleController 专用）
 *
 * 为什么不放进 roleService：这些判据的产物是「HTTP 响应已经发出」这件事
 * （ApiResponse.codeError(res, ...)），服务层只负责数据访问。放服务层会让
 * 数据访问代码持有 res，userController/rolePermissionController 的口径就此分裂。
 *
 * 为什么单独成文件而不是留在 roleController：控制器的体积门禁（max-lines 300）
 * 是硬约束，而这里 8 个判据是角色写路径共享的，抽出来同时让 deleteRole 与
 * updateRole 用同一份跨层级守卫（原本两处各写一遍，错误码已经出现过分叉）。
 *
 * 约定：所有 guard 自己发响应并返回 true/false（"是否已拒"）。
 * 刻意不返回 ApiResponse 的结果让调用方判真值——调用方写成 if (guard(...)) return;
 * 后，控制流不再依赖 codeError 的返回值形状；测试里的 res 桩只实现 status/json 而不返回
 * 链式对象，若按返回值判真，"名称为空"这类守卫会静默放行到 save()（实测踩过）。
 */

const ApiResponse = require('../utils/apiResponse');
const permissionHelper = require('../utils/permissionHelper');
const logger = require('../utils/logger');
const roleService = require('../services/roleService');
const { getDataScope } = require('../middleware/rbac');

// 取值清单与 Permission/Role schema、roleRoutes/permissionRoutes 的 isIn 同源
const { RESOURCE_STATUSES: ROLE_STATUSES } = require('../constants/permission');

/**
 * 操作者授权解析器（按请求记忆化）
 *
 * getOperatorMaxLevel 是一次 User→roles 的 populate 查询。同一次角色写请求里，
 * applyRoleScopeToQuery（拼 level<=max 的范围条件）、跨层级守卫、以及
 * 「改 level 时不得高于自己」的守卫原本各算一次——部门范围操作者要打 3 次同形查询。
 * 这里按请求记忆化：一次解析、多处复用。
 *
 * 刻意不跨请求缓存：授权层级必须即时生效（角色被停用/降权的下一毫秒就不该再享受旧层级）。
 * userPermissionService 的 TTL 缓存是另一回事，它保存权限解析结果，
 * 且在这些写路径成功后由 invalidatePermissionCache() 主动作废。
 */
const createAuthorityResolver = (userId) => {
  let pending = null;
  return {
    maxLevel: () => {
      if (!pending) pending = permissionHelper.getOperatorMaxLevel(userId);
      return pending;
    },
  };
};

/** 把数据范围翻译成角色查询条件；authority 传入可复用本请求已解析的层级 */
const applyRoleScopeToQuery = async (
  query,
  userId,
  authority = createAuthorityResolver(userId)
) => {
  const dataScope = await getDataScope(userId);
  if (dataScope.type === 'all') return { query, dataScope };
  if (dataScope.type === 'none') {
    return { query: { ...query, _id: { $in: [] } }, dataScope };
  }

  const operatorMaxLevel = await authority.maxLevel();
  return {
    query: { ...query, level: { $lte: operatorMaxLevel } },
    dataScope,
  };
};

/** 跨层级操作守卫：非 ALL 范围的操作者不得处置比自己层级高的角色 */
const guardRoleWithinOperatorLevel = async ({
  res,
  role,
  dataScope,
  authority,
  forbiddenCode,
  higherLevelCode,
}) => {
  if (dataScope.type === 'none') {
    ApiResponse.codeError(res, forbiddenCode);
    return true;
  }
  if (dataScope.type === 'all') return false;
  if ((role.level || 0) > (await authority.maxLevel())) {
    ApiResponse.codeError(res, higherLevelCode);
    return true;
  }
  return false;
};

/** 内置角色的名称与层级不可改：内置角色按 code 寻址（播种/迁移/授权链），改名等于换了一个它 */
const guardBuiltInNameOrLevel = ({ res, role, name, level }) => {
  if (role.isBuiltIn && (name !== undefined || level !== undefined)) {
    ApiResponse.codeError(res, 'BUILTIN_ROLE_NAME_LEVEL_LOCKED');
    return true;
  }
  return false;
};

/** status 既要是合法值，也不能落在内置角色上（停用内置角色会让按 code 的授权链整体断裂） */
const guardRoleStatusValue = ({ res, role, status }) => {
  if (status === undefined) return false;
  if (!ROLE_STATUSES.includes(status)) {
    ApiResponse.codeError(res, 'ROLE_STATUS_INVALID');
    return true;
  }
  if (role.isBuiltIn) {
    ApiResponse.codeError(res, 'BUILTIN_ROLE_STATUS_LOCKED');
    return true;
  }
  return false;
};

/**
 * 「把角色改成某个层级」的提权守卫，两条臂分别对应：
 * - 目标层级高于自己 → 造出比自己高的角色（随即可授给自己，越权）
 * - 被改角色原本就高于自己 → 借"降级"改写字段，把高层级角色重挂到低层级。
 *   第二条臂保留告警：这是有人在试探层级边界的信号，不能只留一个 403。
 */
const guardRoleLevelTarget = async ({ req, res, role, level, authority }) => {
  if (level === undefined) return false;
  const operatorMaxLevel = await authority.maxLevel();
  const operatorPermCodes = await roleService.getOperatorPermissions(req.user.userId);
  const isGlobalAdmin = operatorPermCodes.includes('*:*');

  if (!isGlobalAdmin && level > operatorMaxLevel) {
    ApiResponse.codeError(res, 'ROLE_LEVEL_ABOVE_SELF_FORBIDDEN');
    return true;
  }
  if (!isGlobalAdmin && (role.level || 0) > operatorMaxLevel) {
    logger.warn(
      `角色降级提权尝试被拒：operator=${req.user.username || req.user.userId}` +
        `(L${operatorMaxLevel}) role=${role.code}(L${role.level}) → L${level}`
    );
    ApiResponse.codeError(res, 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN');
    return true;
  }
  return false;
};

/** PATCH 语义应用可编辑字段：undefined 表示"不改"，与 null/空串区分；名称为空必须在赋值前拒掉 */
const applyRoleEditableFields = ({ res, role, name, description, level, status }) => {
  if (name !== undefined && !String(name).trim()) {
    ApiResponse.codeError(res, 'ROLE_NAME_REQUIRED');
    return true;
  }
  if (name !== undefined) role.name = String(name).trim();
  if (description !== undefined) role.description = description;
  if (level !== undefined) role.level = level;
  if (status !== undefined) role.status = status;
  return false;
};

module.exports = {
  ROLE_STATUSES,
  createAuthorityResolver,
  applyRoleScopeToQuery,
  guardRoleWithinOperatorLevel,
  guardBuiltInNameOrLevel,
  guardRoleStatusValue,
  guardRoleLevelTarget,
  applyRoleEditableFields,
};
