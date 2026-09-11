/**
 * 超级管理员唯一性与不可变更约束
 *
 * 背景：SUPER_ADMIN 是系统内唯一持有 `*:*` 通配权限的角色（initData 的
 * rolePermissionMap）。它同时是「谁都管不了它」的终点——所有层级校验
 * （targetLevel >= operatorLevel）在 level=10 处收敛。因此该角色的归属
 * 一旦出错，系统会进入不可恢复状态：
 *
 * - 归属丢失（0 个持有者）：无人再拥有 `*:*`，凡是要求超管的操作
 *   （全网段 IP 名单、重置他人 MFA、修改内置角色权限）全部永久不可用，
 *   且无法通过接口修回——因为修回本身需要超管权限。
 * - 归属扩散（多个持有者）：审计上无法界定"最终责任人"，等保 2.0
 *   三级要求的特权账户可追溯性失效。
 *
 * 因此本模块把「唯一超管」提升为系统不变量（invariant）：
 * 1. 归属只由启动期对账决定（initData.reconcileSuperAdmin），不经任何 HTTP 接口
 * 2. 所有可能改变归属的接口一律拒绝，含操作者本人（无 isSelf 例外）
 *
 * 为什么不留 isSelf 例外：原 assignRoles 允许超管改自己的角色，这构成
 * 自锁死路径——超管一次误操作即永久失去最高权限，且没有任何接口能恢复。
 * 实际数据也印证了这一点（SUPER_ADMIN 角色存在但 0 持有者）。
 */

const SUPER_ADMIN_ROLE_CODE = 'SUPER_ADMIN';

/**
 * 唯一超管账户名。允许用环境变量覆盖以适配已有部署，
 * 未配置时固定为 initData 创建的默认管理员 admin。
 *
 * 空白值必须回退而非原样返回：若返回空串，启动对账会去查
 * `username: ''`，查不到即静默跳过整个对账流程——归属丢失时不再自愈。
 */
const getSuperAdminUsername = () => {
  const configured = (process.env.SUPER_ADMIN_USERNAME || '').trim();
  return configured || 'admin';
};

/**
 * 判断角色文档是否为内置超管角色
 * 必须同时满足 code 与 isBuiltIn：仅凭 code 判断会被
 * 「新建一个同名 code 的自定义角色」绕过（code 有 unique 约束，
 * 但历史数据或直连数据库仍可能出现异常记录）
 * @param {{code?: string, isBuiltIn?: boolean}} role
 * @returns {boolean}
 */
const isSuperAdminRole = (role) =>
  !!role && role.code === SUPER_ADMIN_ROLE_CODE && role.isBuiltIn === true;

/**
 * 校验一次角色集合变更是否改变了超管归属
 *
 * 「改变」包含两个方向，二者都必须拒绝：
 * - 剥离：当前持有超管，变更后不含 → 会导致归属丢失
 * - 授予：当前不持有，变更后含 → 会导致归属扩散
 *
 * 返回结构化错误，携带错误码（供前端 i18n 翻译）与中文 message
 * （作为后端原文案兜底）。null 表示合规放行。
 *
 * @param {Array<{code?: string, isBuiltIn?: boolean}>} currentRoles 变更前的角色文档
 * @param {Array<{code?: string, isBuiltIn?: boolean}>} nextRoles 变更后的角色文档
 * @returns {{code: string, message: string}|null}
 */
const checkSuperAdminMembership = (currentRoles = [], nextRoles = []) => {
  const had = currentRoles.some(isSuperAdminRole);
  const will = nextRoles.some(isSuperAdminRole);

  if (had && !will) {
    return {
      code: 'SUPER_ADMIN_ROLE_NOT_DETACHABLE',
      message:
        '超级管理员角色不可被剥离：该角色是系统唯一的最高权限来源，' + '剥离后无任何接口可将其恢复',
    };
  }
  if (!had && will) {
    return {
      code: 'SUPER_ADMIN_ROLE_NOT_GRANTABLE',
      message:
        '超级管理员角色不可被授予：系统只允许存在一位超级管理员，' + '其归属由启动期对账固定',
    };
  }
  return null;
};

module.exports = {
  SUPER_ADMIN_ROLE_CODE,
  getSuperAdminUsername,
  isSuperAdminRole,
  checkSuperAdminMembership,
};
