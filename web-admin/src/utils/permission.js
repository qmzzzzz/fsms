/**
 * 权限匹配纯函数 —— 通配逻辑的唯一实现（单源）
 *
 * 规则：精确匹配 > 超级通配 *:* > 模块通配 module:*
 * 消费方：store getter、usePermission composable、路由守卫、布局菜单过滤。
 * 保持纯函数（无 Vue/Pinia 依赖）以便直接单测。
 */

/**
 * 检查权限列表是否覆盖指定权限编码
 * @param {string[]} perms - 当前拥有的权限编码列表
 * @param {string} perm - 待校验的权限编码，如 'device:create'
 * @returns {boolean}
 */
export function matchPermission(perms, perm) {
  if (!perm) return true
  if (!perms || perms.length === 0) return false
  if (perms.includes('*:*')) return true
  if (perms.includes(perm)) return true
  const [mod] = perm.split(':')
  return perms.includes(`${mod}:*`)
}

/**
 * 是否覆盖全部权限
 * @param {string[]} perms
 * @param {string[]} required
 */
export function matchAllPermissions(perms, required) {
  return (required || []).every((p) => matchPermission(perms, p))
}

/**
 * 是否覆盖任一权限
 * @param {string[]} perms
 * @param {string[]} required
 */
export function matchAnyPermission(perms, required) {
  if (!required || required.length === 0) return true
  return required.some((p) => matchPermission(perms, p))
}
