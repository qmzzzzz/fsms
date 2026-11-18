/**
 * 权限目录的共享展示工具与权限树展平（B-DRY 单一来源）
 *
 * 背景（2026-11-17 审计 B 组）：useRolePermissions 与 usePrivilegeGrantOptions
 * 各自维护了一份模块图标表、模块名 i18n 映射和权限树展平实现，且已经漂移：
 * 图标表 6 vs 11 个模块、展平去重键 _id vs code。这里收口为一份：
 *
 *  - 图标/名称映射取两侧并集（11 个模块键）；共用模块的图标与 i18n 键完全一致，
 *    消费方各自的语义（名称回退顺序、渲染期求值）由调用侧保留。
 *  - 展平的去重键差异是**有意的业务差异**（非漂移 bug），按参数保留各自口径：
 *      · 角色编辑（useRolePermissions）：勾选集合的身份域是 ObjectId，
 *        按 _id 去重；不过滤无 code 的节点。
 *      · 授权目录（usePrivilegeGrantOptions）：授权载荷的身份域是 code，
 *        按 code 去重；无 code 的权限对授权无意义，不收录。
 */

/** 模块图标映射（两侧并集；未知模块退化为 📦） */
const PERMISSION_MODULE_ICONS = {
  system: '⚙️',
  user: '👤',
  role: '🔑',
  permission: '🛡️',
  device: '🔧',
  alarm: '🚨',
  inspection: '📋',
  report: '📊',
  security: '🛡️',
  privilege: '🎫',
  pii: '🔒',
}

/** 模块名 i18n 键（两侧并集；两侧共用模块的键一致） */
const PERMISSION_MODULE_NAME_KEYS = {
  system: 'nav.system',
  user: 'nav.users',
  role: 'nav.roles',
  permission: 'role.permissions',
  device: 'nav.devices',
  alarm: 'nav.alarms',
  inspection: 'nav.inspections',
  report: 'nav.reports',
  security: 'security.title',
  privilege: 'nav.privilegeGrants',
  pii: 'privilegeGrant.modulePii',
}

/** 模块图标：未知模块退化为 📦 */
export const permissionModuleIcon = (module) => PERMISSION_MODULE_ICONS[module] || '📦'

/**
 * 模块显示名：i18n 映射优先，未命中（或翻译缺失退回键名本身）时用后端 name，
 * 再退 module 码。t 由调用方传入（useI18n 的 t），随语言响应。
 */
export const permissionModuleName = (t, module, backendName) => {
  const key = PERMISSION_MODULE_NAME_KEYS[module]
  const translated = key ? t(key) : ''
  return translated && translated !== key ? translated : backendName || module
}

/**
 * 权限树展平：递归收集所有层级的真实权限节点（合法 ObjectId），
 * 虚拟分组节点（module-xxx 等，_id 非 ObjectId）跳过自身但继续下钻。
 * 关键：权限树存在「权限挂权限」的多级嵌套（子权限的 parent 是另一个权限
 * 而非模块），只读模块第一层 children 会丢失嵌套权限。
 *
 * @param {Array} nodes 权限树（模块的 children 或其子级）
 * @param {object} [options]
 * @param {string} [options.module=''] 顶层所属模块（tagModule 时作为
 *        node.module 缺失时的回退值；调用方通常传当前遍历的模块码）
 * @param {'_id'|'code'} [options.dedupeBy='_id'] 去重键（身份域差异见文件头）
 * @param {boolean} [options.requireCode=false] 是否要求 node.code 才收录
 * @param {boolean} [options.tagModule=false] 给节点补 module 字段
 *        （node.module 优先，缺失时回退 options.module）；true 时返回节点副本
 * @returns {Array} 展平后的权限节点
 */
export function flattenPermissionTree(
  nodes,
  { module = '', dedupeBy = '_id', requireCode = false, tagModule = false } = {}
) {
  const acc = []
  const seen = new Set()
  const walk = (list, ownerModule) => {
    ;(list || []).forEach((node) => {
      if (!node) return
      const key = String(node[dedupeBy] || '')
      const isRealPermission = /^[0-9a-fA-F]{24}$/.test(String(node._id || ''))
      if (isRealPermission && (!requireCode || node.code) && !seen.has(key)) {
        seen.add(key)
        acc.push(tagModule ? { ...node, module: node.module || ownerModule } : node)
      }
      // 真实权限还可能挂自己的子权限；虚拟分组节点也要下钻
      walk(node.children, ownerModule)
    })
  }
  walk(nodes, module)
  return acc
}
