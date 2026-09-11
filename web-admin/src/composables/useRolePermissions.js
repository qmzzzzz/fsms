/**
 * 角色权限编辑状态机（自 RoleView 拆出）
 *
 * 职责：权限树 → 模块列表转换、勾选/原始集合管理、增删差异显示、
 * 模块级全选/清空、关键字过滤与统计。数据加载（API 调用）留在视图层，
 * 本 composable 只提供纯状态原语：setTree / setChecked / clearChecked。
 */
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'

// 模块图标映射
const MODULE_ICONS = {
  system: '⚙️',
  device: '🔧',
  alarm: '🚨',
  inspection: '📋',
  report: '📊',
  security: '🛡️',
}

// 将后端权限树转换为模块列表
// 关键：权限树存在"权限挂权限"的多级嵌套（子权限的 parent 是另一个权限而非模块），
// 仅读取模块第一层 children 会丢失嵌套权限，导致已启用权限显示不全、也无法单独修改。
// 这里递归展平树中所有层级的真实权限节点（合法 ObjectId），保证完整渲染。
const flattenPermissionNodes = (nodes, acc = [], seen = new Set()) => {
  ;(nodes || []).forEach((node) => {
    if (!node) return
    const id = node._id || ''
    if (/^[0-9a-fA-F]{24}$/.test(id)) {
      if (!seen.has(id)) {
        seen.add(id)
        acc.push(node)
      }
      // 继续下钻该权限自身的子权限
      flattenPermissionNodes(node.children, acc, seen)
    } else {
      // 虚拟分组节点（module-xxx）：跳过自身但下钻其子级
      flattenPermissionNodes(node.children, acc, seen)
    }
  })
  return acc
}

export function useRolePermissions() {
  const { t } = useI18n()

  // 权限树原始数据
  const permissionTree = ref([])
  // 模块列表（由权限树转换而来）
  const moduleList = ref([])
  // 当前选中的权限 ID 集合
  const checkedPermIds = ref(new Set())
  // 原始选中状态（用于重置与"已有/新增/移除"差异显示）
  const originalPermIds = ref(new Set())
  // 权限搜索关键字
  const permSearch = ref('')
  // 是否有未保存变更
  const hasUnsavedChanges = ref(false)

  const MODULE_NAMES = computed(() => ({
    system: t('nav.system'),
    user: t('nav.users'),
    role: t('nav.roles'),
    permission: t('role.permissions'),
    device: t('nav.devices'),
    alarm: t('nav.alarms'),
    inspection: t('nav.inspections'),
    report: t('nav.reports'),
    security: t('security.title'),
  }))

  // 权限类型显示标签
  const typeLabel = (type) =>
    ({ api: 'API', menu: t('common.all'), button: t('common.operation'), page: t('common.all') })[
      type
    ] || t('role.permissions')

  const buildModuleList = (tree) => {
    if (!Array.isArray(tree)) return []
    return tree.map((mod) => {
      const permissions = flattenPermissionNodes(mod.children)
      const activeCount = permissions.filter((p) => checkedPermIds.value.has(p._id)).length
      return {
        module: mod.module,
        // i18n 映射优先于后端 name：后端权限树返回的是中文模块名（getModuleName），
        // 英文界面直接渲染会漏翻译；zh-CN 下映射值与后端语义一致，行为不变
        name: MODULE_NAMES.value[mod.module] || mod.name || mod.module,
        icon: MODULE_ICONS[mod.module] || '📦',
        permissions,
        activeCount,
      }
    })
  }

  // 刷新模块列表的 activeCount
  const refreshModuleCounts = () => {
    moduleList.value.forEach((mod) => {
      mod.activeCount = mod.permissions.filter((p) => checkedPermIds.value.has(p._id)).length
    })
  }

  /** 设置权限树并重建模块列表 */
  const setTree = (tree) => {
    permissionTree.value = Array.isArray(tree) ? tree : []
    moduleList.value = buildModuleList(permissionTree.value)
  }

  /** 设置角色当前权限（同时记录为原始状态） */
  const setChecked = (permIds) => {
    const next = permIds instanceof Set ? permIds : new Set(permIds || [])
    checkedPermIds.value = next
    originalPermIds.value = new Set(next)
    permSearch.value = ''
    hasUnsavedChanges.value = false
    refreshModuleCounts()
  }

  const clearChecked = () => {
    checkedPermIds.value = new Set()
    originalPermIds.value = new Set()
    hasUnsavedChanges.value = false
  }

  // ===== 权限状态判定 =====
  // 已启用（当前选中）
  const isPermChecked = (permId) => checkedPermIds.value.has(permId)
  // 本次新增：当前选中但原始没有
  const isPermAdded = (permId) =>
    checkedPermIds.value.has(permId) && !originalPermIds.value.has(permId)
  // 本次移除：原始有但当前未选中（保存前仍可点击恢复）
  const isPermRemoved = (permId) =>
    !checkedPermIds.value.has(permId) && originalPermIds.value.has(permId)

  // 权限项 tooltip：编码 + 类型 + API 路径 + 差异状态说明
  const permTooltip = (perm) => {
    const parts = [perm.code, typeLabel(perm.type)]
    if (perm.path) parts.push(`${perm.method || 'GET'} ${perm.path}`)
    if (isPermAdded(perm._id)) parts.push(t('role.permAdded'))
    else if (isPermRemoved(perm._id)) parts.push(t('role.permRemoved'))
    return parts.join(' · ')
  }

  // ===== 模块级状态 =====
  const moduleState = (module) => {
    if (!module.permissions.length || module.activeCount === 0) return 'none'
    if (module.activeCount === module.permissions.length) return 'full'
    return 'partial'
  }

  const moduleStateText = (module) =>
    ({
      full: t('role.moduleFull'),
      partial: t('role.modulePartial'),
      none: t('role.moduleNone'),
    })[moduleState(module)]

  const modulePercent = (module) => {
    if (!module.permissions.length) return 0
    return Math.round((module.activeCount / module.permissions.length) * 100)
  }

  // 模块级全选 / 清空
  const toggleModule = (module) => {
    // 前端复审 B-1：搜索态下模块级全选/清空仅作用于「当前可见（过滤后）」的权限，
    // 与用户直觉一致；非搜索态行为不变（作用于模块全部权限）。
    const kw = permSearch.value.trim().toLowerCase()
    const visiblePerms = kw
      ? module.permissions.filter(
          (p) =>
            (p.name || '').toLowerCase().includes(kw) || (p.code || '').toLowerCase().includes(kw)
        )
      : module.permissions
    // 过滤结果为空（理论上不会出现：过滤后模块不可见）时保守不动集合
    if (visiblePerms.length === 0) return
    const visibleIds = new Set(visiblePerms.map((p) => p._id))
    const allOn = visiblePerms.every((p) => checkedPermIds.value.has(p._id))
    checkedPermIds.value.forEach((id) => {
      if (allOn && visibleIds.has(id)) checkedPermIds.value.delete(id)
    })
    if (!allOn) {
      visiblePerms.forEach((p) => checkedPermIds.value.add(p._id))
    }
    checkedPermIds.value = new Set(checkedPermIds.value)
    hasUnsavedChanges.value = true
    refreshModuleCounts()
  }

  // ===== 顶部统计 =====
  const totalPermCount = computed(() =>
    moduleList.value.reduce((sum, m) => sum + m.permissions.length, 0)
  )

  const checkedCount = computed(() => checkedPermIds.value.size)

  const addedCount = computed(() => {
    let n = 0
    checkedPermIds.value.forEach((id) => {
      if (!originalPermIds.value.has(id)) n++
    })
    return n
  })

  const removedCount = computed(() => {
    let n = 0
    originalPermIds.value.forEach((id) => {
      if (!checkedPermIds.value.has(id)) n++
    })
    return n
  })

  // 按关键字过滤模块与权限（匹配名称或编码）
  const filteredModules = computed(() => {
    // 读取 checkedPermIds 建立依赖：搜索态下点选权限时本计算属性实时重算，
    // 卡片的 activeCount/进度条/全选按钮随之刷新，moduleState 不再基于过期快照误判
    void checkedPermIds.value.size
    const kw = permSearch.value.trim().toLowerCase()
    if (!kw) return moduleList.value
    return moduleList.value
      .map((m) => ({
        ...m,
        activeCount: m.permissions.filter((p) => checkedPermIds.value.has(p._id)).length,
        permissions: m.permissions.filter(
          (p) =>
            (p.name || '').toLowerCase().includes(kw) || (p.code || '').toLowerCase().includes(kw)
        ),
      }))
      .filter((m) => m.permissions.length > 0)
  })

  // 切换权限选中状态
  const togglePerm = (permId) => {
    if (checkedPermIds.value.has(permId)) {
      checkedPermIds.value.delete(permId)
    } else {
      checkedPermIds.value.add(permId)
    }
    // 触发响应式更新
    checkedPermIds.value = new Set(checkedPermIds.value)
    hasUnsavedChanges.value = true
    refreshModuleCounts()
  }

  // 重置为原始状态
  const resetChecked = () => {
    checkedPermIds.value = new Set(originalPermIds.value)
    refreshModuleCounts()
    hasUnsavedChanges.value = false
  }

  return {
    // 状态
    permissionTree,
    moduleList,
    checkedPermIds,
    originalPermIds,
    permSearch,
    hasUnsavedChanges,
    // 数据原语
    setTree,
    setChecked,
    clearChecked,
    // 判定与操作
    typeLabel,
    isPermChecked,
    isPermAdded,
    isPermRemoved,
    permTooltip,
    moduleState,
    moduleStateText,
    modulePercent,
    toggleModule,
    togglePerm,
    resetChecked,
    // 统计与过滤
    totalPermCount,
    checkedCount,
    addedCount,
    removedCount,
    filteredModules,
  }
}
