import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, isCanceledError } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { isReservedCode } from '@/utils/privilegeGrant'
// 模块图标/名称映射与权限树展平收口到共享目录（2026-11-17 审计 B-DRY）：
// 与 useRolePermissions 的双实现已漂移，单一来源见 utils/permissionCatalog
import {
  permissionModuleIcon,
  permissionModuleName,
  flattenPermissionTree,
} from '@/utils/permissionCatalog'

/**
 * PrivilegeGrantView 的候选项加载域（P1-3 拆分）：表单所需的用户候选
 * （服务端搜索）与权限目录（权限树扁平化）收口在这里。
 * moduleName 是目录分组的展示辅助；图标/名称映射与展平实现见共享模块。
 */
export function usePrivilegeGrantOptions({ hasPerm }) {
  const { t } = useI18n()
  const userSearchGuard = useLatestRequest()

  const usersState = ref('idle')
  const userOptions = ref([])
  // 用户候选项走服务端搜索：生产环境用户数远超单页上限，一次性拉全量既慢又搜不到人
  const USER_SEARCH_LIMIT = 50
  const userSearching = ref(false)
  const userSearchFailed = ref(false)
  // 已选用户的对象副本：远程搜索会整表替换候选项，没有它「已选：xxx」会退回裸 _id
  const userCache = ref(new Map())
  const permissionState = ref('idle')
  const permissionGroups = ref([])
  const permissionMap = ref(new Map())

  // 模块名解析走共享映射；保留原签名（PrivilegeGrantView 解构使用）
  const moduleName = (group) => permissionModuleName(t, group.module, group.name)

  /** 记住加载过的用户对象：远程搜索换页后，已选中的用户仍要显示姓名而不是裸 _id */
  const rememberUsers = (list) => {
    list.forEach((user) => userCache.value.set(String(user._id), user))
    return list
  }

  /**
   * 候选用户加载：keyword 为空时拉首页（进表单即可直接点选常用用户），
   * 有关键词时走服务端 search（用户名前缀 / 姓名子串 / 邮箱片段）；
   * 用户数超过单页上限时，没有服务端搜索就根本找不到目标用户。
   * 刻意不传 AbortSignal：并发由门票丢弃；若把取消当正常返回，
   * 控件会永久停在 loading（取消分支既不落数据也不复位状态）。
   */
  const loadUserOptions = async (keyword) => {
    if (!hasPerm('user:read') || typeof api.users?.getList !== 'function') {
      usersState.value = 'unavailable'
      return
    }
    const term = String(keyword || '').trim()
    const isCurrent = userSearchGuard()
    const firstLoad = usersState.value !== 'ready'
    if (firstLoad) usersState.value = 'loading'
    else userSearching.value = true
    try {
      const res = await api.users.getList(
        {
          status: 'active',
          page: 1,
          limit: USER_SEARCH_LIMIT,
          ...(term ? { search: term } : {}),
        },
        { silentErrors: true }
      )
      if (!isCurrent()) return
      const payload = res?.data?.data
      userOptions.value = rememberUsers(
        Array.isArray(payload)
          ? payload
              .filter((user) => user && user._id)
              .sort((a, b) => String(a.username || '').localeCompare(String(b.username || '')))
          : []
      )
      userSearchFailed.value = false
      if (firstLoad) usersState.value = userOptions.value.length > 0 ? 'ready' : 'empty'
    } catch (e) {
      if (isCanceledError(e) || !isCurrent()) return
      if (firstLoad) {
        // 首次加载失败（缺 user:read 或接口不可用）：退回手填用户 ID
        usersState.value = 'unavailable'
        return
      }
      // 搜索失败清空候选：宁可让用户重试，也不能留着上一个关键词的结果让人误选
      userOptions.value = []
      userSearchFailed.value = true
    } finally {
      if (isCurrent()) userSearching.value = false
    }
  }

  const loadPermissionCatalog = async () => {
    if (permissionState.value === 'loading' || permissionState.value === 'ready') return
    if (
      !(hasPerm('permission:read') || hasPerm('permission:tree')) ||
      typeof api.roles?.getPermissionTree !== 'function'
    ) {
      permissionState.value = 'unavailable'
      return
    }
    permissionState.value = 'loading'
    try {
      const res = await api.roles.getPermissionTree({ silentErrors: true })
      const tree = res?.data?.data
      const rawGroups = (Array.isArray(tree) ? tree : []).filter(Boolean).map((mod) => ({
        module: mod.module,
        name: moduleName(mod),
        icon: permissionModuleIcon(mod.module),
        // 授权目录的身份域是 code：按 code 去重、无 code 不收录、补所属模块
        // （与原私有实现同语义，实现收口到 utils/permissionCatalog）
        permissions: flattenPermissionTree(mod.children, {
          module: mod.module,
          dedupeBy: 'code',
          requireCode: true,
          tagModule: true,
        }),
      }))
      const map = new Map()
      rawGroups.forEach((group) => group.permissions.forEach((perm) => map.set(perm.code, perm)))
      permissionMap.value = map
      // 保留通配权限（*:*）在目录里存在、但任何授予入口都会拒绝：不渲染成选项，
      // 避免「点得中、提交才 400」。名称映射仍保留，老记录的详情才能显示名字
      const groups = rawGroups
        .map((group) => ({
          ...group,
          permissions: group.permissions.filter((perm) => !isReservedCode(perm.code)),
        }))
        .filter((group) => group.permissions.length > 0)
      permissionGroups.value = groups
      permissionState.value = groups.length > 0 ? 'ready' : 'empty'
    } catch (e) {
      if (isCanceledError(e)) return
      permissionState.value = 'unavailable'
    }
  }

  const ensureOptions = () => {
    loadUserOptions()
    loadPermissionCatalog()
  }

  return {
    usersState,
    userOptions,
    userSearching,
    userSearchFailed,
    userCache,
    permissionState,
    permissionGroups,
    permissionMap,
    loadUserOptions,
    loadPermissionCatalog,
    ensureOptions,
    moduleName,
  }
}
