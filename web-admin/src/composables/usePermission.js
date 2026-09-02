/**
 * 权限校验 Composable
 * 按钮级权限控制，通配匹配逻辑单源复用 utils/permission.js
 */
import { computed } from 'vue'
import { useAuthStore } from '@/store'
import { matchPermission, matchAllPermissions, matchAnyPermission } from '@/utils/permission'

export function usePermission() {
  const authStore = useAuthStore()

  const permissions = computed(() => authStore.permissions || [])

  /**
   * 检查是否拥有指定权限
   * @param {string} perm - 权限编码，如 'device:create'
   * @returns {boolean}
   */
  const hasPerm = (perm) => matchPermission(permissions.value, perm)

  /**
   * 检查是否拥有所有指定权限
   * @param {string[]} perms
   * @returns {boolean}
   */
  const hasAllPerms = (perms) => matchAllPermissions(permissions.value, perms)

  /**
   * 检查是否拥有任一指定权限
   * @param {string[]} perms
   * @returns {boolean}
   */
  const hasAnyPerm = (perms) => matchAnyPermission(permissions.value, perms)

  return {
    permissions,
    hasPerm,
    hasAllPerms,
    hasAnyPerm,
  }
}

export default usePermission
