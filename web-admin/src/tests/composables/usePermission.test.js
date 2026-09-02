/**
 * 权限 Composable 测试（usePermission，基于真实 pinia store）
 */
import { describe, test, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { usePermission } from '@/composables/usePermission'
import { useAuthStore } from '@/store'

describe('usePermission', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    sessionStorage.clear()
  })

  test('hasPerm 走单源通配逻辑（精确/模块通配/拒绝）', () => {
    const auth = useAuthStore()
    auth.setPermissions(['device:read', 'user:*'])
    const { hasPerm } = usePermission()

    expect(hasPerm('device:read')).toBe(true) // 精确
    expect(hasPerm('user:delete')).toBe(true) // 模块通配
    expect(hasPerm('device:create')).toBe(false)
    expect(hasPerm('')).toBe(true) // 可选权限语义
  })

  test('hasAllPerms / hasAnyPerm 组合判断', () => {
    const auth = useAuthStore()
    auth.setPermissions(['device:read', 'device:create'])
    const { hasAllPerms, hasAnyPerm } = usePermission()

    expect(hasAllPerms(['device:read', 'device:create'])).toBe(true)
    expect(hasAllPerms(['device:read', 'user:read'])).toBe(false)
    expect(hasAnyPerm(['user:read', 'device:create'])).toBe(true)
    expect(hasAnyPerm(['user:read'])).toBe(false)
  })

  test('permissions 计算属性随 store 响应式更新', async () => {
    const auth = useAuthStore()
    auth.setPermissions([])
    const { permissions, hasPerm } = usePermission()
    expect(hasPerm('device:read')).toBe(false)

    auth.setPermissions(['device:read'])
    await Promise.resolve()
    expect(permissions.value).toEqual(['device:read'])
    expect(hasPerm('device:read')).toBe(true)
  })
})
