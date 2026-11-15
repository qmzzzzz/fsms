/**
 * 权限匹配纯函数测试（单源 utils/permission.js）
 * 覆盖：精确匹配、超级通配、模块通配、空值与空列表边界
 */
import { describe, test, expect } from 'vitest'
import { matchPermission, matchAllPermissions, matchAnyPermission } from '@/utils/permission'

describe('matchPermission', () => {
  test('精确匹配', () => {
    expect(matchPermission(['device:read', 'user:read'], 'device:read')).toBe(true)
    expect(matchPermission(['device:read'], 'device:create')).toBe(false)
  })

  test('超级通配 *:* 命中一切', () => {
    expect(matchPermission(['*:*'], 'device:create')).toBe(true)
    expect(matchPermission(['*:*', 'user:read'], 'anything:here')).toBe(true)
  })

  test('模块通配 mod:* 命中同模块全部动作', () => {
    expect(matchPermission(['user:*'], 'user:create')).toBe(true)
    expect(matchPermission(['user:*'], 'user:delete')).toBe(true)
    expect(matchPermission(['user:*'], 'device:read')).toBe(false)
  })

  test('空权限列表一律拒绝', () => {
    expect(matchPermission([], 'user:read')).toBe(false)
    expect(matchPermission([], 'user:*')).toBe(false)
  })

  test('待校验权限为空 fail-closed（P3：空码只可能是调用缺陷，不得静默放行）', () => {
    // 语义变更记录：旧行为「空权限码=可选权限，判真」已废弃——「无需权限」
    // 由调用方在调用前短路表达（布局菜单/路由守卫均已如此），函数内判真
    // 会让传错参数的缺陷变成无差别放行
    expect(matchPermission([], '')).toBe(false)
    expect(matchPermission([], null)).toBe(false)
    expect(matchPermission([], undefined)).toBe(false)
    // 即使持有全量通配，空码也拒绝（码本身不可信）
    expect(matchPermission(['*:*'], '')).toBe(false)
  })

  test('null/undefined 权限列表安全拒绝', () => {
    expect(matchPermission(null, 'user:read')).toBe(false)
    expect(matchPermission(undefined, 'user:read')).toBe(false)
  })
})

describe('matchAllPermissions / matchAnyPermission', () => {
  test('all：全部命中才通过', () => {
    const perms = ['device:read', 'device:create']
    expect(matchAllPermissions(perms, ['device:read', 'device:create'])).toBe(true)
    expect(matchAllPermissions(perms, ['device:read', 'device:delete'])).toBe(false)
    expect(matchAllPermissions(perms, [])).toBe(true)
  })

  test('any：任一命中即通过，空需求视为通过', () => {
    const perms = ['device:read']
    expect(matchAnyPermission(perms, ['device:read', 'device:create'])).toBe(true)
    expect(matchAnyPermission(perms, ['user:read'])).toBe(false)
    expect(matchAnyPermission(perms, [])).toBe(true)
  })
})
