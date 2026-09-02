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

  test('待校验权限为空视为通过（可选权限语义）', () => {
    expect(matchPermission([], '')).toBe(true)
    expect(matchPermission([], null)).toBe(true)
    expect(matchPermission([], undefined)).toBe(true)
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
