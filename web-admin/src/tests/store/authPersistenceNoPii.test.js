/**
 * 身份持久化不得把 PII 写进 localStorage（P2，2026-10-24）
 *
 * 缺陷本体：`store/auth.js` 把整个 `currentUser` 原样 `safeLocal.setJSON`，
 * 而后端登录响应与 `/auth/me` 都含 `email` / `realName`（另有 department 等）。
 * 原注释写着「currentUser/permissions 为非敏感界面状态」——与事实不符。
 *
 * 影响：httpOnly cookie 的全部收益就是「JS 读不到凭证」；把邮箱与真实姓名
 * 明文摆进同一作用域，等于把收益退掉一半。共用设备上一次 XSS 或一个恶意扩展
 * 就能批量拿走全员邮箱（管理员账号尤其值钱：它是钓鱼的精准名单）。
 *
 * 修复口径：持久化走 `toPersistedUser` 白名单投影（id 别名 + 账号名 + 角色），
 * PII 只留在内存。本文件同时钉住「投影后刷新仍能认出身份」——否则一个
 * 安全修复把登录态搞坏，就是拿可用性换来的假安全。
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore, toPersistedUser, normalizeUser } from '@/store'

/** 后端登录响应形状（含 PII） */
const LOGIN_USER = {
  userId: 'u-1',
  username: 'alice',
  email: 'alice@example.com',
  realName: '张三',
  phone: '13800000000',
  department: '东区',
  roles: ['ADMIN'],
}

/** 后端 /auth/me 形状（只有 id，无 userId） */
const ME_USER = {
  id: 'u-1',
  username: 'alice',
  email: 'alice@example.com',
  realName: '张三',
  department: '东区',
  roles: ['ADMIN'],
}

const PII_KEYS = ['email', 'realName', 'phone', 'department']

const readPersisted = () => JSON.parse(window.localStorage.getItem('currentUser') || 'null')

describe('身份持久化只写非 PII 白名单', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    window.localStorage.clear()
    window.sessionStorage.clear()
    vi.stubGlobal('location', { replace: vi.fn(), href: 'http://localhost/' })
  })

  test('toPersistedUser 是纯过滤器：只保留白名单里**确实存在**的键', () => {
    const projected = toPersistedUser({ ...LOGIN_USER, token: 'x', secret: 'y' })
    // 它是过滤器不是归一化器：LOGIN_USER 只有 userId，不负责补 id/_id
    // （补别名是 normalizeUser 的职责，store 里先归一化再投影）
    expect(Object.keys(projected).sort()).toEqual(['roles', 'userId', 'username'])
    // 反向：任何 PII 键都不在白名单里
    for (const key of PII_KEYS) expect(projected).not.toHaveProperty(key)
    // 归一化产物里的三个别名都会被保留（P3-38 的「是否本人」判断依赖它们）
    expect(Object.keys(toPersistedUser(normalizeUser(LOGIN_USER))).sort()).toEqual([
      '_id',
      'id',
      'roles',
      'userId',
      'username',
    ])
  })

  test('setAuth（登录路径）落盘的 currentUser 不含 email/realName/phone/department', () => {
    const store = useAuthStore()
    expect(store.setAuth(LOGIN_USER, ['device:read'])).toBe(true)

    const persisted = readPersisted()
    for (const key of PII_KEYS) {
      expect(persisted, `localStorage 不应出现 ${key}`).not.toHaveProperty(key)
    }
    // 非 PII 骨架必须留下：刷新后要能认出「是谁」
    expect(persisted).toMatchObject({ userId: 'u-1', username: 'alice' })
    expect(persisted.roles).toEqual(['ADMIN'])
  })

  test('内存中的 currentUser 仍保留完整字段（安全修复不得让界面失去数据）', () => {
    const store = useAuthStore()
    store.setAuth(LOGIN_USER, [])

    expect(store.currentUser.email).toBe('alice@example.com')
    expect(store.currentUser.realName).toBe('张三')
    expect(store.userEmail).toBe('alice@example.com')
  })

  test('setCurrentUser（/auth/me 覆盖路径）同样不落 PII，且 id 三个别名齐备', () => {
    const store = useAuthStore()
    store.setAuth(LOGIN_USER, [])
    expect(store.setCurrentUser(ME_USER)).toBe(true)

    const persisted = readPersisted()
    for (const key of PII_KEYS) expect(persisted).not.toHaveProperty(key)
    // 归一化产物仍要写全：三个别名恒等，否则「是否本人」判断会失效（P3-38）
    expect(persisted.userId).toBe('u-1')
    expect(persisted.id).toBe('u-1')
    expect(persisted._id).toBe('u-1')
  })

  test('刷新后从 localStorage 重建 store：身份骨架可用（不因去 PII 而丢登录态）', () => {
    const first = useAuthStore()
    first.setAuth(LOGIN_USER, ['device:read'])

    // 模拟刷新：新 pinia 实例会重新执行 state()，从 localStorage 读取
    setActivePinia(createPinia())
    const second = useAuthStore()

    expect(second.isAuthenticated).toBe(true)
    expect(second.currentUserId).toBe('u-1')
    expect(second.username).toBe('alice')
    expect(second.userRoles).toEqual(['ADMIN'])
    // 权限是独立键，不受身份投影影响
    expect(second.hasPermission('device:read')).toBe(true)
    // PII 在刷新后为空，由路由守卫的 /auth/me 补齐（router 里 sessionVerified 不持久化）
    expect(second.currentUser.email).toBeUndefined()
  })

  test('历史遗留的脏数据（旧版本写过 PII）在下次写入时被投影覆盖', () => {
    window.localStorage.setItem(
      'currentUser',
      JSON.stringify({ ...LOGIN_USER, userId: 'u-1', id: 'u-1', _id: 'u-1' })
    )
    const store = useAuthStore()
    // 读进来的内存对象带着历史 PII，这是允许的（内存不落盘）
    expect(store.currentUser.email).toBe('alice@example.com')

    store.setCurrentUser(ME_USER)
    for (const key of PII_KEYS) expect(readPersisted()).not.toHaveProperty(key)
  })
})
