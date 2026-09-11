/**
 * 认证 Store 测试（I-01 cookie 方案）
 * 核心断言：令牌不进任何 JS 可读存储；currentUser 驱动 isAuthenticated；
 * 会话身份状态存 localStorage（与 cookie 的浏览器级作用域对齐，支撑多标签页共享）；
 * 旧版 sessionStorage 状态可就地迁移；无本地状态时可用 cookie 探测恢复会话
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '@/store'

// restoreSession 动态 import('@/utils/api')，此处 mock 掉网络层。
// 注意 restoreSession 是「两步探测」：先 /auth/session 确认有会话，再 /auth/me 拉详情。
// 只 mock getMe 会让 getSessionStatus 成为 undefined，抛错后被 catch 吞掉、
// 一律返回 false —— 断言全部失真却看不出原因，故两个入口都必须 mock。
const getMeMock = vi.fn()
const getSessionStatusMock = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getMe: (...args) => getMeMock(...args),
      getSessionStatus: (...args) => getSessionStatusMock(...args),
    },
  },
}))

/** 会话探测返回「已登录」（restoreSession 的第一步前置条件） */
const mockSessionAuthenticated = () => {
  getSessionStatusMock.mockResolvedValue({ data: { success: true, data: { authenticated: true } } })
}

describe('useAuthStore（I-01 httpOnly cookie 方案）', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    sessionStorage.clear()
    localStorage.clear()
    getMeMock.mockReset()
    getSessionStatusMock.mockReset()
    // handleRemoteAuthEvent 会整页跳转，测试中 stub 掉 location
    vi.stubGlobal('location', { replace: vi.fn(), href: 'http://localhost/' })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  test('初始未认证（无 currentUser）', () => {
    const store = useAuthStore()
    expect(store.isAuthenticated).toBe(false)
  })

  test('setAuth 写入用户与权限，但不持久化令牌', () => {
    const store = useAuthStore()
    store.setAuth(
      'jwt-should-not-be-stored',
      'refresh-should-not-be-stored',
      { username: 'alice', roles: [] },
      ['device:read']
    )

    expect(store.isAuthenticated).toBe(true)
    expect(store.currentUser.username).toBe('alice')
    expect(store.permissions).toEqual(['device:read'])

    // 令牌绝不落 JS 可读存储
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(sessionStorage.getItem('refreshToken')).toBeNull()
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('refreshToken')).toBeNull()
    // 会话身份状态落 localStorage（浏览器级共享，新标签页可直接复用）
    expect(JSON.parse(localStorage.getItem('currentUser')).username).toBe('alice')
    expect(JSON.parse(localStorage.getItem('permissions'))).toEqual(['device:read'])
    // 不再写 sessionStorage（标签页级隔离会导致新标签页判为未登录）
    expect(sessionStorage.getItem('currentUser')).toBeNull()
  })

  test('setAuth 清理迁移前残留的旧令牌与旧介质会话状态', () => {
    sessionStorage.setItem('token', 'legacy-token')
    sessionStorage.setItem('refreshToken', 'legacy-refresh')
    sessionStorage.setItem('currentUser', JSON.stringify({ username: 'stale' }))
    const store = useAuthStore()
    store.setAuth('t', 'r', { username: 'bob' }, [])
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(sessionStorage.getItem('refreshToken')).toBeNull()
    expect(sessionStorage.getItem('currentUser')).toBeNull()
  })

  test('clearAuth 清空用户/权限与两种介质的残留', () => {
    sessionStorage.setItem('token', 'legacy-token')
    const store = useAuthStore()
    store.setAuth('t', 'r', { username: 'carol' }, ['user:read'])
    store.clearAuth()

    expect(store.isAuthenticated).toBe(false)
    expect(store.currentUser).toBeNull()
    expect(store.permissions).toEqual([])
    expect(localStorage.getItem('currentUser')).toBeNull()
    expect(localStorage.getItem('permissions')).toBeNull()
    expect(sessionStorage.getItem('currentUser')).toBeNull()
    expect(sessionStorage.getItem('token')).toBeNull()
  })

  test('刷新页面恢复：localStorage 中的 currentUser 重建已登录态', () => {
    localStorage.setItem('currentUser', JSON.stringify({ username: 'dave' }))
    localStorage.setItem('permissions', JSON.stringify(['device:read']))
    const store = useAuthStore()
    expect(store.isAuthenticated).toBe(true)
    expect(store.hasPermission('device:read')).toBe(true)
  })

  test('旧版 sessionStorage 会话状态被就地迁移到 localStorage', () => {
    // 改介质前已登录的标签页：状态在 sessionStorage，不迁移会被判为未登录
    sessionStorage.setItem('currentUser', JSON.stringify({ username: 'legacy_user' }))
    sessionStorage.setItem('permissions', JSON.stringify(['user:read']))

    const store = useAuthStore()
    expect(store.isAuthenticated).toBe(true)
    expect(store.currentUser.username).toBe('legacy_user')
    // 迁移后新介质有值、旧介质已清空（避免两处状态分叉）
    expect(JSON.parse(localStorage.getItem('currentUser')).username).toBe('legacy_user')
    expect(sessionStorage.getItem('currentUser')).toBeNull()
    expect(sessionStorage.getItem('permissions')).toBeNull()
  })

  test('hasPermission 走单源通配逻辑', () => {
    const store = useAuthStore()
    store.setPermissions(['user:*'])
    expect(store.hasPermission('user:delete')).toBe(true)
    expect(store.hasPermission('device:read')).toBe(false)
  })

  // ========== 会话恢复（同一浏览器共享 cookie 会话） ==========

  describe('restoreSession — 用 cookie 探测重建本地身份', () => {
    test('cookie 有效时重建会话，并把 id 归一为 userId', async () => {
      mockSessionAuthenticated()
      getMeMock.mockResolvedValue({
        data: {
          success: true,
          data: { user: { id: 'u-1', username: 'admin' }, permissions: ['user:read'] },
        },
      })

      const store = useAuthStore()
      await expect(store.restoreSession()).resolves.toBe(true)

      expect(store.isAuthenticated).toBe(true)
      // 跨标签页身份比对依赖 userId，/auth/me 只给 id，必须归一
      expect(store.currentUser.userId).toBe('u-1')
      expect(store.permissions).toEqual(['user:read'])
      expect(JSON.parse(localStorage.getItem('currentUser')).userId).toBe('u-1')
      // 探测须声明 silent401，否则未登录用户会看到「登录已过期」提示
      expect(getMeMock).toHaveBeenCalledWith({ silent401: true })
    })

    test('会话探测返回未登录时直接放弃，不再打 /auth/me', async () => {
      // 两步探测的第一步就是为了避免未登录用户经历
      // 401 → refresh 400 的连锁请求，因此这条路径必须短路
      getSessionStatusMock.mockResolvedValue({
        data: { success: true, data: { authenticated: false } },
      })
      const store = useAuthStore()
      await expect(store.restoreSession()).resolves.toBe(false)
      expect(getMeMock).not.toHaveBeenCalled()
    })

    test('已有本地身份时直接返回 true，不发请求', async () => {
      const store = useAuthStore()
      store.setAuth('t', 'r', { userId: 'u-1', username: 'admin' }, [])
      await expect(store.restoreSession()).resolves.toBe(true)
      expect(getMeMock).not.toHaveBeenCalled()
      expect(getSessionStatusMock).not.toHaveBeenCalled()
    })

    test('并发调用只探测一次（守卫与在途请求同时触发）', async () => {
      mockSessionAuthenticated()
      getMeMock.mockResolvedValue({
        data: { success: true, data: { user: { id: 'u-1', username: 'admin' }, permissions: [] } },
      })
      const store = useAuthStore()
      const results = await Promise.all([
        store.restoreSession(),
        store.restoreSession(),
        store.restoreSession(),
      ])
      expect(results).toEqual([true, true, true])
      expect(getMeMock).toHaveBeenCalledTimes(1)
      expect(getSessionStatusMock).toHaveBeenCalledTimes(1)
    })

    test('401（未登录）返回 false 且不再重复探测（负缓存）', async () => {
      mockSessionAuthenticated()
      getMeMock.mockRejectedValue({ response: { status: 401 } })
      const store = useAuthStore()

      await expect(store.restoreSession()).resolves.toBe(false)
      await expect(store.restoreSession()).resolves.toBe(false)

      expect(store.isAuthenticated).toBe(false)
      expect(getMeMock).toHaveBeenCalledTimes(1)
    })

    test('主动登出后不再自动恢复（防止把刚清掉的会话救回来）', async () => {
      mockSessionAuthenticated()
      getMeMock.mockResolvedValue({
        data: { success: true, data: { user: { id: 'u-1', username: 'admin' }, permissions: [] } },
      })
      const store = useAuthStore()
      store.setAuth('t', 'r', { userId: 'u-1', username: 'admin' }, [])
      store.clearAuth()

      await expect(store.restoreSession()).resolves.toBe(false)
      expect(getMeMock).not.toHaveBeenCalled()
    })

    test('重新登录后重置负缓存，允许后续再次恢复', async () => {
      mockSessionAuthenticated()
      getMeMock.mockRejectedValueOnce({ response: { status: 401 } })
      const store = useAuthStore()
      await store.restoreSession()

      store.setAuth('t', 'r', { userId: 'u-2', username: 'bob' }, [])
      store.currentUser = null

      getMeMock.mockResolvedValueOnce({
        data: { success: true, data: { user: { id: 'u-2', username: 'bob' }, permissions: [] } },
      })
      await expect(store.restoreSession()).resolves.toBe(true)
    })
  })

  // ========== 跨标签页会话同步（cookie 覆盖防护） ==========

  test('其他标签页登录不同用户：本地会话立即失效并跳登录页', () => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u-alice', username: 'alice' }, ['device:read'])
    expect(store.isAuthenticated).toBe(true)

    store.handleRemoteAuthEvent({ type: 'login', userId: 'u-admin', username: 'admin' })

    expect(store.isAuthenticated).toBe(false)
    expect(localStorage.getItem('currentUser')).toBeNull()
    // 跳转提示经 sessionStorage 传递（仅本标签页可见），由登录页消费
    expect(sessionStorage.getItem('authSyncNotice')).toBe('login.sessionReplaced')
    expect(window.location.replace).toHaveBeenCalledWith('/login')
  })

  test('其他标签页登录同一用户：本标签页不受影响', () => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u-alice', username: 'alice' }, ['device:read'])

    store.handleRemoteAuthEvent({ type: 'login', userId: 'u-alice', username: 'alice' })

    expect(store.isAuthenticated).toBe(true)
    expect(window.location.replace).not.toHaveBeenCalled()
  })

  test('其他标签页登出同一用户：本标签页同步登出', () => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u-alice', username: 'alice' }, [])

    store.handleRemoteAuthEvent({ type: 'logout', userId: 'u-alice' })

    expect(store.isAuthenticated).toBe(false)
    expect(sessionStorage.getItem('authSyncNotice')).toBe('login.sessionEnded')
    expect(window.location.replace).toHaveBeenCalledWith('/login')
  })

  test('其他标签页登出别的用户：本标签页不受影响', () => {
    const store = useAuthStore()
    store.setAuth('t', 'r', { userId: 'u-alice', username: 'alice' }, [])

    store.handleRemoteAuthEvent({ type: 'logout', userId: 'u-bob' })

    expect(store.isAuthenticated).toBe(true)
    expect(window.location.replace).not.toHaveBeenCalled()
  })

  test('未登录时收到任何事件：直接忽略', () => {
    const store = useAuthStore()
    store.handleRemoteAuthEvent({ type: 'login', userId: 'u-admin' })
    store.handleRemoteAuthEvent({ type: 'logout', userId: 'u-admin' })
    expect(store.currentUser).toBeNull()
    expect(window.location.replace).not.toHaveBeenCalled()
  })

  test('用户对象 id 字段名差异（id/_id）均可比对', () => {
    const store = useAuthStore()
    // /auth/me 返回 id 字段，登录响应返回 userId 字段，均应正确识别为同一用户
    store.setAuth('t', 'r', { id: 'u-alice', username: 'alice' }, [])
    store.handleRemoteAuthEvent({ type: 'login', userId: 'u-admin' })
    expect(store.isAuthenticated).toBe(false)
  })
})
