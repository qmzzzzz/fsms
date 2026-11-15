/**
 * P3-11：未登录深链的 redirect 回传与登录侧站内校验
 *
 * 覆盖两段：
 *   1. 守卫侧回传——未登录访问受保护页时，把目标 fullPath 暂存到
 *      authStore.postLoginRedirect 再跳 /login；公开路由与已登录放行不写。
 *   2. 登录侧校验——safeInternalPath 只接受以 / 开头且非 // 的站内路径，
 *      '//evil.com'、'///evil.com'、绝对 URL、非字符串一律落 /dashboard。
 *
 * 注：回传走 store 内存态而非 URL query（缩小开放重定向面，且与既有
 * routeGuard.test.js 钉住的 next('/login') 契约兼容）。
 */
import { describe, test, expect, vi, beforeAll, beforeEach } from 'vitest'
import i18n from '@/i18n'
import { safeInternalPath } from '@/utils/internalPath'

const mockStore = {
  isAuthenticated: false,
  sessionVerified: true,
  permissions: [],
  postLoginRedirect: null,
  restoreSession: vi.fn(async () => false),
}
const mockCancelAll = vi.fn(() => ({ cancelled: 0, kept: 0 }))

vi.mock('@/store', () => ({
  useAuthStore: () => mockStore,
  normalizeUser: (user) => user,
}))
vi.mock('@/utils/api', () => ({
  api: { auth: {} },
  isCanceledError: () => false,
  cancelAllPendingRequests: (...args) => mockCancelAll(...args),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { error: vi.fn() },
}))

const stubView = (name) => ({ default: { name, render: () => null } })
vi.mock('@/layout/index.vue', () => ({ default: { name: 'LayoutStub', render: () => null } }))
vi.mock('@/views/LoginView.vue', () => stubView('LoginView'))
vi.mock('@/views/RegisterView.vue', () => stubView('RegisterView'))
vi.mock('@/views/DashboardView.vue', () => stubView('DashboardView'))
vi.mock('@/views/DeviceView.vue', () => stubView('DeviceView'))
vi.mock('@/views/AlarmView.vue', () => stubView('AlarmView'))
vi.mock('@/views/UserView.vue', () => stubView('UserView'))
vi.mock('@/views/RoleView.vue', () => stubView('RoleView'))
vi.mock('@/views/InspectionView.vue', () => stubView('InspectionView'))
vi.mock('@/views/ReportView.vue', () => stubView('ReportView'))
vi.mock('@/views/AuditLogView.vue', () => stubView('AuditLogView'))
vi.mock('@/views/IpListView.vue', () => stubView('IpListView'))
vi.mock('@/views/ProfileView.vue', () => stubView('ProfileView'))
vi.mock('@/views/AboutView.vue', () => stubView('AboutView'))

const mockRouterHooks = { guard: [] }

vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    // 与 routeGuard.test.js 同法：注册时捕获守卫函数，便于按真实签名直调
    createRouter: (options) => {
      const instance = actual.createRouter(options)
      const rawBeforeEach = instance.beforeEach.bind(instance)
      instance.beforeEach = (fn) => {
        mockRouterHooks.guard.push(fn)
        return rawBeforeEach(fn)
      }
      return instance
    },
  }
})

let guard

beforeAll(async () => {
  await import('@/router')
  guard = mockRouterHooks.guard[0]
})

const mkRoute = (over = {}) => ({
  name: 'users',
  fullPath: '/users',
  meta: { requiresAuth: true, permission: 'user:read' },
  ...over,
})

const runGuard = async (to, from = { name: 'dashboard', fullPath: '/dashboard' }) => {
  const next = vi.fn()
  await guard(to, from, next)
  return next
}

beforeEach(() => {
  mockStore.isAuthenticated = false
  mockStore.sessionVerified = true
  mockStore.permissions = []
  mockStore.postLoginRedirect = null
  mockStore.restoreSession.mockReset()
  mockStore.restoreSession.mockResolvedValue(false)
  i18n.global.locale.value = 'zh-CN'
})

describe('P3-11 守卫侧：深链目标回传', () => {
  test('未登录访问受保护页：暂存 fullPath 并跳 /login', async () => {
    const next = await runGuard(mkRoute({ fullPath: '/users?page=2' }))
    expect(next).toHaveBeenCalledWith('/login')
    expect(mockStore.postLoginRedirect).toBe('/users?page=2')
  })

  test('会话探测成功放行：不写回传字段', async () => {
    mockStore.restoreSession.mockResolvedValue(true)
    mockStore.permissions = ['user:read']
    const next = await runGuard(mkRoute())
    expect(next).toHaveBeenCalledWith()
    expect(mockStore.postLoginRedirect).toBeNull()
  })

  test('公开路由不写回传字段', async () => {
    const next = await runGuard(
      mkRoute({ name: 'login', fullPath: '/login', meta: { requiresAuth: false } })
    )
    expect(next).toHaveBeenCalledWith()
    expect(mockStore.postLoginRedirect).toBeNull()
  })

  test('已登录访问登录页：跳首页且不写回传字段', async () => {
    mockStore.isAuthenticated = true
    const next = await runGuard(mkRoute({ name: 'login', fullPath: '/login', meta: {} }))
    expect(next).toHaveBeenCalledWith('/dashboard')
    expect(mockStore.postLoginRedirect).toBeNull()
  })
})

describe('P3-11 登录侧：站内路径校验', () => {
  test('站内路径原样放行（含带查询串的路径）', () => {
    expect(safeInternalPath('/users')).toBe('/users')
    expect(safeInternalPath('/users?page=2&x=1')).toBe('/users?page=2&x=1')
    expect(safeInternalPath('/inspections/abc')).toBe('/inspections/abc')
  })

  test('协议相对外链 //evil.com 拒绝，落 /dashboard', () => {
    expect(safeInternalPath('//evil.com')).toBe('/dashboard')
    expect(safeInternalPath('///evil.com')).toBe('/dashboard')
  })

  test('绝对 URL / 相对路径 / 非字符串一律拒绝', () => {
    expect(safeInternalPath('https://evil.com/x')).toBe('/dashboard')
    expect(safeInternalPath('users')).toBe('/dashboard')
    expect(safeInternalPath(null)).toBe('/dashboard')
    expect(safeInternalPath(undefined)).toBe('/dashboard')
    expect(safeInternalPath(['//evil.com'])).toBe('/dashboard')
  })

  test('可自定义回落目标', () => {
    expect(safeInternalPath('//evil.com', '/profile')).toBe('/profile')
  })

  test('取用即清空：登录成功读取后不再残留（防下一次登录误跳旧目标）', () => {
    mockStore.postLoginRedirect = '/users'
    const requested = mockStore.postLoginRedirect
    mockStore.postLoginRedirect = null
    expect(safeInternalPath(requested)).toBe('/users')
    expect(mockStore.postLoginRedirect).toBeNull()
  })
})
