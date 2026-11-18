/**
 * P3-11：未登录深链的 redirect 回传与登录侧站内校验
 *
 * 覆盖三段：
 *   1. 守卫侧回传——未登录访问受保护页时，把目标 fullPath 暂存到
 *      authStore.postLoginRedirect 再跳 /login；公开路由与已登录放行不写。
 *   2. 登录侧校验——safeInternalPath 只接受以 / 开头且非 //、不含反斜杠的
 *      站内路径；'//evil.com'、'///evil.com'、'/\evil.com'（WHATWG 特殊协议
 *      把 \ 视同 /，等价 //evil.com）、绝对 URL、非字符串一律落 /dashboard。
 *   3. 取用即清空——用**真实 LoginView** 走一遍登录成功链路：守卫写入的
 *      回传目标经 safeInternalPath 校验后跳转，且读取后立即从 store 清除
 *      （此前该用例在测试里手写「读后置空」三行，与生产行为无关，属同义反复）。
 *
 * 注：回传走 store 内存态而非 URL query（缩小开放重定向面，且与既有
 * routeGuard.test.js 钉住的 next('/login') 契约兼容）。
 */
import { describe, test, expect, vi, beforeAll, beforeEach } from 'vitest'
import i18n from '@/i18n'
import { safeInternalPath } from '@/utils/internalPath'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import LoginView from '@/views/LoginView.vue'

const mockStore = {
  isAuthenticated: false,
  sessionVerified: true,
  permissions: [],
  postLoginRedirect: null,
  restoreSession: vi.fn(async () => false),
  // LoginView 登录成功链路会调用 setAuth 并以返回值决定是否继续跳转
  setAuth: vi.fn(() => true),
}
const mockCancelAll = vi.fn(() => ({ cancelled: 0, kept: 0 }))
const apiAuthLogin = vi.fn()
const apiAuthGetCaptcha = vi.fn()
const apiAuthGetCaptchaStatus = vi.fn()
const encryptPassword = vi.fn()

// 局部 mock：只换掉 useAuthStore（守卫/登录消费链路都用这个假 store），
// 其余导出（如 AuthPrefs 依赖的 useAppStore）保持真实实现——整模块假掉会让
// 真实 LoginView 的子组件在 setup 阶段拿不到依赖而连锁报错。
vi.mock('@/store', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    useAuthStore: () => mockStore,
    normalizeUser: (user) => user,
  }
})
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      login: (...args) => apiAuthLogin(...args),
      getCaptcha: (...args) => apiAuthGetCaptcha(...args),
      getCaptchaStatus: (...args) => apiAuthGetCaptchaStatus(...args),
    },
  },
  isCanceledError: () => false,
  cancelAllPendingRequests: (...args) => mockCancelAll(...args),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { error: vi.fn(), success: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...args) => encryptPassword(...args),
}))

const stubView = (name) => ({ default: { name, render: () => null } })
vi.mock('@/layout/index.vue', () => ({ default: { name: 'LayoutStub', render: () => null } }))
// 注意：LoginView 不再 mock——「取用即清空」必须走真实登录消费链路（见文件头③）
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
  mockStore.setAuth.mockClear()
  apiAuthLogin.mockReset()
  apiAuthGetCaptcha.mockReset()
  apiAuthGetCaptchaStatus.mockReset()
  encryptPassword.mockReset()
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

  test('反斜杠形态一律拒绝（WHATWG 特殊协议把 \\ 视同 /，/\\evil.com 等价 //evil.com）', () => {
    expect(safeInternalPath('/\\evil.com')).toBe('/dashboard')
    expect(safeInternalPath('/\\')).toBe('/dashboard')
    expect(safeInternalPath('/users\\..\\..\\evil.com')).toBe('/dashboard')
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
})

describe('P3-11 登录侧：取用即清空（真实 LoginView 消费链路）', () => {
  const routes = [
    { path: '/login', name: 'login', component: { render: () => null } },
    { path: '/dashboard', name: 'dashboard', component: { render: () => null } },
    { path: '/users', name: 'users', component: { render: () => null } },
    { path: '/:pathMatch(.*)*', name: 'fallback', component: { render: () => null } },
  ]

  /** 挂载真实登录页：验证码开关关闭（本套件只关心回传目标的消费） */
  const openLogin = async () => {
    apiAuthGetCaptchaStatus.mockResolvedValue({
      data: { data: { loginCaptchaEnabled: false } },
    })
    apiAuthGetCaptcha.mockResolvedValue({
      data: { success: true, data: { captchaId: 'cap-1', svg: '<svg/>' } },
    })
    encryptPassword.mockResolvedValue('ENC-PAYLOAD')
    const c = mountComponent(LoginView, { routes, initialRoute: '/login' })
    await flush(6)
    return c
  }

  /** 通过真实 DOM 输入框填入表单（走 v-model 的 input 事件） */
  const fill = async (c, username, password) => {
    const inputs = c.findAll('input.el-input__inner')
    inputs[0].value = username
    inputs[0].dispatchEvent(new window.Event('input', { bubbles: true }))
    inputs[1].value = password
    inputs[1].dispatchEvent(new window.Event('input', { bubbles: true }))
    inputs[1].dispatchEvent(new window.Event('blur', { bubbles: true }))
    await flush(6)
  }

  const submitBtn = (c) => c.findAll('.glass-btn--primary').slice(-1)[0]

  const loginSucceeds = () => {
    apiAuthLogin.mockResolvedValue({
      data: {
        success: true,
        data: { user: { _id: 'u1', username: 'alice', permissions: ['user:read'] } },
      },
    })
  }

  test('守卫回传 /\\evil.com：登录成功后经 safeInternalPath 落 /dashboard，且回传字段不残留', async () => {
    loginSucceeds()
    mockStore.postLoginRedirect = '/\\evil.com'
    const c = await openLogin()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => c.router.currentRoute.value.path === '/dashboard', {
      message: '非法回传目标应落 /dashboard',
    })
    // 取用即清空（LoginView 登录成功侧读取后立即置 null），下次登录不再误跳旧目标
    expect(mockStore.postLoginRedirect).toBeNull()
    expect(c.errors).toEqual([])
  })

  test('守卫回传 /users?page=2：登录成功后跳回原目标，且读取后即清空', async () => {
    loginSucceeds()
    mockStore.postLoginRedirect = '/users?page=2'
    const c = await openLogin()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => c.router.currentRoute.value.fullPath === '/users?page=2', {
      message: '合法深链应原样跳回',
    })
    expect(mockStore.postLoginRedirect).toBeNull()
    expect(c.errors).toEqual([])
  })
})
