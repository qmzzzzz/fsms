/**
 * 路由守卫与 chunk 加载失败恢复（src/router/index.js）行为测试
 *
 * 这是前端的「访问控制唯一入口」：所有页面级鉴权都经过 beforeEach。一旦退化
 * （未登录放行、权限判反、会话恢复探测缺失、重定向目标错误），用户看到的可能
 * 是一个能渲染出数据的页面、或一个白屏死循环，而控制台不报任何错——属典型的
 * 静默失效。本文件分三层钉住：
 *
 *   A. 守卫决策表：直接按真实签名调用注册进 router 的守卫函数，逐格断言 next()
 *      的实参（放行 / 跳登录 / 跳首页 / 提示文案），覆盖「登录态 × 权限 ×
 *      页面类型」的交叉格。
 *   B. 真实导航：真 vue-router + 真实路由表 + 真实重定向链，断言最终落点。
 *      并遍历路由表里每一条声明了 permission 的页面，验证两条全局安全性质：
 *        - 匿名访问一律落到 /login（没有一条权限页漏挂守卫）；
 *        - 零权限用户访问一律落到 /dashboard 且能稳定停住（重定向目标自身
 *          不得再要求权限，否则形成无限重定向）。
 *   C. onError 的 chunk 加载失败恢复：非 chunk 错误不得触发恢复、同源资源强制
 *      重取、15s 窗口防刷新风暴、跨域资源不代取、BASE_URL 子路径前缀、
 *      fetch 失败仍兜底重载、sessionStorage 不可用（隐私模式）不阻断。
 *
 * 测试手段说明（为什么可以这样测）：
 *   - 守卫与 onError 处理器无法从模块外部取得，本文件在 createRouter 上做了一层
 *     「注册时捕获」的薄包装：不改变 router 自身行为，只把注册进来的函数记下来，
 *     之后按真实签名调用。断言的是处理器自身的决策，不是包装层。
 *   - 13 个视图与 Layout 用空壳替身：本文件测的是路由层，视图内部行为由各自的
 *     测试文件负责；替身同时避免加载 element-plus 造成的额外耗时与噪声。
 *   - 路由表不做复制，直接从被测 router 实例读取，故新增路由会被 B 组遍历用例
 *     自动纳入覆盖。
 */
import { describe, test, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import i18n from '@/i18n'

const mockStore = {
  isAuthenticated: false,
  permissions: [],
  restoreSession: vi.fn(async () => false),
}
const mockRouterHooks = { error: [], guard: [] }
const mockCancelAll = vi.fn(() => ({ cancelled: 0, kept: 0 }))
const mockMessageError = vi.fn()

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
  ElMessage: { error: (...args) => mockMessageError(...args) },
}))

// 路由层测试不关心视图内部实现，统一用空壳替身（否则每次导航都会拉起
// element-plus 全量组件，把一个路由用例拖成秒级）
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

vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    createRouter: (options) => {
      const instance = actual.createRouter(options)
      const rawOnError = instance.onError.bind(instance)
      const rawBeforeEach = instance.beforeEach.bind(instance)
      instance.onError = (fn) => {
        mockRouterHooks.error.push(fn)
        return rawOnError(fn)
      }
      instance.beforeEach = (fn) => {
        mockRouterHooks.guard.push(fn)
        return rawBeforeEach(fn)
      }
      return instance
    },
  }
})

let router
let guard
let onError

beforeAll(async () => {
  router = (await import('@/router')).default
  guard = mockRouterHooks.guard[0]
  onError = mockRouterHooks.error[0]
})

beforeEach(() => {
  mockStore.isAuthenticated = false
  mockStore.permissions = []
  mockStore.restoreSession.mockReset()
  mockStore.restoreSession.mockResolvedValue(false)
  mockCancelAll.mockClear()
  mockMessageError.mockClear()
  i18n.global.locale.value = 'zh-CN'
  sessionStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

/** 只声明被测守卫真正读取的字段，避免用假字段掩盖真实读取路径 */
const mkRoute = (over = {}) => ({
  name: 'users',
  fullPath: '/users',
  meta: { requiresAuth: true, permission: 'user:read' },
  ...over,
})

const FROM_ROUTE = { name: 'dashboard', fullPath: '/dashboard' }

/** 按真实签名调用守卫，返回 vi.fn 形态的 next 以便断言实参 */
const runGuard = async (to, from = FROM_ROUTE) => {
  const next = vi.fn()
  await guard(to, from, next)
  return next
}

/** 轮询等待导航终态：memory/web history 的导航是异步的，固定 sleep 会偶发假红 */
const settle = async (predicate, message) => {
  for (let i = 0; i < 80; i += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  throw new Error('settle 超时：' + message)
}

const push = async (target) => {
  const errors = []
  await router.push(target).catch((error) => errors.push(error))
  return errors
}

const stubLocation = () => {
  const fake = {
    replace: vi.fn(),
    href: 'http://localhost:3000/',
    origin: 'http://localhost:3000',
  }
  vi.stubGlobal('location', fake)
  return fake
}

const stubFetch = () => {
  const fetchMock = vi.fn(async () => ({ ok: true }))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

const chunkError = (url) => new Error('Failed to fetch dynamically imported module: ' + url)

describe('A. 守卫决策表', () => {
  test('首屏导航（from.name 为 undefined）不取消在途请求；路由间切换才取消', async () => {
    const nextFirst = await runGuard(mkRoute({ name: 'login', meta: { requiresAuth: false } }), {
      name: undefined,
    })
    expect(nextFirst).toHaveBeenCalledWith()
    expect(mockCancelAll).not.toHaveBeenCalled()

    const nextSwitch = await runGuard(mkRoute({ name: 'login', meta: { requiresAuth: false } }), {
      name: 'dashboard',
    })
    expect(nextSwitch).toHaveBeenCalledWith()
    expect(mockCancelAll).toHaveBeenCalledTimes(1)
  })

  test('未登录访问受保护页：先探测会话再跳登录页（顺序不可颠倒）', async () => {
    const next = await runGuard(mkRoute())
    expect(mockStore.restoreSession).toHaveBeenCalledTimes(1)
    expect(next).toHaveBeenCalledTimes(1)
    expect(next).toHaveBeenCalledWith('/login')
    expect(mockStore.restoreSession.mock.invocationCallOrder[0]).toBeLessThan(
      next.mock.invocationCallOrder[0]
    )
  })

  test('未登录但 cookie 仍有有效会话：探测成功后放行，不把已登录用户踢到登录页', async () => {
    mockStore.restoreSession.mockImplementation(async () => {
      mockStore.isAuthenticated = true
      return true
    })
    const next = await runGuard(mkRoute({ name: 'profile', meta: { requiresAuth: true } }))
    expect(next).toHaveBeenCalledWith()
  })

  test('已登录时不探测会话（登录态路径零额外请求）并放行', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = ['user:read']
    const next = await runGuard(mkRoute())
    expect(mockStore.restoreSession).not.toHaveBeenCalled()
    expect(next).toHaveBeenCalledWith()
  })

  test('已登录访问登录页：跳首页（否则用户会看到一个已登录状态下的登录表单）', async () => {
    mockStore.isAuthenticated = true
    const next = await runGuard(mkRoute({ name: 'login', meta: {}, fullPath: '/login' }))
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  test('未登录访问登录页：放行（此分支若判反，登录页自身永远进不去）', async () => {
    const next = await runGuard(mkRoute({ name: 'login', meta: { requiresAuth: false } }))
    expect(next).toHaveBeenCalledWith()
  })

  test('未登录访问注册页（meta.requiresAuth = false）：放行', async () => {
    const next = await runGuard(mkRoute({ name: 'register', meta: { requiresAuth: false } }))
    expect(next).toHaveBeenCalledWith()
  })

  test('已登录但权限不足：跳首页并提示权限不足（文案取当前语言）', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = ['alarm:read']
    const next = await runGuard(mkRoute())
    expect(next).toHaveBeenCalledWith('/dashboard')
    expect(mockMessageError).toHaveBeenCalledTimes(1)
    expect(mockMessageError).toHaveBeenCalledWith('权限不足，无法访问该页面')
  })

  test('权限不足的提示文案随界面语言切换（不得把中文写死在守卫里）', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = []
    i18n.global.locale.value = 'en-US'
    await runGuard(mkRoute())
    expect(mockMessageError).toHaveBeenCalledWith('Permission denied, cannot access this page')
    expect(i18n.global.t('messages.permissionDenied')).toBe(
      'Permission denied, cannot access this page'
    )
  })

  test('权限判定：精确命中、模块通配、超级通配三条路径都放行', async () => {
    mockStore.isAuthenticated = true

    mockStore.permissions = ['user:read']
    expect(await runGuard(mkRoute())).toHaveBeenCalledWith()

    mockStore.permissions = ['user:*']
    expect(await runGuard(mkRoute())).toHaveBeenCalledWith()

    mockStore.permissions = ['*:*']
    expect(await runGuard(mkRoute())).toHaveBeenCalledWith()
    expect(mockMessageError).not.toHaveBeenCalled()
  })

  test('权限集合形状异常（null）：判为无权限而不是抛错，仍给出提示', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = null
    const next = await runGuard(mkRoute())
    expect(next).toHaveBeenCalledWith('/dashboard')
    expect(mockMessageError).toHaveBeenCalledWith('权限不足，无法访问该页面')
  })

  test.each(['dashboard', 'profile', 'about'])(
    '%s 页不声明 permission：任何登录用户都放行（不依赖权限集合内容）',
    async (name) => {
      mockStore.isAuthenticated = true
      mockStore.permissions = []
      const next = await runGuard(mkRoute({ name, meta: { requiresAuth: true } }))
      expect(next).toHaveBeenCalledWith()
    }
  )
})

describe('B. 真实导航（守卫 + 路由表 + 重定向链的联合行为）', () => {
  test('未登录访问受保护页：最终落在 /login，且导航不抛错', async () => {
    const errors = await push('/users')
    await settle(() => router.currentRoute.value.path === '/login', '等 /login')
    expect(router.currentRoute.value.path).toBe('/login')
    expect(errors).toEqual([])
  })

  test('已登录且权限不足访问受保护页：最终落在 /dashboard 并提示', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = []
    await push('/devices')
    await settle(() => router.currentRoute.value.path === '/dashboard', '等 /dashboard')
    expect(router.currentRoute.value.path).toBe('/dashboard')
    expect(mockMessageError).toHaveBeenCalledWith('权限不足，无法访问该页面')
  })

  test('已登录且有权限访问受保护页：真正落到目标页', async () => {
    mockStore.isAuthenticated = true
    mockStore.permissions = ['device:read']
    await push('/devices')
    await settle(() => router.currentRoute.value.path === '/devices', '等 /devices')
    expect(router.currentRoute.value.path).toBe('/devices')
    expect(mockMessageError).not.toHaveBeenCalled()
  })

  test('已登录访问 /login：被送回家页', async () => {
    mockStore.isAuthenticated = true
    await push('/login')
    await settle(() => router.currentRoute.value.path === '/dashboard', '等 /dashboard')
    expect(router.currentRoute.value.path).toBe('/dashboard')
  })

  test('未知路径：兜底重定向后仍要过守卫（已登录落在首页）', async () => {
    mockStore.isAuthenticated = true
    await push('/no/such/deep/path')
    await settle(() => router.currentRoute.value.path === '/dashboard', '等 /dashboard')
    expect(router.currentRoute.value.path).toBe('/dashboard')
  })

  test('路由切换时取消在途请求（每次切换发生，不随登录态改变）', async () => {
    mockStore.isAuthenticated = true
    const before = mockCancelAll.mock.calls.length
    await push('/about')
    await settle(() => router.currentRoute.value.path === '/about', '等 /about')
    expect(mockCancelAll.mock.calls.length).toBeGreaterThan(before)
  })

  test('路由表里每一条声明了 permission 的页面：匿名访问一律落到 /login', async () => {
    const guarded = router.getRoutes().filter((record) => record.meta && record.meta.permission)
    expect(guarded.length).toBeGreaterThan(0)
    for (const record of guarded) {
      mockStore.restoreSession.mockResolvedValue(false)
      await push(record.path)
      await settle(
        () => router.currentRoute.value.path === '/login',
        '等 /login（来自 ' + record.path + '）'
      )
      expect(router.currentRoute.value.path, record.path + ' 未受守卫保护').toBe('/login')
    }
  })

  test('零权限用户访问任意权限页：一律落到 /dashboard 且稳定停住（重定向目标不得自身要权限）', async () => {
    mockStore.isAuthenticated = true
    const guarded = router.getRoutes().filter((record) => record.meta && record.meta.permission)
    expect(guarded.length).toBeGreaterThan(0)
    for (const record of guarded) {
      mockStore.permissions = []
      mockMessageError.mockClear()
      await push(record.path)
      await settle(
        () => router.currentRoute.value.path === '/dashboard',
        '等 /dashboard（来自 ' + record.path + '）'
      )
      expect(router.currentRoute.value.path, record.path + ' 的拒绝落点异常').toBe('/dashboard')
      expect(mockMessageError, record.path + ' 缺权限提示').toHaveBeenCalled()
    }
  })
})

describe('C. chunk 加载失败恢复（onError）', () => {
  test('非 chunk 类错误一律不触发恢复（否则任何 JS 异常都会变成整页刷新）', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    await onError(new Error('Cannot read properties of undefined'), { fullPath: '/about' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fake.replace).not.toHaveBeenCalled()
  })

  test('chunk 加载失败：同源资源被强制重新拉取（cache: reload）后整页重载到目标路由', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    await onError(chunkError('http://localhost:3000/assets/About-abc.js'), {
      fullPath: '/about',
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('http://localhost:3000/assets/About-abc.js')
    expect(fetchMock.mock.calls[0][1]).toEqual({ cache: 'reload' })
    expect(fake.replace).toHaveBeenCalledTimes(1)
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })

  test('另一类真实报错文案（Importing a module script failed）同样被识别', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    await onError(new Error('Importing a module script failed.'), { fullPath: '/reports' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fake.replace).toHaveBeenCalledWith('/reports')
  })

  test('15 秒窗口内的重复失败不再恢复（服务器故障时防止刷新风暴）', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    const error = chunkError('http://localhost:3000/assets/A.js')
    await onError(error, { fullPath: '/about' })
    expect(fake.replace).toHaveBeenCalledTimes(1)

    fetchMock.mockClear()
    fake.replace.mockClear()
    await onError(error, { fullPath: '/about' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fake.replace).not.toHaveBeenCalled()
  })

  test('恢复窗口按目标路由隔离：一条路由的失败不抑制另一条路由的恢复', async () => {
    const fake = stubLocation()
    stubFetch()
    await onError(chunkError('http://localhost:3000/assets/A.js'), { fullPath: '/about' })
    expect(fake.replace).toHaveBeenCalledWith('/about')

    fake.replace.mockClear()
    await onError(chunkError('http://localhost:3000/assets/B.js'), { fullPath: '/reports' })
    expect(fake.replace).toHaveBeenCalledWith('/reports')
  })

  test('窗口过期后允许再次恢复（时间戳由上一次恢复写入）', async () => {
    const fake = stubLocation()
    stubFetch()
    const target = { fullPath: '/about' }
    const expired = String(Date.now() - 16000)
    sessionStorage.setItem('router:chunkRetry:/about', expired)

    await onError(chunkError('http://localhost:3000/assets/A.js'), target)
    expect(fake.replace).toHaveBeenCalledWith('/about')
    expect(Number(sessionStorage.getItem('router:chunkRetry:/about'))).toBeGreaterThan(
      Number(expired)
    )
  })

  test('失败资源跨域时不代取，但仍执行恢复性重载', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    await onError(chunkError('https://cdn.example.com/assets/A.js'), { fullPath: '/about' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })

  test('错误消息里没有 URL 时跳过重取，仍执行恢复性重载', async () => {
    const fake = stubLocation()
    const fetchMock = stubFetch()
    await onError(new Error('Failed to fetch dynamically imported module'), { fullPath: '/about' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })

  test('强制重取失败（离线/断网）时仍兜底重载', async () => {
    const fake = stubLocation()
    const fetchMock = vi.fn(async () => {
      throw new Error('offline')
    })
    vi.stubGlobal('fetch', fetchMock)
    await onError(chunkError('http://localhost:3000/assets/A.js'), { fullPath: '/about' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })

  test('to 缺失时回落到根路径', async () => {
    const fake = stubLocation()
    stubFetch()
    await onError(chunkError('http://localhost:3000/assets/A.js'), undefined)
    expect(fake.replace).toHaveBeenCalledWith('/')
  })

  test('子路径部署（BASE_URL = /admin/）下重载带部署前缀，不跳出应用', async () => {
    const fake = stubLocation()
    stubFetch()
    vi.stubEnv('BASE_URL', '/admin/')
    await onError(chunkError('http://localhost:3000/admin/assets/A.js'), { fullPath: '/about' })
    expect(fake.replace).toHaveBeenCalledWith('/admin/about')
  })

  test('BASE_URL 为空串时回退根路径（不拼出 undefined/双斜杠）', async () => {
    // 防退化：`String(import.meta.env.BASE_URL || '/')` 的 || '/' 兜底被去掉
    // → BASE_URL 为空串时 base 为 ''，replace('') 仍是相对路径（行为偶然正确），
    // 但若改成 `?? '/'` 就会把空串透传成 '' 并让某些部署形态跳到错误地址。
    // 本用例钉住「空串 → 根路径」这一契约。
    const fake = stubLocation()
    stubFetch()
    vi.stubEnv('BASE_URL', '')
    await onError(chunkError('http://localhost:3000/assets/A.js'), { fullPath: '/devices' })
    expect(fake.replace).toHaveBeenCalledWith('/devices')
    // 不得出现双斜杠或 undefined
    const arg = fake.replace.mock.calls[0][0]
    expect(arg).not.toContain('//')
    expect(arg).not.toContain('undefined')
  })

  test('BASE_URL 只有斜杠（/）时 base 归一为空，路径不重复加斜杠', async () => {
    // 防退化：去掉 .replace(/\/+$/, '') 的尾斜杠归一 → base='/' + '/about' = '//about'
    // （协议相对 URL，浏览器会当成 host 解析，跳出应用）
    const fake = stubLocation()
    stubFetch()
    vi.stubEnv('BASE_URL', '/')
    await onError(chunkError('http://localhost:3000/assets/A.js'), { fullPath: '/about' })
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })

  test('sessionStorage 不可用（隐私模式/被禁用）不阻断恢复', async () => {
    const fake = stubLocation()
    stubFetch()
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage disabled')
    })
    try {
      await onError(chunkError('http://localhost:3000/assets/A.js'), { fullPath: '/about' })
    } finally {
      spy.mockRestore()
    }
    expect(fake.replace).toHaveBeenCalledWith('/about')
  })
})
