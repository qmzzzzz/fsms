/**
 * api.js 请求管线行为测试（认证 / 取消 / 错误归一 / 形状校验 / 端点契约）
 *
 * 与既有测试的分工（不重复已覆盖分支）：
 *  - apiStatusCodes.test.js      → 405/409/413/415/431/500/503 的码化与兜底
 *  - apiDriftLru.test.js         → 漂移去重、LRU 上限与淘汰顺序、/auth/me 告警
 *  - canceledErrorGuards.test.js → isCanceledError 判定、视图 catch 守卫（源码级）
 *  - sessionManager.test.js      → revokeSession 的源码级断言（本文件补行为级）
 * 本文件只补上述未覆盖的：
 *  401 刷新/登出/并发合流、silent401、认证入口 401、400/403/404/429/default、
 *  网络/配置错误、AUTH_ENCRYPTED_CREDENTIAL_INVALID 自愈、取消语义与控制器清理、
 *  形状校验的守卫与路由/方法匹配、api 方法表的动词与路径契约、baseURL 拼装。
 *
 * 驱动方式：真实 apiClient + 自定义 adapter 走真实拦截器。
 * 每个用例 vi.resetModules() 后动态 import 取干净模块实例——api.js 有多处模块级
 * 单例（isRefreshing / refreshPromise / pendingControllers / reportedDrifts /
 * _isHandling401），不隔离会跨用例串味。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { AxiosError, CanceledError } from 'axios'

const msg = vi.hoisted(() => ({
  error: vi.fn(),
  warning: vi.fn(),
  success: vi.fn(),
  info: vi.fn(),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: msg }))

const invalidatePublicKeyCache = vi.hoisted(() => vi.fn())
vi.mock('@/utils/loginCipher', () => ({ invalidatePublicKeyCache }))

let consoleErrorSpy

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  // 漂移告警走 console.error；全局静音避免测试输出噪音，断言用 consoleErrorSpy.mock.calls
  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

/** 取干净模块图（api.js 的模块级单例必须逐用例隔离） */
const loadAll = async () => {
  vi.resetModules()
  const apiMod = await import('@/utils/api')
  const i18n = (await import('@/i18n')).default
  const router = (await import('@/router')).default
  const axios = (await import('axios')).default
  const pinia = await import('pinia')
  const storeMod = await import('@/store')
  // 固定英文：兜底文案若被硬编码中文，断言会红
  i18n.global.locale.value = 'en-US'
  return { ...apiMod, i18n, router, axios, pinia, storeMod }
}

const jsonOk = (config, data = { success: true, data: null }) => ({
  data,
  status: 200,
  statusText: 'OK',
  headers: {},
  config,
})

const httpError = (config, status, data) =>
  new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_REQUEST,
    config,
    null,
    {
      status,
      data,
      statusText: String(status),
      headers: {},
      config,
    }
  )

const networkError = (config) =>
  new AxiosError('Network Error', AxiosError.ERR_NETWORK, config, { __fakeRequest: true })

const sleep = (ms = 0) => new Promise((r) => setTimeout(r, ms))

/** 轮转真实定时器等待条件成立（waitFor 只推 nextTick，推不动这条微任务链） */
const waitUntil = async (predicate, rounds = 200) => {
  for (let i = 0; i < rounds; i += 1) {
    if (predicate()) return
    await sleep(0)
  }
  throw new Error('waitUntil 超时：被测行为未发生')
}

const flush = async (rounds = 8) => {
  for (let i = 0; i < rounds; i += 1) await sleep(0)
}

/**
 * axios 的 xhr 适配器在 signal abort 时以 CanceledError 拒绝
 * （node_modules/axios/lib/adapters/xhr.js 的 onCanceled 分支）。
 * 这里按同一契约模拟在途请求，被测的是 api.js 的拦截器与取消表行为。
 */
const hangingAdapter = (config, onConfig) => {
  onConfig?.(config)
  return new Promise((resolve, reject) => {
    config.__resolve = () => resolve(jsonOk(config))
    if (config.signal.aborted) {
      reject(new CanceledError(null, config))
      return
    }
    config.signal.addEventListener('abort', () => reject(new CanceledError(null, config)), {
      once: true,
    })
  })
}

const driftCount = () =>
  consoleErrorSpy.mock.calls.filter((a) => String(a[0]).includes('[schema-drift]')).length

describe('apiClient 默认配置', () => {
  test('cookie 认证与 CSRF 口径：withCredentials/超时/内容类型/默认 baseURL', async () => {
    // 防退化：withCredentials 被关 → 分域部署 cookie 不再随请求；timeout 被去掉 →
    // 请求可无限悬挂；Content-Type 被改 → 写请求不再是 JSON（CSRF 前提被破坏）
    const { apiClient } = await loadAll()
    expect(apiClient.defaults.baseURL).toBe('/api')
    expect(apiClient.defaults.timeout).toBe(15000)
    expect(apiClient.defaults.withCredentials).toBe(true)
    expect(apiClient.defaults.headers['Content-Type']).toBe('application/json')
  })
})

describe('baseURL 拼装（子路径部署）', () => {
  test('刷新请求走 baseURL + /auth/refresh，且不经过 apiClient 拦截器（防循环）', async () => {
    // 防退化：刷新 URL 被硬编码为 /api/... → 子路径部署下刷新打到错误路径；
    // 刷新改走 apiClient → 会再次进 401 拦截器（循环/双提示）
    const { apiClient, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const seen = []
    let n = 0
    apiClient.defaults.adapter = (config) => {
      seen.push(config.url)
      n += 1
      if (n === 1) return Promise.reject(httpError(config, 401, {}))
      return Promise.resolve(jsonOk(config))
    }
    const resp = await apiClient.get('/devices')
    expect(resp.status).toBe(200)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(postSpy.mock.calls[0][0]).toBe('/api/auth/refresh')
    expect(seen).toEqual(['/devices', '/devices'])
  })

  test('VITE_API_BASE_URL 覆盖时 baseURL 与刷新 URL 同时跟随（/sub/api）', async () => {
    // 防退化：只让 baseURL 跟随环境变量、刷新仍写死 /api → 子路径部署下刷新 404
    vi.stubEnv('VITE_API_BASE_URL', '/sub/api')
    const { apiClient, axios } = await loadAll()
    expect(apiClient.defaults.baseURL).toBe('/sub/api')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      if (n === 1) return Promise.reject(httpError(config, 401, {}))
      return Promise.resolve(jsonOk(config))
    }
    await apiClient.get('/devices')
    expect(postSpy.mock.calls[0][0]).toBe('/sub/api/auth/refresh')
  })
})

describe('401 刷新链（含并发合流）', () => {
  test('刷新成功：重试一次、去掉旧 Authorization、不提示不跳转', async () => {
    // 防退化：不重试（用户被无谓登出）；无限重试（请求风暴）；
    // 重试仍带过期 Authorization（服务端可能优先按头拒绝）；重复弹提示/跳转
    const { apiClient, router, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    const seen = []
    apiClient.defaults.adapter = (config) => {
      seen.push({ url: config.url, auth: config.headers.Authorization })
      if (seen.length === 1) return Promise.reject(httpError(config, 401, {}))
      return Promise.resolve(jsonOk(config))
    }
    const resp = await apiClient.get('/devices', { headers: { Authorization: 'Bearer stale' } })
    expect(resp.status).toBe(200)
    expect(seen).toHaveLength(2)
    expect(seen[0].auth).toBe('Bearer stale')
    expect(seen[1].auth).toBeUndefined()
    expect(seen.map((c) => c.url)).toEqual(['/devices', '/devices'])
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(postSpy.mock.calls[0][0]).toBe('/api/auth/refresh')
    expect(postSpy.mock.calls[0][2]).toEqual({ timeout: 10000, withCredentials: true })
    expect(msg.error).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
  })

  test('并发 401 且刷新成功：刷新只执行一次，两个请求都重试成功', async () => {
    // 防退化：去掉 isRefreshing/refreshPromise 合流 → 每个 401 各刷一次（刷新风暴）
    const { apiClient, axios } = await loadAll()
    let releaseRefresh
    const postSpy = vi.spyOn(axios, 'post').mockImplementation(
      () =>
        new Promise((resolve) => {
          releaseRefresh = () => resolve({ data: { success: true } })
        })
    )
    const attempts = { '/a': 0, '/b': 0 }
    apiClient.defaults.adapter = (config) => {
      attempts[config.url] += 1
      if (attempts[config.url] === 1) return Promise.reject(httpError(config, 401, {}))
      return Promise.resolve(jsonOk(config))
    }
    const p1 = apiClient.get('/a')
    const p2 = apiClient.get('/b')
    await waitUntil(() => attempts['/a'] === 1 && attempts['/b'] === 1)
    expect(postSpy).toHaveBeenCalledTimes(1)
    releaseRefresh()
    const [r1, r2] = await Promise.all([p1, p2])
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
    expect(attempts).toEqual({ '/a': 2, '/b': 2 })
    expect(postSpy).toHaveBeenCalledTimes(1)
  })

  test('并发 401 且刷新失败：登出提示与跳转只发生一次，两个调用方都收到 401', async () => {
    // 防退化：去掉 _isHandling401 合流 → 每个失败请求各弹一次「会话已失效」并各跳一次
    const { apiClient, router, axios, i18n } = await loadAll()
    vi.spyOn(axios, 'post').mockRejectedValue(new Error('refresh down'))
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, {}))
    const [e1, e2] = await Promise.all([
      apiClient.get('/a').catch((e) => e),
      apiClient.get('/b').catch((e) => e),
    ])
    await flush()
    expect(e1.response.status).toBe(401)
    expect(e2.response.status).toBe(401)
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.sessionExpired'))
    expect(pushSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
  })

  test('逐波 401：刷新与登出闭锁在每波后复位（不会只处理第一波）', async () => {
    // 防退化：isRefreshing/_isHandling401 只在 finally 复位；若漏掉复位，
    // 第二波 401 既不再刷新也不再登出，会话彻底失去兜底
    const { apiClient, router, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockRejectedValue(new Error('down'))
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, {}))
    await apiClient.get('/a').catch((e) => e)
    await flush()
    await apiClient.get('/b').catch((e) => e)
    await flush()
    expect(postSpy).toHaveBeenCalledTimes(2)
    expect(msg.error).toHaveBeenCalledTimes(2)
    expect(pushSpy).toHaveBeenCalledTimes(2)
  })

  test('登出提示文案优先级：码化翻译 > 后端 message > sessionExpired 兜底', async () => {
    // 防退化：优先回显后端原文（英文界面串中文）；丢掉兜底（无 message 时静默登出）
    const { apiClient, router, axios, i18n } = await loadAll()
    vi.spyOn(axios, 'post').mockRejectedValue(new Error('refresh down'))
    vi.spyOn(router, 'push').mockResolvedValue()
    const run = async (data) => {
      apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, data))
      msg.error.mockClear()
      await apiClient.get('/devices').catch((e) => e)
      await flush(10)
      expect(msg.error).toHaveBeenCalledTimes(1)
      return msg.error.mock.calls[0][0]
    }
    expect(await run({ errors: { errorCode: 'AUTH_TOKEN_EXPIRED' }, message: 'RAW' })).toBe(
      i18n.global.t('errors.authTokenExpired')
    )
    expect(await run({ message: 'RAW-BACKEND' })).toBe('RAW-BACKEND')
    expect(await run({})).toBe(i18n.global.t('messages.sessionExpired'))
  })

  test('认证入口 401 不参与刷新：立即提示、不跳转', async () => {
    // 防退化：login/register/refresh 的 401 也去刷新 → 输错密码要等满刷新超时才提示，
    // 且残留 refresh cookie 时刷新成功还会重发一次注定失败的登录请求
    const { apiClient, router, axios, i18n } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 401, { message: 'BAD-CREDS' }))
    for (const url of ['/auth/login', '/auth/register', '/auth/refresh']) {
      msg.error.mockClear()
      const e = await apiClient.post(url, {}).catch((err) => err)
      await flush()
      expect(e.response.status, url).toBe(401)
      expect(msg.error, url).toHaveBeenCalledTimes(1)
      expect(msg.error.mock.calls[0][0], url).toBe('BAD-CREDS')
      expect(postSpy, url).not.toHaveBeenCalled()
      expect(pushSpy, url).not.toHaveBeenCalled()
    }
    // 无 message 时的兜底
    msg.error.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, {}))
    await apiClient.post('/auth/login', {}).catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('login.failed'))
  })

  test('认证入口匹配用 includes：带 baseURL 前缀的 URL 同样豁免刷新', async () => {
    // 防退化：改用全等匹配 → 子路径/带前缀部署下 config.url 是 '/api/auth/login' 这类形态，
    // 豁免失效，输错密码又要等满刷新超时
    const { apiClient, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 401, { message: 'BAD' }))
    const e = await apiClient.post('/api/auth/login', {}).catch((err) => err)
    await flush()
    expect(e.response.status).toBe(401)
    expect(postSpy).not.toHaveBeenCalled()
    expect(msg.error.mock.calls[0][0]).toBe('BAD')
  })

  test('silent401：刷新失败不提示不跳转，但刷新确实被尝试过', async () => {
    // 防退化：silent401 提前短路（会话恢复时 access 过期+refresh 有效也救不回来）；
    // 或 silent401 把 401 也当成需要弹提示的失败（未登录用户首访每次弹「会话已失效」）
    const { apiClient, router, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockRejectedValue(new Error('down'))
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, {}))
    const e = await apiClient.get('/auth/me', { silent401: true }).catch((err) => err)
    await flush()
    expect(e.response.status).toBe(401)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(msg.error).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
  })

  test('silent401：刷新成功仍会重试并返回结果（会话可被救回）', async () => {
    // 防退化：silent401 直接放弃重试 → 本地状态丢失但 cookie 有效的用户被误判未登录
    const { apiClient, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      if (n === 1) return Promise.reject(httpError(config, 401, {}))
      return Promise.resolve(
        jsonOk(config, {
          success: true,
          data: { user: { id: 'u1', username: 'alice' }, permissions: [] },
        })
      )
    }
    const r = await apiClient.get('/auth/me', { silent401: true })
    expect(r.status).toBe(200)
    expect(n).toBe(2)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(msg.error).not.toHaveBeenCalled()
    expect(msg.warning).not.toHaveBeenCalled()
  })

  test('silent401 只压制 401：403 仍必须提示', async () => {
    // 防退化：把 silent401 提前到状态分支之前 → 会话恢复探测会把真实权限失败也吞掉
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 403, { errors: { errorCode: 'AUTH_IP_RANGE_DENIED' } }))
    await apiClient.get('/auth/me', { silent401: true }).catch((e) => e)
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('errors.authIpRangeDenied'))
  })

  test('重试后仍 401：不再刷新、不无限循环，调用方收到 401', async () => {
    // 防退化：去掉 _retried 标记 → 401 无限重试（刷新风暴 + 页面卡死）。
    // 适配器设硬上限：真出现无限重试时以明确断言失败，而不是把 worker 打到 OOM
    // （OOM 只会报「Worker exited unexpectedly」，掩盖真正的缺陷原因）。
    const { apiClient, axios } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const MAX_ATTEMPTS = 8
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      if (n > MAX_ATTEMPTS) throw new Error('无限重试：超过适配器调用上限')
      return Promise.reject(httpError(config, 401, {}))
    }
    const e = await apiClient.get('/devices').catch((err) => err)
    expect(n).toBe(2)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(e.response.status).toBe(401)
  })

  test('刷新响应 success 非布尔真值不算成功（严格 === true）', async () => {
    // 防退化：把 === true 放宽为真值判断 → 畸形刷新响应被当作成功，
    // 重试注定失败且因 _retried 静默，用户既无提示也未被登出
    const { apiClient, router, axios } = await loadAll()
    vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: 'yes' } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      return Promise.reject(httpError(config, 401, {}))
    }
    await apiClient.get('/devices').catch((e) => e)
    await flush()
    expect(n).toBe(1)
    expect(pushSpy).toHaveBeenCalledTimes(1)
    expect(msg.error).toHaveBeenCalledTimes(1)
  })

  test('刷新失败清认证：clearAuth 先于 router.push("/login")', async () => {
    // 防退化：不清 store（界面仍显示旧用户、请求继续以失效会话发出）；
    // 先跳转后清理（守卫按旧 currentUser 判定，可能被弹回受保护页）
    const { apiClient, router, axios, pinia, storeMod } = await loadAll()
    pinia.setActivePinia(pinia.createPinia())
    const authStore = storeMod.useAuthStore()
    authStore.setAuth(null, null, { userId: 'u1', username: 'alice' }, ['device:read'])
    const clearSpy = vi.spyOn(authStore, 'clearAuth')
    vi.spyOn(axios, 'post').mockRejectedValue(new Error('down'))
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401, {}))
    await apiClient.get('/devices').catch((e) => e)
    await flush()
    expect(clearSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
    expect(clearSpy.mock.invocationCallOrder[0]).toBeLessThan(pushSpy.mock.invocationCallOrder[0])
    expect(authStore.currentUser).toBeNull()
    expect(localStorage.getItem('currentUser')).toBeNull()
  })
})

describe('状态码错误归一（400/403/404/429/default）', () => {
  test('400：码化翻译优先，warning 级', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 400, { errors: { errorCode: 'VALIDATION_FAILED' }, message: 'RAW' })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('errors.validationFailed'))
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('400：未码化时回显后端 message；都没有时走 requestParamError 兜底', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 400, { message: 'RAW-400' }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning.mock.calls[0][0]).toBe('RAW-400')
    msg.warning.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 400, {}))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('messages.requestParamError'))
  })

  test('403：码化翻译优先，error 级（IP 白名单拒绝）', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 403, { errors: { errorCode: 'AUTH_IP_RANGE_DENIED' }, message: 'RAW' })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('errors.authIpRangeDenied'))
    expect(msg.warning).not.toHaveBeenCalled()
  })

  test('403：未码化时回显后端 message；都没有时走 accessDenied 兜底', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 403, { message: 'RAW-403' }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe('RAW-403')
    msg.error.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 403, {}))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.accessDenied'))
  })

  test('404：码化翻译优先，error 级', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 404, { errors: { errorCode: 'ALARM_NOT_FOUND' } }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('errors.alarmNotFound'))
  })

  test('404：未码化时回显后端 message；都没有时走 resourceNotFound 兜底', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 404, { message: 'RAW-404' }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe('RAW-404')
    msg.error.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 404, {}))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.resourceNotFound'))
  })

  test('429：码化翻译优先（MFA 防爆破），warning 级', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 429, { errors: { errorCode: 'MFA_ATTEMPTS_EXCEEDED' }, message: 'RAW' })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('errors.mfaAttemptsExceeded'))
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('429：未码化时回显后端 message；都没有时走 tooManyRequests 兜底', async () => {
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 429, { message: 'RAW-429' }))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning.mock.calls[0][0]).toBe('RAW-429')
    msg.warning.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 429, {}))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('messages.tooManyRequests'))
  })

  test('500/503 三级兜底链：码化翻译 > 后端 message > 本地化 serverError', async () => {
    // 防退化：兜底链任一环被截断/换序 → 5xx 时用户看到 undefined、空白，
    // 或英文界面回显后端中文原文
    const { apiClient, i18n } = await loadAll()
    const run = async (status, data) => {
      msg.error.mockClear()
      apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, status, data))
      await apiClient.get('/x').catch((e) => e)
      expect(msg.error, 'status ' + status).toHaveBeenCalledTimes(1)
      return msg.error.mock.calls[0][0]
    }
    for (const status of [500, 503]) {
      // 第一级：码化翻译
      expect(await run(status, { errors: { errorCode: 'INTERNAL_ERROR' }, message: 'RAW' })).toBe(
        i18n.global.t('errors.internalError')
      )
      // 第二级：后端未码化时回显其 message（如反代/网关产生的 5xx）
      expect(await run(status, { message: 'GATEWAY-RAW' })).toBe('GATEWAY-RAW')
      // 第三级：空体兜底
      expect(await run(status, undefined)).toBe(i18n.global.t('messages.serverError'))
    }
  })

  test('未枚举状态码（如 418）：不查码化映射，直接回显后端 message', async () => {
    // 防退化：default 分支也走 resolveErrorMessage → 与「映射缺失即回退」口径不符；
    // 或静默不提示 → 未知错误用户完全无反馈
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 418, { errors: { errorCode: 'VALIDATION_FAILED' }, message: 'TEAPOT' })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe('TEAPOT')
    msg.error.mockClear()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 418, {}))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.requestFailed'))
  })

  test('错误归一后原样 reject：调用方拿到原始 error（不被替换/包装）', async () => {
    // 防退化：拦截器把错误替换成普通 Error 或吞掉 reject → 调用方失去 status/config 判定能力
    const { apiClient } = await loadAll()
    const original = httpError({}, 400, { message: 'x' })
    apiClient.defaults.adapter = () => Promise.reject(original)
    const got = await apiClient.get('/x').catch((e) => e)
    expect(got).toBe(original)
  })
})

describe('网络错误 / 配置错误 / 取消的错误分派', () => {
  test('无 response 有 request：网络错误走 networkError 文案', async () => {
    // 防退化：网络错误落入「配置错误」或直接静默
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) => Promise.reject(networkError(config))
    const got = await apiClient.get('/x').catch((e) => e)
    expect(got.request).toBeTruthy()
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.networkError'))
  })

  test('请求配置错误（无 request 无 response）：优先回显 error.message，空 message 走兜底', async () => {
    // 防退化：配置错误也显示「网络错误」（误导排查方向）；空 message 时提示空白
    const { apiClient, i18n } = await loadAll()
    apiClient.interceptors.request.use(() => {
      throw new Error('cfg-boom')
    })
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config))
    await apiClient.get('/x').catch((e) => e)
    expect(msg.error.mock.calls[0][0]).toBe('cfg-boom')
    msg.error.mockClear()

    // 空 message 的配置错误
    const fresh = await loadAll()
    fresh.apiClient.interceptors.request.use(() => {
      throw new Error('')
    })
    fresh.apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config))
    await fresh.apiClient.get('/x').catch((e) => e)
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.requestConfigError'))
  })

  test('取消错误：reject 原始 CanceledError，不弹任何提示', async () => {
    // 防退化：取消被当业务错误弹红框（用户切页后看到上一页的假错误）
    const { apiClient } = await loadAll()
    const canceled = new CanceledError(null, { url: '/x' })
    apiClient.defaults.adapter = () => Promise.reject(canceled)
    const got = await apiClient.get('/x').catch((e) => e)
    expect(got).toBe(canceled)
    expect(got.code).toBe('ERR_CANCELED')
    expect(msg.error).not.toHaveBeenCalled()
    expect(msg.warning).not.toHaveBeenCalled()
  })
})

describe('AUTH_ENCRYPTED_CREDENTIAL_INVALID 自愈', () => {
  test('密文被拒：统一失效公钥缓存，且不影响原有错误提示', async () => {
    // 防退化：只在 LoginView 接自愈 → 注册/改密入口换钥后不再自愈；
    // 或自愈时吞掉错误提示
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        httpError(config, 400, { errors: { errorCode: 'AUTH_ENCRYPTED_CREDENTIAL_INVALID' } })
      )
    await apiClient.get('/x').catch((e) => e)
    expect(invalidatePublicKeyCache).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(
      i18n.global.t('errors.authEncryptedCredentialInvalid')
    )
  })

  test('登录端点的凭据无效同样失效公钥缓存（ENC_INVALID 合并后自愈不丢）', async () => {
    // 防退化：登录 ENC_INVALID 与 INVALID_CREDENTIALS 对客合并为同一 401 后，
    // 若不自带失效，服务端轮换密钥时用户每次提交都拿到旧公钥、永远失败
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 401, { errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' } }))
    await apiClient.post('/auth/login', { encPassword: 'x' }).catch((e) => e)
    expect(invalidatePublicKeyCache).toHaveBeenCalledTimes(1)
  })

  test('其他错误码/其他端点不触发公钥缓存失效', async () => {
    // 防退化：无差别 invalidate → 每次登录失败都多打一次公钥请求
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 400, { errors: { errorCode: 'AUTH_INVALID_CREDENTIALS' } }))
    await apiClient.get('/x').catch((e) => e)
    expect(invalidatePublicKeyCache).not.toHaveBeenCalled()
  })
})

describe('请求取消机制', () => {
  test('cancelAllPendingRequests：只取消 GET，写请求保留并返回计数', async () => {
    // 防退化：无条件取消全部 → 写请求可能已落库却被前端当「取消」，用户重复提交；
    // 或计数错误（调用方/监控依赖它）
    const { apiClient, cancelAllPendingRequests } = await loadAll()
    const inflight = {}
    apiClient.defaults.adapter = (config) => hangingAdapter(config, (c) => (inflight[c.url] = c))
    const getP = apiClient.get('/slow-get').catch((e) => e)
    const postP = apiClient.post('/write', { a: 1 }).catch((e) => e)
    const delP = apiClient.delete('/write/1').catch((e) => e)
    await waitUntil(() => inflight['/slow-get'] && inflight['/write'] && inflight['/write/1'])

    const result = cancelAllPendingRequests('test-reason')
    expect(result).toEqual({ cancelled: 1, kept: 2 })

    const getErr = await getP
    expect(getErr.code).toBe('ERR_CANCELED')
    expect(getErr.name).toBe('CanceledError')
    expect(inflight['/slow-get'].signal.reason).toBe('test-reason')

    // 写请求未被 abort，仍可正常完成
    inflight['/write'].__resolve()
    inflight['/write/1'].__resolve()
    expect((await postP).status).toBe(200)
    expect((await delP).status).toBe(200)
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('取消后 pendingControllers 已清空：重复调用返回零计数', async () => {
    // 防退化：取消后不删表 → 表项泄漏（长会话内存增长）、重复取消重复计数
    const { apiClient, cancelAllPendingRequests } = await loadAll()
    const inflight = {}
    apiClient.defaults.adapter = (config) => hangingAdapter(config, (c) => (inflight[c.url] = c))
    const p = apiClient.get('/a').catch((e) => e)
    await waitUntil(() => inflight['/a'])
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 1, kept: 0 })
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 0, kept: 0 })
    await p
  })

  test('成功与失败请求都会从取消表清理（不泄漏 controller）', async () => {
    // 防退化：只在取消路径删表 → 正常完成的请求永久滞留（内存泄漏），
    // 且后续 cancelAllPendingRequests 会把已完成的请求计入 cancelled
    const { apiClient, cancelAllPendingRequests } = await loadAll()
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config))
    await apiClient.get('/ok')
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 0, kept: 0 })

    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 500, { message: 'x' }))
    await apiClient.get('/fail').catch((e) => e)
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 0, kept: 0 })
  })

  test('取消错误不触发登出/跳转（401 分支不得误伤取消）', async () => {
    // 防退化：取消判定放在 401 分支之后 → 被取消请求若带 response 401 语义会触发登出；
    // 这里用「取消错误带 401 形态 response」锁定判定顺序
    const { apiClient, router } = await loadAll()
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    const canceled = new CanceledError(null, { url: '/x' })
    canceled.response = { status: 401, data: {}, config: { url: '/x' } }
    apiClient.defaults.adapter = () => Promise.reject(canceled)
    const got = await apiClient.get('/x').catch((e) => e)
    expect(got).toBe(canceled)
    expect(pushSpy).not.toHaveBeenCalled()
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('取消判定两种形态各自独立成立：name-only 与 code-only 都不弹提示', async () => {
    // 防退化：|| 被改成 && → 只有同时带 code 与 name 的错误才被识别；
    // 任何只带其一的取消形态都会掉进业务错误分支，切页后弹假红框
    const { apiClient } = await loadAll()
    const nameOnly = Object.assign(new Error('name-only'), { name: 'CanceledError' })
    apiClient.defaults.adapter = () => Promise.reject(nameOnly)
    const gotName = await apiClient.get('/x').catch((e) => e)
    expect(gotName).toBe(nameOnly)

    const codeOnly = Object.assign(new Error('code-only'), { code: 'ERR_CANCELED' })
    apiClient.defaults.adapter = () => Promise.reject(codeOnly)
    const gotCode = await apiClient.get('/x').catch((e) => e)
    expect(gotCode).toBe(codeOnly)

    expect(msg.error).not.toHaveBeenCalled()
    expect(msg.warning).not.toHaveBeenCalled()
  })

  test('取消的调用方拿到 reject（而非 resolve 一个假响应）', async () => {
    // 防退化：拦截器把取消「转成功」→ 视图会把空数据当真实列表渲染
    const { apiClient, cancelAllPendingRequests } = await loadAll()
    const inflight = {}
    apiClient.defaults.adapter = (config) => hangingAdapter(config, (c) => (inflight[c.url] = c))
    let settled = 'pending'
    const p = apiClient.get('/slow').then(
      () => (settled = 'resolved'),
      () => (settled = 'rejected')
    )
    await waitUntil(() => inflight['/slow'])
    cancelAllPendingRequests()
    await p
    expect(settled).toBe('rejected')
  })
})

describe('响应形状校验（verifyResponseShape）', () => {
  test('关键路径 /auth/me 形状漂移：console.error + ElMessage.warning', async () => {
    // 防退化：漂移不再打扰用户 → 登录/权限判断静默失效（本仓库已踩过 P3-38）
    const { apiClient, i18n } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { user: { username: 42 } } }))
    const r = await apiClient.get('/auth/me')
    expect(r.status).toBe(200) // 校验失败不阻断业务
    expect(driftCount()).toBe(1)
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('[schema-drift]')
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('/auth/me')
    expect(msg.warning).toHaveBeenCalledTimes(1)
    expect(msg.warning.mock.calls[0][0]).toBe(i18n.global.t('messages.schemaDrift'))
  })

  test('通用包络漂移：只记录不打扰用户', async () => {
    // 防退化：通用包络也弹窗 → 告警疲劳，真漂移被忽略
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: 'not-boolean' }))
    await apiClient.get('/devices')
    expect(driftCount()).toBe(1)
    expect(msg.warning).not.toHaveBeenCalled()
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('并发同 key 漂移：只记录一次（去重表在首个完成时即生效）', async () => {
    // 防退化：去重判定与写入之间存在异步间隙 → 同一漂移并发各报一次（告警风暴）
    const { apiClient, __getDriftCount } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: 'not-boolean' }))
    await Promise.all([apiClient.get('/same'), apiClient.get('/same')])
    expect(driftCount()).toBe(1)
    expect(__getDriftCount()).toBe(1)
  })

  test('同一 URL 不同 detail 视为两条漂移（键含 detail，非仅 URL）', async () => {
    // 防退化：漂移键退化为仅 URL → 同一接口第二种漂移被静默
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config, { success: 'bad' }))
    await apiClient.get('/same')
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, pagination: { page: 'bad' } }))
    await apiClient.get('/same')
    expect(driftCount()).toBe(2)
  })

  test('二进制与标量响应跳过形状校验（xlsx 导出不被误报）', async () => {
    // 防退化：二进制响应被当 JSON 校验 → 每次导出都弹一次假漂移告警
    const { apiClient, __getDriftCount } = await loadAll()
    const cases = [
      [new Blob(['x']), undefined],
      [new ArrayBuffer(8), undefined],
      [new Uint8Array([1, 2]), undefined],
      ['plain text', undefined],
      [{ any: 'thing' }, 'blob'],
      [null, undefined],
      [42, undefined],
    ]
    for (const [data, responseType] of cases) {
      apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config, data))
      await apiClient.get('/reports/export', responseType ? { responseType } : undefined)
    }
    expect(driftCount()).toBe(0)
    expect(__getDriftCount()).toBe(0)
  })

  test('形状校验自身抛错绝不影响业务响应（守卫分支）', async () => {
    // 防退化：去掉 try/catch → 校验器遇到恶意/畸形对象抛错时整个响应失败
    const { apiClient } = await loadAll()
    const hostile = new Proxy(
      {},
      {
        get(_t, k) {
          if (typeof k === 'symbol' || k === 'then') return Reflect.get(_t, k)
          throw new Error('validator-boom')
        },
      }
    )
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config, hostile))
    const r = await apiClient.get('/x')
    expect(r.status).toBe(200)
    expect(r.data).toBe(hostile)
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('/auth/session 用 SessionStatus schema：会话列表形状不会串到探测接口', async () => {
    // 防退化：SCHEMA_ROUTE_MAP 顺序/匹配写错 → 探测接口被按列表 schema 校验（或反之），
    // 每次会话恢复都误报漂移
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { authenticated: true } }))
    await apiClient.get('/auth/session')
    expect(driftCount()).toBe(0)

    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { authenticated: 'yes' } }))
    await apiClient.get('/auth/session')
    expect(driftCount()).toBe(1)
  })

  test('/auth/sessions GET 用列表 schema；DELETE 不误用（method 约束）', async () => {
    // 防退化：去掉 method 约束 → 每次踢除设备（DELETE 返回 { sid }）都误报一次漂移
    const { apiClient } = await loadAll()
    const session = { sid: 's1', current: true }
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { sessions: [session] } }))
    await apiClient.get('/auth/sessions')
    expect(driftCount()).toBe(0)

    // GET 时缺 sid → 列表 schema 应报漂移
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { sessions: [{ current: true }] } }))
    await apiClient.get('/auth/sessions')
    expect(driftCount()).toBe(1)

    // DELETE /auth/sessions/:sid 返回 { sid }：不属于 GET 列表 schema，也不属于
    // SessionStatus schema（要求 authenticated），只走通用包络 → 无漂移
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { sid: 's1' } }))
    await apiClient.delete('/auth/sessions/others')
    expect(driftCount()).toBe(1)
  })

  test('/auth/login 用登录 schema：MFA 一期无 user 合法，错误 user 形状报漂移', async () => {
    // 防退化：登录 schema 丢掉 optional → MFA 分支（无 user）被误报；
    // 或完全不校验 → userId/id/_id 全缺的 user 静默进入 store（P3-38 同类）
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { mfaRequired: true } }))
    await apiClient.get('/auth/login')
    expect(driftCount()).toBe(0)

    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { user: { username: 'alice' } } }))
    await apiClient.get('/auth/login')
    expect(driftCount()).toBe(1)
  })

  test('路由匹配基于 includes：带 query/前缀的 URL 仍命中专用 schema', async () => {
    // 防退化：改用全等匹配 → /auth/me?x=1 或 baseURL 前缀形态漏校验（静默失效类缺陷）
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { user: { username: 42 } } }))
    await apiClient.get('/auth/me?ts=1')
    expect(driftCount()).toBe(1)
  })
})

describe('api 方法表契约（动词/路径/参数透传）', () => {
  /** [调用路径, 期望动词, 期望 URL, 调用参数, 附加期望] */
  const ENTRIES = [
    ['auth.login', 'post', '/auth/login', [{ u: 1 }], { data: { u: 1 } }],
    ['auth.getCaptcha', 'get', '/auth/captcha', [], {}],
    ['auth.getCaptchaStatus', 'get', '/auth/captcha-status', [], {}],
    ['auth.register', 'post', '/auth/register', [{ u: 1 }], { data: { u: 1 } }],
    ['auth.logout', 'post', '/auth/logout', [], {}],
    ['auth.getMe', 'get', '/auth/me', [{ silent401: true }], { silent401: true }],
    ['auth.getSessionStatus', 'get', '/auth/session', [], {}],
    ['auth.changePassword', 'put', '/auth/password', [{ u: 1 }], { data: { u: 1 } }],
    ['auth.updateProfile', 'put', '/auth/profile', [{ u: 1 }], { data: { u: 1 } }],
    ['auth.refreshToken', 'post', '/auth/refresh', [{ u: 1 }], { data: { u: 1 } }],
    ['auth.getMfaStatus', 'get', '/auth/mfa/status', [], {}],
    ['auth.mfaEnroll', 'post', '/auth/mfa/enroll', [], {}],
    [
      'auth.mfaEnable',
      'post',
      '/auth/mfa/enable',
      [{ code: '123456' }],
      { data: { code: '123456' } },
    ],
    [
      'auth.mfaDisable',
      'post',
      '/auth/mfa/disable',
      [{ code: '123456' }],
      { data: { code: '123456' } },
    ],
    [
      'auth.regenerateRecoveryCodes',
      'post',
      '/auth/mfa/recovery-codes',
      [{ password: 'x' }],
      { data: { password: 'x' } },
    ],
    ['auth.listSessions', 'get', '/auth/sessions', [], {}],
    // 路径参数必须 encodeURIComponent：斜杠/问号/井号不得改变 URL 结构
    ['auth.revokeSession', 'delete', '/auth/sessions/a%2Fb%3Fc%23d', ['a/b?c#d'], {}],
    // 固定字面量，不能退化为 revokeSession('others') 的 :sid 分支
    ['auth.revokeOtherSessions', 'delete', '/auth/sessions/others', [], {}],

    ['users.getList', 'get', '/users', [{ page: 2 }], { params: { page: 2 } }],
    ['users.getById', 'get', '/users/u1', ['u1'], {}],
    ['users.getStats', 'get', '/users/stats', [], {}],
    ['users.create', 'post', '/users', [{ u: 1 }], { data: { u: 1 } }],
    ['users.update', 'put', '/users/u1', ['u1', { u: 1 }], { data: { u: 1 } }],
    ['users.delete', 'delete', '/users/u1', ['u1'], {}],
    [
      'users.assignRoles',
      'put',
      '/users/u1/roles',
      ['u1', { roles: ['r'] }],
      { data: { roles: ['r'] } },
    ],

    ['roles.getList', 'get', '/roles', [{ page: 2 }], { params: { page: 2 } }],
    ['roles.getAll', 'get', '/roles/all', [], {}],
    ['roles.getById', 'get', '/roles/r1', ['r1'], {}],
    ['roles.create', 'post', '/roles', [{ u: 1 }], { data: { u: 1 } }],
    ['roles.update', 'put', '/roles/r1', ['r1', { u: 1 }], { data: { u: 1 } }],
    ['roles.delete', 'delete', '/roles/r1', ['r1'], {}],
    [
      'roles.assignPermissions',
      'put',
      '/roles/r1/permissions',
      ['r1', { permissions: [] }],
      { data: { permissions: [] } },
    ],
    ['roles.getPermissionTree', 'get', '/roles/permissions/tree', [], {}],

    ['permissions.getList', 'get', '/permissions', [{ page: 1 }], { params: { page: 1 } }],
    ['permissions.getById', 'get', '/permissions/p1', ['p1'], {}],
    ['permissions.create', 'post', '/permissions', [{ u: 1 }], { data: { u: 1 } }],
    ['permissions.update', 'put', '/permissions/p1', ['p1', { u: 1 }], { data: { u: 1 } }],
    ['permissions.delete', 'delete', '/permissions/p1', ['p1'], {}],
    ['permissions.batchCreate', 'post', '/permissions/batch', [{ u: 1 }], { data: { u: 1 } }],

    ['devices.getList', 'get', '/devices', [{ page: 1 }], { params: { page: 1 } }],
    ['devices.getById', 'get', '/devices/d1', ['d1'], {}],
    ['devices.create', 'post', '/devices', [{ u: 1 }], { data: { u: 1 } }],
    ['devices.update', 'put', '/devices/d1', ['d1', { u: 1 }], { data: { u: 1 } }],
    ['devices.delete', 'delete', '/devices/d1', ['d1'], {}],
    [
      'devices.updateStatus',
      'put',
      '/devices/d1/status',
      ['d1', { status: 'on' }],
      { data: { status: 'on' } },
    ],
    [
      'devices.addMaintenance',
      'post',
      '/devices/d1/maintenance',
      ['d1', { content: 'x' }],
      { data: { content: 'x' } },
    ],
    ['devices.getStats', 'get', '/devices/stats', [], {}],
    ['devices.getExpiring', 'get', '/devices/expiring', [{ days: 7 }], { params: { days: 7 } }],

    ['alarms.getList', 'get', '/alarms', [{ page: 1 }], { params: { page: 1 } }],
    ['alarms.getById', 'get', '/alarms/a1', ['a1'], {}],
    ['alarms.report', 'post', '/alarms/report', [{ u: 1 }], { data: { u: 1 } }],
    ['alarms.dispatch', 'put', '/alarms/a1/dispatch', ['a1', { u: 1 }], { data: { u: 1 } }],
    ['alarms.arrive', 'put', '/alarms/a1/arrive', ['a1'], {}],
    ['alarms.resolve', 'put', '/alarms/a1/resolve', ['a1', { u: 1 }], { data: { u: 1 } }],
    [
      'alarms.markAsFalse',
      'put',
      '/alarms/a1/false-alarm',
      ['a1', { reason: 'x' }],
      { data: { reason: 'x' } },
    ],
    ['alarms.getStats', 'get', '/alarms/stats', [{ from: 'x' }], { params: { from: 'x' } }],

    ['inspections.getList', 'get', '/inspections', [{ page: 1 }], { params: { page: 1 } }],
    ['inspections.getById', 'get', '/inspections/i1', ['i1'], {}],
    ['inspections.create', 'post', '/inspections', [{ u: 1 }], { data: { u: 1 } }],
    ['inspections.update', 'put', '/inspections/i1', ['i1', { u: 1 }], { data: { u: 1 } }],
    ['inspections.start', 'put', '/inspections/i1/start', ['i1'], {}],
    [
      'inspections.complete',
      'put',
      '/inspections/i1/complete',
      ['i1', { u: 1 }],
      { data: { u: 1 } },
    ],
    ['inspections.review', 'put', '/inspections/i1/review', ['i1', { u: 1 }], { data: { u: 1 } }],
    [
      'inspections.cancel',
      'put',
      '/inspections/i1/cancel',
      ['i1', { reason: 'x' }],
      { data: { reason: 'x' } },
    ],
    ['inspections.delete', 'delete', '/inspections/i1', ['i1'], {}],
    ['inspections.getStats', 'get', '/inspections/stats', [], {}],

    ['reports.getDashboard', 'get', '/reports/dashboard', [], {}],
    ['reports.getMetrics', 'get', '/metrics', [], {}],
    ['reports.getDevices', 'get', '/reports/devices', [{ page: 1 }], { params: { page: 1 } }],
    ['reports.getAlarms', 'get', '/reports/alarms', [{ page: 1 }], { params: { page: 1 } }],
    [
      'reports.getInspections',
      'get',
      '/reports/inspections',
      [{ page: 1 }],
      { params: { page: 1 } },
    ],
    [
      'reports.export',
      'get',
      '/reports/export',
      [{ format: 'xlsx' }],
      { params: { format: 'xlsx' }, responseType: 'blob' },
    ],

    ['security.getOverview', 'get', '/security/overview', [], {}],
    ['security.getAlerts', 'get', '/security/alerts', [], {}],
    [
      'security.queryAuditLogs',
      'get',
      '/security/audit-logs',
      [{ page: 1 }],
      { params: { page: 1 } },
    ],
    ['security.getRegistrationConfig', 'get', '/security/config/allowPublicRegistration', [], {}],
    [
      'security.setRegistrationConfig',
      'put',
      '/security/config/allowPublicRegistration',
      [{ allow: true }],
      { data: { allow: true } },
    ],
    ['security.getLoginCaptchaConfig', 'get', '/security/config/loginCaptchaEnabled', [], {}],
    [
      'security.setLoginCaptchaConfig',
      'put',
      '/security/config/loginCaptchaEnabled',
      [{ enabled: true }],
      { data: { enabled: true } },
    ],
    ['security.getRegisterCaptchaConfig', 'get', '/security/config/registerCaptchaEnabled', [], {}],
    [
      'security.setRegisterCaptchaConfig',
      'put',
      '/security/config/registerCaptchaEnabled',
      [{ enabled: true }],
      { data: { enabled: true } },
    ],
    ['security.getIPList', 'get', '/security/ip-list', [{ page: 1 }], { params: { page: 1 } }],
    ['security.resetUserMfa', 'put', '/security/users/u1/mfa/reset', ['u1'], {}],
    [
      'security.addIPEntry',
      'post',
      '/security/ip-list',
      [{ ip: '1.2.3.4' }],
      { data: { ip: '1.2.3.4' } },
    ],
    ['security.removeIPEntry', 'delete', '/security/ip-list/e1', ['e1'], {}],
  ]

  test('全部端点的动词与路径符合后端契约，参数/响应类型原样透传', async () => {
    // 防退化：动词或路径被改错（如 update 误用 post、:sid 分支误用 others 字面量、
    // 导出丢掉 responseType: blob）→ 生产环境才暴露的 404/405/损坏下载
    const { api, apiClient } = await loadAll()
    const calls = []
    apiClient.defaults.adapter = (config) => {
      calls.push(config)
      return Promise.resolve(jsonOk(config))
    }
    for (const [path, method, url, args, extra] of ENTRIES) {
      const fn = path.split('.').reduce((obj, key) => obj[key], api)
      const resp = await fn(...args)
      const cfg = calls.at(-1)
      const label = `${path} (${method} ${url})`
      expect(resp.status, label).toBe(200)
      expect(cfg.method, label).toBe(method)
      expect(cfg.url, label).toBe(url)
      // 无条件断言全部维度：未声明的维度必须以 undefined 通过，避免「漏写期望」静默放行
      expect(cfg.params ?? null, label).toEqual(extra.params ?? null)
      expect(cfg.data === undefined ? null : JSON.parse(cfg.data), label).toEqual(
        extra.data ?? null
      )
      expect(cfg.responseType ?? null, label).toBe(extra.responseType ?? null)
      expect(cfg.silent401 ?? null, label).toBe(extra.silent401 ?? null)
    }
    expect(calls).toHaveLength(ENTRIES.length)
  })

  test('导出形态：具名 apiClient 与默认导出同一实例（全站 import 口径）', async () => {
    // 防退化：默认导出换成裸 axios 或新实例 → 全站拦截器/取消表失效
    const mod = await loadAll()
    expect(mod.default).toBe(mod.apiClient)
    expect(Object.keys(mod.api).sort()).toEqual([
      'alarms',
      'auth',
      'devices',
      'inspections',
      'permissions',
      'reports',
      'roles',
      'security',
      'users',
    ])
  })
})

describe('请求拦截器', () => {
  test('每个请求关联独立 AbortSignal，且未取消时不处于 aborted', async () => {
    // 防退化：共用同一个 controller（取消一个请求会误伤其他在途请求）
    const { apiClient } = await loadAll()
    const seen = []
    apiClient.defaults.adapter = (config) => {
      seen.push(config)
      return Promise.resolve(jsonOk(config))
    }
    await Promise.all([apiClient.get('/a'), apiClient.get('/b')])
    expect(seen).toHaveLength(2)
    for (const cfg of seen) {
      expect(cfg.signal).toBeInstanceOf(AbortSignal)
      expect(cfg.signal.aborted).toBe(false)
    }
    expect(seen[0].signal).not.toBe(seen[1].signal)
  })

  test('并发同 URL：取消表以不同 key 登记，两个在途请求都能被取消', async () => {
    // 防退化：reqKey 去掉随机段/时间戳 → 同 URL 并发请求互相覆盖，取消漏网
    const { apiClient, cancelAllPendingRequests } = await loadAll()
    const inflight = []
    apiClient.defaults.adapter = (config) => {
      inflight.push(config)
      return hangingAdapter(config)
    }
    const p1 = apiClient.get('/same').catch((e) => e)
    const p2 = apiClient.get('/same').catch((e) => e)
    await waitUntil(() => inflight.length === 2)
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 2, kept: 0 })
    const [e1, e2] = await Promise.all([p1, p2])
    expect(e1.code).toBe('ERR_CANCELED')
    expect(e2.code).toBe('ERR_CANCELED')
  })

  test('默认取消原因可观测；无在途请求时为零计数', async () => {
    // 防退化：默认原因丢失（调试时无法区分取消来源）；空表时误报计数
    const { apiClient, cancelAllPendingRequests, i18n } = await loadAll()
    expect(cancelAllPendingRequests()).toEqual({ cancelled: 0, kept: 0 })
    const inflight = []
    apiClient.defaults.adapter = (config) => {
      inflight.push(config)
      return hangingAdapter(config)
    }
    const p = apiClient.get('/slow').catch((e) => e)
    await waitUntil(() => inflight.length === 1)
    cancelAllPendingRequests()
    // 第 34 轮 L2：默认原因走 i18n（loadAll 固定 en-US，硬编码中文此处即红）；
    // 顺带钉住 en-US 词条值本身，防止词表被误改成别的文案
    expect(i18n.global.t('common.routeChangeCancel')).toBe(
      'Route change, cancelling in-flight requests'
    )
    expect(inflight[0].signal.reason).toBe(i18n.global.t('common.routeChangeCancel'))
    await p
  })

  test('不注入 Authorization 头（I-01 httpOnly cookie 方案）', async () => {
    // 防退化：重新引入 JS 侧令牌注入 → 回到 XSS 可窃取令牌的旧方案
    const { apiClient } = await loadAll()
    const seen = []
    apiClient.defaults.adapter = (config) => {
      seen.push(config)
      return Promise.resolve(jsonOk(config))
    }
    await apiClient.get('/devices')
    expect(seen[0].headers.Authorization).toBeUndefined()
    expect(seen[0].headers.authorization).toBeUndefined()
  })

  test('请求拦截器抛错：错误原样传递并走配置错误提示，适配器不被调用', async () => {
    // 防退化：拦截器异常被吞 → 请求静默消失，界面永远 loading
    const { apiClient, i18n } = await loadAll()
    let adapterCalls = 0
    apiClient.defaults.adapter = (config) => {
      adapterCalls += 1
      return Promise.resolve(jsonOk(config))
    }
    apiClient.interceptors.request.use(() => {
      throw new Error('req-interceptor-boom')
    })
    const got = await apiClient.get('/x').catch((e) => e)
    expect(adapterCalls).toBe(0)
    expect(got.message).toBe('req-interceptor-boom')
    expect(msg.error.mock.calls[0][0]).toBe('req-interceptor-boom')
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(i18n.global.t('messages.requestConfigError')).toBe('Request configuration error')
  })
})

describe('响应拦截器：成功路径', () => {
  test('成功响应原样返回，且不弹任何提示', async () => {
    const { apiClient } = await loadAll()
    const payload = { success: true, data: { list: [1, 2] } }
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config, payload))
    const r = await apiClient.get('/devices')
    expect(r.data).toBe(payload)
    expect(r.status).toBe(200)
    expect(msg.error).not.toHaveBeenCalled()
    expect(msg.warning).not.toHaveBeenCalled()
  })

  test('responseType: json 显式声明时仍做形状校验', async () => {
    // 防退化：跳过条件写成 responseType 真值即跳过 → 显式 json 的响应全部漏校验
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) => Promise.resolve(jsonOk(config, { success: 'bad' }))
    await apiClient.get('/devices', { responseType: 'json' })
    expect(driftCount()).toBe(1)
  })

  test('漂移告警文案与日志：URL 与 detail 都出现在 console.error', async () => {
    // 防退化：日志丢掉 URL/detail → 排障时无法定位是哪个接口漂了
    const { apiClient } = await loadAll()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve(jsonOk(config, { success: true, data: { sessions: [{ current: true }] } }))
    await apiClient.get('/auth/sessions')
    expect(driftCount()).toBe(1)
    const logged = consoleErrorSpy.mock.calls[0][0]
    expect(logged).toContain('/auth/sessions')
    expect(logged).toContain('sid')
    expect(msg.warning).toHaveBeenCalledTimes(1)
  })
})
