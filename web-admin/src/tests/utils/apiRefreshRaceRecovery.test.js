/**
 * 刷新失败的会话判定：只有「明确被拒」才登出（2026-10-30）
 *
 * 缺陷（修复前）：401 拦截器里刷新一失败就无条件 forceSessionReset ——
 * `catch (_) {}` 之后没有区分「刷新令牌被服务端拒绝」与「刷新请求根本没打通」。
 * 真实可达的两种误杀：
 *  1. 多标签页几乎同时刷新：后端对并发刷新有宽限（services/authService/token.js
 *     的 ROTATE_REPLAY_GRACE_MS / CONCURRENT），败者拿到 503
 *     SECURITY_SERVICE_UNAVAILABLE（controllers/authController/credentials.js 的
 *     REFRESH_OUTCOME_RESPONSES）。此时浏览器里的 refresh cookie 已被胜者的
 *     Set-Cookie 换成新令牌，会话**完全有效**，却因为一次竞态被所有标签页登出；
 *  2. 刷新请求遇到网络抖动/超时/后端重启（5xx）：cookie 仍有效，同样被登出。
 *
 * 判据（本文件钉死）：
 *  - 只有「明确拒绝」（401/403，或 400 REFRESH_TOKEN_MISSING = 连刷新令牌都没有）
 *    才允许清会话；
 *  - 503 给一次静默恢复：等一小段让兄弟标签页的 Set-Cookie 落地后重试刷新，
 *    成功即重放原请求；仍失败则放弃本次请求（不提示、不登出）；
 *  - 网络错误/其它 5xx：直接放弃本次请求，不登出、不提示。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { AxiosError } from 'axios'

const msg = vi.hoisted(() => ({
  error: vi.fn(),
  warning: vi.fn(),
  success: vi.fn(),
  info: vi.fn(),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: msg }))

const invalidatePublicKeyCache = vi.hoisted(() => vi.fn())
vi.mock('@/utils/loginCipher', () => ({ invalidatePublicKeyCache }))

const load = async () => {
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

const jsonOk = (config, data) => ({ data, status: 200, statusText: 'OK', headers: {}, config })

const httpError = (config, status, data = {}) =>
  new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_REQUEST,
    config,
    null,
    { status, data, statusText: String(status), headers: {}, config }
  )

/** 刷新端点返回业务错（带 status + 错误码）：服务端「明确拒绝」的形态 */
const refreshRejection = (status, errorCode) =>
  new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_RESPONSE,
    { url: '/api/auth/refresh' },
    null,
    {
      status,
      data: { success: false, errors: { errorCode } },
      statusText: String(status),
      headers: {},
    }
  )

/** 网络层失败：没有 response（DNS/连接拒绝/超时/CORS） */
const refreshNetworkError = () =>
  new AxiosError(
    'Network Error',
    AxiosError.ERR_NETWORK,
    { url: '/api/auth/refresh' },
    {
      __fakeRequest: true,
    }
  )

const REFRESH_503 = () => refreshRejection(503, 'SECURITY_SERVICE_UNAVAILABLE')

/** 真实定时器轮转：forceSessionReset 的登出链是 fire-and-forget 的异步 IIFE */
const flush = async (ms = 40) => new Promise((r) => setTimeout(r, ms))

describe('刷新失败不得把有效会话登出（503 / 网络错误）', () => {
  let ctx

  const prepare = async () => {
    ctx = await load()
    ctx.pinia.setActivePinia(ctx.pinia.createPinia())
    msg.error.mockClear()
    msg.warning.mockClear()
    const authStore = ctx.storeMod.useAuthStore()
    authStore.setAuth({ userId: 'u1', username: 'alice' }, ['device:read'])
    const clearSpy = vi.spyOn(authStore, 'clearAuth')
    const pushSpy = vi.spyOn(ctx.router, 'push').mockResolvedValue()
    return { authStore, clearSpy, pushSpy }
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useRealTimers()
  })

  afterEach(() => {
    // axios 等 node_modules 依赖被 vitest 外部化、实例跨用例共享：
    // 不 restore 会让上一个用例的 spy 与 mockRejectedValueOnce 队列串到下一个用例。
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  test('503（并发刷新宽限的败者）：不登出、不提示；静默恢复只再刷一次即放弃本次请求', async () => {
    const { authStore, clearSpy, pushSpy } = await prepare()
    const { apiClient, axios, REFRESH_RACE_RECOVERY_DELAY_MS } = ctx
    const postSpy = vi.spyOn(axios, 'post').mockRejectedValue(REFRESH_503())
    let attempts = 0
    apiClient.defaults.adapter = (config) => {
      attempts += 1
      return Promise.reject(httpError(config, 401))
    }

    vi.useFakeTimers()
    const pending = apiClient.get('/devices').catch((e) => e)
    await vi.advanceTimersByTimeAsync(REFRESH_RACE_RECOVERY_DELAY_MS + 50)
    const err = await pending

    expect(err?.response?.status).toBe(401)
    // 恢复也失败：放弃本次请求，不重放（写请求重放有副作用风险）
    expect(attempts).toBe(1)
    // 首刷 + 静默恢复各一次；旧实现只有 1 次（没有恢复路径）
    expect(postSpy).toHaveBeenCalledTimes(2)
    // 旧实现：clearAuth + 广播 logout + 跳 /login + 弹「会话已失效」——全部不得发生
    expect(clearSpy).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
    expect(msg.error).not.toHaveBeenCalled()
    expect(authStore.currentUser).not.toBeNull()
  })

  test('503 静默恢复成功：重放原请求并返回结果（兄弟标签页已把 cookie 换新）', async () => {
    const { clearSpy, pushSpy } = await prepare()
    const { apiClient, axios, REFRESH_RACE_RECOVERY_DELAY_MS } = ctx
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValueOnce(REFRESH_503())
      .mockResolvedValueOnce({ data: { success: true } })
    let attempts = 0
    apiClient.defaults.adapter = (config) => {
      attempts += 1
      if (attempts === 1) return Promise.reject(httpError(config, 401))
      return Promise.resolve(jsonOk(config, { success: true, data: { items: [1, 2] } }))
    }

    vi.useFakeTimers()
    const pending = apiClient.get('/devices')
    await vi.advanceTimersByTimeAsync(REFRESH_RACE_RECOVERY_DELAY_MS + 50)
    const resp = await pending

    expect(resp.status).toBe(200)
    expect(resp.data.data.items).toEqual([1, 2])
    expect(attempts).toBe(2)
    expect(postSpy).toHaveBeenCalledTimes(2)
    expect(clearSpy).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('对照：刷新被明确拒绝（401）仍然登出——不能矫枉过正把「会话真死了」也放过', async () => {
    const { authStore, clearSpy, pushSpy } = await prepare()
    const { apiClient, axios, i18n } = ctx
    vi.spyOn(axios, 'post').mockRejectedValue(refreshRejection(401, 'REFRESH_TOKEN_INVALID'))
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401))
    const err = await apiClient.get('/devices').catch((e) => e)
    await flush()

    expect(err?.response?.status).toBe(401)
    expect(clearSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
    expect(authStore.currentUser).toBeNull()
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.sessionExpired'))
  })

  test('网络错误（无 response）：不登出、不提示，只让本次请求失败', async () => {
    const { authStore, clearSpy, pushSpy } = await prepare()
    const { apiClient, axios } = ctx
    const postSpy = vi.spyOn(axios, 'post').mockRejectedValue(refreshNetworkError())
    let attempts = 0
    apiClient.defaults.adapter = (config) => {
      attempts += 1
      return Promise.reject(httpError(config, 401))
    }
    const err = await apiClient.get('/devices').catch((e) => e)

    expect(err?.response?.status).toBe(401)
    expect(attempts).toBe(1)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(clearSpy).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
    expect(msg.error).not.toHaveBeenCalled()
    expect(authStore.currentUser).not.toBeNull()
  })

  test('刷新 403（明确拒绝该刷新请求）：按会话不可用处理，登出', async () => {
    const { clearSpy, pushSpy } = await prepare()
    const { apiClient, axios } = ctx
    vi.spyOn(axios, 'post').mockRejectedValue(refreshRejection(403, 'FORBIDDEN'))
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 401))
    await apiClient.get('/devices').catch((e) => e)
    await flush()

    expect(clearSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
  })
})
