/**
 * 升级轮询所需的 api.js 能力（P1-3 / P2-5）
 *
 * 驱动方式与 apiRequestPipeline.test.js 一致：真实 apiClient + 自定义 adapter，
 * 每个用例 vi.resetModules() 取干净模块图（api.js 有若干模块级单例）。
 *
 * 这里只钉两条「少了就无法正确轮询」的契约：
 *  1. 调用方自带的 AbortSignal 必须被**转发**（原实现直接覆盖 config.signal：
 *     弹窗关闭后 abort 无效，旧任务的响应照样回填、盖住新任务）；
 *  2. config.silentErrors 只吞提示（3s 一次的自动轮询不该每次失败都弹红框），
 *     且不得顺带吞掉其它语义。
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
    { status, data, statusText: String(status), headers: {}, config }
  )

const networkError = (config) =>
  new AxiosError('Network Error', AxiosError.ERR_NETWORK, config, { __fakeRequest: true })

const sleep = (ms = 0) => new Promise((r) => setTimeout(r, ms))

/** 在途请求：abort 时以 CanceledError 拒绝（对齐 axios xhr 适配器的契约） */
const hangingAdapter = (config) =>
  new Promise((resolve, reject) => {
    if (config.signal.aborted) {
      reject(new CanceledError(null, config))
      return
    }
    config.signal.addEventListener('abort', () => reject(new CanceledError(null, config)), {
      once: true,
    })
  })

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('调用方 AbortSignal 的转发（P1-3）', () => {
  test('abort 调用方的 signal 能真正中断在途请求（原实现覆盖了 config.signal）', async () => {
    const { apiClient } = await load()
    let seenSignal
    apiClient.defaults.adapter = (config) => {
      seenSignal = config.signal
      return hangingAdapter(config)
    }

    const caller = new AbortController()
    const done = apiClient
      .get('/security/upgrade/jobs/job-1', { signal: caller.signal, silentErrors: true })
      .catch((e) => e)
    await sleep(0)
    expect(seenSignal).toBeTruthy()
    expect(seenSignal.aborted).toBe(false)

    caller.abort()
    const err = await done
    // 真正的取消语义：以 CanceledError 结束，而不是请求继续在飞、响应照样回填
    expect(err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError').toBe(true)
    // 取消是预期结果：不弹提示
    expect(msg.error).not.toHaveBeenCalled()
  })

  test('路由切换的批量取消仍然有效（自带 signal 不得破坏 pendingControllers）', async () => {
    const { apiClient, cancelAllPendingRequests } = await load()
    apiClient.defaults.adapter = (config) => hangingAdapter(config)

    const caller = new AbortController()
    const done = apiClient
      .get('/security/upgrade/jobs/job-2', { signal: caller.signal, silentErrors: true })
      .catch((e) => e)
    await sleep(0)

    const result = cancelAllPendingRequests('route change')
    expect(result.cancelled).toBe(1)
    const err = await done
    expect(err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError').toBe(true)
  })
})

describe('silentErrors：轮询失败不打扰用户（P2-5）', () => {
  test('4xx / 5xx / 网络错误三种形态都不弹提示', async () => {
    const { apiClient } = await load()
    for (const failure of [
      (config) => Promise.reject(httpError(config, 404, {})),
      (config) => Promise.reject(httpError(config, 502, {})),
      (config) => Promise.reject(httpError(config, 403, {})),
      (config) => Promise.reject(networkError(config)),
    ]) {
      msg.error.mockClear()
      msg.warning.mockClear()
      apiClient.defaults.adapter = failure
      const err = await apiClient
        .get('/security/upgrade/jobs/job-3', { silentErrors: true })
        .catch((e) => e)
      expect(err).toBeTruthy()
      expect(msg.error).not.toHaveBeenCalled()
      expect(msg.warning).not.toHaveBeenCalled()
    }
  })

  test('对照：未声明 silentErrors 时照旧弹一次具体文案（静默不是全局静音）', async () => {
    const { apiClient } = await load()
    apiClient.defaults.adapter = (config) => Promise.reject(httpError(config, 404, {}))
    await apiClient.get('/security/upgrade/jobs/job-4').catch((e) => e)
    expect(msg.error).toHaveBeenCalledTimes(1)
  })
})

describe('升级端点透传 config', () => {
  test('getUpgradeJob / getUpgradeOverview 把 signal 与 silentErrors 交给 axios', async () => {
    const { api, apiClient } = await load()
    const seen = []
    apiClient.defaults.adapter = (config) => {
      seen.push(config)
      return Promise.resolve(jsonOk(config, { success: true, data: { job: { id: 'job-5' } } }))
    }
    const ctrl = new AbortController()

    await api.security.getUpgradeJob('job-5', { signal: ctrl.signal, silentErrors: true })
    await api.security.getUpgradeOverview({ silentErrors: true })

    expect(seen[0].url).toBe('/security/upgrade/jobs/job-5')
    expect(seen[0].silentErrors).toBe(true)
    // 请求拦截器把调用方的 signal 转发到内部 controller（见 api.js 注释）
    expect(seen[0].signal).toBeTruthy()
    expect(seen[0].signal).not.toBe(ctrl.signal)
    expect(seen[1].url).toBe('/security/upgrade')
    expect(seen[1].silentErrors).toBe(true)
  })
})

describe('silentErrors 不得吞掉 401 登出链（A1 回归）', () => {
  /**
   * 判据：静音只作用于「提示」，401 的刷新 + forceSessionReset 必须照旧。
   *
   * 退化形态（修复前）：`if (!silentErrors)` 把整个 switch 一起关掉，于是
   * 「刷新成功后重发仍 401」既不登出也不跳登录页，页面带着失效会话继续轮询。
   * 升级进度轮询是唯一的 silentErrors 调用方（3s 一次），这条路径真实可达。
   */
  test('静音态 + 刷新成功 + 重发仍 401 ⇒ 必须 forceSessionReset（清认证并跳登录）', async () => {
    const { apiClient, router, axios, pinia, storeMod, i18n } = await load()
    pinia.setActivePinia(pinia.createPinia())
    const authStore = storeMod.useAuthStore()
    authStore.setAuth({ userId: 'u1', username: 'alice' }, ['security:config'])
    const clearSpy = vi.spyOn(authStore, 'clearAuth')
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    // 刷新成功（Set-Cookie 由浏览器处理），但重发依旧 401
    vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    let attempts = 0
    apiClient.defaults.adapter = (config) => {
      attempts += 1
      return Promise.reject(httpError(config, 401, {}))
    }

    const err = await apiClient
      .get('/security/upgrade/jobs/job-6', { silentErrors: true })
      .catch((e) => e)
    await sleep(20)

    expect(err?.response?.status).toBe(401)
    // 刷新确实被尝试过（不是提前短路）
    expect(attempts).toBe(2)
    // 登出链照旧：清本地认证 + 跳登录页
    expect(clearSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
    expect(authStore.currentUser).toBeNull()
    // 静音只吞「普通失败的提示」：登出链自带的「会话已失效」属于登出本身，
    // 只弹一次（不是每次轮询一条），因此这里断言"恰好 1 条且是会话失效文案"。
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(msg.error.mock.calls[0][0]).toBe(i18n.global.t('messages.sessionExpired'))
  })

  test('对照：静音态下 403 仍不弹提示（结论由 reject 交还调用方）', async () => {
    const { apiClient } = await load()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(httpError(config, 403, { errors: { errorCode: 'FORBIDDEN' } }))
    const err = await apiClient
      .get('/security/upgrade/jobs/job-7', { silentErrors: true })
      .catch((e) => e)
    expect(err?.response?.status).toBe(403)
    expect(msg.error).not.toHaveBeenCalled()
  })
})
