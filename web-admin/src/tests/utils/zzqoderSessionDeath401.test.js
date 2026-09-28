/**
 * 刷新成功但重试仍 401：会话已彻底不可用，必须提示并登出（Qoder 轮7）
 *
 * 401 拦截器的门是 `status===401 && !config._retried && !isAuthEntryPoint`。
 * 重试请求带着 `_retried=true`，所以第二次 401 既不再刷新、也进不了那段登出逻辑，
 * 直落 `switch case 401`，而那里只对**认证入口**（登录/MFA）提示 →
 * 普通接口的"第二次 401"得到的是：**没有提示、没有跳转、界面仍然显示已登录**。
 *
 * 真实可达形态：设备被踢/强制下线后 sid 失效，但 refresh cookie 还有效。
 * 于是每一次请求都是「刷新成功 → 重发 → 又 401 → 静默」，
 * 运维看到的是满屏空面板却不知道为什么，而 SessionManager 那边已经把他踢了。
 * 既有测试 `重试后仍 401：不再刷新、不无限循环` 只断言了"不循环"，没断言"要有反馈"。
 *
 * 修的是可观测性，不改循环约束：仍然只打一次刷新、只重发一次（n===2 照样成立）。
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

const loadAll = async () => {
  vi.resetModules()
  const apiMod = await import('@/utils/api')
  const i18n = (await import('@/i18n')).default
  const router = (await import('@/router')).default
  const axios = (await import('axios')).default
  i18n.global.locale.value = 'en-US'
  return { ...apiMod, i18n, router, axios }
}

const httpError = (config, status, data) =>
  new AxiosError(
    `Request failed with status code ${status}`,
    AxiosError.ERR_BAD_REQUEST,
    config,
    null,
    { status, data: data ?? {}, statusText: String(status), headers: {}, config }
  )

// 登出走的是 (async () => {...})() 的即发异步链，需要让出若干个宏任务
const settle = async () => {
  for (let i = 0; i < 6; i++) await new Promise((resolve) => setTimeout(resolve, 0))
}

describe('会话不可恢复的 401 必须给用户反馈', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('刷新成功但重试仍 401 → 提示 + 跳转登录，且仍然只重试一次', async () => {
    const { apiClient, axios, router } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      expect(n).toBeLessThanOrEqual(3) // 循环上限自证：真出现重试风暴这里先红
      return Promise.reject(httpError(config, 401, {}))
    }

    const e = await apiClient.get('/devices').catch((err) => err)

    expect(e.response.status).toBe(401)
    expect(n).toBe(2) // 一次原始 + 一次重试，不多不少
    expect(postSpy).toHaveBeenCalledTimes(1) // 不得刷新风暴
    await settle()
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
  })

  test('反向保护：silent401 探测在重试后仍 401 时依旧不打扰用户', async () => {
    const { apiClient, axios, router } = await loadAll()
    vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      return Promise.reject(httpError(config, 401, {}))
    }

    await apiClient.get('/auth/me', { silent401: true }).catch((e) => e)
    await settle()

    expect(n).toBe(2)
    expect(msg.error).not.toHaveBeenCalled()
    expect(pushSpy).not.toHaveBeenCalled()
  })

  test('反向保护：认证入口（登录）401 只提示一次，且绝不跳转', async () => {
    const { apiClient, axios, router } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({ data: { success: true } })
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      return Promise.reject(httpError(config, 401, { message: 'bad credentials' }))
    }

    await apiClient.post('/auth/login', { username: 'a', password: 'b' }).catch((e) => e)
    await settle()

    expect(n).toBe(1) // 登录入口不刷新
    expect(postSpy).not.toHaveBeenCalled() // P3-41: 不拿 refresh 去撞密码错误
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(pushSpy).not.toHaveBeenCalled()
  })

  test('刷新失败的路径提示不变（本次改动没有把两条路径变成两处弹一次）', async () => {
    const { apiClient, axios, router } = await loadAll()
    const postSpy = vi.spyOn(axios, 'post').mockRejectedValue(new Error('network'))
    const pushSpy = vi.spyOn(router, 'push').mockResolvedValue()
    let n = 0
    apiClient.defaults.adapter = (config) => {
      n += 1
      return Promise.reject(httpError(config, 401, {}))
    }

    await apiClient.get('/devices').catch((e) => e)
    await settle()

    expect(n).toBe(1) // 刷新失败 → 不重发
    expect(postSpy).toHaveBeenCalledTimes(1) // 确实试过刷新，失败后才登出
    expect(msg.error).toHaveBeenCalledTimes(1)
    expect(pushSpy).toHaveBeenCalledWith('/login')
  })
})
