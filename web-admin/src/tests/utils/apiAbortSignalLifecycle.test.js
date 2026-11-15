/**
 * api.js 调用方 AbortSignal 转发监听的生命周期（P3-21）
 *
 * 缺陷回顾：请求拦截器把调用方 signal 的 abort 事件转发给内部 controller 时
 * 挂了监听，但只在「被取消」时由 once 语义移除——正常完成/失败路径不移除，
 * 同一个 AbortController 的多次请求会在其 signal 上按次数累积监听器（内存泄漏）。
 *
 * 驱动方式与 apiRequestPipeline.test.js 相同：真实 apiClient + 自定义 adapter
 * 走真实拦截器；signal 用可检数的替身（EventTarget 不暴露监听器清单）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
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

/** 可检数的 signal 替身：记录当前挂着的 abort 监听器 */
const makeFakeSignal = () => {
  const listeners = new Set()
  return {
    listeners,
    aborted: false,
    reason: undefined,
    addEventListener: (type, fn) => {
      if (type === 'abort') listeners.add(fn)
    },
    removeEventListener: (type, fn) => {
      listeners.delete(fn)
    },
  }
}

const loadApi = async () => {
  vi.resetModules()
  return import('@/utils/api')
}

describe('调用方 AbortSignal 的转发监听不累积（P3-21）', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    vi.resetModules()
  })

  test('同一 signal 连发多次成功请求：完成后监听器清零', async () => {
    const { apiClient } = await loadApi()
    apiClient.defaults.adapter = (config) =>
      Promise.resolve({
        data: { success: true, data: null },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      })
    const signal = makeFakeSignal()
    for (let i = 0; i < 5; i += 1) {
      await apiClient.get('/devices', { signal })
    }
    expect(signal.listeners.size).toBe(0)
  })

  test('请求失败（带 config 的 axios 错误）同样摘除监听器', async () => {
    const { apiClient } = await loadApi()
    apiClient.defaults.adapter = (config) =>
      Promise.reject(
        new AxiosError(
          'Request failed with status code 500',
          AxiosError.ERR_BAD_REQUEST,
          config,
          null,
          {
            status: 500,
            data: { success: false },
            statusText: '500',
            headers: {},
            config,
          }
        )
      )
    const signal = makeFakeSignal()
    await expect(apiClient.get('/devices', { signal })).rejects.toThrow()
    expect(signal.listeners.size).toBe(0)
  })

  test('调用方 abort 仍会转发给内部 controller（转发语义不被收敛破坏）', async () => {
    const { apiClient } = await loadApi()
    let adapterAbortReason
    apiClient.defaults.adapter = (config) =>
      new Promise((_, reject) => {
        config.signal.addEventListener('abort', () => {
          adapterAbortReason = config.signal.reason
          reject(new AxiosError('canceled', AxiosError.ERR_CANCELED, config))
        })
      })
    const controller = new AbortController()
    const p = apiClient.get('/devices', { signal: controller.signal }).catch((e) => e)
    // 等请求拦截器与 adapter 都跑完（均为微任务）再 abort，模拟真实调用时序
    await new Promise((r) => setTimeout(r, 0))
    controller.abort(new Error('route changed'))
    const err = await p
    expect(err.code).toBe(AxiosError.ERR_CANCELED)
    expect(adapterAbortReason).toBeInstanceOf(Error)
    expect(adapterAbortReason.message).toBe('route changed')
  })
})
