/**
 * G-1余：Sentry 可选扇出测试
 *
 * 锁定两件事：
 * 1. 配置 VITE_SENTRY_DSN 时，错误条目转发到 Sentry（且 Sentry 不开全局集成，
 *    双报防护：全局事件监听只归 errorReporter 一家）；
 * 2. 未配置 DSN 时，Sentry 完全不加载、不调用，零副作用。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const captureException = vi.fn()
const captureMessage = vi.fn()
const init = vi.fn()

vi.mock('@sentry/vue', () => ({
  init,
  captureException,
  captureMessage,
}))

describe('errorReporter Sentry 扇出', () => {
  beforeEach(() => {
    vi.resetModules()
    captureException.mockClear()
    captureMessage.mockClear()
    init.mockClear()
    localStorage.clear()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test('配置 DSN：组件错误转发 Sentry，且全局集成保持关闭', async () => {
    vi.stubEnv('VITE_SENTRY_DSN', 'https://public@example.ingest.sentry.io/1')
    const { initErrorHandling } = await import('@/utils/errorReporter')
    const app = { config: {} }
    initErrorHandling(app)

    app.config.errorHandler(new Error('render boom'), null, 'render')

    await vi.waitFor(() => expect(captureException).toHaveBeenCalledTimes(1))
    // 锁定 Sentry 零自动采集集成：defaultIntegrations:false + integrations:[] 双保险，
    // 防止 WebVitals/BrowserTracing 的 INP 采集（undefined.startTime TypeError）被误开
    expect(init).toHaveBeenCalledWith(
      expect.objectContaining({
        dsn: 'https://public@example.ingest.sentry.io/1',
        defaultIntegrations: false,
        integrations: [],
      })
    )
    const initArg = init.mock.calls[0][0]
    const enabledIntegrations = Array.isArray(initArg.integrations) ? initArg.integrations : []
    expect(enabledIntegrations.map((i) => i.name)).not.toEqual(
      expect.arrayContaining(['WebVitals', 'BrowserTracing'])
    )
  })

  test('未配置 DSN：不调用、不初始化，错误仍入本地缓冲', async () => {
    vi.stubEnv('VITE_SENTRY_DSN', '')
    const { initErrorHandling, getLoggedErrors } = await import('@/utils/errorReporter')
    const app = { config: {} }
    initErrorHandling(app)

    app.config.errorHandler(new Error('local only'), null, 'render')
    await new Promise((resolve) => setTimeout(resolve, 30))

    expect(init).not.toHaveBeenCalled()
    expect(captureException).not.toHaveBeenCalled()
    expect(getLoggedErrors()).toHaveLength(1)
  })
})
