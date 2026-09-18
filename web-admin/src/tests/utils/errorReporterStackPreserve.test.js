/**
 * P3-68 回归：Sentry 转发必须携带**原始** stack
 *
 * 缺陷回顾：forwardToSentry 用 new Error(entry.message) 合成错误对象再交给
 * captureException。Sentry 读取 error.stack 做分组与归因，读到的是
 * 「forwardToSentry 调用位置」的合成栈 —— 真实出错点被替换，
 * Sentry 事件价值大幅降低（所有错误都会被归到同一帧）。
 *
 * 观测点：Sentry.captureException 收到的 Error 对象。有修复时其 stack
 * 等于被收集的原始 stack 字符串；未修复时是本地合成的栈（含本测试文件路径）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const captureException = vi.fn()
const captureMessage = vi.fn()
const init = vi.fn()

vi.mock('@sentry/vue', () => ({ init, captureException, captureMessage }))

const ORIGINAL_STACK = 'ORIGINAL_STACK_MARKER\n    at realErrorSite (app.js:1:1)'

describe('Sentry 转发保留原始 stack（P3-68）', () => {
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

  test('带 stack 的错误：captureException 收到原始 stack 而非合成栈', async () => {
    vi.stubEnv('VITE_SENTRY_DSN', 'https://public@example.ingest.sentry.io/1')
    const { initErrorHandling } = await import('@/utils/errorReporter')
    const app = { config: {} }
    initErrorHandling(app)

    const err = new Error('boom with stack')
    err.stack = ORIGINAL_STACK
    app.config.errorHandler(err, null, 'render')

    await vi.waitFor(() => expect(captureException).toHaveBeenCalledTimes(1))
    const captured = captureException.mock.calls[0][0]
    expect(captured.stack).toBe(ORIGINAL_STACK)
    expect(captured.message).toBe('boom with stack')
    // 合成栈会包含本模块/本测试文件的位置，原始栈不会
    expect(captured.stack).not.toContain('errorReporter')
    expect(captured.stack).not.toContain('javascript')
  })

  test('无 stack 时仍走 captureMessage（栈保留逻辑不改变该分支）', async () => {
    vi.stubEnv('VITE_SENTRY_DSN', 'https://public@example.ingest.sentry.io/1')
    const { initErrorHandling } = await import('@/utils/errorReporter')
    const app = { config: {} }
    initErrorHandling(app)

    const err = new Error('no stack here')
    err.stack = ''
    app.config.errorHandler(err, null, 'render')

    await vi.waitFor(() => expect(captureMessage).toHaveBeenCalledTimes(1))
    expect(captureException).not.toHaveBeenCalled()
  })
})
