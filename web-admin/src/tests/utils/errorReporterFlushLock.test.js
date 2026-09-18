/**
 * P3-67 回归：errorReporter.flush() 的并发锁
 *
 * 缺陷回顾（报告 §13 V-3）：flush 可被三条路径同时触发（scheduleFlush 定时器、
 * pagehide、显式调用），彼此无互斥。两条并发 flush 会各自取走同一批 batch 并
 * 各发一次 —— 收集端收到重复条目。
 *
 * 观测点：flush 的发送动作（sendBeacon 或 fetch 回退）。本套件让 fetch 悬挂在
 * 一个受控 Promise 上，模拟「第一路 flush 仍在进行中」，随后触发第二路 flush：
 * 有锁时第二路直接返回（fetch 只被调用一次）；无锁时第二路会重复发送同一批。
 * 锁必须在完成（resolve 或 reject）后释放，否则后续条目将永远发不出去。
 *
 * 隔离手法：每个用例 vi.resetModules() 后重新 import，会得到**新的**模块实例，
 * 但它注册的 pagehide 监听挂在同一个 jsdom window 上、旧实例的监听无法移除。
 * 因此这里拦下 addEventListener，只保留本实例注册的 pagehide 处理器并直接调用，
 * 避免旧实例（及其残留 pending）干扰计数。
 *
 * 前提：jsdom 不提供 navigator.sendBeacon（下方断言显式校验），
 * 若未来 jsdom 补上该能力，测试会失败提醒适配，而不是静默测不到东西。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const entryVia = (app, message) => {
  app.config.errorHandler(new Error(message), null, 'render')
}

let pagehideHandlers = []

/** 全新模块实例 + 捕获其 pagehide 处理器 */
const setup = async (reportUrl = 'https://collect.example/ingest') => {
  vi.stubEnv('VITE_ERROR_REPORT_URL', reportUrl)
  vi.resetModules()
  pagehideHandlers = []
  const originalAdd = window.addEventListener.bind(window)
  vi.spyOn(window, 'addEventListener').mockImplementation((type, handler, options) => {
    if (type === 'pagehide') {
      pagehideHandlers.push(handler)
      return
    }
    originalAdd(type, handler, options)
  })

  const mod = await import('@/utils/errorReporter')
  const app = { config: {} }
  mod.initErrorHandling(app)
  return { mod, app }
}

/** 触发本实例注册的 pagehide → flush（绕过旧实例残留监听） */
const triggerFlush = () => {
  expect(pagehideHandlers.length).toBeGreaterThan(0)
  pagehideHandlers.forEach((handler) => handler())
}

describe('flush 并发锁（P3-67）', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test('fetch 回退路径：并发触发 flush 只发送一次，完成后释放锁', async () => {
    expect(typeof navigator.sendBeacon).not.toBe('function') // 前提：走 fetch 回退

    let resolveFetch
    const fetchMock = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve
        })
    )
    vi.stubGlobal('fetch', fetchMock)

    const { mod, app } = await setup()
    entryVia(app, 'first entry')

    triggerFlush()
    triggerFlush() // 第二路并发：必须被锁挡下

    expect(fetchMock).toHaveBeenCalledTimes(1) // 无锁时此处为 2（重复发送同一批）
    expect(mod.__isFlushInFlight()).toBe(true)

    resolveFetch({ ok: true })
    await vi.waitFor(() => expect(mod.__isFlushInFlight()).toBe(false))

    // 锁已释放：新条目可以再次发送（防止「锁泄漏导致再也发不出去」）
    entryVia(app, 'second entry')
    triggerFlush()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('fetch 失败时锁在 finally 中释放，不阻塞后续发送', async () => {
    const fetchMock = vi.fn(() => Promise.reject(new Error('collector down')))
    vi.stubGlobal('fetch', fetchMock)

    const { mod, app } = await setup()
    entryVia(app, 'entry a')

    triggerFlush()
    await vi.waitFor(() => expect(mod.__isFlushInFlight()).toBe(false))

    entryVia(app, 'entry b')
    triggerFlush()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('sendBeacon 同步成功路径不受锁影响（连续两批都能发出）', async () => {
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)
    try {
      const { mod, app } = await setup()
      expect(typeof navigator.sendBeacon).toBe('function')

      entryVia(app, 'beacon batch 1')
      triggerFlush()
      entryVia(app, 'beacon batch 2')
      triggerFlush()

      expect(beacon).toHaveBeenCalledTimes(2)
      expect(fetchMock).not.toHaveBeenCalled()
      expect(mod.__isFlushInFlight()).toBe(false) // 同步路径不应留下锁
    } finally {
      delete navigator.sendBeacon
    }
  })

  test('无待发送条目时不触发任何发送（flush 的既有短路语义）', async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)

    const { mod } = await setup()
    triggerFlush()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(mod.__isFlushInFlight()).toBe(false)
  })
})
