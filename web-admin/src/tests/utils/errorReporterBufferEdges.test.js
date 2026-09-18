/**
 * errorReporter 缓冲上限 / 截断边界 / 负载描述 / 扇出过滤 的分支补强（H-1）
 *
 * 由来：对既有 4 个 errorReporter 测试文件做手工变异，以下判据实测存活
 * （改坏源码一行，测试仍全绿），本文件逐条钉死：
 *   E13 pending 上限 30 被改小 → 待发送队列的裁剪语义无测试
 *   E15 truncate 的 `>` 改成 `>=` → 恰好等于上限的消息被多截一个字符，无测试
 *   E16 describeReason 的对象分支被删 → 非 Error 的 rejection 原因会退化成
 *       '[object Object]'，排障信息丢失，无测试
 *   E18 `entry.kind !== 'vitals'` 的 Sentry 过滤被删 → 性能指标被当异常外发，无测试
 *   E19 loadStored 的 Array.isArray 校验被删 → 损坏的本地留档会让读取直接抛错，无测试
 *   E20 persist 的 try/catch 被删 → 隐私模式下写入失败会反噬业务（record 抛错），无测试
 *   E22 isSensitiveKey 的下划线中缀判据（foo_token_bar）被删 → 漏码，无测试
 *   E24 errorHandler 的非 Error 归一化被删 → 消息变成 'undefined'，无测试
 *
 * 手法：每个用例 vi.resetModules() + 动态 import（errorReporter 有模块级缓冲与
 * 计时器状态）；同时拦下 window.addEventListener 只保留本实例的 pagehide 处理器，
 * 避免先前实例挂在同一 jsdom window 上的残留监听干扰计数（与 errorReporterFlushLock
 * 同一手法）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const captureException = vi.fn()
const captureMessage = vi.fn()
const init = vi.fn()
vi.mock('@sentry/vue', () => ({ init, captureException, captureMessage }))

class FakePerformanceObserver {
  static instances = []

  constructor(callback) {
    this.callback = callback
    FakePerformanceObserver.instances.push(this)
  }

  observe(options) {
    this.options = options
  }

  takeRecords() {
    return []
  }

  emit(entries) {
    this.callback({ getEntries: () => entries })
  }

  static byType(type) {
    return FakePerformanceObserver.instances.find((o) => o.options && o.options.type === type)
  }
}

let pagehideHandlers = []

/** 全新模块实例 + 捕获其（及 webVitals 的）pagehide 处理器 */
const setup = async ({ reportUrl = '', dsn = '' } = {}) => {
  vi.stubEnv('VITE_ERROR_REPORT_URL', reportUrl)
  vi.stubEnv('VITE_SENTRY_DSN', dsn)
  vi.resetModules()
  FakePerformanceObserver.instances.length = 0
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

/** 触发本实例注册的全部 pagehide 处理器（errorReporter.flush 与 webVitals.flush） */
const triggerFlush = () => {
  expect(pagehideHandlers.length).toBeGreaterThan(0)
  pagehideHandlers.forEach((handler) => handler())
}

const entryVia = (app, message) => {
  app.config.errorHandler(new Error(message), null, 'render')
}

describe('errorReporter 缓冲与负载边界（H-1）', () => {
  beforeEach(() => {
    localStorage.clear()
    captureException.mockClear()
    captureMessage.mockClear()
    init.mockClear()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  test('E13：待发送队列上限 30 条，超出后丢弃最旧（发出的批次是最新 30 条的开头）', async () => {
    const fetchMock = vi.fn(() => new Promise(() => {}))
    vi.stubGlobal('fetch', fetchMock)
    const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })

    for (let i = 0; i < 35; i += 1) entryVia(app, `m${i}`)

    triggerFlush()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const body = JSON.parse(fetchMock.mock.calls[0][1].body)
    // BATCH_SIZE=10：只发前 10 条；若上限 30 失效（35 条全留），这里会是 m0..m9
    expect(body.entries).toHaveLength(10)
    expect(body.entries[0].message).toBe('m5')
    expect(body.entries[9].message).toBe('m14')
  })

  test('E15：消息截断边界——恰好 500 字符不截断，501 字符截为 500 字符 + 省略号', async () => {
    const { mod, app } = await setup()
    const exact = 'a'.repeat(500)
    const over = 'b'.repeat(501)

    entryVia(app, exact)
    entryVia(app, over)

    const entries = mod.getLoggedErrors()
    expect(entries[0].message).toBe(exact)
    expect(entries[0].message).toHaveLength(500)
    expect(entries[1].message).toBe('b'.repeat(500) + '\u2026')
    expect(entries[1].message).toHaveLength(501)
  })

  test('E15b：超长 stack 按 2000 字符上限截断（同类边界，另一常量）', async () => {
    const { mod, app } = await setup()
    const err = new Error('stacked')
    err.stack = 'S'.repeat(2500)
    app.config.errorHandler(err, null, 'render')

    const entry = mod.getLoggedErrors()[0]
    expect(entry.stack).toBe('S'.repeat(2000) + '\u2026')
  })

  test('E16：非 Error 的 rejection 原因被 JSON 化（不得丢成 [object Object]）', async () => {
    const { mod } = await setup()
    const event = new Event('unhandledrejection')
    event.reason = { code: 42, detail: 'boom' }
    window.dispatchEvent(event)

    const entry = mod.getLoggedErrors().find((e) => e.kind === 'promise')
    expect(entry.message).toBe('{"code":42,"detail":"boom"}')
    expect(entry.stack).toBe('')
  })

  test('E16b：不可序列化（循环引用）的原因回退 String()，不抛错', async () => {
    const { mod } = await setup()
    const circular = {}
    circular.self = circular
    const event = new Event('unhandledrejection')
    event.reason = circular
    expect(() => window.dispatchEvent(event)).not.toThrow()

    const entry = mod.getLoggedErrors().find((e) => e.kind === 'promise')
    expect(entry.message).toBe('[object Object]')
  })

  test('E16c：字符串原因原样保留，不被 JSON 加引号', async () => {
    const { mod } = await setup()
    const event = new Event('unhandledrejection')
    event.reason = 'plain rejection'
    window.dispatchEvent(event)

    const entry = mod.getLoggedErrors().find((e) => e.kind === 'promise')
    expect(entry.message).toBe('plain rejection')
  })

  test('E19：本地留档不是数组时按空缓冲处理（损坏数据不得让读取抛错）', async () => {
    localStorage.setItem('fsrbac.errorLog', JSON.stringify({ not: 'array' }))
    const { mod, app } = await setup()

    expect(mod.getLoggedErrors()).toEqual([])

    entryVia(app, 'after corrupt')
    expect(mod.getLoggedErrors().map((e) => e.message)).toEqual(['after corrupt'])
  })

  test('E20：localStorage 写入被拒时 record 不抛错，缓冲仍在内存中可用', async () => {
    const { mod, app } = await setup()
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })
    try {
      expect(() => entryVia(app, 'quota full')).not.toThrow()
      expect(mod.getLoggedErrors().map((e) => e.message)).toEqual(['quota full'])
    } finally {
      spy.mockRestore()
    }
  })

  test('E22：下划线中缀/前缀/后缀三种边界组合都打码，postcode 类仍不误伤', async () => {
    const { mod } = await setup()
    // 中缀：旧实现只判 === / endsWith / startsWith 时这一条漏码（E22）
    expect(mod.redactUrl('/x?my_token_x=1')).toBe('/x?my_token_x=***')
    expect(mod.redactUrl('/x?token_scope=1')).toBe('/x?token_scope=***')
    expect(mod.redactUrl('/x?scope_token=1')).toBe('/x?scope_token=***')
    expect(mod.redactUrl('/x?postcode=100080')).toBe('/x?postcode=100080')
  })

  test('E24：errorHandler 收到非 Error 值时消息按 String() 归一（不得变成 undefined）', async () => {
    const { mod, app } = await setup()
    app.config.errorHandler('plain string failure', null, 'render')
    app.config.errorHandler({ code: 7 }, null, 'render')

    const entries = mod.getLoggedErrors()
    expect(entries[0].kind).toBe('vue')
    expect(entries[0].message).toBe('plain string failure')
    expect(entries[1].message).toBe('[object Object]')
  })

  test('sendBeacon 返回 false 时回退 fetch（beacon 队列满/被拒不得让批次丢失）', async () => {
    const beacon = vi.fn(() => false) // 浏览器拒绝入队
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)
    try {
      const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })
      entryVia(app, 'beacon refused')

      triggerFlush()

      expect(beacon).toHaveBeenCalledTimes(1)
      // 关键：false 必须走 fetch 回退，否则条目永远发不出去（只在内存里等下次）
      expect(fetchMock).toHaveBeenCalledTimes(1)
      const body = JSON.parse(fetchMock.mock.calls[0][1].body)
      expect(body.entries.map((e) => e.message)).toEqual(['beacon refused'])
    } finally {
      delete navigator.sendBeacon
    }
  })

  test('sendBeacon 成功时不发 fetch（正常路径不得产生重复上报）', async () => {
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)
    try {
      const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })
      entryVia(app, 'beacon accepted')

      triggerFlush()

      expect(beacon).toHaveBeenCalledTimes(1)
      expect(fetchMock).not.toHaveBeenCalled()
      // 负载内容经 Blob 传入：取回文本校验来源与条目
      const blob = beacon.mock.calls[0][1]
      const text = await blob.text()
      expect(JSON.parse(text)).toMatchObject({ source: 'web-admin' })
      expect(JSON.parse(text).entries.map((e) => e.message)).toEqual(['beacon accepted'])
    } finally {
      delete navigator.sendBeacon
    }
  })

  test('fetch 回退的出站请求契约：POST + JSON Content-Type + keepalive（收集端解析与页面卸载可靠性）', async () => {
    let resolveFetch
    const fetchMock = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve
        })
    )
    vi.stubGlobal('fetch', fetchMock)
    const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })
    entryVia(app, 'contract check')

    triggerFlush()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('https://collect.example/ingest')
    expect(init.method).toBe('POST')
    // 收集端按 Content-Type 决定是否 JSON.parse；缺失会导致条目被当纯文本丢弃
    expect(init.headers['Content-Type']).toBe('application/json')
    // keepalive：页面卸载途中发出的请求必须允许存活（否则 pagehide 通道形同虚设）
    expect(init.keepalive).toBe(true)
    // 主体形状与 source 标识
    expect(JSON.parse(init.body)).toMatchObject({ source: 'web-admin' })

    resolveFetch({ ok: true })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
  })

  test('未配置 VITE_ERROR_REPORT_URL：条目只入本地缓冲，任何时机都不得发起网络请求', async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
    const beacon = vi.fn(() => true)
    vi.stubGlobal('fetch', fetchMock)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    try {
      const { mod, app } = await setup({ reportUrl: '' })
      entryVia(app, 'no collector configured')

      triggerFlush()
      await new Promise((resolve) => setTimeout(resolve, 20))

      // 本地留档仍然生效（排障能力不依赖收集端）
      expect(mod.getLoggedErrors().map((e) => e.message)).toEqual(['no collector configured'])
      // 但一个字节都不许外发：flush 的 !reportUrl 短路必须生效
      expect(fetchMock).not.toHaveBeenCalled()
      expect(beacon).not.toHaveBeenCalled()
    } finally {
      delete navigator.sendBeacon
    }
  })

  test('scheduleFlush：10s 后定时器自动 flush，不需要任何页面事件（掉线用户的兜底通道）', async () => {
    vi.useFakeTimers()
    try {
      const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
      vi.stubGlobal('fetch', fetchMock)

      const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })
      entryVia(app, 'timer driven')

      // 未到点：不得发送
      expect(fetchMock).not.toHaveBeenCalled()
      await vi.advanceTimersByTimeAsync(9999)
      expect(fetchMock).not.toHaveBeenCalled()

      // 到点：定时器自己把批次发出去
      await vi.advanceTimersByTimeAsync(2)
      expect(fetchMock).toHaveBeenCalledTimes(1)
      const body = JSON.parse(fetchMock.mock.calls[0][1].body)
      expect(body.entries.map((e) => e.message)).toEqual(['timer driven'])
    } finally {
      vi.useRealTimers()
    }
  })

  test('scheduleFlush：定时器触发后 flushTimer 被复位，后续条目仍能被下一轮定时器发出', async () => {
    vi.useFakeTimers()
    try {
      const fetchMock = vi.fn(() => Promise.resolve({ ok: true }))
      vi.stubGlobal('fetch', fetchMock)
      const { app } = await setup({ reportUrl: 'https://collect.example/ingest' })

      entryVia(app, 'first window')
      await vi.advanceTimersByTimeAsync(10001)
      expect(fetchMock).toHaveBeenCalledTimes(1)

      // 关键：flushTimer 必须已复位为 null，否则 scheduleFlush 会永久短路，
      // 第二条及以后的错误只能等 pagehide 才发得出去（长驻页面上等于丢报）
      entryVia(app, 'second window')
      await vi.advanceTimersByTimeAsync(10001)
      expect(fetchMock).toHaveBeenCalledTimes(2)
      const body = JSON.parse(fetchMock.mock.calls[1][1].body)
      expect(body.entries.map((e) => e.message)).toEqual(['second window'])
    } finally {
      vi.useRealTimers()
    }
  })

  test('E18：vitals 条目只入本地缓冲，不转发 Sentry；普通错误仍转发（反证链路接通）', async () => {
    vi.stubGlobal('PerformanceObserver', FakePerformanceObserver)
    vi.spyOn(performance, 'getEntriesByType').mockImplementation(() => [])

    const { mod, app } = await setup({
      dsn: 'https://public@example.ingest.sentry.io/1',
    })

    FakePerformanceObserver.byType('event').emit([{ duration: 50 }])
    triggerFlush()

    const vitals = mod.getLoggedErrors().filter((e) => e.kind === 'vitals')
    expect(vitals).toHaveLength(1)
    expect(vitals[0].metric).toBe('INP')

    // 反证先做：普通错误确实会转发，证明 Sentry 链路已接上、异步加载已完成。
    // （若先断言「vitals 没转发」，可能只是动态 import 还没 resolve 的假阴性）
    app.config.errorHandler(new Error('real error'), null, 'render')
    await vi.waitFor(() => expect(captureException).toHaveBeenCalledTimes(1))
    expect(captureException.mock.calls[0][0].message).toBe('real error')

    // 此时链路已就绪：vitals 若会被转发，早就该出现第二次调用了
    expect(captureException).toHaveBeenCalledTimes(1)
    expect(captureMessage).not.toHaveBeenCalled()
  })
})
