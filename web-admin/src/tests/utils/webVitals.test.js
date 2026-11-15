/**
 * Web Vitals 采集（G-1）测试
 *
 * jsdom 无 PerformanceObserver/真实性能条目，这里以桩替代：
 * 验证五类指标（TTFB/FCP/LCP/CLS/INP）的采集口径与页面隐藏时的一次性上报。
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'

class MockPerformanceObserver {
  static instances = []

  constructor(callback) {
    this.callback = callback
    MockPerformanceObserver.instances.push(this)
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
    return MockPerformanceObserver.instances.find((o) => o.options && o.options.type === type)
  }
}

describe('webVitals 采集', () => {
  // P3（2026-11-15 审计）：initWebVitals 是模块级单例（started 旗标），旧写法在
  // beforeAll 里初始化一次并共享同一个 metrics 数组——「pagehide 上报」与
  // 「flush 幂等」两条用例都派发 pagehide，LCP 计数取决于谁先跑（乱序必红），
  // 单抽用例也要靠前面用例的副作用垫场。改为每条用例 resetModules 后独立
  // 初始化 + 局部数组：任一用例单独抽跑、任意顺序都自洽。
  let initWebVitals
  let metrics
  let getEntriesSpy

  beforeAll(() => {
    vi.stubGlobal('PerformanceObserver', MockPerformanceObserver)
    getEntriesSpy = vi
      .spyOn(performance, 'getEntriesByType')
      .mockImplementation((type) => (type === 'navigation' ? [{ responseStart: 120 }] : []))
  })

  beforeEach(async () => {
    vi.resetModules()
    MockPerformanceObserver.instances = []
    ;({ initWebVitals } = await import('@/utils/webVitals'))
    metrics = []
    initWebVitals((metric) => metrics.push(metric))
  })

  afterAll(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  /** 本用例组共用的四类性能条目（LCP 取最后一条、CLS 排除输入引发、INP 三样本） */
  const emitVitals = () => {
    MockPerformanceObserver.byType('paint').emit([
      { name: 'first-contentful-paint', startTime: 300 },
    ])
    MockPerformanceObserver.byType('largest-contentful-paint').emit([
      { startTime: 700 },
      { startTime: 900 }, // 规范取最后一条
    ])
    MockPerformanceObserver.byType('layout-shift').emit([
      { hadRecentInput: false, value: 0.05 },
      { hadRecentInput: true, value: 0.9 }, // 用户输入引发的位移不计入
    ])
    MockPerformanceObserver.byType('event').emit([
      { duration: 50 },
      { duration: 120 },
      { duration: 80 },
    ])
  }

  test('TTFB 在初始化时即从 navigation 条目取得', () => {
    expect(metrics).toContainEqual({ name: 'TTFB', value: 120 })
    expect(getEntriesSpy).toHaveBeenCalledWith('navigation')
  })

  test('FCP 取 first-contentful-paint 条目', () => {
    MockPerformanceObserver.byType('paint').emit([
      { name: 'first-contentful-paint', startTime: 300 },
    ])
    expect(metrics).toContainEqual({ name: 'FCP', value: 300 })
  })

  test('pagehide 时一次性上报 LCP（最后一条）/CLS（排除输入引发）/INP', () => {
    emitVitals()
    window.dispatchEvent(new Event('pagehide'))

    const names = metrics.map((m) => m.name)
    expect(names).toContain('LCP')
    expect(names).toContain('CLS')
    expect(names).toContain('INP')

    expect(metrics.find((m) => m.name === 'LCP').value).toBe(900)
    expect(metrics.find((m) => m.name === 'CLS').value).toBe(0.05)
    // INP P75：3 个样本按 nearest-rank 取最高档（约 120）
    expect(metrics.find((m) => m.name === 'INP').value).toBe(120)
  })

  test('flush 幂等：重复隐藏事件不重复上报', () => {
    emitVitals()
    window.dispatchEvent(new Event('pagehide'))
    window.dispatchEvent(new Event('pagehide'))
    document.dispatchEvent(new Event('visibilitychange'))

    const lcpCount = metrics.filter((m) => m.name === 'LCP').length
    expect(lcpCount).toBe(1)
  })

  test('重复 init 不重复注册（幂等）', () => {
    const before = MockPerformanceObserver.instances.length
    initWebVitals(() => {})
    expect(MockPerformanceObserver.instances.length).toBe(before)
  })
})
