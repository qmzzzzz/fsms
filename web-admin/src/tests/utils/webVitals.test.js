/**
 * Web Vitals 采集（G-1）测试
 *
 * jsdom 无 PerformanceObserver/真实性能条目，这里以桩替代：
 * 验证五类指标（TTFB/FCP/LCP/CLS/INP）的采集口径与页面隐藏时的一次性上报。
 */
import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest'
import { initWebVitals } from '@/utils/webVitals'

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
  let metrics
  let getEntriesSpy

  beforeAll(() => {
    metrics = []
    vi.stubGlobal('PerformanceObserver', MockPerformanceObserver)
    getEntriesSpy = vi
      .spyOn(performance, 'getEntriesByType')
      .mockImplementation((type) => (type === 'navigation' ? [{ responseStart: 120 }] : []))

    initWebVitals((metric) => metrics.push(metric))

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
  })

  afterAll(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  test('TTFB 在初始化时即从 navigation 条目取得', () => {
    expect(metrics).toContainEqual({ name: 'TTFB', value: 120 })
    expect(getEntriesSpy).toHaveBeenCalledWith('navigation')
  })

  test('FCP 取 first-contentful-paint 条目', () => {
    expect(metrics).toContainEqual({ name: 'FCP', value: 300 })
  })

  test('pagehide 时一次性上报 LCP（最后一条）/CLS（排除输入引发）/INP', () => {
    window.dispatchEvent(new Event('pagehide'))

    const names = metrics.map((m) => m.name)
    expect(names).toContain('LCP')
    expect(names).toContain('CLS')
    expect(names).toContain('INP')

    expect(metrics.find((m) => m.name === 'LCP').value).toBe(900)
    expect(metrics.find((m) => m.name === 'CLS').value).toBe(0.05)
    // INP 约 P98：3 个样本取最高档（约 120）
    expect(metrics.find((m) => m.name === 'INP').value).toBe(120)
  })

  test('flush 幂等：重复隐藏事件不重复上报', () => {
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
