/**
 * P3-69 回归：INP 采集口径为 P75（而非 P98 / 最大值 / 平均值）
 *
 * 缺陷回顾：durations 排序后取 Math.floor(n * 0.98) —— 近似 P98，
 * 样本越多越贴近最差值，面板显示的不再是「多数用户的实际体验」。
 * Google 对 INP 的定义是第 75 百分位。
 *
 * 观测点：initWebVitals 回调里 metric.name === 'INP' 的数值。
 * 用 n=10 的样本 [10..100]（各自互不相同）区分三种口径：
 *   - nearest-rank P75 → index ceil(10*0.75)-1 = 7 → 80
 *   - 旧 P98          → index floor(10*0.98) = 9  → 100（最大值）
 *   - 平均值          → 55
 * 只有 80 能同时排除其余两种，断言因此具备区分力。
 *
 * 每个用例 vi.resetModules() + 动态 import：initWebVitals 有模块级 started
 * 幂等标记（防止重复注册监听），跨用例必须拿到全新模块实例。
 */
import { describe, test, expect, afterEach, vi } from 'vitest'

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

const collect = async (durations) => {
  vi.resetModules()
  MockPerformanceObserver.instances.length = 0
  // 必须在 import 之前完成打桩：initWebVitals 在调用时读全局 PerformanceObserver
  vi.stubGlobal('PerformanceObserver', MockPerformanceObserver)
  vi.spyOn(performance, 'getEntriesByType').mockImplementation(() => [])

  const { initWebVitals } = await import('@/utils/webVitals')
  const metrics = []
  initWebVitals((metric) => metrics.push(metric))
  MockPerformanceObserver.byType('event').emit(durations.map((duration) => ({ duration })))
  window.dispatchEvent(new Event('pagehide'))
  return metrics.find((m) => m.name === 'INP')
}

describe('INP 口径为 P75（P3-69）', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  test('10 个样本取 P75（80），不是 P98 也不是平均值', async () => {
    const inp = await collect([100, 10, 90, 20, 80, 30, 70, 40, 60, 50])
    expect(inp).toBeDefined()
    expect(inp.value).toBe(80)
    expect(inp.value).not.toBe(100)
    expect(inp.value).not.toBe(55)
  })

  test('样本不足时退化为该样本（n=1 即样本值，不会被 P75 取整吃掉）', async () => {
    const inp = await collect([120])
    expect(inp.value).toBe(120)
  })

  test('n=4 的 nearest-rank P75 取排序后第 3 个（ceil(4*0.75)-1 = 2）', async () => {
    const inp = await collect([10, 40, 20, 30])
    expect(inp.value).toBe(30)
  })

  test('INP 样本封顶：仅保留最近 50 条，更早的样本不参与统计（P3-20）', async () => {
    // 前 10 条是久远的高延迟交互（9999），后 50 条是 10..59：
    // 封顶后只统计最近 50 条 → P75 = sorted[ceil(50*0.75)-1] = 47；
    // 若不封顶（60 条全参与）P75 会是 54，且 9999 一旦留在样本里更会直接污染结果。
    const samples = Array.from({ length: 60 }, (_, i) => (i < 10 ? 9999 : i))
    const inp = await collect(samples)
    expect(inp.value).toBe(47)
    expect(inp.value).not.toBe(9999)
  })
})
