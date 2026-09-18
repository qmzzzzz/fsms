/**
 * Web Vitals 采集口径的**分支级**补强（H-1）
 *
 * 由来：webVitals.test.js / webVitalsP75.test.js 覆盖了「正常路径」，
 * 但对手工变异（改坏源码一行）实测有 6 处存活：
 *   W3  duration > 0 过滤被删   → 0ms 样本混入分位计算
 *   W4  TTFB 的 responseStart > 0 门被删 → 上报 0/NaN 的伪 TTFB
 *   W6  FCP 的 entry.name 判据被删 → 任意 paint 条目都被当成 FCP
 *   W7  CLS 的 1/1000 舍入被删 → 浮点误差直接外发（0.1+0.2 → 0.30000000000000004）
 *   W9  无交互样本时的 FID 回退被删 → 老内核上 FID 永久丢失
 *   W10 visibilitychange 的 hidden 判据被删 → 页面可见时就提前 flush（指标被截断）
 * 本文件逐个把这些判据钉死：每条断言对应源码里一个可删除的判据。
 *
 * 手法与 webVitalsP75.test.js 一致：每个用例 vi.resetModules() + 动态 import，
 * 因为 initWebVitals 有模块级 started 幂等标记，跨用例必须拿到全新模块实例。
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

/** 建立全新模块实例，返回 { metrics, emit, setNav } 供用例驱动 */
const setup = async ({ navEntries = [] } = {}) => {
  vi.resetModules()
  MockPerformanceObserver.instances.length = 0
  vi.stubGlobal('PerformanceObserver', MockPerformanceObserver)
  const nav = navEntries
  vi.spyOn(performance, 'getEntriesByType').mockImplementation((type) =>
    type === 'navigation' ? nav : []
  )

  const { initWebVitals } = await import('@/utils/webVitals')
  const metrics = []
  initWebVitals((metric) => metrics.push(metric))
  return {
    metrics,
    emit: (type, entries) => MockPerformanceObserver.byType(type).emit(entries),
    flush: () => window.dispatchEvent(new Event('pagehide')),
  }
}

describe('Web Vitals 分支补强（H-1）', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  test('W3：duration=0 的事件样本被过滤，不参与 INP 分位（0ms 不是「慢」）', async () => {
    const { metrics, emit, flush } = await setup()
    // 有过滤：[50,100] → P75 index = ceil(2*0.75)-1 = 1 → 100
    // 无过滤：[0,0,50,100] → index = ceil(4*0.75)-1 = 2 → 50（分位被 0 值稀释）
    emit('event', [{ duration: 0 }, { duration: 0 }, { duration: 50 }, { duration: 100 }])
    flush()
    expect(metrics.find((m) => m.name === 'INP').value).toBe(100)
  })

  test('W4：navigation.responseStart 为 0 时不上报 TTFB（不得外发 0/NaN 伪值）', async () => {
    const { metrics } = await setup({ navEntries: [{ responseStart: 0 }] })
    expect(metrics.filter((m) => m.name === 'TTFB')).toHaveLength(0)
  })

  test('W4b：navigation 条目缺少 responseStart 字段同样不上报', async () => {
    const { metrics } = await setup({ navEntries: [{}] })
    expect(metrics.filter((m) => m.name === 'TTFB')).toHaveLength(0)
  })

  test('W4c：responseStart 为正数时正常上报（避免 W4 的修复把正常路径一起关掉）', async () => {
    const { metrics } = await setup({ navEntries: [{ responseStart: 88 }] })
    expect(metrics).toContainEqual({ name: 'TTFB', value: 88 })
  })

  test('W6：非 first-contentful-paint 的 paint 条目不产生 FCP', async () => {
    const { metrics, emit } = await setup()
    emit('paint', [{ name: 'first-paint', startTime: 111 }])
    expect(metrics.filter((m) => m.name === 'FCP')).toHaveLength(0)
  })

  test('W6b：同一批 paint 里只有 FCP 条目被采纳（名字判据逐条生效）', async () => {
    const { metrics, emit } = await setup()
    emit('paint', [
      { name: 'first-paint', startTime: 111 },
      { name: 'first-contentful-paint', startTime: 222 },
    ])
    const fcp = metrics.filter((m) => m.name === 'FCP')
    expect(fcp).toEqual([{ name: 'FCP', value: 222 }])
  })

  test('W7：CLS 按 1/1000 舍入，浮点累加误差不外发（0.1+0.2 → 0.3）', async () => {
    const { metrics, emit, flush } = await setup()
    emit('layout-shift', [
      { hadRecentInput: false, value: 0.1 },
      { hadRecentInput: false, value: 0.2 },
    ])
    flush()
    const cls = metrics.find((m) => m.name === 'CLS')
    expect(cls.value).toBe(0.3)
    // 反证：未舍入时真实值是 0.30000000000000004
    expect(cls.value).not.toBe(0.1 + 0.2)
  })

  test('W7b：全部位移都来自用户输入时不上报 CLS（不得外发 0 伪装成「零位移」）', async () => {
    const { metrics, emit, flush } = await setup()
    emit('layout-shift', [{ hadRecentInput: true, value: 0.9 }])
    flush()
    expect(metrics.filter((m) => m.name === 'CLS')).toHaveLength(0)
  })

  test('W7c：LCP 为 0 时不外发（startTime 0 属无效样本）', async () => {
    const { metrics, emit, flush } = await setup()
    emit('largest-contentful-paint', [{ startTime: 0 }])
    flush()
    expect(metrics.filter((m) => m.name === 'LCP')).toHaveLength(0)
  })

  test('W9：无交互样本时回退上报 FID = processingStart - startTime', async () => {
    const { metrics, emit, flush } = await setup()
    emit('first-input', [{ processingStart: 130, startTime: 30 }])
    flush()
    const fid = metrics.find((m) => m.name === 'FID')
    expect(fid).toBeDefined()
    expect(fid.value).toBe(100)
    // FID 与 INP 互斥：无交互样本时不得同时上报 INP
    expect(metrics.filter((m) => m.name === 'INP')).toHaveLength(0)
  })

  test('W9b：有交互样本时优先 INP，不再上报 FID（口径不重复计）', async () => {
    const { metrics, emit, flush } = await setup()
    emit('first-input', [{ processingStart: 130, startTime: 30 }])
    emit('event', [{ duration: 60 }])
    flush()
    expect(metrics.filter((m) => m.name === 'INP')).toHaveLength(1)
    expect(metrics.filter((m) => m.name === 'FID')).toHaveLength(0)
  })

  // 说明：本用例锁定的是「老内核不崩」这一用户可见契约，而非某个具体实现手法。
  // 实测：把全局守卫 `typeof PerformanceObserver === 'undefined'` 去掉后本用例仍绿，
  // 因为每段 `new PerformanceObserver(...)` 都各自被 try/catch 包住——两条实现路径
  // 对外都表现为「静默、零指标」，属**等价变异**（无缺陷差异）。将来若有人删掉那些
  // try/catch，本用例会立刻变红，这正是它的价值所在。
  test('W11：无 PerformanceObserver 的老内核静默跳过（注册零个 observer，不抛错）', async () => {
    vi.resetModules()
    MockPerformanceObserver.instances.length = 0
    vi.stubGlobal('PerformanceObserver', undefined)
    vi.spyOn(performance, 'getEntriesByType').mockImplementation(() => [])

    const { initWebVitals } = await import('@/utils/webVitals')
    const metrics = []
    expect(() => initWebVitals((m) => metrics.push(m))).not.toThrow()
    expect(metrics).toEqual([])
  })

  test('W12：空的 LCP/首输入批次不覆盖已有值、也不产生 NaN 指标', async () => {
    const { metrics, emit, flush } = await setup()
    emit('largest-contentful-paint', [{ startTime: 640 }])
    // 空批次：实现里 `if (entries.length)` 守卫必须拦住，否则 lcpValue 被写成 undefined
    emit('largest-contentful-paint', [])
    emit('first-input', [])
    flush()

    expect(metrics.find((m) => m.name === 'LCP').value).toBe(640)
    expect(metrics.filter((m) => m.name === 'FID')).toHaveLength(0)
    expect(metrics.every((m) => Number.isFinite(m.value))).toBe(true)
  })

  test('W10：页面可见时触发 visibilitychange 不 flush（指标未采集完不得提前上报）', async () => {
    const { metrics, emit } = await setup()
    emit('largest-contentful-paint', [{ startTime: 500 }])
    const spy = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible')
    document.dispatchEvent(new Event('visibilitychange'))
    spy.mockRestore()
    expect(metrics.filter((m) => m.name === 'LCP')).toHaveLength(0)
  })

  test('W10b：页面隐藏时触发 visibilitychange 完成 flush（移动内核主通道）', async () => {
    const { metrics, emit } = await setup()
    emit('largest-contentful-paint', [{ startTime: 500 }])
    const spy = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    document.dispatchEvent(new Event('visibilitychange'))
    spy.mockRestore()
    expect(metrics.find((m) => m.name === 'LCP').value).toBe(500)
  })
})
