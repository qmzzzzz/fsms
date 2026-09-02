// Web Vitals 零依赖采集（G-1）
//
// 为什么不用 web-vitals 库：核心指标用 PerformanceObserver 即可覆盖，
// 引一个依赖换来构建期多一段 chunk 与一条供应链面，收益不成立。
//
// 采集口径（与 Google Core Web Vitals 对齐）：
//   TTFB —— navigation.responseStart
//   FCP  —— paint 首帧内容绘制
//   LCP  —— largest-contentful-paint 的最后一条（规范取最后一次）
//   CLS  —— layout-shift 中非用户输入引发的位移累计
//   INP  —— event 交互时长的约 P98；无交互数据时回退 FID
// 结果在页面隐藏时一次性上报（record('vitals', ...)），避免采集本身
// 成为运行时开销来源。不支持的浏览器静默跳过，绝不影响业务。

let started = false

export function initWebVitals(onMetric) {
  if (started) return
  started = true
  if (typeof window === 'undefined' || typeof PerformanceObserver === 'undefined') return

  const report = (name, value) => {
    try {
      onMetric({ name, value })
    } catch (_) {
      // 上报链路异常不得反噬页面
    }
  }

  try {
    const [nav] = performance.getEntriesByType('navigation')
    if (nav && nav.responseStart > 0) report('TTFB', nav.responseStart)
  } catch (_) {
    /* 旧浏览器无 navigation 条目 */
  }

  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === 'first-contentful-paint') report('FCP', entry.startTime)
      }
    }).observe({ type: 'paint', buffered: true })
  } catch (_) {
    /* paint observer 不可用 */
  }

  let lcpValue = 0
  try {
    new PerformanceObserver((list) => {
      const entries = list.getEntries()
      if (entries.length) lcpValue = entries[entries.length - 1].startTime
    }).observe({ type: 'largest-contentful-paint', buffered: true })
  } catch (_) {
    /* LCP 不可用（老内核） */
  }

  let clsValue = 0
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        // hadRecentInput：用户输入后 500ms 内的位移不计入（规范口径）
        if (!entry.hadRecentInput) clsValue += entry.value
      }
    }).observe({ type: 'layout-shift', buffered: true })
  } catch (_) {
    /* CLS 不可用（无 layout-shift 的浏览器） */
  }

  const durations = []
  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.duration > 0) durations.push(entry.duration)
      }
    }).observe({ type: 'event', buffered: true, durationThreshold: 40 })
  } catch (_) {
    /* event timing 不可用 */
  }

  let fidValue = null
  try {
    new PerformanceObserver((list) => {
      const entry = list.getEntries()[0]
      if (entry) fidValue = entry.processingStart - entry.startTime
    }).observe({ type: 'first-input', buffered: true })
  } catch (_) {
    /* first-input 不可用 */
  }

  let flushed = false
  const flush = () => {
    if (flushed) return
    flushed = true
    if (lcpValue > 0) report('LCP', lcpValue)
    if (clsValue > 0) report('CLS', Math.round(clsValue * 1000) / 1000)
    if (durations.length > 0) {
      durations.sort((a, b) => a - b)
      // 官方 INP 取近似 P98（交互样本极少时即最差值）
      const idx = Math.min(durations.length - 1, Math.floor(durations.length * 0.98))
      report('INP', durations[idx])
    } else if (fidValue !== null) {
      report('FID', fidValue)
    }
  }

  // pagehide 为主通道；部分移动内核只触发 visibilitychange，双保险且仅执行一次
  window.addEventListener('pagehide', flush)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flush()
  })
}
