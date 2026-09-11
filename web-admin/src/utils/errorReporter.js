// 全局错误兜底（G-1）
// 线上前端异常的三个主要来源都到不了控制台之外：
//   1. Vue 组件渲染/生命周期错误被框架内部捕获（须挂 app.config.errorHandler）；
//   2. 脚本与资源加载错误需在捕获阶段监听 window error 才能拿到；
//   3. 未处理的 Promise rejection 有独立事件。
// 三路统一收敛到 localStorage 环形缓冲（上限 50 条），现场排障可直接取回；
// 配置 VITE_ERROR_REPORT_URL 后额外批量上报到收集端（上报失败静默，不影响页面）。
// 第四路：Web Vitals 性能指标（utils/webVitals.js）以 kind='vitals' 同通道上报。
// 可选扇出（G-1余）：配置 VITE_SENTRY_DSN 后，错误类条目动态加载 @sentry/vue
// 转发一份到 Sentry（Sentry 不接管全局事件，只被动接收本模块的转发，避免双报）。

import { initWebVitals } from './webVitals'

const STORAGE_KEY = 'fsrbac.errorLog'
const MAX_STORED = 50
const MAX_PENDING = 30
const BATCH_SIZE = 10
const FLUSH_INTERVAL_MS = 10000
const DEDUPE_WINDOW_MS = 5000
const MAX_MESSAGE_LEN = 500
const MAX_STACK_LEN = 2000

const reportUrl = import.meta.env.VITE_ERROR_REPORT_URL || ''
const sentryDsn = import.meta.env.VITE_SENTRY_DSN || ''

let stored = []
let pending = []
let flushTimer = null
const recentKeys = new Map()

// Sentry 动态加载：无 DSN 时永不 import（打包为独立 chunk，不占首屏）。
// 只做 captureException/captureMessage 的被动转发终点，全局事件监听归本模块。
// integrations: [] 显式关闭全部自动采集集成，尤其不能让 Sentry 的
// WebVitals/BrowserTracing 启动——其 INP 采集（web-vitals InteractionManager）
// 在浏览器性能条目时序竞争下会读 undefined.startTime 抛 TypeError。
// 本项目性能指标由自研 utils/webVitals.js 走同一缓冲通道上报，不依赖 Sentry。
//
// 2026-09-03 排查备忘（该 TypeError 复发时的处置）：
// - 报错函数 reportAllChanges 全仓唯一来源是 @sentry/browser-utils 的
//   web-vitals INP 采集器（getINP.js 的 InteractionManager），触发点在其
//   setTimeout 去抖回调（堆栈 n.timeout），无痕模式同样复现（非缓存问题）。
// - 注意 vite 只在启动时读取 .env：DSN 若是 dev server 启动后才移除，
//   运行中进程的 import.meta.env.VITE_SENTRY_DSN 仍是旧值，Sentry 仍会
//   动态加载——处置：重启 vite dev server。
// - 若项目配置过 vite-plugin-pwa，已注册的 Service Worker 可能缓存着
//   修复前的旧构建（旧版 Sentry 用法），Chrome 隐身窗口同样会运行已注册
//   的 SW——处置：DevTools → Application → Service Workers → Unregister
//   后硬刷新（或 chrome://serviceworker-internals 注销）。
let sentryLoading = null
function getSentry() {
  if (!sentryDsn) return null
  if (!sentryLoading) {
    sentryLoading = import('@sentry/vue')
      .then((Sentry) => {
        Sentry.init({
          dsn: sentryDsn,
          defaultIntegrations: false,
          autoSessionTracking: false,
          // 公开 API 再锁一次：不装载任何集成（含 WebVitals/BrowserTracing/GlobalHandlers）
          integrations: [],
        })
        return Sentry
      })
      .catch(() => null)
  }
  return sentryLoading
}

function forwardToSentry(entry) {
  const loader = getSentry()
  if (!loader) return
  loader.then((Sentry) => {
    if (!Sentry) return
    // 签名取跨版本最稳的最小集：错误带堆栈走 captureException，其余走消息级
    if (entry.stack) {
      Sentry.captureException(new Error(entry.message))
    } else {
      Sentry.captureMessage(`${entry.kind}: ${entry.message}`, 'error')
    }
  })
}

function loadStored() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed : []
  } catch (_) {
    return []
  }
}

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stored))
  } catch (_) {
    // 隐私模式/配额满时本地留档不可用，不应影响页面本身
  }
}

function truncate(value, max) {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function entryKey(entry) {
  return `${entry.kind}|${entry.message}|${(entry.stack || '').slice(0, 120)}`
}

function record(kind, message, stack = '', extra = {}) {
  const entry = {
    t: new Date().toISOString(),
    kind,
    message: truncate(message, MAX_MESSAGE_LEN),
    stack: truncate(stack, MAX_STACK_LEN),
    url: location.href,
    count: 1,
    ...extra,
  }

  // 同一错误短时间重复触发（如渲染循环报错）只累计计数，避免刷爆缓冲
  const key = entryKey(entry)
  const now = Date.now()
  const lastSeen = recentKeys.get(key)
  if (lastSeen && now - lastSeen < DEDUPE_WINDOW_MS) {
    const duplicate = stored.find((item) => entryKey(item) === key)
    if (duplicate) duplicate.count += 1
    persist()
    return
  }
  recentKeys.set(key, now)
  if (recentKeys.size > 200) recentKeys.clear()

  stored.push(entry)
  if (stored.length > MAX_STORED) stored.splice(0, stored.length - MAX_STORED)
  persist()

  if (reportUrl) {
    pending.push(entry)
    if (pending.length > MAX_PENDING) pending.splice(0, pending.length - MAX_PENDING)
    scheduleFlush()
  }

  // Sentry 扇出与批量上报相互独立；性能指标不进 Sentry（量大且非异常）
  if (entry.kind !== 'vitals') {
    forwardToSentry(entry)
  }
}

function scheduleFlush() {
  if (!reportUrl || flushTimer) return
  flushTimer = setTimeout(() => {
    flushTimer = null
    flush()
  }, FLUSH_INTERVAL_MS)
}

function flush() {
  if (!reportUrl || pending.length === 0) return
  const batch = pending.slice(0, BATCH_SIZE)
  const body = JSON.stringify({ source: 'web-admin', entries: batch })
  const sent =
    typeof navigator.sendBeacon === 'function'
      ? navigator.sendBeacon(reportUrl, new Blob([body], { type: 'application/json' }))
      : false
  if (sent) {
    pending = pending.slice(batch.length)
    return
  }
  fetch(reportUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    keepalive: true,
  })
    .then(() => {
      pending = pending.slice(batch.length)
    })
    .catch(() => {
      // 收集端不可达时保留待下次重试，静默避免二次干扰
    })
}

function describeReason(reason) {
  if (reason instanceof Error) return { message: reason.message, stack: reason.stack || '' }
  if (typeof reason === 'object' && reason !== null) {
    try {
      return { message: JSON.stringify(reason), stack: '' }
    } catch (_) {
      return { message: String(reason), stack: '' }
    }
  }
  return { message: String(reason), stack: '' }
}

export function initErrorHandling(app) {
  stored = loadStored()

  app.config.errorHandler = (error, _instance, info) => {
    const message = error instanceof Error ? error.message : String(error)
    record('vue', message, error instanceof Error ? error.stack || '' : '', { info })
    console.error('[errorHandler]', info, error)
  }

  window.addEventListener(
    'error',
    (event) => {
      const target = event.target
      // 捕获阶段能拿到元素级资源加载失败（script/link/img），与运行时错误分开归类
      if (target && target !== window && (target.src || target.href)) {
        record('resource', `加载失败: ${target.tagName} ${target.src || target.href}`, '', {
          tag: target.tagName,
        })
        return
      }
      record('window', event.message || 'unknown error', '', {
        file: event.filename || '',
        line: event.lineno || 0,
        col: event.colno || 0,
      })
    },
    true
  )

  window.addEventListener('unhandledrejection', (event) => {
    const { message, stack } = describeReason(event.reason)
    record('promise', message, stack)
  })

  if (reportUrl) {
    window.addEventListener('pagehide', flush)
    scheduleFlush()
  }

  // Web Vitals：页面隐藏时一次性上报（TTFB/FCP/LCP/CLS/INP，见 webVitals.js）
  initWebVitals(({ name, value }) => {
    const unit = name === 'CLS' ? '' : 'ms'
    record('vitals', `${name}=${Math.round(value * 100) / 100}${unit}`, '', {
      metric: name,
      value: Math.round(value * 100) / 100,
    })
  })
}

export function getLoggedErrors() {
  return [...stored]
}

export function clearLoggedErrors() {
  stored = []
  persist()
}
