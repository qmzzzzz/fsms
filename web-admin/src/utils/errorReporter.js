// 全局错误兜底（G-1）
// 线上前端异常的三个主要来源都到不了控制台之外：
//   1. Vue 组件渲染/生命周期错误被框架内部捕获（须挂 app.config.errorHandler）；
//   2. 脚本与资源加载错误需在捕获阶段监听 window error 才能拿到；
//   3. 未处理的 Promise rejection 有独立事件。
// 三路统一收敛到 localStorage 环形缓冲（上限 50 条），现场排障可直接取回；
// 配置 VITE_ERROR_REPORT_URL 后额外批量上报到收集端（上报失败静默，不影响页面）。
// 第四路：Web Vitals 性能指标（utils/webVitals.js）以 kind='vitals' 同通道上报。
//
// L-11：留档的 URL 经 redactUrl 打码后才写入（见该函数注释）。
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

// L-11：上报 URL 前对 query/hash 做敏感值打码。
//
// 与后端 utils/helpers.js 的 redactUrlQuery 同口径（键名保留、值替换为 ***），
// 但这里是**独立实现**而非跨端共享代码——前后端无法共享模块，
// 故两边的敏感键清单需要同步维护（改动时请一并更新，勿只改一侧）。
//
// 为什么要做：本模块把 URL 写入 localStorage 环形缓冲，并在配置
// VITE_ERROR_REPORT_URL / VITE_SENTRY_DSN 时扇出到外部收集端。
// 一旦出现 `?token=` / `?code=` / `?signature=` 类参数，明文凭据就会同时
// 落到浏览器本地存储与第三方服务，且**不会被清理**（缓冲按条数滚动，
// 不按时间过期）。当前路由确实没有这类参数，但这属于「今天安全、
// 明天加一个回调链接就泄露」的典型脆弱点，防护应在上报侧而非路由侧。
const SENSITIVE_QUERY_KEYS = [
  'password',
  'passwd',
  'pwd',
  'token',
  'access_token',
  'refresh_token',
  'secret',
  'apikey',
  'api_key',
  'code',
  'signature',
  'sign',
  'mfa',
  'otp',
  'captcha',
  'authorization',
  'session',
]

// 与后端一致的下划线边界感知：短键（code/sign）若用 includes 子串匹配，
// 会把 postcode / zipcode 这类合法业务参数一并打码，损失排障信息。
const isSensitiveKey = (lower) =>
  SENSITIVE_QUERY_KEYS.some(
    (s) =>
      lower === s ||
      lower.endsWith(`_${s}`) ||
      lower.startsWith(`${s}_`) ||
      lower.includes(`_${s}_`)
  )

/**
 * 对 URL 的 query 与 hash 做敏感值打码，保留路径与键名便于排障
 * @param {string} rawUrl 原始 URL（location.href 或相对路径）
 * @returns {string} 敏感值替换为 *** 后的 URL；入参非法时原样返回
 */
function redactUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return rawUrl

  const [beforeHash, ...hashParts] = rawUrl.split('#')
  const hash = hashParts.join('#')

  const qIndex = beforeHash.indexOf('?')
  const path = qIndex === -1 ? beforeHash : beforeHash.slice(0, qIndex)
  const query = qIndex === -1 ? '' : beforeHash.slice(qIndex + 1)

  const redactPairs = (text) =>
    text
      .split('&')
      .map((pair) => {
        const eq = pair.indexOf('=')
        if (eq === -1) return pair
        const key = pair.slice(0, eq)
        return isSensitiveKey(key.toLowerCase()) ? `${key}=***` : pair
      })
      .join('&')

  // hash 同样可能承载参数，两种形态都要处理：
  //   ① 路由 hash 内嵌 query：`#/cb?token=xxx`（SPA 常见）
  //   ② OAuth 隐式流的裸片段：`#access_token=xxx&expires_in=3600`
  // ① 的 `?` 之后才是参数区，若整段按 & 切分，`/cb?token` 会被当成键名，
  // 敏感键判定失配 → 漏码（本轮测试正是据此发现的）。
  let redactedHash = hash
  if (redactedHash) {
    const innerQ = redactedHash.indexOf('?')
    redactedHash =
      innerQ === -1
        ? redactPairs(redactedHash)
        : `${redactedHash.slice(0, innerQ + 1)}${redactPairs(redactedHash.slice(innerQ + 1))}`
    redactedHash = `#${redactedHash}`
  }

  if (qIndex === -1) return `${beforeHash}${redactedHash}`
  return `${path}?${redactPairs(query)}${redactedHash}`
}

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
    // 签名取跨版本最稳的最小集：错误带堆栈走 captureException，其余走消息级。
    // P3-68：必须把原始 stack 交给 Sentry，否则 Sentry 侧只看到「这里 new 出来的
    // 错误」的合成栈（forwardToSentry 的调用位置），真实出错点被替换掉。
    // 做法：用原始 stack 覆盖合成 Error 的 stack（Sentry 读 error.stack 做分组与
    // 归因），同时保留 message。
    if (entry.stack) {
      const captured = new Error(entry.message)
      captured.stack = entry.stack
      Sentry.captureException(captured)
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
    // L-11：原为 location.href 原样留档，query/hash 里的凭据会随之落盘并外发
    url: redactUrl(location.href),
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

// P3-67：并发锁。flush 可被三条路径同时触发（scheduleFlush 定时器、pagehide、
// 显式调用），彼此之间没有互斥：两条并发 flush 会各自取走同一批 batch 并各发一次，
// 收集端收到重复条目（去重靠 entry key，成本高且可能漏）。
// 锁的粒度是「一次 flush 调用」：sync 阶段（sendBeacon 成功）在同一个 tick 内完成，
// 异步阶段（fetch 回退）由 inFlight 挡住后续调用，完成后释放。
let flushInFlight = false

function flush() {
  if (flushInFlight) return
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
  flushInFlight = true
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
    .finally(() => {
      flushInFlight = false
    })
}

/** 供测试观察并发锁状态 */
export const __isFlushInFlight = () => flushInFlight

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
        // L-11：资源 URL 与 entry.url 同属上报字段，query/hash 里的凭据同样要打码
        //（如第三方脚本带上 ?token=... 时，此前的原样拼接会把凭据写进环形缓冲并外发）
        record(
          'resource',
          `加载失败: ${target.tagName} ${redactUrl(target.src || target.href)}`,
          '',
          {
            tag: target.tagName,
          }
        )
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

/**
 * 降级路径上报入口（P1-18）
 *
 * 供「能力降级但流程继续」的场景留痕（如 WebCrypto 不可用、WS 建连失败、
 * 权限热同步订阅失败）。这些降级此前完全静默：界面看起来正常，实际能力已
 * 削弱，线上无从发现。经此入口统一进入环形缓冲与可选外发通道。
 *
 * 与直接调用 record 的区别：kind 固定为 'degrade'，便于在留档中单独检索降级事件；
 * 去重行为与 record 一致（同一描述在 5s 窗口内折叠计数，避免重连风暴刷爆缓冲）。
 * @param {string} message 降级描述（含场景与后果）
 * @param {object} [extra] 附加上下文（如 error message / url）
 * @returns {void}
 */
export function reportDegradation(message, extra = {}) {
  const detail = typeof message === 'string' ? message : String(message)
  record('degrade', detail, '', extra)
}

export function getLoggedErrors() {
  return [...stored]
}

// L-11：导出脱敏函数供测试直接驱动（不导出则只能靠构造 location.href，
// jsdom 下改动 location 需整页导航，测不干净）。
export { redactUrl }

export function clearLoggedErrors() {
  stored = []
  persist()
}
