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
const MAX_SANITIZE_DEPTH = 4
const MAX_SANITIZE_KEYS = 32
const MAX_SANITIZE_ITEMS = 20

// F-03 生命周期与体积上限。
// 条数上限（MAX_STORED）只挡住"写得多"，挡不住"写得旧"和"单条特别大"：
//   · 缓冲按条数滚动、不按时间过期时，一条上周的 `?token=...` 会一直躺在
//     localStorage 里，直到被 50 条新错误挤掉为止——排障价值早就没了，
//     泄露窗口却一直开着；
//   · message/stack 各自截断、extra 递归清洗，但 50 条叠加仍可能吃满配额，
//     而写入失败时 persist 静默吞掉异常（配额满 = 一条都留不下）。
// 两道闸都在落盘与加载时生效，且"至少保留一条最新现场"——宁可少留历史，
// 也不能把刚发生的错误一起裁掉。
const MAX_ENTRY_AGE_MS = 7 * 24 * 60 * 60 * 1000
const MAX_STORED_BYTES = 128 * 1024

// 错误对象经常是 AxiosError 的普通对象副本。请求配置、请求/响应对象和
// body/header 是排障时最容易携带口令、令牌和 Cookie 的部分，不能进入任何
// 本地缓冲或外发负载。这里按键整体丢弃，而不是把值替换成 ***，避免
// config.data 等深层结构被误认为可安全保留。
const DROPPED_OBJECT_KEYS = new Set([
  'config',
  'data',
  'headers',
  'request',
  'response',
  'cookie',
  'cookies',
])

// 普通对象 rejection 只保留错误摘要字段。detail 允许保留，
// 但其嵌套值仍会经过同一递归清洗，既保留定位信息又不复制任意业务对象。
const SAFE_REASON_KEYS = new Set([
  'name',
  'message',
  'code',
  'status',
  'status_text',
  'url',
  'pathname',
  'detail',
  'type',
])

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
// 仅在**字符串形态**做键值打码时补的复合键：对象键路径已由 normalizeObjectKey 折叠成
// mfa_code / api_key 这样的形态命中上面的清单，字符串里却是照原文写的，故两种写法都要收。
const COMPOUND_SENSITIVE_KEYS = ['mfa_code', 'captcha_id', 'session_id', 'secret_key', 'api_key']

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
  'id_token',
  'jwt',
  'bearer',
  // 会话标识：能直接定位一次登录态，属于凭据而非普通业务参数
  'sid',
]

// 与后端一致的下划线边界感知：短键（code/sign）若用 includes 子串匹配，
// 会把 postcode / zipcode 这类合法业务参数一并打码，损失排障信息。
// 入参传**原始键名**（不是 toLowerCase 后的），以便先补驼峰边界：
// accessToken / ACCESS_TOKEN / access_token 归一到同一 snake 形态再判，
// 否则 'accessToken'.toLowerCase()='accesstoken' 既不等于也不以 '_token' 结尾 → 漏码，
// 明文令牌会被写入 localStorage 环形缓冲并扇出到 Sentry/收集端。
const isSensitiveKey = (key) => {
  const lower = String(key).toLowerCase()
  const snake = String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
  return SENSITIVE_QUERY_KEYS.some((s) =>
    [lower, snake].some(
      (k) => k === s || k.endsWith(`_${s}`) || k.startsWith(`${s}_`) || k.includes(`_${s}_`)
    )
  )
}

/**
 * query/hash 的键名判据：先按对象键那套强归一化（补驼峰边界、非字母数字折叠成 _）
 * 再走同一份敏感清单，最后额外去掉 [] 这类数组/嵌套下标形态。
 * 与后端 utils/helpers.js 的 redactUrlQuery 同口径（键名保留、值替换为 ***）。
 */
const isSensitivePairKey = (rawKey) => {
  let decoded = rawKey
  try {
    decoded = decodeURIComponent(rawKey)
  } catch (_) {
    // 非法百分号编码保持原样判定：宁可多打码，不要把"解不开"当成"不敏感"
  }
  const normalized = normalizeObjectKey(decoded.replace(/\[[^\]]*\]/g, ''))
  return normalized === 'code' || isSensitiveKey(decoded) || isSensitiveKey(normalized)
}

/**
 * 对 URL 的 query 与 hash 做敏感值打码，保留路径与键名便于排障
 * @param {string} rawUrl 原始 URL（location.href 或相对路径）
 * @returns {string} 敏感值替换为 *** 后的 URL；入参非法时原样返回
 */
function redactUrl(rawUrl, depth = 0) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return rawUrl
  // 值里嵌 URL 时最多下沉 3 层：OAuth 回调把 next/redirect_uri 层层套起来是常见写法，
  // 但没有边界的递归会被构造成"值里再套值"的自相似串打爆（r17-web F2）。
  // 到顶后必须**失败关闭**：这里已至少被编码 3 次（说明是套起来的嵌套串），
  // 而深层那份凭据正是 detector 再也追不到的——返回原文等于给"套 4 层"留了后门
  // （本轮用例实测：500 层嵌套下 token 明文存活）。所以整体抹成 ***，键名与结构仍在，排障信息只损值。
  // 判据必须是无条件的：早先写成"只在仍是百分号编码时才抹"（想保留可读的 4 层明文），
  // 第 18 轮 audit-web 实测把那个推断推翻了——4 层纯明文照样把 token 原文留在上报里
  // （分界在 3/4 层，与编码形态无关）。到顶即抹，代价是丢失一个 4 层嵌套的排障串。
  if (depth > 3) return '***'

  const [beforeHash, ...hashParts] = rawUrl.split('#')
  const hash = hashParts.join('#')

  const qIndex = beforeHash.indexOf('?')
  const path = qIndex === -1 ? beforeHash : beforeHash.slice(0, qIndex)
  const query = qIndex === -1 ? '' : beforeHash.slice(qIndex + 1)

  // 值**也要看**：next=/redirect_uri= 里嵌的 URL 常带自己的 token（r17-web F2 实测
  // /cb?next=https://x/cb?token=SECRET 明文外发）。只看 key 等于把"凭据可以藏进值里"当成了
  // 不存在的写法；而 record 每次都会写 url:redactUrl(location.href)，不依赖 message 是否被调用。
  const redactNestedValue = (rawValue) => {
    let decoded
    try {
      decoded = decodeURIComponent(rawValue)
    } catch (_) {
      return rawValue // 非法百分号编码：不动它，宁可少码也不要产出半截编码
    }
    if (!/[?&#]/.test(decoded)) return rawValue
    const inner = redactUrl(decoded, depth + 1)
    if (inner === decoded) return rawValue
    // 入参已是编码形态就回写到同样的编码形态，否则原样回写（不改写调用方看到的形状）
    return /%[0-9A-Fa-f]{2}/.test(rawValue) ? encodeURIComponent(inner) : inner
  }

  const redactPairs = (text) =>
    text
      .split('&')
      .map((pair) => {
        const eq = pair.indexOf('=')
        if (eq === -1) return pair
        const key = pair.slice(0, eq)
        if (!isSensitivePairKey(key)) {
          const value = pair.slice(eq + 1)
          const inner = redactNestedValue(value)
          return inner === value ? pair : `${key}=${inner}`
        }
        // 键名先做与对象键同一套强归一化再去判定：axios 会把数组参数序列化成
        // token[]=、嵌套参数序列化成 password[x]=，而 access.token / x-auth-token
        // 这类变体也不是驼峰形态。只拆驼峰（isSensitiveKey 的旧口径）对这三种形态
        // 全部失配 ⇒ 明文凭据留在上报负载里。归一化后仍然保留原始键名输出。
        return `${key}=***`
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

/**
 * 按保留期与体积预算裁剪缓冲（纯函数，便于直接测边界）
 *
 * 顺序有意义：先按时间淘汰（过期条目无论多新都该走），再按体积从最旧开始丢，
 * 直到落回预算内。`length > 1` 的守卫保证最新一条永远留下——把"刚出错"的现场
 * 和"上周的旧账"一起裁掉，等于用生命周期限制毁掉排障能力。
 *
 * 时间戳不可解析（历史格式或人工写入）时**不**按时间淘汰：读不懂时间不等于
 * 证据该删，它仍受条数与体积上限约束。
 * @param {Array<object>} entries 现有缓冲（按时间升序）
 * @returns {Array<object>} 裁剪后的新数组（不改入参）
 */
function pruneEntries(entries) {
  const now = Date.now()
  const fresh = entries.filter((entry) => {
    const ts = Date.parse(entry && entry.t)
    return Number.isNaN(ts) ? true : now - ts <= MAX_ENTRY_AGE_MS
  })
  while (fresh.length > 1 && JSON.stringify(fresh).length > MAX_STORED_BYTES) {
    fresh.shift()
  }
  return fresh
}

function loadStored() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    if (!Array.isArray(parsed)) return []
    const loaded = parsed
      .slice(-MAX_STORED)
      .map((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
        const safe = sanitizeValue(entry)
        return safe && typeof safe === 'object' && !Array.isArray(safe) ? safe : null
      })
      .filter(Boolean)
    // 加载时就要裁：条数滚动只发生在 push 路径，过期条目否则会被原样写回，
    // 一直占着配额直到被新错误挤掉
    return pruneEntries(loaded)
  } catch (_) {
    return []
  }
}

function persist() {
  // 落盘前裁一次：既保证配额不被旧账吃掉，也保证"已经写进 localStorage 的东西"
  // 满足保留期承诺（只在上报侧打码、不在存储侧过期，等于泄露窗口无限长）
  stored = pruneEntries(stored)
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

// 错误消息/堆栈里可能内嵌完整 URL（如 "GET https://x/y?token=..."）：
// 逐个抽出按 query/hash 规则打码后再截断，避免凭据经自由文本字段绕过 redactUrl
function redactInlineUrls(value) {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return (
    text
      .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => redactUrl(url))
      // API errors often contain a relative endpoint (`POST /auth/refresh?...`).
      // Handle it as well so absolute-URL-only matching cannot leave a token in
      // a short message or stack.
      .replace(/\/[^\s"'<>?#]+(?:\?[^\s"'<>#]*)?(?:#[^\s"'<>]*)?/g, (url) =>
        url.includes('?') || url.includes('#') ? redactUrl(url) : url
      )
      .replace(/#[^\s"'<>]+/g, (hash) => redactUrl(hash))
  )
}

const normalizeObjectKey = (key) =>
  String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '')

const isSensitiveObjectKey = (key) => {
  const normalized = normalizeObjectKey(key)
  if (DROPPED_OBJECT_KEYS.has(normalized)) return true
  // `code` is a safe error code, but mfaCode/accessCode and similar compound
  // fields are credentials and must still be discarded.
  if (normalized === 'code') return false
  return (
    SENSITIVE_QUERY_KEYS.some(
      (s) =>
        normalized === s ||
        normalized.endsWith(`_${s}`) ||
        normalized.startsWith(`${s}_`) ||
        normalized.includes(`_${s}_`)
    ) ||
    [
      'password',
      'currentpassword',
      'newpassword',
      'mfacode',
      'token',
      'refreshtoken',
      'secret',
      'apikey',
    ].some((s) => normalized.replace(/_/g, '').includes(s))
  )
}

// Error messages can contain a serialized fragment such as
// `password=...` even when the surrounding value is only a string. Keep this
// last-resort scrub in addition to object-key filtering and URL redaction.
function redactSensitiveText(value) {
  const text = typeof value === 'string' ? value : String(value ?? '')
  // 顺序有意义：Authorization 的值本身就是 "Bearer <JWT>"，若先跑通用键值规则，
  // 它会把 "Bearer" 当成值吃掉（Authorization:*** eyJ...），后面的凭据形态规则
  // 再也看不到原文，JWT 就明文留在日志里。凭据形态规则必须先跑。
  return (
    text
      // Digest **必须单独一条**：它的凭据在参数列表里（response="…"），而下面那条通用方案规则
      // 只吃"方案 + 一个 token"，于是 Digest 的 response 会明文存活（r17-web F4）。
      // 参数列表按 RFC 7616 的形态整体吃掉：逗号分隔的 name="value" / name=value。
      .replace(
        /\bDigest\s+[A-Za-z]+\s*=\s*(?:"[^"]*"|[^\s,]+)(?:\s*,\s*[A-Za-z]+\s*=\s*(?:"[^"]*"|[^\s,]+))*/gi,
        'Digest ***'
      )
      // 认证方案 + 凭据（Bearer JWT / Basic base64 / Negotiate ...）：整段吃掉方案与凭据
      .replace(/\b(Bearer|Basic|Negotiate)\s+[A-Za-z0-9._~+/=:-]+/gi, '$1 ***')
      // 键值形态：Authorization: Bearer <JWT> / token=Bearer abc 等（方案已在上一条处理，
      // 这里兜住 "x-auth-token"、"access.token" 这类变体键名）
      .replace(
        new RegExp(
          // 键清单从 SENSITIVE_QUERY_KEYS 派生（而不是手抄一份更窄的）：两套清单各写一份时，
          // 同一凭据换个书写位置就从"已防护"变成"明文外发"——本轮实测 signature=/otp=/
          // mfaCode=/captchaId=/sessionId=/sid=/jwt=/bearer=/secret_key= 在字符串形态全部幸存。
          // 长键优先，避免 code 先把 mfaCode 的后半段吃掉，留下 "mfa" + "***" 的残形。
          '["\']?(' +
            // `code` 必须剔除：它是**安全的错误码**（对象键路径里 isSensitiveObjectKey 也显式放行，
            // 见 :344 的 `if (normalized === 'code') return false`）。不剔的话
            // JSON.stringify({code:42}) 会被打成 "{code:***"，把排障要用的错误码一并毁掉——
            // 这是本轮修复自身的回归，由 E16 用例当场抓住。
            [...SENSITIVE_QUERY_KEYS.filter((k) => k !== 'code'), ...COMPOUND_SENSITIVE_KEYS]
              .sort((a, b) => b.length - a.length)
              .map((k) => k.replace(/[_]/g, '[._-]?'))
              .join('|') +
            ')["\']?\\s*([:=])\\s*(?:"[^"]*"|\'[^\']*\'|[^\\s,;}&]+)',
          'gi'
        ),
        '$1$2***'
      )
  )
}

function safePathname(value) {
  if (typeof value !== 'string' || value.length === 0) return undefined
  try {
    const origin =
      typeof location !== 'undefined' && location.origin ? location.origin : 'http://localhost'
    return new URL(value, origin).pathname || '/'
  } catch (_) {
    // Keep only the path prefix when an invalid URL is supplied. Query/hash
    // content is intentionally discarded rather than returned for debugging.
    return truncate(value.split(/[?#]/, 1)[0], MAX_MESSAGE_LEN)
  }
}

function sanitizeValue(value, depth = 0, seen = new WeakSet(), key = '') {
  if (value === null || value === undefined) return value
  if (typeof value === 'string') {
    const text =
      key === 'url' || key === 'file' || key === 'href'
        ? redactUrl(value)
        : redactSensitiveText(redactInlineUrls(value))
    // stack 必须用更宽的上限：record 阶段按 MAX_STACK_LEN(2000) 截断并落盘，
    // 若加载时按 MAX_MESSAGE_LEN(500) 再截一次，同一份留档在刷新前后内容不同
    // （内存里 2000 字符、读回只剩 500），排障时对不上号。
    return truncate(text, key === 'stack' ? MAX_STACK_LEN : MAX_MESSAGE_LEN)
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'bigint') return String(value)
  if (typeof value !== 'object') return String(value)
  if (depth >= MAX_SANITIZE_DEPTH) return '[深度超限]'
  if (seen.has(value)) return '[循环引用]'
  seen.add(value)

  try {
    if (value instanceof Date) {
      return Number.isNaN(value.getTime()) ? '[无效时间]' : value.toISOString()
    }
    if (Array.isArray(value)) {
      return value.slice(0, MAX_SANITIZE_ITEMS).map((item) => sanitizeValue(item, depth + 1, seen))
    }

    const cleaned = {}
    let count = 0
    for (const [childKey, childValue] of Object.entries(value)) {
      if (count >= MAX_SANITIZE_KEYS || childKey === 'toJSON') break
      if (isSensitiveObjectKey(childKey)) continue
      Object.defineProperty(cleaned, childKey, {
        value: sanitizeValue(childValue, depth + 1, seen, normalizeObjectKey(childKey)),
        enumerable: true,
        writable: true,
        configurable: true,
      })
      count += 1
    }
    return cleaned
  } catch (_) {
    return '[不可序列化]'
  } finally {
    seen.delete(value)
  }
}

function sanitizeReasonObject(reason) {
  const isAxiosLike =
    reason?.isAxiosError === true ||
    reason?.name === 'AxiosError' ||
    Object.prototype.hasOwnProperty.call(reason, 'config') ||
    Object.prototype.hasOwnProperty.call(reason, 'request') ||
    Object.prototype.hasOwnProperty.call(reason, 'response')

  if (!isAxiosLike) {
    const safe = {}
    for (const [key, value] of Object.entries(reason)) {
      const normalized = normalizeObjectKey(key)
      if (!SAFE_REASON_KEYS.has(normalized) || isSensitiveObjectKey(key)) continue
      Object.defineProperty(safe, key, {
        value: sanitizeValue(value, 0, new WeakSet(), normalized),
        enumerable: true,
        writable: true,
        configurable: true,
      })
    }
    return safe
  }

  const safe = {}
  const response = reason.response && typeof reason.response === 'object' ? reason.response : null
  const config = reason.config && typeof reason.config === 'object' ? reason.config : null
  const set = (key, value) => {
    if (value === undefined || value === null || value === '') return
    Object.defineProperty(safe, key, {
      value: key === 'url' ? safePathname(value) : sanitizeValue(value, 0, new WeakSet(), key),
      enumerable: true,
      writable: true,
      configurable: true,
    })
  }

  set('name', reason.name)
  set('code', reason.code)
  set('status', reason.status ?? response?.status)
  set('statusText', reason.statusText ?? response?.statusText)
  set('message', reason.message)
  set('url', reason.url ?? config?.url ?? response?.config?.url)
  return safe
}

// extra 来自各调用点，键名不受控：先按 URL 字段打码，且它不得覆盖 record
// 自己生成的受控字段（否则 { url: 原始地址 } 会盖掉已脱敏的 entry.url）
function sanitizeExtra(extra) {
  if (!extra || typeof extra !== 'object') return {}
  const safe = sanitizeValue(extra)
  return safe && typeof safe === 'object' && !Array.isArray(safe) ? safe : {}
}

function entryKey(entry) {
  return `${entry.kind}|${entry.message}|${(entry.stack || '').slice(0, 120)}`
}

function record(kind, message, stack = '', extra = {}) {
  const entry = {
    ...sanitizeExtra(extra),
    t: new Date().toISOString(),
    kind,
    message: truncate(redactSensitiveText(redactInlineUrls(message)), MAX_MESSAGE_LEN),
    stack: truncate(redactSensitiveText(redactInlineUrls(stack)), MAX_STACK_LEN),
    // L-11：原为 location.href 原样留档，query/hash 里的凭据会随之落盘并外发
    url: redactUrl(location.href),
    count: 1,
  }

  // 同一错误短时间重复触发（如渲染循环报错）只累计计数，避免刷爆缓冲
  const key = entryKey(entry)
  const now = Date.now()
  const lastSeen = recentKeys.get(key)
  if (lastSeen && now - lastSeen < DEDUPE_WINDOW_MS) {
    const duplicate = stored.find((item) => entryKey(item) === key)
    if (duplicate) {
      duplicate.count += 1
      persist()
      return
    }
    // 原条目已被裁剪（本轮审计 F4）：去重窗口仍开着，但"要累加的那条"已经不在了。
    // 旧实现在这里直接 return，于是这次错误一条都不留——缓冲里 0 条，
    // 而排障者看到的正是"刚出错"的现场。窗口命中但无宿主 ⇒ 继续往下走，按新条目落库。
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
  if (reason instanceof Error) {
    return {
      message: redactSensitiveText(reason.message),
      stack: redactSensitiveText(reason.stack || ''),
    }
  }
  if (typeof reason === 'object' && reason !== null) {
    try {
      const safe = sanitizeReasonObject(reason)
      const message = JSON.stringify(safe)
      const stack = typeof reason.stack === 'string' ? redactSensitiveText(reason.stack) : ''
      return { message: message === '{}' ? '[object Object]' : message, stack }
    } catch (_) {
      return { message: redactSensitiveText(String(reason)), stack: '' }
    }
  }
  return { message: redactSensitiveText(String(reason)), stack: '' }
}

export function initErrorHandling(app) {
  stored = loadStored()

  app.config.errorHandler = (error, _instance, info) => {
    const message = error instanceof Error ? error.message : String(error)
    const stack = error instanceof Error ? error.stack || '' : ''
    record('vue', message, stack, { info })
    // 控制台也可能被浏览器扩展、远程调试或支持工具采集，不能直接打印
    // AxiosError（其中可能挂着 config/data/headers/request/response）。
    console.error('[errorHandler]', info, {
      message: truncate(redactSensitiveText(redactInlineUrls(message)), MAX_MESSAGE_LEN),
      stack: truncate(redactSensitiveText(redactInlineUrls(stack)), MAX_STACK_LEN),
    })
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
