/**
 * 版本探测：发现「服务端已换版、本标签页还是旧壳子」时提示刷新
 *
 * 为什么需要它：PWA 的 Service Worker 只知道自己缓存的那份前端资源，
 * 蓝绿切换后旧标签页里的 SW 可能仍然认为一切正常（尤其当新版本的前端产物
 * 哈希恰好没变化，或 SW 的更新检查被浏览器节流）。此时用户看到的是旧界面，
 * 而服务端已经在跑新代码——两者 API 语义一旦有差异，表现是零散 500，
 * 排查方向会完全错（以为后端坏了）。
 *
 * 判据：本页构建时钉下的 __APP_BUILD_ID__ 与服务端 GET /api/version 的 buildId。
 *
 * 三条「宁可不动」的纪律：
 *   1. 任何一侧不可比对（空 / 'unknown' / 'dev'）就**不提示**。
 *      否则本地构建包连生产时会立刻误报「有新版本」，而这个提示无法关掉。
 *   2. 探测失败（断网、接口 404、返回非 JSON）一律静默。版本探测是尽力而为，
 *      不能因为探测失败给用户弹错，更不能把失败当成「有更新」。
 *   3. 页面隐藏时不发请求；重新可见时补查一次。轮询只在用户真的在看页面时消耗配额。
 */

import { API_BASE_URL } from '@/utils/api'

export const DEFAULT_INTERVAL_MS = 5 * 60 * 1000

/** 本页的构建标识（vite define 注入；测试/开发态可能不存在） */
export const LOCAL_BUILD_ID = typeof __APP_BUILD_ID__ === 'string' ? __APP_BUILD_ID__ : ''

/**
 * 是否可与对端比对。
 *
 * 'unknown' 来自后端「环境变量与 git 都取不到」的兜底，'dev' 来自前端未注入
 * APP_BUILD_ID 的兜底——两者都不是真实版本，拿它们比对只会得到恒假的「有更新」。
 */
export function isComparableBuildId(id) {
  if (typeof id !== 'string') return false
  const value = id.trim()
  return value !== '' && value !== 'unknown' && value !== 'dev'
}

/**
 * 版本接口地址：复用统一 API base（与 utils/api.js 同源，P2-8）。
 *
 * 原实现用 BASE_URL 拼 `${BASE_URL}/api/version`，完全忽略 VITE_API_BASE_URL：
 * 独立 API 域或 VITE_API_BASE_URL='/sub/api' 的部署下探测会静默 404 ——
 * 头注第 2 条纪律要求探测失败静默，于是没有任何信号能暴露这个配置错。
 */
function versionUrl() {
  const base = String(API_BASE_URL || '/api').replace(/\/+$/, '')
  return `${base}/version`
}

/** 探测超时（P2-7）：悬挂的请求会让 inFlight 永久为真，此后所有轮询都被它挡掉 */
export const DEFAULT_TIMEOUT_MS = 10 * 1000

/** 默认取数：显式 no-store，避免代理/浏览器缓存让比对恒等；signal 由调用方注入（P2-7） */
async function defaultFetchVersion(options = {}) {
  const { signal } = options
  const res = await fetch(versionUrl(), {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!res.ok) throw new Error(`version probe failed: ${res.status}`)
  const body = await res.json()
  // 统一信封 { success, data } —— 兼容裸对象，但两者都没有 buildId 时按失败处理
  return (body && body.data) || body
}

/**
 * 页面是否不可见（全仓统一判据，P2-6）。
 *
 * 原判据只认 `visibilityState === 'hidden'`：本仓 jsdom 的默认可见性是 'prerender'
 * （document.hidden 恒为 true），AboutView 另用了一套 `=== 'visible'` —— 同一仓三套
 * 判据，谁都没覆盖 'prerender'。这里统一为「不可见 = visibilityState 不是 'visible'」，
 * 拿不到 visibilityState 时退回 document.hidden。
 *
 * doc 可注入：测试无需改动全局 document。
 */
export function isPageHidden(doc = typeof document !== 'undefined' ? document : null) {
  if (!doc) return false
  const state = doc.visibilityState
  if (typeof state === 'string' && state !== '') return state !== 'visible'
  return doc.hidden === true
}

const defaultIsHidden = () => isPageHidden()

/**
 * @param {object} [options]
 * @param {string} [options.localBuildId] 本页构建标识（测试注入用）
 * @param {(options: {signal?: AbortSignal}) => Promise<object>} [options.fetchVersion] 取数实现
 * @param {number} [options.intervalMs] 轮询间隔
 * @param {number} [options.timeoutMs] 单次探测超时（超时即 abort 并释放 inFlight）
 * @param {(info: {localBuildId: string, remoteBuildId: string}) => void} [options.onUpdateAvailable]
 * @param {() => boolean} [options.isHidden] 页面是否不可见
 */
export function createVersionWatcher(options = {}) {
  const {
    localBuildId = LOCAL_BUILD_ID,
    fetchVersion = defaultFetchVersion,
    intervalMs = DEFAULT_INTERVAL_MS,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    onUpdateAvailable = () => {},
    isHidden = defaultIsHidden,
  } = options

  let timer = null
  let inFlight = false
  let started = false
  let notified = false
  /**
   * 代号（P2-7）：stop / start 各 +1。停止之后才回来的响应据此丢弃——
   * 原实现只看 inFlight/started，停止后回来的响应照样 onUpdateAvailable。
   */
  let generation = 0
  let controller = null

  const local = typeof localBuildId === 'string' ? localBuildId.trim() : ''

  /** 中止在途探测并复位 inFlight：请求悬挂时唯一能让轮询继续下去的手段 */
  const abortInFlight = () => {
    if (controller) {
      try {
        controller.abort()
      } catch (_) {
        // abort 自身失败不应影响停止流程
      }
      controller = null
    }
    inFlight = false
  }

  const check = async () => {
    if (!started) return
    // 上一次还没回来就不叠加请求：慢网络下叠加只会把配额烧穿
    if (inFlight) return
    // 本页没有可比的标识 ⇒ 探测没有意义（见头注第 1 条纪律）
    if (!isComparableBuildId(local)) return
    if (isHidden()) return

    const gen = generation
    inFlight = true
    controller = typeof AbortController === 'function' ? new AbortController() : null

    // 超时兜底：即使取数实现忽略 signal，也要让 inFlight 有机会复位
    let timerId = null
    const timeoutPromise = new Promise((_, reject) => {
      if (!(typeof timeoutMs === 'number' && timeoutMs > 0)) return
      timerId = setTimeout(() => {
        if (controller) {
          try {
            controller.abort()
          } catch (_) {
            // 同上：超时路径不得因 abort 失败而中断
          }
        }
        reject(new Error('version probe timeout'))
      }, timeoutMs)
    })
    // 竞速已定后 timeout 仍会 reject：不接住就是一条 unhandledrejection
    timeoutPromise.catch(() => {})

    try {
      const payload = await Promise.race([
        fetchVersion(controller ? { signal: controller.signal } : undefined),
        timeoutPromise,
      ])
      // 停止 / 重启之后回来的响应一律丢弃
      if (!started || gen !== generation) return
      const remote = payload && typeof payload.buildId === 'string' ? payload.buildId.trim() : ''
      if (!isComparableBuildId(remote)) return
      if (remote === local) return
      if (notified) return
      notified = true
      onUpdateAvailable({ localBuildId: local, remoteBuildId: remote })
    } catch (_) {
      // 见头注第 2 条纪律：静默（含超时与被 abort 的探测）
    } finally {
      if (timerId !== null) clearTimeout(timerId)
      if (gen === generation) {
        inFlight = false
        controller = null
      }
    }
  }

  const onVisibilityChange = () => {
    // 只处理「重新可见」：隐藏时补查一次没有意义，反而在后台标签页里白烧请求
    if (!isHidden()) check()
  }

  const start = () => {
    if (started) return
    started = true
    // 复位：stop 之后再 start 必须能重新探测、重新提示（原实现把两者都留成旧值）
    generation += 1
    inFlight = false
    notified = false
    if (typeof document !== 'undefined' && document.addEventListener) {
      document.addEventListener('visibilitychange', onVisibilityChange)
    }
    if (typeof setInterval === 'function') {
      timer = setInterval(check, intervalMs)
    }
    check()
  }

  const stop = () => {
    started = false
    generation += 1
    // 停止 = 连在途请求一起中止：否则停止后回来的响应仍会 onUpdateAvailable
    abortInFlight()
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
    if (typeof document !== 'undefined' && document.removeEventListener) {
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }

  return { start, stop, checkNow: check, isStarted: () => started }
}

/**
 * 生产装配：探测到服务端换版 → 置位共享状态（界面由 UpdateNoticeBar 消费）。
 * 开发态不启动——本地没有 APP_BUILD_ID，比对只会得到噪音。
 */
export function startVersionWatcher(options = {}) {
  const watcher = createVersionWatcher(options)
  watcher.start()
  return watcher
}
