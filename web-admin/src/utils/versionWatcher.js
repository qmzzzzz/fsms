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

/** 子路径部署（BASE_URL='/admin/'）下必须带上部署基路径，否则请求打到站点根 */
function versionUrl() {
  const base = String((import.meta.env && import.meta.env.BASE_URL) || '/').replace(/\/+$/, '')
  return `${base}/api/version`
}

/** 默认取数：显式 no-store，避免代理/浏览器缓存让比对恒等 */
async function defaultFetchVersion() {
  const res = await fetch(versionUrl(), {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  })
  if (!res.ok) throw new Error(`version probe failed: ${res.status}`)
  const body = await res.json()
  // 统一信封 { success, data } —— 兼容裸对象，但两者都没有 buildId 时按失败处理
  return (body && body.data) || body
}

function defaultIsHidden() {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden'
}

/**
 * @param {object} [options]
 * @param {string} [options.localBuildId] 本页构建标识（测试注入用）
 * @param {() => Promise<object>} [options.fetchVersion] 取数实现
 * @param {number} [options.intervalMs] 轮询间隔
 * @param {(info: {localBuildId: string, remoteBuildId: string}) => void} [options.onUpdateAvailable]
 * @param {() => boolean} [options.isHidden] 页面是否不可见
 */
export function createVersionWatcher(options = {}) {
  const {
    localBuildId = LOCAL_BUILD_ID,
    fetchVersion = defaultFetchVersion,
    intervalMs = DEFAULT_INTERVAL_MS,
    onUpdateAvailable = () => {},
    isHidden = defaultIsHidden,
  } = options

  let timer = null
  let inFlight = false
  let started = false
  let notified = false

  const local = typeof localBuildId === 'string' ? localBuildId.trim() : ''

  const check = async () => {
    if (!started) return
    // 上一次还没回来就不叠加请求：慢网络下叠加只会把配额烧穿
    if (inFlight) return
    // 本页没有可比的标识 ⇒ 探测没有意义（见头注第 1 条纪律）
    if (!isComparableBuildId(local)) return
    if (isHidden()) return

    inFlight = true
    try {
      const payload = await fetchVersion()
      const remote = payload && typeof payload.buildId === 'string' ? payload.buildId.trim() : ''
      if (!isComparableBuildId(remote)) return
      if (remote === local) return
      if (notified) return
      notified = true
      onUpdateAvailable({ localBuildId: local, remoteBuildId: remote })
    } catch (_) {
      // 见头注第 2 条纪律：静默
    } finally {
      inFlight = false
    }
  }

  const onVisibilityChange = () => {
    // 只处理「重新可见」：隐藏时补查一次没有意义，反而在后台标签页里白烧请求
    if (!isHidden()) check()
  }

  const start = () => {
    if (started) return
    started = true
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
