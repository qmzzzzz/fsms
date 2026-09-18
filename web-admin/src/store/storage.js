/**
 * Store 共享的安全存储工具（D-3 自 store/index.js 拆出）
 *
 * 分工：
 * - 认证令牌：httpOnly cookie（JS 不可读，见 I-01）
 * - 会话身份界面状态（currentUser/permissions）与主题偏好：localStorage
 * - 标签页级临时状态（计数器、语言、迁移残留）：sessionStorage
 */

/**
 * 安全读写 sessionStorage（兼容隐私模式下的 Edge / Firefox / Chrome）
 *
 * 认证令牌已迁移至 httpOnly cookie（I-01）：login/refresh 由后端 Set-Cookie 下发
 * access_token(path=/api) 与 refresh_token(path=/api/auth)，JS 完全不可读，
 * XSS 无法窃取。此处仅存放 currentUser/permissions 等非敏感界面状态，
 * 支撑刷新页面后的路由守卫与权限判断；真实鉴权始终由后端按 cookie 校验。
 */
export const safeStorage = {
  get(key, fallback = null) {
    try {
      const raw = sessionStorage.getItem(key)
      // 缺失键同样走 fallback：原实现只在「介质抛错」时用 fallback，
      // 调用方写 safeStorage.get(k, 默认值) 会静默拿到 null，参数形同虚设，
      // 与 getJSON 的「无值即 fallback」语义也不一致
      return raw === null ? fallback : raw
    } catch (_) {
      return fallback
    }
  },
  set(key, value) {
    try {
      sessionStorage.setItem(key, value)
    } catch (_) {}
  },
  remove(key) {
    try {
      sessionStorage.removeItem(key)
    } catch (_) {}
  },
  getJSON(key, fallback = null) {
    try {
      const raw = sessionStorage.getItem(key)
      return raw ? JSON.parse(raw) : fallback
    } catch (_) {
      return fallback
    }
  },
  setJSON(key, value) {
    try {
      sessionStorage.setItem(key, JSON.stringify(value))
    } catch (_) {}
  },
}

/**
 * 安全读写 localStorage
 *
 * 与 safeStorage(sessionStorage) 的分工：
 * - 认证令牌：httpOnly cookie（JS 不可读）
 * - 会话身份界面状态（currentUser/permissions）：localStorage
 *   —— cookie 是「浏览器级」共享的，若身份状态存 sessionStorage（标签页级隔离），
 *   新标签页/复制 URL 打开会出现「有 cookie 但无本地身份」→ 守卫误判未登录 → 跳登录页。
 *   两者作用域必须对齐，否则同一浏览器内的会话无法持久共享。
 * - 主题等偏好：localStorage
 */
export const safeLocal = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key)
      // 与 safeStorage.get 同一契约：缺失键即 fallback（详见上方注释）
      return raw === null ? fallback : raw
    } catch (_) {
      return fallback
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, value)
    } catch (_) {}
  },
  remove(key) {
    try {
      localStorage.removeItem(key)
    } catch (_) {}
  },
  getJSON(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key)
      return raw ? JSON.parse(raw) : fallback
    } catch (_) {
      return fallback
    }
  },
  setJSON(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch (_) {}
  },
}

/**
 * 会话身份状态读取：localStorage 优先，回退读取旧版 sessionStorage 并就地迁移
 *
 * 迁移必要性：改用 localStorage 前已登录的标签页把状态写在 sessionStorage，
 * 若直接切换存储介质，这些用户刷新页面即被判为未登录（体验上等同强制登出）。
 */
export const readSessionState = (key) => {
  const fromLocal = safeLocal.getJSON(key)
  if (fromLocal !== null) return fromLocal

  const legacy = safeStorage.getJSON(key)
  if (legacy !== null) {
    safeLocal.setJSON(key, legacy)
    // 确认写入落地后才清旧副本：配额写满/隐私模式下 setJSON 会静默失败，
    // 若照删 sessionStorage 里的唯一副本，用户刷新即被判未登录
    // —— 这正是本次迁移要避免的故障。写回失败则保留旧副本，下次再试。
    if (safeLocal.get(key) !== null) safeStorage.remove(key)
    return legacy
  }
  return null
}
