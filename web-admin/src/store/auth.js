import { defineStore } from 'pinia'
import { matchPermission } from '@/utils/permission'
import { broadcastAuthChange } from '@/utils/sessionSync'
import { toPermissionCodes } from '@/schemas'
import { safeStorage, safeLocal, readSessionState } from './storage'
import { clearReauthTicket } from '@/utils/reauthTicket'

/**
 * 归一化用户对象形状（P3-38）
 *
 * 后端三条路径给出三种形状，前端却把它们混存在同一个 currentUser 里：
 *   POST /auth/login  → { userId, username, ... }        （有 userId 无 id）
 *   GET  /auth/me     → { id, username, ... }            （有 id 无 userId）
 *   ProfileView 保存后 → 用 /auth/me 的形状覆盖，userId 丢失
 * 而界面用 `currentUser._id` 做「是否本人」判断 —— 三种形状里都没有 `_id`，
 * 判断恒为 undefined，于是管理员在自己那行也看到删除/重置 MFA 按钮。
 * （后端 CANNOT_DELETE_SELF 会兜住，所以这是 UI 缺陷而非越权，
 * 但「点了才知道不行」本身就是缺陷，且会让人怀疑权限系统是否可靠。）
 *
 * 解法：所有写入 currentUser 的入口统一过这个函数，保证三个字段
 * （userId / id / _id）恒等且始终存在，任何一处的读法都能命中。
 * 只补别名不改语义，因此不影响既有读 `id` 或读 `userId` 的代码。
 * @param {object|null} user 任意来源的用户对象
 * @returns {object|null} 补齐 id 别名后的用户对象
 */
export const normalizeUser = (user) => {
  // 只接受「普通对象」。标量（true / "1" / 123）或数组经 JSON.parse 也能还原成真值，
  // 若原样返回：currentUser 变成真值 → isAuthenticated 误判为已登录 → 路由放行进入空壳，
  // 而 restoreSession 的 `if (this.currentUser)` 又会永久短路 /auth/me 自愈，
  // 用户卡在「无菜单无按钮」的状态直到手动清存储。截断/配额部分的写入或历史脏值即可触发。
  if (!user || typeof user !== 'object' || Array.isArray(user)) return null
  const id = user.userId ?? user.id ?? user._id ?? null
  // 没有可用 id 的对象不是身份：返回 {...user} 会让 isAuthenticated 判真、
  // 路由放行，而所有「是否本人」判断恒为 false。此类形状漂移必须 fail-closed。
  if (id === null || id === undefined || String(id).trim() === '') return null
  const idStr = String(id)
  return { ...user, userId: idStr, id: idStr, _id: idStr }
}

/**
 * 写入 localStorage 的身份投影（P2：localStorage 里的 PII）
 *
 * 内存中的 currentUser 需要 email / realName / department 等字段供界面直接渲染，
 * 但**持久化**只需要够用来做「看起来还登录着」的骨架：身份 id、账号名、角色。
 *
 * 共用设备上任何同源脚本（XSS、恶意扩展、别的标签页里的调试代码）都能读
 * localStorage；httpOnly cookie 的全部收益就在「JS 读不到凭证」——把
 * email/realName/phone 明文摆进同一作用域，等于把收益退掉一半，而收益是
 * 拿「不用 localStorage 存 token」换来的。
 *
 * 丢掉的字段不影响正确性：路由守卫在每次页面加载都 `await restoreSession()`
 * （`sessionVerified` 不持久化，恒为 false），受保护视图挂载时内存里已是
 * /auth/me 的完整对象。localStorage 里的这份只是「上次见到的身份」提示。
 */
const PERSISTED_USER_FIELDS = [
  'userId',
  'id',
  '_id',
  'username',
  'roles',
  // P1-2：仅用于刷新后先把用户引到改密页；服务端 authenticate 仍会独立兜底
  'mustChangePassword',
]

/**
 * @param {object|null} user 归一化后的用户对象
 * @returns {object|null} 只含非 PII 字段的投影（用于持久化，不用于渲染）
 */
export const toPersistedUser = (user) => {
  if (!user || typeof user !== 'object' || Array.isArray(user)) return null
  const out = {}
  for (const key of PERSISTED_USER_FIELDS) {
    if (user[key] !== undefined) out[key] = user[key]
  }
  return out
}

// 用户认证 Store
export const useAuthStore = defineStore('auth', {
  state: () => ({
    // I-01 httpOnly cookie 方案：令牌不进 JS 可读存储，由浏览器按 path 自动携带。
    // currentUser 存 localStorage 是为了让「新标签页 / 复制 URL 直达」有一个身份骨架，
    // 但它**不是非敏感数据**：后端登录响应含 email / realName。故持久化只走
    // toPersistedUser 的白名单投影（id + 账号名 + 角色），PII 只留在内存里。
    // cookie 失效时首个 401 会触发刷新/登出闭环。
    // P3-38：读取时也归一化——迁移前存下的旧形状（缺 _id/userId）需就地补齐
    currentUser: normalizeUser(readSessionState('currentUser')) || null,
    permissions: toPermissionCodes(readSessionState('permissions')),
    // 本页面生命周期内是否已由服务端确认过身份。localStorage 可被改写/截断，
    // 其中的 currentUser 只代表「上次见到的身份」，不能当作已认证事实；
    // 路由守卫据此在每次页面加载后至少向服务端核对一次。
    sessionVerified: false,
    // 会话恢复的在途 Promise：多个守卫/请求并发触发时只探测一次 /auth/me
    restorePromise: null,
    // 本次页面加载内是否已探测过且失败（负缓存）：匿名用户在 /login 与
    // /register 之间来回跳时不应每次都打一发 /auth/me
    restoreFailed: false,
  }),

  getters: {
    isAuthenticated: (state) => !!state.currentUser,
    username: (state) => state.currentUser?.username || '',
    userEmail: (state) => state.currentUser?.email || '',
    userRoles: (state) => state.currentUser?.roles || [],
    hasPermission: (state) => (permission) => matchPermission(state.permissions, permission),
    /**
     * 当前登录用户 id（P3-38：统一出口，避免各视图各写一种读法）
     * 归一化后三个字段恒等，取任一即可；此处按 userId 优先以对齐登录响应口径。
     */
    currentUserId: (state) =>
      state.currentUser?.userId ?? state.currentUser?.id ?? state.currentUser?._id ?? null,
    /**
     * 判断给定 id 是否为当前登录用户（列表行「是否本人」的唯一判断入口）
     * @returns {(id: unknown) => boolean}
     */
    isSelf() {
      const self = this.currentUserId
      return (id) => self !== null && id != null && String(id) === String(self)
    },
  },

  actions: {
    // 令牌走 httpOnly cookie（JS 不可读），本 action 只接收用户与权限
    // @returns {boolean} 写入是否成功（用户对象缺少可用 id 时拒绝写入）
    setAuth(user, permissions = []) {
      const normalized = normalizeUser(user)
      if (!normalized) return false
      // 权限一律归一化为 string[]：后端两种口径（code 数组 / populate 对象数组）
      // 都可能出现，而 matchPermission 只认字符串——存了对象会让所有按钮判否
      const codes = toPermissionCodes(permissions)
      this.currentUser = normalized
      this.permissions = codes
      // 登录响应由服务端签发，身份与权限同源，直接视为已核实
      this.sessionVerified = true
      // 登录成功即重置负缓存：下次若本地状态丢失仍应允许探测恢复
      this.restoreFailed = false
      safeLocal.setJSON('currentUser', toPersistedUser(normalized))
      safeLocal.setJSON('permissions', codes)
      // 清理 I-01 迁移前写入 sessionStorage 的旧令牌与旧会话状态残留
      safeStorage.remove('token')
      safeStorage.remove('refreshToken')
      safeStorage.remove('currentUser')
      safeStorage.remove('permissions')
      // 通知其他标签页：cookie 身份已切换为该用户
      broadcastAuthChange('login', normalized)
      return true
    },

    // @returns {boolean} 写入是否成功（形状漂移的用户对象不得覆盖现有身份）
    setCurrentUser(user) {
      // P3-38：ProfileView 用 /auth/me 的形状（只有 id）覆盖此处，
      // 不归一化会让 userId/_id 丢失，「是否本人」判断随之失效
      const normalized = normalizeUser(user)
      if (!normalized) return false
      this.currentUser = normalized
      safeLocal.setJSON('currentUser', toPersistedUser(normalized))
      return true
    },

    setPermissions(permissions) {
      if (!Array.isArray(permissions)) return false
      const codes = toPermissionCodes(permissions)
      this.permissions = codes
      safeLocal.setJSON('permissions', codes)
      return true
    },

    /**
     * 用 WebSocket 推送的完整权限码集合就地更新（乐观更新）
     *
     * 后端 emitPermissionSync 下发的是收件人的**完整**权限集，可直接整体替换。
     * 相比重新拉 /auth/me 的优势是零网络往返、界面即时响应；
     * 代价是信任推送内容，因此调用方须在此之后再做一次权威校验
     * （见 syncPermissionsFromEvent）。
     *
     * @param {unknown} permissions 权限码集合（string[] 或 populate 对象数组）
     * @returns {boolean} 是否实际应用（未登录或入参非数组时不应用）
     */
    applyPermissionCodes(permissions) {
      if (!this.currentUser) return false
      if (!Array.isArray(permissions)) return false
      const codes = toPermissionCodes(permissions)
      this.permissions = codes
      safeLocal.setJSON('permissions', codes)
      return true
    },

    /**
     * 从服务端重新拉取权限（权威来源）
     *
     * 与 restoreSession 的区别：本方法用于**已登录**状态下的权限刷新，
     * 因此不看也不写 restoreFailed 负缓存、不参与并发去重——权限变更事件
     * 本身是低频的，而每次都必须拿到最新值。
     *
     * @returns {Promise<boolean>} 是否成功刷新
     */
    async refreshPermissionsFromServer() {
      if (!this.currentUser) return false
      // 竞态基线：/auth/me 是一次网络往返，其间用户可能登出（clearAuth 把 currentUser
      // 置 null）或切换账号（currentUser 变成另一个对象）。用引用身份钉住"发起时的那个人"。
      const epoch = this.currentUser
      try {
        // 动态导入避免 store ← api ← store 的模块循环依赖
        const { api } = await import('@/utils/api')
        // silent401：会话可能刚好在此刻失效（管理员强制下线），
        // 那属于预期结果，交由既有的 401 闭环处理，不在这里弹二次提示
        const { data: resp } = await api.auth.getMe({ silent401: true })
        if (!resp?.success || !resp.data?.user) return false
        // 回填前复核身份未变：若往返期间已登出/换号，这里必须放弃——否则把旧的 /auth/me
        // 结果写回去会「复活」一个已登出会话（restoreSession 之后被 `if (this.currentUser)`
        // 永久短路，用户再也无法自动恢复），并让界面以已失效身份继续显示。
        if (this.currentUser !== epoch) return false

        // 写 store 前先校验服务端形状：/auth/me 缺 id 或 permissions 非数组属于
        // schema 漂移，此时写入会把界面置于「已登录但无法确定身份/权限」的半坏状态。
        // 保留现有状态并返回失败，等待下一次权威刷新。
        const normalized = normalizeUser(resp.data.user)
        if (!normalized || !Array.isArray(resp.data.permissions)) return false
        const codes = toPermissionCodes(resp.data.permissions)
        this.currentUser = normalized
        this.permissions = codes
        this.sessionVerified = true
        safeLocal.setJSON('currentUser', toPersistedUser(normalized))
        safeLocal.setJSON('permissions', codes)
        return true
      } catch (_) {
        // 刷新失败保留现有权限：清空会让界面突然「什么都不能点」，
        // 而真实原因可能只是一次网络抖动
        return false
      }
    },

    /**
     * 处理权限变更推送：先乐观更新，再后台向服务端核对
     *
     * 两段式的理由：
     *  - 乐观更新让界面立即反映新权限（这正是「免重登生效」的用户可感部分）；
     *  - 后台校验兜住两种情况：推送里没带 permissionCodes（后端重算失败时
     *    会刻意省略该字段），以及推送内容与服务端实际状态不一致
     *    （多进程部署下推送来自 A 进程、鉴权发生在 B 进程）。
     * 服务端始终是最终事实来源，前端的乐观值只是过渡态。
     *
     * @param {{permissionCodes?: unknown}} [event] WebSocket 事件载荷
     * @returns {Promise<boolean>} 最终是否与服务端核对成功
     */
    async syncPermissionsFromEvent(event) {
      if (!this.currentUser) return false
      // 第一段：乐观更新（推送未带完整集合时跳过，直接进入权威校验）。
      // 安全边界：推送载荷**绝不允许携带超管通配** `*:*` / `*`——通配只能由 /auth/me 权威授予。
      // 否则一个伪造/被 MITM 的 permission-sync 帧即可把整个界面提成全权限并写入 localStorage。
      const raw = event?.permissionCodes
      const push = Array.isArray(raw)
        ? toPermissionCodes(raw).filter((c) => c !== '*:*' && c !== '*')
        : raw
      this.applyPermissionCodes(push)
      // 第二段：权威校验（其结果覆盖乐观值；失败则保留，避免网络抖动把界面打空——见该方法注释）
      return this.refreshPermissionsFromServer()
    },

    /**
     * 用 httpOnly cookie 探测并重建本地会话身份
     *
     * 触发场景：浏览器里已有有效 access_token cookie，但本标签页没有本地身份状态
     * （localStorage 被清、跨设备同步差异、或旧版 sessionStorage 状态已随标签页关闭消失）。
     * 此时若直接判为未登录会把用户踢到登录页——而 cookie 明明还有效。
     *
     * 并发去重：路由守卫与在途请求可能同时触发，用 restorePromise 保证只探测一次。
     * @returns {Promise<boolean>} 是否成功重建会话
     */
    async restoreSession() {
      // 探测请求走在路由守卫的关键路径上：后端完全不可达时，全局 15s 超时乘以
      // 串行两步 = 最坏 30s 才放行（用户对着原页面以为卡死）。探测本身是轻量只读，
      // 10s 足够慢网通过，且与 doRefreshToken 的既有超时同口径。
      const RESTORE_TIMEOUT = 10000
      // 只有「本页已由服务端确认」才允许短路。localStorage 中的 currentUser 可被
      // 改写/残留，不能仅凭它为真就跳过核实（否则登出后残留的身份永远不会被发现）。
      if (this.currentUser && this.sessionVerified) return true
      if (this.restoreFailed) return false
      if (this.restorePromise) return this.restorePromise

      const hadCachedIdentity = !!this.currentUser
      const epoch = this.currentUser
      /** 明确未登录/身份不可信时清除本地缓存身份（不广播：其他标签页各自会核实） */
      const dropStaleIdentity = () => {
        this.currentUser = null
        this.permissions = []
        this.sessionVerified = false
        safeLocal.remove('currentUser')
        safeLocal.remove('permissions')
      }

      this.restorePromise = (async () => {
        try {
          // 动态导入避免 store ← api ← store 的模块循环依赖
          const { api } = await import('@/utils/api')
          // 第一步：轻量会话探测（始终 200，不触发 token 刷新链）。
          // 未登录用户首次访问 login 页时，若直接 getMe 会经历
          // 401 → doRefreshToken → refresh 400 的连锁请求，产生无意义日志。
          const { data: statusResp } = await api.auth.getSessionStatus({ timeout: RESTORE_TIMEOUT })
          if (!statusResp?.success || !statusResp.data?.authenticated) {
            this.restoreFailed = true
            if (hadCachedIdentity) dropStaleIdentity()
            return false
          }
          // 第二步：确认有有效会话后，再拉取完整用户信息。
          // silent401：getMe 在 access token 恰好过期但 refresh 有效时返回 401，
          // 此时拦截器会刷新并重试，属预期路径，不弹「登录已过期」
          const { data: resp } = await api.auth.getMe({ silent401: true, timeout: RESTORE_TIMEOUT })
          if (!resp?.success || !resp.data?.user) {
            this.restoreFailed = true
            if (hadCachedIdentity) dropStaleIdentity()
            return false
          }
          // 核实期间用户可能已登出/切换账号：此时不得把旧结果写回
          if (hadCachedIdentity && this.currentUser !== epoch) return false

          const { user, permissions } = resp.data
          // 与 login 响应的 user 对象口径对齐：/auth/me 返回 id，登录返回 userId
          // （P3-38：归一化统一补齐 userId/id/_id 三个别名）
          // 形状漂移（缺 id / permissions 非数组）时宁可不写：写进去只会得到
          // 「已登录但无法判断身份/权限」的半坏界面，且本地缓存会继续传播该脏值。
          const normalized = normalizeUser(user)
          if (!normalized || !Array.isArray(permissions)) {
            this.restoreFailed = true
            if (hadCachedIdentity) dropStaleIdentity()
            return false
          }
          this.currentUser = normalized
          this.permissions = toPermissionCodes(permissions)
          this.sessionVerified = true
          safeLocal.setJSON('currentUser', toPersistedUser(normalized))
          safeLocal.setJSON('permissions', this.permissions)
          // 不广播 login：这不是身份切换，只是本标签页补齐状态，
          // 广播会让其他标签页误判为「另一账号登录」而自我失效
          return true
        } catch (err) {
          // P3-42：区分「服务端明确答复未登录」与「请求没打通」。
          //
          // 原实现一律置 restoreFailed=true：弱网/离线/后端重启期间的一次
          // 网络失败，会让本标签页在**整个页面生命周期内**不再尝试恢复会话——
          // 网络恢复后用户仍被当作未登录，必须手动刷新页面才能回到已登录态，
          // 而 cookie 其实一直有效。
          //
          // 2026-10-30 收窄：只有 401/403 才是「服务端明确答复未登录」。
          // 原先按「4xx 一律算明确答复」处理，把这些同样不掌握会话状态的状态码
          // 也写进了负缓存，代价同样是整个页面生命周期不再探测：
          //   - 429：全站限流器（app.js 的 generalLimiter）打回，与登录态无关；
          //   - 404：后端版本比前端旧（/auth/session 尚未上线）或网关改写了路径；
          //   - 400：请求本身被拒（查询参数闸等），不代表会话失效；
          //   - 5xx / 网络错误 / 超时：无法核实。
          // 它们一律不写 restoreFailed，留给下一次触发（路由切换、下一个请求）重试。
          const status = err?.response?.status
          const isDefiniteAnswer = status === 401 || status === 403
          if (isDefiniteAnswer) {
            this.restoreFailed = true
            // 401/403 明确表示会话不可用：连同本地缓存身份一起清除
            if (hadCachedIdentity) dropStaleIdentity()
            return false
          }
          if (hadCachedIdentity) {
            // 打不通：无法核实，但后端仍是最终鉴权方（所有请求带 cookie）。
            // 保留已有身份与页面，下一次路由切换会继续尝试核实（sessionVerified 仍为 false）。
            return true
          }
          return false
        } finally {
          this.restorePromise = null
        }
      })()

      return this.restorePromise
    },

    // 本地状态清除；令牌 cookie 由后端 /auth/logout 响应清除（clearAuthCookies）
    clearAuth() {
      // 清除前捕获用户：用于向其他标签页广播「该用户已登出」
      const outgoingUser = this.currentUser
      this.currentUser = null
      this.permissions = []
      // 主动登出/会话失效后禁止再自动探测恢复：若登出请求未能清干净 cookie，
      // 路由守卫的恢复探测会把刚被清掉的会话又「救」回来
      this.restoreFailed = true
      this.sessionVerified = false
      // 票据是绑定账号+会话的短期凭证，登出后必须就地销毁（内存态，不落盘）
      clearReauthTicket()
      safeLocal.remove('currentUser')
      safeLocal.remove('permissions')
      // 兼容清理 I-01 迁移前的旧令牌与旧介质残留
      safeStorage.remove('currentUser')
      safeStorage.remove('permissions')
      safeStorage.remove('token')
      safeStorage.remove('refreshToken')
      if (outgoingUser) {
        broadcastAuthChange('logout', outgoingUser)
      }
    },

    /** 处理其他标签页广播的认证变更（由 main.js 的 initSessionSync 回调进入）。
     *
     * 规则：
     * - login 事件且本地已登录另一账号：cookie 已被覆盖，本地会话身份错位，
     *   必须立即失效（否则界面显示旧用户、请求以新用户身份执行）
     * - logout 事件且本地是同一用户：登出全局生效，本标签页同步登出
     * - 其余情况（未登录 / 同账号重复登录 / 其他账号登出）不影响本标签页
     *
     * 此 action 只清本地状态，不再广播——避免事件回环。 */
    handleRemoteAuthEvent(event) {
      if (!event || !this.currentUser) return

      const localUserId = String(
        this.currentUser.userId ?? this.currentUser.id ?? this.currentUser._id ?? ''
      )
      const remoteUserId = String(event.userId ?? '')

      let replaced = false
      if (event.type === 'login' && remoteUserId && remoteUserId !== localUserId) {
        replaced = true
      } else if (event.type === 'logout' && remoteUserId === localUserId) {
        replaced = true
      }
      if (!replaced) return

      // 仅清本地，不广播（防回环）
      this.currentUser = null
      this.permissions = []
      // 身份已被覆盖/终止，禁止本页再探测恢复
      this.restoreFailed = true
      this.sessionVerified = false
      // 旧会话的二次验证票据不能留给下一个身份使用
      clearReauthTicket()
      safeLocal.remove('currentUser')
      safeLocal.remove('permissions')
      safeStorage.remove('currentUser')
      safeStorage.remove('permissions')
      safeStorage.remove('token')
      safeStorage.remove('refreshToken')

      // 提示经 sessionStorage 传递（本标签页 location.replace 后仍可读，
      // 且不会污染其他标签页），由登录页挂载时消费——避免在此动态 import
      // router/i18n：会被打包器依赖分析追踪，把整个路由表拉进依赖图
      const noticeKey = event.type === 'login' ? 'login.sessionReplaced' : 'login.sessionEnded'
      safeStorage.set('authSyncNotice', noticeKey)

      // 整页跳转：会话被覆盖属于异常态，整页重置可顺带清空内存中的路由状态
      // 与进行中的请求；replace 不留历史记录，防止后退回已失效的页面
      //
      // P3-42：路径必须带上部署基路径。router 用 createWebHistory(BASE_URL)
      // 构造，若应用部署在子路径（如 /admin/）下，硬编码的 '/login' 会跳到
      // 站点根目录 —— 那里通常是另一个应用或 404，用户直接丢失上下文。
      const base = String(import.meta.env.BASE_URL || '/').replace(/\/+$/, '')
      const loginUrl = `${base}/login`
      try {
        window.location.replace(loginUrl)
      } catch (_) {
        window.location.href = loginUrl
      }
    },
  },
})
