import { defineStore } from 'pinia'
import { matchPermission } from '@/utils/permission'
import { broadcastAuthChange } from '@/utils/sessionSync'
import { toPermissionCodes } from '@/schemas'
import { safeStorage, safeLocal, readSessionState } from './storage'

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
  if (!user || typeof user !== 'object') return user
  const id = user.userId ?? user.id ?? user._id ?? null
  if (id === null) return { ...user }
  const idStr = String(id)
  return { ...user, userId: idStr, id: idStr, _id: idStr }
}

// 用户认证 Store
export const useAuthStore = defineStore('auth', {
  state: () => ({
    // I-01 httpOnly cookie 方案：令牌不进 JS 可读存储，由浏览器按 path 自动携带；
    // currentUser/permissions 为非敏感界面状态，存 localStorage 与 cookie 的
    // 浏览器级作用域对齐（新标签页、复制 URL、子路径直达均复用同一会话），
    // cookie 失效时首个 401 会触发刷新/登出闭环
    // P3-38：读取时也归一化——迁移前存下的旧形状（缺 _id/userId）需就地补齐
    currentUser: normalizeUser(readSessionState('currentUser')) || null,
    permissions: toPermissionCodes(readSessionState('permissions')),
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
    // token/refreshToken 参数仅为兼容既有调用签名，值被忽略（令牌走 httpOnly cookie）
    setAuth(_token, _refreshToken, user, permissions = []) {
      const normalized = normalizeUser(user)
      // 权限一律归一化为 string[]：后端两种口径（code 数组 / populate 对象数组）
      // 都可能出现，而 matchPermission 只认字符串——存了对象会让所有按钮判否
      const codes = toPermissionCodes(permissions)
      this.currentUser = normalized
      this.permissions = codes
      // 登录成功即重置负缓存：下次若本地状态丢失仍应允许探测恢复
      this.restoreFailed = false
      safeLocal.setJSON('currentUser', normalized)
      safeLocal.setJSON('permissions', codes)
      // 清理 I-01 迁移前写入 sessionStorage 的旧令牌与旧会话状态残留
      safeStorage.remove('token')
      safeStorage.remove('refreshToken')
      safeStorage.remove('currentUser')
      safeStorage.remove('permissions')
      // 通知其他标签页：cookie 身份已切换为该用户
      broadcastAuthChange('login', normalized)
    },

    setCurrentUser(user) {
      // P3-38：ProfileView 用 /auth/me 的形状（只有 id）覆盖此处，
      // 不归一化会让 userId/_id 丢失，「是否本人」判断随之失效
      const normalized = normalizeUser(user)
      this.currentUser = normalized
      safeLocal.setJSON('currentUser', normalized)
    },

    setPermissions(permissions) {
      const codes = toPermissionCodes(permissions)
      this.permissions = codes
      safeLocal.setJSON('permissions', codes)
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
      try {
        // 动态导入避免 store ← api ← store 的模块循环依赖
        const { api } = await import('@/utils/api')
        // silent401：会话可能刚好在此刻失效（管理员强制下线），
        // 那属于预期结果，交由既有的 401 闭环处理，不在这里弹二次提示
        const { data: resp } = await api.auth.getMe({ silent401: true })
        if (!resp?.success || !resp.data?.user) return false

        const normalized = normalizeUser(resp.data.user)
        const codes = toPermissionCodes(resp.data.permissions)
        this.currentUser = normalized
        this.permissions = codes
        safeLocal.setJSON('currentUser', normalized)
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
      // 第一段：乐观更新（推送未带完整集合时跳过，直接进入权威校验）
      this.applyPermissionCodes(event?.permissionCodes)
      // 第二段：权威校验（其结果覆盖乐观值）
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
      if (this.currentUser) return true
      if (this.restoreFailed) return false
      if (this.restorePromise) return this.restorePromise

      this.restorePromise = (async () => {
        try {
          // 动态导入避免 store ← api ← store 的模块循环依赖
          const { api } = await import('@/utils/api')
          // 第一步：轻量会话探测（始终 200，不触发 token 刷新链）。
          // 未登录用户首次访问 login 页时，若直接 getMe 会经历
          // 401 → doRefreshToken → refresh 400 的连锁请求，产生无意义日志。
          const { data: statusResp } = await api.auth.getSessionStatus()
          if (!statusResp?.success || !statusResp.data?.authenticated) {
            this.restoreFailed = true
            return false
          }
          // 第二步：确认有有效会话后，再拉取完整用户信息。
          // silent401：getMe 在 access token 恰好过期但 refresh 有效时返回 401，
          // 此时拦截器会刷新并重试，属预期路径，不弹「登录已过期」
          const { data: resp } = await api.auth.getMe({ silent401: true })
          if (!resp?.success || !resp.data?.user) {
            this.restoreFailed = true
            return false
          }

          const { user, permissions } = resp.data
          // 与 login 响应的 user 对象口径对齐：/auth/me 返回 id，登录返回 userId
          // （P3-38：归一化统一补齐 userId/id/_id 三个别名）
          const normalized = normalizeUser(user)
          this.currentUser = normalized
          this.permissions = toPermissionCodes(permissions)
          safeLocal.setJSON('currentUser', normalized)
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
          // 只有 4xx（服务端明确表态）才写负缓存；网络错误/超时/5xx 不写，
          // 留给下一次触发（路由切换、下一个请求）重试。
          const status = err?.response?.status
          const isDefiniteAnswer = typeof status === 'number' && status >= 400 && status < 500
          if (isDefiniteAnswer) {
            this.restoreFailed = true
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
