/**
 * WebSocket 服务 - 基于 socket.io-client，与后端 src/services/websocketService/（Socket.IO）对齐
 *
 * 相对旧版「原生 new WebSocket」实现的关键修正：
 *  1. 协议对齐：后端使用 Socket.IO（engine.io 帧），原生 WebSocket 无法完成握手与认证；
 *  2. 地址对齐：始终同源连接 window.location.origin，开发经 Vite 代理 /socket.io/ -> 后端 3000，
 *     生产经 Nginx 代理 /socket.io/ -> 后端 3000（见 deployment/nginx.conf.example），不再硬编码端口；
 *  3. 重连：直接使用 socket.io-client 内置的带退避自动重连（reconnectionDelay/Max），
 *     替代旧版线性定时器，解决此前「WS 重连无退避」问题。
 */

import { io } from 'socket.io-client'
import { reportDegradation } from '@/utils/errorReporter'

// 始终同源：开发/Vite 代理与生产/Nginx 代理都会把 /socket.io/ 转发到后端 3000。
// 如需开发期直连后端（绕过代理），可设置 VITE_WS_URL=http://localhost:3000 覆盖。
const resolveWsUrl = () => import.meta.env.VITE_WS_URL || window.location.origin

/**
 * 未连接时丢弃上报的节流窗口（F-13）
 *
 * 断线期间 `send()` 会被业务代码反复调用（定时刷新、批量订阅）。每次都
 * `reportDegradation` 会把错误上报通道自己打爆，而调用方看面板只会看到
 * "全是 websocket 错误"——反而盖住了真正的首因。窗口内的丢弃仍计入
 * `droppedSends`，只是不重复上报。
 */
const DROP_REPORT_INTERVAL_MS = 10000

export class WebSocketService {
  constructor(url = null, options = {}) {
    this.url = url || resolveWsUrl()
    this.options = {
      // 默认先 polling 再升级 websocket，对各类反向代理兼容性最好
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 20000,
      // I-01：握手阶段携带 httpOnly 的 access_token cookie 完成认证
      // （后端 websocketService 优先读握手请求头 cookie，无需再 emit 令牌）
      withCredentials: true,
      ...options,
    }
    this.socket = null
    this.handlers = new Map()
    this.isConnecting = false
    this._onConnect = null
    this._onConnectError = null
    this._onDisconnect = null
    this._onReconnectFailed = null
    // P3-43：重连彻底失败的回调（默认为空，由调用方注入 UI 提示）
    this._onGiveUp = null
    /** 是否已耗尽重连次数（供调用方查询「实时推送是否已失效」） */
    this.reconnectExhausted = false
    /**
     * 需要加入的房间集合
     *
     * 不再无条件 join 'role-management'：该房间要求 SUPER_ADMIN/SECURITY_ADMIN，
     * 普通用户加入会被后端拒绝并回一条 error 事件。而权限同步（permission-sync）
     * 是按 socket 定向投递的，根本不需要入房——为它连上来的普通用户不该
     * 每次连接都触发一次「无权加入该房间」。房间由调用方按需声明。
     */
    this.rooms = new Set()
    /** 未连接时被丢弃的 send 次数（F-13：让"静默丢弃"变成可读数字） */
    this.droppedSends = 0
    /** 上一次丢弃上报的时间戳，用于节流（见 send 的注释） */
    this._lastDropReportAt = 0
  }

  /**
   * 注册「重连彻底失败」回调（P3-43）
   *
   * socket.io-client 在 reconnectionAttempts 次尝试全部失败后触发
   * reconnect_failed 并**永久停止重连**。原实现没有监听该事件：
   * 连接就此静默死亡，界面上一切正常（列表还在、按钮能点），
   * 只是角色变更、报警推送等实时更新再也不来了。用户看到的是
   * 「过期数据」而不是「连接断开」——比明确报错危险得多，
   * 因为他会基于陈旧数据做决策。
   * @param {() => void} handler 失败回调
   * @returns {void}
   */
  onGiveUp(handler) {
    this._onGiveUp = typeof handler === 'function' ? handler : null
  }

  /**
   * 声明需要加入的房间（连接后自动 join，重连后自动重新 join）
   *
   * 重连后必须重新 join：socket.io 重连产生的是**新的** socket id，
   * 服务端的房间成员表按 socket id 记录，旧的成员关系随断连即失效。
   * @param {string} room 房间名（须在后端 ALLOWED_ROOMS 白名单内）
   * @returns {void}
   */
  joinRoom(room) {
    if (!room) return
    this.rooms.add(room)
    if (this.socket && this.socket.connected) {
      this.socket.emit('join-room', room)
    }
  }

  /**
   * 声明不再需要某个房间（与 joinRoom 成对，后端 websocketService 对称处理 leave-room）
   *
   * 为什么必须有：joinRoom 只往 this.rooms 里加名字，而重连后 connect 处理器会
   * 无差别重新 join 全部声明过的房间（socket id 已变，服务端成员关系随断连失效）。
   * 若使用方卸载时只释放引用而不撤房间，房间名就跨页面存活：布局层的权限同步
   * 仍持有引用 ⇒ 连接不断开 ⇒ 下一次建连时该房间被重新 join。对后端要求
   * SUPER_ADMIN/SECURITY_ADMIN 的房间（如 role-management），持 role:read 的
   * 普通管理员每次重连都要白吃一次后端拒绝。
   * @param {string} room 房间名
   * @returns {void}
   */
  leaveRoom(room) {
    if (!room) return
    this.rooms.delete(room)
    if (this.socket && this.socket.connected) {
      this.socket.emit('leave-room', room)
    }
  }
  connect() {
    if (this.isConnecting || (this.socket && this.socket.connected)) return

    // 重连耗尽场景：旧 socket 仍持有退避重连定时器，先解绑全部监听并断开，
    // 再新建连接，防止旧 socket 的重连定时器复活产生双连接
    if (this.socket) {
      this.socket.removeAllListeners()
      this.socket.disconnect()
      this.socket = null
      this.isConnecting = false
    }

    this.isConnecting = true
    // 新一轮连接开始，清除上一轮的耗尽标记
    this.reconnectExhausted = false

    try {
      this.socket = io(this.url, this.options)

      this._onConnect = () => {
        this.isConnecting = false
        this.reconnectExhausted = false
        // I-01：认证由握手 cookie 完成（withCredentials 自动携带 access_token，
        // 后端校验通过后 socket.authenticated=true），无需再发送令牌。
        // 重连后 socket id 已变，服务端房间成员表按 socket id 记录，
        // 必须重新 join 声明过的全部房间，否则重连后再也收不到房间广播
        this.rooms.forEach((room) => this.socket.emit('join-room', room))
      }

      this._onConnectError = () => {
        this.isConnecting = false
        // socket.io-client 内置带退避重连；此处仅标记，不手动重连
      }

      this._onDisconnect = () => {
        this.isConnecting = false
      }

      // P3-43：重连次数耗尽 → 标记失效并通知调用方。
      // 不在此处自动无限重试：那会退化成无退避的连接风暴，
      // 且后端不可用时纯属浪费。把决定权交给调用方（提示用户手动刷新，
      // 或由页面在下次可见时重新 connect()）。
      this._onReconnectFailed = () => {
        this.isConnecting = false
        this.reconnectExhausted = true
        if (this._onGiveUp) {
          try {
            this._onGiveUp()
          } catch (_) {}
        }
      }

      this.socket.on('connect', this._onConnect)
      this.socket.on('connect_error', this._onConnectError)
      this.socket.on('disconnect', this._onDisconnect)
      // io.on 而非 socket.on：reconnect_failed 由 manager 派发
      this.socket.io.on('reconnect_failed', this._onReconnectFailed)

      // 绑定已通过 on() 注册的业务事件（连接建立前后注册均可）
      this.handlers.forEach((list, type) => {
        list.forEach((handler) => this.socket.on(type, handler))
      })
    } catch (error) {
      this.isConnecting = false
      // P1-18：io() 同步抛错（非法 URL / options）会静默吞掉，调用方只看到「没连上」。
      // 降级行为不变（调用方仍走「无实时推送」路径），但上报一次使故障可观测。
      reportDegradation('websocket: 首次建连失败，实时推送不可用', {
        error: error?.message || String(error),
        url: this.url,
      })
    }
  }

  /**
   * 发送事件。返回值是调用方唯一能拿到的送达语义：
   *   `true`  = 已交给 socket.io 的发送队列（**不等于**对端收到）
   *   `false` = 未发送（socket 不存在或未连接），已计入 `droppedSends`
   *
   * 为什么不再"静默丢弃"（F-13，2026-10-17）：断线窗口里丢掉的 join-room 不会自愈——
   * 重连后房间不会自动重建，页面表现是"连着却收不到推送"。现在至少让丢弃可分辨、可见：
   *   1. 返回值区分「已交给发送队列」与「未发送」；
   *   2. `this.droppedSends` 累计数（调用方/监控/测试可读）；
   *   3. `reportDegradation` 上报，但按 `DROP_REPORT_INTERVAL_MS` 节流——断线期间
   *      每次 send 都上报会把错误上报通道自己打爆（降级引发降级）。
   *
   * 刻意**不做**自动排队：排队要先定义容量、过期与顺序语义。幂等事件（join-room、
   * 订阅）重连后由 onConnect 重放更可靠；非幂等事件（指令下发）排队重放会重复执行。
   * 真正需要"必达"的业务事件应由服务端持久化 + 版本号/重新同步承担，不是本方法能兜的。
   *
   * @param {string} event
   * @param {unknown} [payload]
   * @returns {boolean} 是否已交给 socket.io 发送队列
   */
  send(event, payload) {
    if (this.socket && this.socket.connected) {
      this.socket.emit(event, payload)
      return true
    }
    this.droppedSends += 1
    const now = Date.now()
    if (now - this._lastDropReportAt >= DROP_REPORT_INTERVAL_MS) {
      this._lastDropReportAt = now
      reportDegradation('websocket: 未连接，事件未发送', {
        event,
        dropped: this.droppedSends,
        url: this.url,
      })
    }
    return false
  }

  on(type, handler) {
    if (!this.handlers.has(type)) this.handlers.set(type, [])
    this.handlers.get(type).push(handler)
    if (this.socket) this.socket.on(type, handler)
  }

  off(type, handler) {
    const handlers = this.handlers.get(type)
    if (handlers) {
      const index = handlers.indexOf(handler)
      if (index > -1) handlers.splice(index, 1)
    }
    if (this.socket) this.socket.off(type, handler)
  }

  disconnect() {
    if (this.socket) {
      if (this._onConnect) this.socket.off('connect', this._onConnect)
      if (this._onConnectError) this.socket.off('connect_error', this._onConnectError)
      if (this._onDisconnect) this.socket.off('disconnect', this._onDisconnect)
      // P3-43：manager 级监听必须单独解绑——socket.removeAllListeners() 只清
      // socket 自身的监听，manager 上的 reconnect_failed 会残留，
      // 下次 connect() 后同一回调被重复注册（提示弹多次）
      if (this._onReconnectFailed && this.socket.io) {
        try {
          this.socket.io.off('reconnect_failed', this._onReconnectFailed)
        } catch (_) {}
      }
      this.socket.removeAllListeners()
      this.socket.disconnect()
      this.socket = null
    }
    this.handlers.clear()
    this._onGiveUp = null
    this.reconnectExhausted = false
    this.rooms.clear()
  }
}

// 全局 WebSocket 实例
let wsService = null

/**
 * 连接引用计数
 *
 * 此前 RoleView 在 onUnmounted 里直接 disconnectWebSocket()。当权限同步
 * 也需要长连接（且要在整个登录会话期间保持）时，这个行为会变成缺陷：
 * 用户从角色页离开，连接被拆掉，权限变更推送随之收不到——
 * 而「离开角色管理页」和「不再需要权限同步」毫无关系。
 *
 * 改为引用计数：每个使用方 acquire 一次、release 一次，
 * 计数归零才真正断开。
 */
let refCount = 0

export const getWebSocketService = () => {
  if (!wsService) {
    wsService = new WebSocketService()
  }
  return wsService
}

// 便捷方法
export const connectWebSocket = () => {
  const service = getWebSocketService()
  service.connect()
  return service
}

/**
 * 获取连接并登记一次引用（与 releaseWebSocket 成对使用）
 * @returns {WebSocketService}
 */
export const acquireWebSocket = () => {
  refCount += 1
  return connectWebSocket()
}

/**
 * 释放一次引用；计数归零时断开连接
 * @returns {number} 释放后的剩余引用数
 */
export const releaseWebSocket = () => {
  refCount = Math.max(0, refCount - 1)
  if (refCount === 0 && wsService) {
    wsService.disconnect()
    wsService = null
  }
  return refCount
}

/**
 * 无条件断开（登出时调用）
 *
 * 登出必须强制断开并清零计数：残留的连接仍携带旧身份的 cookie，
 * 会继续接收上一个账号的推送。
 */
export const disconnectWebSocket = () => {
  refCount = 0
  if (wsService) {
    wsService.disconnect()
    wsService = null
  }
}

/** 供测试断言当前引用数 */
export const __getRefCount = () => refCount
