/**
 * websocket.js 行为测试（P1-27 的一半）
 *
 * 该模块此前零测试（报告：覆盖率 0/0/0/0）。本套件只覆盖能真实证伪的行为，
 * 不写「调用一遍断言不抛错」的空壳：
 *   1. io() 参数：带退避的重连配置与握手凭证设置确实被传递；
 *   2. 连接状态机：connect 幂等、connect_error 复位、重连耗尽的标记与回调；
 *   3. 房间：连接后 / 重连后自动重新 join，leaveRoom 撤销后重连不再复活；
 *      disconnect() 清空声明；
 *   4. 消息分发：on/off 的注册-解绑；send 未连接时静默丢弃；
 *   5. 断开清理：manager 级 reconnect_failed 解绑（防止下次 connect 后重复注册）；
 *   6. 引用计数：acquire/release 归零才断开；归零后重新 acquire 新建连接（V-2 边界）；
 *      disconnectWebSocket 强制清零；
 *   7. 降级上报：io() 同步抛错时 reportDegradation 被调用且不冒泡。
 *
 * 未覆盖（如实说明，不硬凑）：
 *   - 本模块没有心跳实现（ping/pong 由 socket.io 内部处理，options.timeout 只是
 *     握手/应答超时），因此不存在「心跳超时」分支可测；
 *   - 真实网络重连时序（退避计时、多轮握手）属 socket.io-client 的行为，
 *     不属本模块责任面，mock 层面测无意义。
 *   - disconnect() 里 manager 解绑的 catch 分支（:194）需要 socket.io.off 抛错，
 *     属防御性兜底，无真实触发路径。
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const ioMock = vi.fn()
vi.mock('socket.io-client', () => ({ io: (...args) => ioMock(...args) }))

const reportDegradation = vi.fn()
vi.mock('@/utils/errorReporter', () => ({
  reportDegradation: (...args) => reportDegradation(...args),
}))

class FakeSocket {
  constructor() {
    this.connected = false
    this.handlers = new Map()
    this.emitted = []
    this.disconnectCalls = 0
    this.removedAll = 0
    this.io = {
      handlers: new Map(),
      on(event, handler) {
        if (!this.handlers.has(event)) this.handlers.set(event, [])
        this.handlers.get(event).push(handler)
      },
      off(event, handler) {
        const list = this.handlers.get(event) || []
        const i = list.indexOf(handler)
        if (i > -1) list.splice(i, 1)
      },
      emit(event, ...args) {
        ;(this.handlers.get(event) || []).forEach((h) => h(...args))
      },
    }
  }

  on(event, handler) {
    if (!this.handlers.has(event)) this.handlers.set(event, [])
    this.handlers.get(event).push(handler)
  }

  off(event, handler) {
    const list = this.handlers.get(event) || []
    const i = list.indexOf(handler)
    if (i > -1) list.splice(i, 1)
  }

  removeAllListeners() {
    this.removedAll += 1
    this.handlers.clear()
  }

  emit(event, ...args) {
    this.emitted.push([event, ...args])
  }

  disconnect() {
    this.disconnectCalls += 1
    this.connected = false
  }

  /** 测试驱动：触发客户端监听的事件 */
  fire(event, ...args) {
    ;(this.handlers.get(event) || []).slice().forEach((h) => h(...args))
  }
}

const loadModule = async () => {
  vi.resetModules()
  return import('@/utils/websocket')
}

describe('websocket.js（P1-27）', () => {
  beforeEach(() => {
    ioMock.mockReset()
    reportDegradation.mockReset()
    window.history.pushState({}, '', '/')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('connect 把带退避的重连配置与凭证设置传给 io()', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.connect()

    expect(ioMock).toHaveBeenCalledTimes(1)
    const [url, options] = ioMock.mock.calls[0]
    expect(url).toBe('http://ws.example')
    expect(options).toMatchObject({
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      withCredentials: true,
    })
  })

  test('未传 url 时回退到同源 origin', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    new WebSocketService().connect()
    expect(ioMock.mock.calls[0][0]).toBe(window.location.origin)
  })

  test('connect 幂等：连接中或已连接时不重复建连', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.connect()
    svc.connect() // isConnecting = true
    expect(ioMock).toHaveBeenCalledTimes(1)

    sock.connected = true
    sock.fire('connect')
    svc.connect() // 已连接
    expect(ioMock).toHaveBeenCalledTimes(1)
  })

  test('connect_error 复位 isConnecting（允许后续重试建连）', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.connect()
    sock.fire('connect_error', new Error('boom'))
    expect(svc.isConnecting).toBe(false)

    svc.connect()
    expect(ioMock).toHaveBeenCalledTimes(2)
  })

  test('重连耗尽：reconnectExhausted 置真并通知 onGiveUp，新一轮连接清除标记', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    const giveUp = vi.fn()
    svc.onGiveUp(giveUp)
    svc.connect()
    sock.fire('connect')
    expect(svc.reconnectExhausted).toBe(false)

    sock.io.emit('reconnect_failed')
    expect(svc.reconnectExhausted).toBe(true)
    expect(giveUp).toHaveBeenCalledTimes(1)

    // 再次 connect 会清除耗尽标记（新一轮连接开始）
    svc.connect()
    expect(svc.reconnectExhausted).toBe(false)
    expect(ioMock).toHaveBeenCalledTimes(2)
  })

  test('onGiveUp 回调抛错不影响 socket 状态（隔离保护）', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.onGiveUp(() => {
      throw new Error('ui handler exploded')
    })
    svc.connect()
    expect(() => sock.io.emit('reconnect_failed')).not.toThrow()
    expect(svc.reconnectExhausted).toBe(true)
  })

  test('joinRoom：未连接只登记，已连接立即 emit；连接/重连后自动重新 join', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.joinRoom('alarms')
    expect(sock.emitted).toHaveLength(0) // 未连接时不 emit

    svc.connect()
    sock.connected = true
    svc.joinRoom('devices') // 已连接：立即 emit
    expect(sock.emitted).toEqual([['join-room', 'devices']])

    // 重连（同一 socket 实例上再次触发 connect）→ 两个房间都要重新 join
    sock.emitted = []
    sock.fire('connect')
    expect(sock.emitted).toEqual(
      expect.arrayContaining([
        ['join-room', 'alarms'],
        ['join-room', 'devices'],
      ])
    )
  })

  test('joinRoom 空值忽略', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.joinRoom('')
    svc.joinRoom(null)
    expect(svc.rooms.size).toBe(0)
  })

  test('leaveRoom：已连接时 emit leave-room 并撤出声明集合，重连不再重新 join', async () => {
    // 房间集合跨页面存活（引用计数归零前连接不断），而 connect 处理器会把声明过的
    // 房间全部重新 join。只释放引用不撤房间 ⇒ 房间名跨页面残留，每次重连白吃一次
    // 后端拒绝（如 role-management 要求 SUPER_ADMIN/SECURITY_ADMIN）。
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.joinRoom('alarms')
    svc.joinRoom('devices')
    svc.connect()
    sock.connected = true
    sock.fire('connect')
    expect(sock.emitted).toEqual(
      expect.arrayContaining([
        ['join-room', 'alarms'],
        ['join-room', 'devices'],
      ])
    )

    sock.emitted = []
    svc.leaveRoom('alarms')
    expect(sock.emitted).toEqual([['leave-room', 'alarms']])
    expect(svc.rooms.has('alarms')).toBe(false)

    // 重连后只重新 join 仍声明着的房间，被撤销的不得复活
    sock.emitted = []
    sock.fire('connect')
    expect(sock.emitted).toEqual([['join-room', 'devices']])
  })

  test('leaveRoom：未连接时只撤集合不发包；空值忽略', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.joinRoom('alarms')
    svc.leaveRoom('')
    svc.leaveRoom(null)
    expect(svc.rooms.size).toBe(1)

    // 未连接时撤销：没有连接可发包，但集合必须改——否则下次建连时
    // connect 处理器会把房间重新 join 回来，撤销形同没做
    svc.leaveRoom('alarms')
    expect(sock.emitted).toHaveLength(0)
    expect(svc.rooms.size).toBe(0)

    svc.connect()
    sock.connected = true
    sock.fire('connect')
    expect(sock.emitted).toEqual([])
  })
  test('消息分发：已连接时 on/off 注册与解绑都同步到 socket', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    const received = []
    const handler = (payload) => received.push(payload)
    svc.on('permission-update', handler)

    svc.connect()
    sock.connected = true
    sock.fire('connect')
    sock.fire('permission-update', { roleId: 'r1' })
    expect(received).toEqual([{ roleId: 'r1' }])

    svc.off('permission-update', handler)
    sock.fire('permission-update', { roleId: 'r2' })
    expect(received).toHaveLength(1) // 解绑后不再收到
  })

  test('连接前注册的 on 处理器在建连后仍被绑定（handlers 回放）', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    const received = []
    svc.on('alarm', (p) => received.push(p))
    svc.connect()

    expect(sock.handlers.get('alarm')).toHaveLength(1)
    sock.fire('alarm', { id: 1 })
    expect(received).toEqual([{ id: 1 }])
  })

  test('send 未连接时静默丢弃（不抛出、不 emit）', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    expect(() => svc.send('join-room', 'alarms')).not.toThrow()
    expect(sock.emitted).toHaveLength(0)

    svc.connect()
    sock.connected = true
    svc.send('join-room', 'alarms')
    expect(sock.emitted).toEqual([['join-room', 'alarms']])
  })

  test('disconnect 清理：解绑 manager 监听、清空 handlers 与房间、断开 socket', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.joinRoom('alarms')
    svc.on('x', () => {})
    svc.connect()
    sock.fire('connect')

    const managerHandlers = sock.io.handlers.get('reconnect_failed')
    expect(managerHandlers).toHaveLength(1)

    svc.disconnect()
    // manager 级监听已解绑（否则下次 connect 会重复注册，提示弹多次）
    expect(sock.io.handlers.get('reconnect_failed')).toHaveLength(0)
    expect(sock.disconnectCalls).toBe(1)
    expect(svc.socket).toBeNull()
    expect(svc.handlers.size).toBe(0)
    expect(svc.rooms.size).toBe(0)
    expect(svc.reconnectExhausted).toBe(false)
  })

  test('重连耗尽后再次 connect：旧 socket 先解绑断开，不残留监听', async () => {
    const first = new FakeSocket()
    const second = new FakeSocket()
    ioMock.mockReturnValueOnce(first).mockReturnValueOnce(second)
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('http://ws.example')
    svc.connect()
    first.io.emit('reconnect_failed')

    svc.connect() // 新一轮
    expect(first.removedAll).toBe(1)
    expect(first.disconnectCalls).toBe(1)
    expect(ioMock).toHaveBeenCalledTimes(2)
  })

  test('io() 同步抛错：不冒泡，且上报一条 degrade 降级记录', async () => {
    ioMock.mockImplementation(() => {
      throw new Error('Invalid URL')
    })
    const { WebSocketService } = await loadModule()

    const svc = new WebSocketService('not-a-url')
    expect(() => svc.connect()).not.toThrow()
    expect(svc.isConnecting).toBe(false)

    expect(reportDegradation).toHaveBeenCalledTimes(1)
    const [message, extra] = reportDegradation.mock.calls[0]
    expect(message).toContain('websocket')
    expect(extra.error).toContain('Invalid URL')
    expect(extra.url).toBe('not-a-url')
  })
})

describe('websocket.js 引用计数（P1-27）', () => {
  beforeEach(() => {
    ioMock.mockReset()
    reportDegradation.mockReset()
  })

  afterEach(async () => {
    // 模块级 wsService/refCount 是模块作用域状态：重置模块即回到干净状态
    const { disconnectWebSocket } = await loadModule()
    disconnectWebSocket()
  })

  test('acquire/release 成对：归零才断开，中间保持同一实例', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const mod = await loadModule()

    const a = mod.acquireWebSocket()
    const b = mod.acquireWebSocket()
    expect(b).toBe(a)
    expect(mod.__getRefCount()).toBe(2)

    expect(mod.releaseWebSocket()).toBe(1)
    expect(sock.disconnectCalls).toBe(0) // 还有人用，不能断
    expect(mod.getWebSocketService()).toBe(a)

    expect(mod.releaseWebSocket()).toBe(0)
    expect(sock.disconnectCalls).toBe(1)
  })

  test('多余 release 不产生负计数', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const mod = await loadModule()

    mod.acquireWebSocket()
    expect(mod.releaseWebSocket()).toBe(0)
    expect(mod.releaseWebSocket()).toBe(0)
    expect(mod.__getRefCount()).toBe(0)
  })

  test('归零后重新 acquire：新建实例，不复用已断开的旧 sockets（V-2 边界）', async () => {
    const first = new FakeSocket()
    const second = new FakeSocket()
    ioMock.mockReturnValueOnce(first).mockReturnValueOnce(second)
    const mod = await loadModule()

    const a = mod.acquireWebSocket()
    expect(ioMock).toHaveBeenCalledTimes(1)
    expect(mod.releaseWebSocket()).toBe(0)
    expect(first.disconnectCalls).toBe(1)

    // 归零后再次 acquire 必须拿全新连接——若复用旧实例，用户会挂在已断开的 socket 上静默收不到推送
    const b = mod.acquireWebSocket()
    expect(b).not.toBe(a) // 服务实例重建（旧实例已随归零断开并置空）
    expect(ioMock).toHaveBeenCalledTimes(2) // 第二次 acquire 真的新建了连接
    expect(second.disconnectCalls).toBe(0) // 新连接必须活着
    expect(mod.__getRefCount()).toBe(1)
  })

  test('归零瞬间并发 acquire：释放不误杀刚建立的新连接（V-2 核心竞态）', async () => {
    const first = new FakeSocket()
    const second = new FakeSocket()
    ioMock.mockReturnValueOnce(first).mockReturnValueOnce(second)
    const mod = await loadModule()

    mod.acquireWebSocket()
    mod.releaseWebSocket() // 归零并断开 first
    mod.acquireWebSocket() // 立刻重新建立 second
    mod.releaseWebSocket() // 释放第二个引用

    // 净引用数为 0，second 确实被断开；first 只断开过一次（不被二次引用）
    expect(mod.__getRefCount()).toBe(0)
    expect(second.disconnectCalls).toBe(1)
    expect(first.disconnectCalls).toBe(1)
  })

  test('disconnectWebSocket 强制清零并断开（登出路径）', async () => {
    const sock = new FakeSocket()
    ioMock.mockReturnValue(sock)
    const mod = await loadModule()

    mod.acquireWebSocket()
    mod.acquireWebSocket()
    mod.disconnectWebSocket()

    expect(mod.__getRefCount()).toBe(0)
    expect(sock.disconnectCalls).toBe(1)
  })
})
