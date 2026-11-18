/**
 * useRealtimeRefresh 行为测试（列表页的 WebSocket 订阅接入口）
 *
 * 锁定契约（2026-11-17 审计 D 组修复 + 基本行为）：
 *  1. 挂载：acquire 一次引用，逐个 joinRoom / on；
 *  2. 卸载：off + leaveRoom + release 各一次（引用计数对称）；
 *  3. joinRoom 中途抛错：上报降级、**已加入的房间被回滚**（leaveRoom）、
 *     引用归还一次；之后再卸载不得二次释放（cleanup 幂等收口——修复点：
 *     旧实现 catch 置空 ws 后，卸载清理被 `if (!ws) return` 短路）；
 *  4. ws.on 抛错：同样回滚已加入房间并归还引用；
 *  5. acquire 本身抛错：上报降级、不归还（没有拿到引用）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, createApp } from 'vue'

const wsMocks = vi.hoisted(() => {
  const makeWs = () => {
    const joined = []
    const bound = []
    return {
      joined,
      bound,
      joinRoom: vi.fn((room) => joined.push(room)),
      leaveRoom: vi.fn((room) => {
        const i = joined.indexOf(room)
        if (i > -1) joined.splice(i, 1)
      }),
      on: vi.fn((evt, fn) => bound.push({ evt, fn })),
      off: vi.fn((evt, fn) => {
        const i = bound.findIndex((b) => b.evt === evt && b.fn === fn)
        if (i > -1) bound.splice(i, 1)
      }),
    }
  }
  return { makeWs, acquired: [], released: [], degradations: [] }
})

vi.mock('@/utils/websocket', () => ({
  acquireWebSocket: vi.fn(() => {
    const ws = wsMocks.makeWs()
    wsMocks.acquired.push(ws)
    return ws
  }),
  releaseWebSocket: vi.fn(() => {
    wsMocks.released.push(1)
  }),
}))

vi.mock('@/utils/errorReporter', () => ({
  reportDegradation: vi.fn((msg, extra) => wsMocks.degradations.push({ msg, extra })),
}))

// 必须在 mock 之后动态导入被测模块
const { useRealtimeRefresh } = await import('@/composables/useRealtimeRefresh')
const wsMod = await import('@/utils/websocket')

let mounted = []
/** 在真实组件生命周期内运行 composable（onMounted/onUnmounted 只在组件里生效） */
const mountRefresh = (options) => {
  let api = null
  const Host = defineComponent({
    setup() {
      api = useRealtimeRefresh(options)
      return () => h('div')
    },
  })
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(Host)
  app.mount(root)
  const handle = {
    api: () => api,
    unmount: () => {
      if (handle.done) return
      handle.done = true
      app.unmount()
      root.remove()
    },
  }
  mounted.push(handle)
  return handle
}

beforeEach(() => {
  wsMocks.acquired.length = 0
  wsMocks.released.length = 0
  wsMocks.degradations.length = 0
})

afterEach(() => {
  mounted.forEach((m) => m.unmount())
  mounted = []
  vi.clearAllMocks()
})

describe('useRealtimeRefresh 订阅生命周期', () => {
  test('挂载：acquire 一次并逐个 joinRoom / on；卸载：off + leaveRoom + release 各一次', () => {
    const handler = () => {}
    const c = mountRefresh({
      rooms: ['devices', 'alarms'],
      subscriptions: [{ event: 'device-changed', handler }],
      label: 'device-page',
    })
    expect(wsMocks.acquired).toHaveLength(1)
    expect(wsMocks.acquired[0].joined).toEqual(['devices', 'alarms'])
    expect(wsMocks.acquired[0].bound).toEqual([{ evt: 'device-changed', fn: handler }])

    c.unmount()
    expect(wsMocks.acquired[0].bound).toHaveLength(0)
    expect(wsMocks.acquired[0].joined).toEqual([])
    expect(wsMocks.released).toHaveLength(1)
  })

  test('joinRoom 中途抛错：上报降级、已加入房间回滚、引用归还一次；卸载不二次释放', () => {
    // 2026-11-17 审计 D 组修复点：部分加入失败必须回滚已加入的房间，
    // 且 catch 收口后卸载清理不得被短路（cleanup 幂等）
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      const ws = wsMocks.makeWs()
      wsMocks.acquired.push(ws)
      ws.joinRoom = vi.fn((room) => {
        if (room === 'alarms') throw new Error('join rejected')
        ws.joined.push(room)
      })
      return ws
    })
    const c = mountRefresh({ rooms: ['devices', 'alarms'], label: 'device-page' })
    const ws = wsMocks.acquired[0]
    // 两个房间都尝试过 join（第二个抛错）；cleanup 已同步回滚第一个房间
    expect(ws.joinRoom).toHaveBeenCalledTimes(2)
    expect(ws.leaveRoom).toHaveBeenCalledWith('devices')
    expect(ws.joined).toEqual([])
    expect(wsMocks.degradations[0].msg).toContain('WebSocket 订阅失败')
    expect(wsMocks.degradations[0].extra).toMatchObject({ error: 'join rejected' })
    // 引用归还一次
    expect(wsMocks.released).toHaveLength(1)

    // 失败后再卸载：cleanup 幂等，不得二次释放引用
    c.unmount()
    expect(wsMocks.released).toHaveLength(1)
  })

  test('ws.on 抛错：已加入房间回滚、引用归还一次', () => {
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      const ws = wsMocks.makeWs()
      wsMocks.acquired.push(ws)
      ws.on = vi.fn(() => {
        throw new Error('subscribe boom')
      })
      return ws
    })
    const c = mountRefresh({
      rooms: ['devices'],
      subscriptions: [{ event: 'device-changed', handler: () => {} }],
    })
    const ws = wsMocks.acquired[0]
    expect(ws.joined).toEqual([])
    expect(ws.leaveRoom).toHaveBeenCalledWith('devices')
    expect(wsMocks.released).toHaveLength(1)
    expect(wsMocks.degradations).toHaveLength(1)

    c.unmount()
    expect(wsMocks.released).toHaveLength(1)
  })

  test('acquire 本身抛错：上报降级，不归还引用（没有拿到引用）', () => {
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      throw new Error('socket down')
    })
    expect(() => mountRefresh({ rooms: ['devices'] })).not.toThrow()
    expect(wsMocks.degradations[0].msg).toContain('WebSocket 订阅失败')
    expect(wsMocks.degradations[0].extra).toMatchObject({ error: 'socket down' })
    expect(wsMocks.released).toHaveLength(0)
  })

  test('acquire 抛非 Error（字符串）：String(error) 兜底，不二次抛错', () => {
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      throw 'plain-string-failure'
    })
    expect(() => mountRefresh({ rooms: ['devices'] })).not.toThrow()
    expect(wsMocks.degradations[0].extra.error).toBe('plain-string-failure')
  })
})
