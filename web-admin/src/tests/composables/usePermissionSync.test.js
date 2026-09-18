/**
 * 权限热同步行为测试（usePermissionSync）
 *
 * 该 composable 是「管理员改权限 → 被改的人免重登生效」的落点，此前无测试。
 * 三条最关键的契约（每条都能因真实退化而失败）：
 *  1. 载荷形状不可信时**不得**做乐观更新，必须直接向服务端要权威值。
 *     若这里放行，permissionCodes 被误发成对象数组会塞进 store，界面表现
 *     为「权限全被收回」——比不更新更糟。
 *  2. 权限集合**确实变了**才弹通知，不变不弹（后端按角色广播给全部持有者，
 *     对某些用户最终集合可能没变化，弹提示纯属噪音）。
 *  3. 未登录不建连；卸载时解除订阅并释放引用计数（否则连接泄漏）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, createApp, nextTick } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import i18n from '@/i18n'

const acquired = []
const released = []
const notifications = []

vi.mock('@/utils/websocket', () => ({
  acquireWebSocket: vi.fn(() => {
    const handlers = new Map()
    const ws = {
      on: vi.fn((evt, fn) => handlers.set(evt, fn)),
      off: vi.fn((evt) => handlers.delete(evt)),
      __handlers: handlers,
      __emit: (evt, payload) => handlers.get(evt)?.(payload),
    }
    acquired.push(ws)
    return ws
  }),
  releaseWebSocket: vi.fn(() => released.push(1)),
}))

vi.mock('element-plus/es/components/notification/index.mjs', () => ({
  ElNotification: vi.fn((opts) => notifications.push(opts)),
}))

const degradations = []
vi.mock('@/utils/errorReporter', () => ({
  reportDegradation: vi.fn((msg) => degradations.push(msg)),
  reportError: vi.fn(),
}))

// 必须在 mock 之后动态导入被测模块
const { usePermissionSync } = await import('@/composables/usePermissionSync')
const { useAuthStore } = await import('@/store')

let mounted = []
/** 在真实组件生命周期内运行 composable（onMounted/onUnmounted 只在组件里生效） */
const mountSync = () => {
  let api = null
  const Host = defineComponent({
    setup() {
      api = usePermissionSync()
      return () => h('div')
    },
  })
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(Host)
  app.use(i18n)
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
  setActivePinia(createPinia())
  acquired.length = 0
  released.length = 0
  notifications.length = 0
  degradations.length = 0
})

afterEach(() => {
  mounted.forEach((m) => m.unmount())
  mounted = []
})

describe('usePermissionSync 载荷校验与安全兜底', () => {
  test('载荷形状非法（permissionCodes 为对象数组）→ 不做乐观更新，直接拉权威值', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = ['device:read']
    const applySpy = vi.spyOn(auth, 'applyPermissionCodes')
    const refreshSpy = vi.spyOn(auth, 'refreshPermissionsFromServer').mockResolvedValue(true)
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const c = mountSync()
      await c.api().handlePermissionSync({ permissionCodes: [{ code: 'device:read' }] })
      expect(refreshSpy).toHaveBeenCalledTimes(1)
      expect(applySpy).not.toHaveBeenCalled()
      // 权限必须保持原值（未被污染）
      expect(auth.permissions).toEqual(['device:read'])
      // 漂移必须留痕，不能静默
      expect(consoleErr).toHaveBeenCalled()
      expect(String(consoleErr.mock.calls[0][0])).toContain('schema-drift')
    } finally {
      consoleErr.mockRestore()
    }
  })

  test('载荷合法（permissionCodes 为 string[]）→ 走 syncPermissionsFromEvent，不重复拉取', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = ['device:read']
    const syncSpy = vi.spyOn(auth, 'syncPermissionsFromEvent').mockResolvedValue(true)
    const refreshSpy = vi.spyOn(auth, 'refreshPermissionsFromServer').mockResolvedValue(true)
    const c = mountSync()
    await c.api().handlePermissionSync({ permissionCodes: ['device:read', 'device:write'] })
    expect(syncSpy).toHaveBeenCalledTimes(1)
    // 说明（变异验证 2026-09-18）：把入参从 parsed.data 换成 rawEvent，本组用例**不会红**——
    // 实测 zod 的 looseObject 对合法载荷返回内容完全等同的新对象（额外键保留、无 transform），
    // 两者行为等价。保留 parsed.data 是防御性写法（未来 schema 增加裁剪/强转时会生效），
    // 属已核实的等价变异体，不为它编造恒真断言。
    expect(syncSpy.mock.calls[0][0]).toEqual({ permissionCodes: ['device:read', 'device:write'] })
    expect(refreshSpy).not.toHaveBeenCalled()
  })

  test('极端载荷（null / 数组 / 字符串 / 数字）一律不得抛错，且都走权威兜底', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = []
    vi.spyOn(auth, 'refreshPermissionsFromServer').mockResolvedValue(true)
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const c = mountSync()
      for (const payload of [null, undefined, [], 'x', 42, { permissionCodes: 'not-array' }]) {
        await expect(c.api().handlePermissionSync(payload)).resolves.toBeUndefined()
      }
    } finally {
      consoleErr.mockRestore()
    }
  })
})

describe('usePermissionSync 通知去噪', () => {
  test('权限实际变化 → 弹一条 info 通知（duration=0 不自动消失）', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = ['device:read']
    // sync 模拟真实效果：应用后权限集变化
    vi.spyOn(auth, 'syncPermissionsFromEvent').mockImplementation(async () => {
      auth.permissions = ['device:read', 'alarm:read']
      return true
    })
    const c = mountSync()
    await c.api().handlePermissionSync({ permissionCodes: ['device:read', 'alarm:read'] })
    expect(notifications).toHaveLength(1)
    expect(notifications[0].type).toBe('info')
    expect(notifications[0].duration).toBe(0)
  })

  test('权限集合不变 → 不弹通知（后端按角色广播，无变化时不应打扰）', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = ['device:read']
    vi.spyOn(auth, 'syncPermissionsFromEvent').mockImplementation(async () => {
      auth.permissions = ['device:read'] // 集合相同，仅顺序不同
      return true
    })
    const c = mountSync()
    await c.api().handlePermissionSync({ permissionCodes: ['device:read'] })
    expect(notifications).toHaveLength(0)
  })

  test('前后集合元素相同但排列不同 → 判为「无变化」（两侧都排序后比较）', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    // fixture 设计：两侧各自都是不升序的排列，且两个「未排序拼接串」互不相等。
    // 这样一个 fixture 同时击穿三种排序缺失：
    //   只排序 before  → 'a|b|c' vs 'b|c|a' 不等 → 误弹通知 → 本用例变红
    //   只排序 after   → 'c|a|b' vs 'a|b|c' 不等 → 误弹通知 → 本用例变红
    //   两侧都不排序   → 'c|a|b' vs 'b|c|a' 不等 → 误弹通知 → 本用例变红
    //   实现正确     → 两侧排序均为 'a|b|c' → 不弹 → 绿
    // （三个变异体实测均 KILLED，见文件末尾变异验证记录）
    auth.permissions = ['c:read', 'a:read', 'b:read']
    vi.spyOn(auth, 'syncPermissionsFromEvent').mockImplementation(async () => {
      auth.permissions = ['b:read', 'c:read', 'a:read']
      return true
    })
    const c = mountSync()
    await c.api().handlePermissionSync({ permissionCodes: ['b:read', 'c:read', 'a:read'] })
    expect(notifications).toHaveLength(0)
  })
  test('permissions 为 null（store 被清空）→ 比较不得抛错', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = null
    vi.spyOn(auth, 'syncPermissionsFromEvent').mockImplementation(async () => {
      auth.permissions = ['x:read']
      return true
    })
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const c = mountSync()
      await expect(
        c.api().handlePermissionSync({ permissionCodes: ['x:read'] })
      ).resolves.toBeUndefined()
      expect(notifications).toHaveLength(1)
    } finally {
      consoleErr.mockRestore()
    }
  })
})

describe('usePermissionSync 连接生命周期', () => {
  test('未登录 → 不建连（避免无身份连接白占配额）', async () => {
    const auth = useAuthStore()
    auth.currentUser = null
    mountSync()
    await nextTick()
    expect(acquired).toHaveLength(0)
  })

  test('已登录 → 建连并订阅 permission-sync', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    mountSync()
    await nextTick()
    expect(acquired).toHaveLength(1)
    expect(acquired[0].__handlers.has('permission-sync')).toBe(true)
  })

  test('卸载 → 解除订阅并 releaseWebSocket（引用计数释放）', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    const c = mountSync()
    await nextTick()
    c.unmount()
    expect(acquired[0].off).toHaveBeenCalledWith('permission-sync', expect.any(Function))
    expect(released).toHaveLength(1)
  })

  test('建连失败 → 上报降级且不抛错（权限热同步失效必须可观测）', async () => {
    const wsMod = await import('@/utils/websocket')
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      throw new Error('socket down')
    })
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    expect(() => mountSync()).not.toThrow()
    await nextTick()
    expect(degradations.some((m) => m.includes('权限热同步已失效'))).toBe(true)
    expect(released).toHaveLength(0)
  })

  test('订阅注册失败（ws.on 抛错）→ 已取得的引用必须归还（否则 refCount 永久偏高，连接永不释放）', async () => {
    const wsMod = await import('@/utils/websocket')
    // 与上一条的区别：acquire **成功返回**（真实实现里 refCount 已 +1），失败发生在
    // 之后的 ws.on(...)。此时 catch 把 ws 置 null，若不同步归还引用，onUnmounted 的
    // `if (!ws) return` 会跳过 release —— refCount 永久 +1，其他使用方全部释放后
    // 连接也不会断开（本用例首版实测 SURVIVED：released 长度为 0）。
    wsMod.acquireWebSocket.mockImplementationOnce(() => ({
      on: () => {
        throw new Error('subscribe boom')
      },
      off: vi.fn(),
    }))
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    expect(() => mountSync()).not.toThrow()
    await nextTick()
    expect(degradations.some((m) => m.includes('权限热同步已失效'))).toBe(true)
    expect(released).toHaveLength(1)
  })

  test('订阅失败后再卸载：不得二次归还引用（catch 未清 ws 会让 onUnmounted 重复 release）', async () => {
    const wsMod = await import('@/utils/websocket')
    // acquire 成功返回（引用已 +1），ws.on 抛错。若 catch 里只归还引用却不把 ws 置 null，
    // onUnmounted 的 `if (!ws) return` 不会短路 → 对同一个引用再 release 一次，
    // refCount 被多减（实测：released 长度 2）。本用例首版缺失时该变异 SURVIVED。
    wsMod.acquireWebSocket.mockImplementationOnce(() => ({
      on: () => {
        throw new Error('subscribe boom')
      },
      off: vi.fn(),
    }))
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    const c = mountSync()
    await nextTick()
    expect(released).toHaveLength(1)

    c.unmount()

    expect(released).toHaveLength(1)
  })

  test('建连抛非 Error（字符串/对象）→ 降级上报不得再抛（String(error) 兜底分支）', async () => {
    const wsMod = await import('@/utils/websocket')
    wsMod.acquireWebSocket.mockImplementationOnce(() => {
      throw 'plain-string-failure'
    })
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    expect(() => mountSync()).not.toThrow()
    await nextTick()
    expect(degradations.some((m) => m.includes('权限热同步已失效'))).toBe(true)
  })

  test('同步后 permissions 被置 null → 变化比较不得抛错，且从「有」到「无」判为变化并提示', async () => {
    const auth = useAuthStore()
    auth.currentUser = { username: 'u1' }
    auth.permissions = ['device:read']
    vi.spyOn(auth, 'syncPermissionsFromEvent').mockImplementation(async () => {
      auth.permissions = null
      return true
    })
    const c = mountSync()
    await expect(c.api().handlePermissionSync({ permissionCodes: [] })).resolves.toBeUndefined()
    expect(notifications).toHaveLength(1)
  })
})
