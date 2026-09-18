/**
 * 跨标签页会话同步的**通道层**测试（§13 V-5）
 *
 * 缺口（本轮实测）：`git grep -n "sessionSync\|BroadcastChannel" -- src/tests` 为空。
 * 现有 `store/authStore.test.js:233-292` 的 6 个用例直接调 `handleRemoteAuthEvent`，
 * 绕过了 sessionSync.js 全部通道代码——`ensureChannel` / `broadcastAuthChange` /
 * `initSessionSync` 三函数在生产中零覆盖。V-5 的怀疑（"防护是否已过时"）因此
 * 只能靠读码回答；本套件把结论钉成可失败断言。
 *
 * V-5 结论：**防护仍然有效**。通道（BroadcastChannel + localStorage 镜像键）与身份
 * 存储介质解耦——身份状态从 sessionStorage 迁到 localStorage 只改变"被保护对象"的
 * 存放位置，不改变"变更通知"的投递路径。真正会失效的场景（广播时对方标签页未运行、
 * 隐私模式双通道皆断）已在模块注释 :20-25 如实声明，属已知边界而非缺陷。
 *
 * 断言对象是**投递行为与负载内容**，不是源码文本：
 *  - 删掉 broadcastAuthChange 的 postMessage → 第 1、2 条红；
 *  - 删掉 storage 兜底写入 → 第 3、4 条红；
 *  - 删掉 initSessionSync 的 storage 监听 → 第 6、7 条红；
 *  - 把事件类型写死为 'login' → 第 2 条红。
 *
 * 注意：sessionSync 的 channel 是**模块级缓存**（ensureChannel 只建一次），
 * 因此每个用例都必须重建模块，否则第一个用例创建的通道会被后续用例复用。
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

/** 重建模块，拿到未被上一个用例污染的全新模块级状态 */
const loadModule = async () => {
  vi.resetModules()
  return await import('@/utils/sessionSync')
}

const CHANNEL_NAME = 'auth-session-sync'
const STORAGE_MIRROR_KEY = 'authSessionSyncMirror'

describe('§13 V-5 sessionSync 通道层', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.unstubAllGlobals()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  test('BroadcastChannel 可用：广播经通道投递，负载含类型/用户标识/时间戳', async () => {
    const posted = []
    const instances = []
    class FakeBC {
      constructor(name) {
        this.name = name
        instances.push(this)
      }
      postMessage(payload) {
        posted.push(payload)
      }
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { broadcastAuthChange, CHANNEL_NAME: NAME } = await loadModule()

    broadcastAuthChange('login', { userId: 'u-alice', username: 'alice' })

    expect(NAME).toBe(CHANNEL_NAME)
    expect(instances).toHaveLength(1)
    expect(instances[0].name).toBe(CHANNEL_NAME)
    expect(posted).toHaveLength(1)
    expect(posted[0]).toMatchObject({ type: 'login', userId: 'u-alice', username: 'alice' })
    expect(typeof posted[0].ts).toBe('number')
    // 通道可用时不应再写 localStorage 镜像（避免双份信号）
    expect(localStorage.getItem(STORAGE_MIRROR_KEY)).toBeNull()
  })

  test('logout 事件类型如实透传（不得一律发 login）', async () => {
    const posted = []
    class FakeBC {
      postMessage(p) {
        posted.push(p)
      }
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('logout', { id: 'u-bob', username: 'bob' })

    expect(posted[0].type).toBe('logout')
    // id/_id/userId 三种字段名都可作为标识（登录响应与 /auth/me 形状不同）
    expect(posted[0].userId).toBe('u-bob')
  })

  test('BroadcastChannel 不可用：降级写 localStorage 镜像键（storage 事件通道）', async () => {
    vi.stubGlobal('BroadcastChannel', undefined)
    const { broadcastAuthChange, STORAGE_MIRROR_KEY: KEY } = await loadModule()

    broadcastAuthChange('login', { userId: 'u-carol', username: 'carol' })

    expect(KEY).toBe(STORAGE_MIRROR_KEY)
    const raw = localStorage.getItem(STORAGE_MIRROR_KEY)
    expect(raw).not.toBeNull()
    expect(JSON.parse(raw)).toMatchObject({
      type: 'login',
      userId: 'u-carol',
      username: 'carol',
    })
    expect(typeof JSON.parse(raw).ts).toBe('number')
  })

  test('BroadcastChannel 构造抛错：同样降级到 localStorage 镜像', async () => {
    class ThrowingBC {
      constructor() {
        throw new Error('blocked by policy')
      }
    }
    vi.stubGlobal('BroadcastChannel', ThrowingBC)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('logout', { userId: 'u-dave' })

    const payload = JSON.parse(localStorage.getItem(STORAGE_MIRROR_KEY))
    expect(payload.type).toBe('logout')
    expect(payload.userId).toBe('u-dave')
  })

  test('localStorage 写入被拒（隐私模式）：不抛错，仅失去跨标签页同步', async () => {
    vi.stubGlobal('BroadcastChannel', undefined)
    const { broadcastAuthChange } = await loadModule()
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })

    expect(() => broadcastAuthChange('login', { userId: 'u-x' })).not.toThrow()
    spy.mockRestore()
  })

  test('initSessionSync：storage 事件（镜像键）驱动回调', async () => {
    const received = []
    const { initSessionSync, STORAGE_MIRROR_KEY: KEY } = await loadModule()
    initSessionSync((e) => received.push(e))

    expect(KEY).toBe(STORAGE_MIRROR_KEY)
    const payload = { type: 'login', userId: 'u-admin', username: 'admin', ts: Date.now() }
    window.dispatchEvent(
      new StorageEvent('storage', { key: STORAGE_MIRROR_KEY, newValue: JSON.stringify(payload) })
    )

    expect(received).toHaveLength(1)
    expect(received[0]).toMatchObject({ type: 'login', userId: 'u-admin' })
  })

  test('initSessionSync：其他 key / 空值 / 非法 JSON 一律忽略', async () => {
    const received = []
    const { initSessionSync } = await loadModule()
    initSessionSync((e) => received.push(e))

    // 其他 key（如 currentUser 自身变更）不属本通道
    window.dispatchEvent(new StorageEvent('storage', { key: 'currentUser', newValue: '{}' }))
    // 删除事件（newValue=null）不处理
    window.dispatchEvent(new StorageEvent('storage', { key: STORAGE_MIRROR_KEY, newValue: null }))
    // 非法负载不抛错、不回调
    window.dispatchEvent(
      new StorageEvent('storage', { key: STORAGE_MIRROR_KEY, newValue: 'not-json{' })
    )

    expect(received).toHaveLength(0)
  })

  test('initSessionSync：BroadcastChannel 可用时同时挂 onmessage（双通道投递）', async () => {
    const channels = []
    class FakeBC {
      constructor(name) {
        this.name = name
        this.onmessage = null
        channels.push(this)
      }
      postMessage() {}
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { initSessionSync } = await loadModule()

    const received = []
    initSessionSync((e) => received.push(e))

    expect(channels).toHaveLength(1)
    expect(channels[0].name).toBe(CHANNEL_NAME)
    expect(typeof channels[0].onmessage).toBe('function')

    channels[0].onmessage({ data: { type: 'logout', userId: 'u-eve' } })
    expect(received).toEqual([{ type: 'logout', userId: 'u-eve' }])
  })

  test('用户标识回落链：仅有 _id 时也要取到（不能只认 userId/id）', async () => {
    const posted = []
    class FakeBC {
      postMessage(p) {
        posted.push(p)
      }
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('login', { _id: 'u-mongo-id', username: 'mongo' })

    expect(posted[0].userId).toBe('u-mongo-id')
  })

  test('无 username 时负载保留 username:null 自身键（JSON 镜像通道下 undefined 会整键消失）', async () => {
    // 契约来自模块 JSDoc：username: string|null。若写成 user?.username（无 || null），
    // structured clone 通道尚可，但 JSON 镜像通道里 JSON.stringify 会丢掉该键，
    // 接收方读到的负载形状与契约不一致（排障时无法区分「没传」与「传了空」）。
    vi.stubGlobal('BroadcastChannel', undefined)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('logout', { userId: 'u-noname' })

    const payload = JSON.parse(localStorage.getItem(STORAGE_MIRROR_KEY))
    expect(Object.prototype.hasOwnProperty.call(payload, 'username')).toBe(true)
    expect(payload.username).toBeNull()
  })

  test('通道实例模块级缓存：连续广播不得反复 new BroadcastChannel（防通道泄漏）', async () => {
    const instances = []
    class FakeBC {
      constructor(name) {
        this.name = name
        instances.push(this)
      }
      postMessage() {}
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('login', { userId: 'u-1' })
    broadcastAuthChange('logout', { userId: 'u-1' })
    broadcastAuthChange('login', { userId: 'u-2' })

    expect(instances).toHaveLength(1)
  })

  test('postMessage 抛错时回退写 localStorage 镜像（广播失败不等于放弃通知）', async () => {
    class ThrowingPostBC {
      postMessage() {
        throw new Error('channel closed')
      }
    }
    vi.stubGlobal('BroadcastChannel', ThrowingPostBC)
    const { broadcastAuthChange } = await loadModule()

    expect(() => broadcastAuthChange('logout', { userId: 'u-grace' })).not.toThrow()

    const payload = JSON.parse(localStorage.getItem(STORAGE_MIRROR_KEY))
    expect(payload).toMatchObject({ type: 'logout', userId: 'u-grace' })
  })

  test('构造器持续抛错时只尝试一次（缓存失败标记，不做无效重试）', async () => {
    let attempts = 0
    class AlwaysThrowingBC {
      constructor() {
        attempts += 1
        throw new Error('blocked by policy')
      }
    }
    vi.stubGlobal('BroadcastChannel', AlwaysThrowingBC)
    const { broadcastAuthChange } = await loadModule()

    broadcastAuthChange('login', { userId: 'u-1' })
    broadcastAuthChange('login', { userId: 'u-2' })

    expect(attempts).toBe(1)
    // 两次都应落镜像键（通知不能因为通道不可用而丢）
    const payload = JSON.parse(localStorage.getItem(STORAGE_MIRROR_KEY))
    expect(payload.userId).toBe('u-2')
  })

  test('logout 事件不带 user 对象：userId 落为 null 而不是抛错或 undefined', async () => {
    const posted = []
    class FakeBC {
      postMessage(p) {
        posted.push(p)
      }
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { broadcastAuthChange } = await loadModule()

    expect(() => broadcastAuthChange('logout')).not.toThrow()

    expect(posted).toHaveLength(1)
    expect(posted[0].type).toBe('logout')
    // 契约是 string|null；undefined 在 structured clone 里会整键消失
    expect(posted[0].userId).toBeNull()
    expect(Object.prototype.hasOwnProperty.call(posted[0], 'userId')).toBe(true)
    expect(posted[0].username).toBeNull()
  })

  test('initSessionSync：非函数入参直接忽略（不抛错、不注册通道）', async () => {
    const channels = []
    class FakeBC {
      constructor() {
        channels.push(this)
      }
    }
    vi.stubGlobal('BroadcastChannel', FakeBC)
    const { initSessionSync } = await loadModule()

    expect(() => initSessionSync(undefined)).not.toThrow()
    expect(() => initSessionSync('not-a-function')).not.toThrow()
    expect(channels).toHaveLength(0)
  })
})
