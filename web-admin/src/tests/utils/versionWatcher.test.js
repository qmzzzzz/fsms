/**
 * 版本探测（升级的感知层）
 *
 * 这个模块一旦判错，两种后果都很糟：
 *   · 误报 ⇒ 每次打开页面都弹「有新版本」，用户学会无视它，真升级时也没人点；
 *   · 漏报 ⇒ 用户长期停在旧壳子，与已换版的服务端混跑，表现为零散 500。
 *
 * 所以下面钉的不是「happy path 能跑」，而是四条「宁可不动」的边界：
 * 不可比对的标识、探测失败、页面隐藏、并发请求。
 */

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import {
  createVersionWatcher,
  isComparableBuildId,
  isPageHidden,
  DEFAULT_INTERVAL_MS,
} from '@/utils/versionWatcher'

const setVisibility = (state) => {
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => state,
  })
}

describe('isComparableBuildId', () => {
  test('真实标识可比对', () => {
    expect(isComparableBuildId('9bffda3f8da7')).toBe(true)
    expect(isComparableBuildId(' v1.2.3 ')).toBe(true)
  })

  test('空串、占位值不可比对（拿它们比对只会得到恒假的「有更新」）', () => {
    for (const v of ['', '   ', 'unknown', 'dev', null, undefined, 123]) {
      expect(isComparableBuildId(v)).toBe(false)
    }
  })
})

describe('isPageHidden（全仓统一可见性判据）', () => {
  test('不可见 = visibilityState 不是 visible：hidden 与 prerender 都算', () => {
    // 原判据只认 === 'hidden'，于是 prerender（本仓 jsdom 默认、也是浏览器
    // 预渲染态）被当成「可见」，探测会在不该发的时候发出去
    expect(isPageHidden({ visibilityState: 'prerender', hidden: true })).toBe(true)
    expect(isPageHidden({ visibilityState: 'hidden', hidden: true })).toBe(true)
    expect(isPageHidden({ visibilityState: 'visible', hidden: false })).toBe(false)
  })

  test('拿不到 visibilityState 时退回 document.hidden', () => {
    expect(isPageHidden({ visibilityState: '', hidden: true })).toBe(true)
    expect(isPageHidden({ visibilityState: undefined, hidden: false })).toBe(false)
  })

  test('没有 document（SSR / 测试注入空）时按可见处理，不因判据缺失而停摆', () => {
    expect(isPageHidden(null)).toBe(false)
  })
})

describe('createVersionWatcher', () => {
  beforeEach(() => {
    setVisibility('visible')
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const make = (overrides = {}) =>
    createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion: async () => ({ buildId: 'build-bbb' }),
      intervalMs: 1000,
      ...overrides,
    })

  test('服务端 buildId 与本页不同 ⇒ 回调一次，且只回调一次', async () => {
    const onUpdateAvailable = vi.fn()
    const watcher = make({ onUpdateAvailable })

    watcher.start()
    await watcher.checkNow()
    await watcher.checkNow()

    expect(onUpdateAvailable).toHaveBeenCalledTimes(1)
    expect(onUpdateAvailable).toHaveBeenCalledWith({
      localBuildId: 'build-aaa',
      remoteBuildId: 'build-bbb',
    })
    watcher.stop()
  })

  test('buildId 相同 ⇒ 不回调（正常状态不得打扰用户）', async () => {
    const onUpdateAvailable = vi.fn()
    const watcher = make({
      onUpdateAvailable,
      fetchVersion: async () => ({ buildId: 'build-aaa' }),
    })

    watcher.start()
    await watcher.checkNow()

    expect(onUpdateAvailable).not.toHaveBeenCalled()
    watcher.stop()
  })

  test('远端返回 unknown/dev/空 ⇒ 不回调（防止把「取不到版本」当成「有新版本」）', async () => {
    for (const remote of ['unknown', 'dev', '', '   ', undefined, null]) {
      const onUpdateAvailable = vi.fn()
      const watcher = make({
        onUpdateAvailable,
        fetchVersion: async () => ({ buildId: remote }),
      })
      watcher.start()
      await watcher.checkNow()
      expect(onUpdateAvailable).not.toHaveBeenCalled()
      watcher.stop()
    }
  })

  test('本页没有可比对的标识 ⇒ 一次请求都不发（本地构建包连生产时不得误报）', async () => {
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-bbb' }))
    const watcher = createVersionWatcher({ localBuildId: 'dev', fetchVersion, intervalMs: 1000 })

    watcher.start()
    await watcher.checkNow()

    expect(fetchVersion).not.toHaveBeenCalled()
    watcher.stop()
  })

  test('探测失败静默：断网/404/非 JSON 都不得抛错，也不得当成有更新', async () => {
    const onUpdateAvailable = vi.fn()
    const watcher = make({
      onUpdateAvailable,
      fetchVersion: async () => {
        throw new Error('network down')
      },
    })

    watcher.start()
    await expect(watcher.checkNow()).resolves.toBeUndefined()
    expect(onUpdateAvailable).not.toHaveBeenCalled()
    watcher.stop()
  })

  test('页面处于 prerender 时同样不发请求（原判据漏掉这个状态）', async () => {
    setVisibility('prerender')
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-bbb' }))
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
    })

    watcher.start()
    await watcher.checkNow()

    expect(fetchVersion).not.toHaveBeenCalled()
    watcher.stop()
  })

  test('页面隐藏时不发请求（后台标签页不烧配额）', async () => {
    setVisibility('hidden')
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-bbb' }))
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
    })

    watcher.start()
    await watcher.checkNow()

    expect(fetchVersion).not.toHaveBeenCalled()
    watcher.stop()
  })

  test('上一次请求未返回时不叠加新请求', async () => {
    let resolveFirst
    const fetchVersion = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveFirst = resolve
        })
    )
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
    })

    watcher.start()
    const first = watcher.checkNow()
    await watcher.checkNow() // 第二次应立即返回，不发请求
    expect(fetchVersion).toHaveBeenCalledTimes(1)

    resolveFirst({ buildId: 'build-aaa' })
    await first
    watcher.stop()
  })

  test('按间隔轮询；stop 之后不再触发', async () => {
    vi.useFakeTimers()
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-aaa' }))
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: DEFAULT_INTERVAL_MS,
    })

    watcher.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchVersion).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(DEFAULT_INTERVAL_MS)
    expect(fetchVersion).toHaveBeenCalledTimes(2)

    watcher.stop()
    await vi.advanceTimersByTimeAsync(DEFAULT_INTERVAL_MS * 3)
    expect(fetchVersion).toHaveBeenCalledTimes(2)
  })

  test('探测超时：悬挂的请求到期即中止并释放 inFlight（否则轮询被永久挡掉）', async () => {
    vi.useFakeTimers()
    let aborted = false
    const fetchVersion = vi.fn(
      ({ signal } = {}) =>
        new Promise((_, reject) => {
          signal?.addEventListener('abort', () => {
            aborted = true
            reject(new Error('aborted'))
          })
        })
    )
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
      timeoutMs: 5000,
    })

    watcher.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchVersion).toHaveBeenCalledTimes(1)

    // 未超时前不叠加请求（慢网络下叠加只会烧穿配额）
    await vi.advanceTimersByTimeAsync(3000)
    expect(fetchVersion).toHaveBeenCalledTimes(1)

    // 到点即 abort：请求真的被中止，而不是只是我们自己不再等它
    await vi.advanceTimersByTimeAsync(2000)
    expect(aborted).toBe(true)

    // inFlight 已释放 ⇒ 下一个周期恢复探测（原实现会永久卡死在这里）
    await vi.advanceTimersByTimeAsync(1000)
    expect(fetchVersion).toHaveBeenCalledTimes(2)
    watcher.stop()
  })

  test('stop 中止在途探测：停止后回来的响应不得再回调', async () => {
    let resolveFetch
    let capturedSignal
    const onUpdateAvailable = vi.fn()
    const fetchVersion = vi.fn(({ signal } = {}) => {
      capturedSignal = signal
      return new Promise((resolve) => {
        resolveFetch = () => resolve({ buildId: 'build-bbb' })
      })
    })
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
      timeoutMs: 0,
      onUpdateAvailable,
    })

    watcher.start()
    expect(fetchVersion).toHaveBeenCalledTimes(1)
    expect(capturedSignal).toBeTruthy()

    watcher.stop()
    expect(capturedSignal.aborted).toBe(true)

    resolveFetch()
    await watcher.checkNow()
    expect(onUpdateAvailable).not.toHaveBeenCalled()
  })

  test('stop 后再 start：允许重新探测并重新提示（原实现把 inFlight/notified 留成旧值）', async () => {
    const onUpdateAvailable = vi.fn()
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-bbb' }))
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: 1000,
      onUpdateAvailable,
    })

    watcher.start()
    await vi.waitFor(() => expect(onUpdateAvailable).toHaveBeenCalledTimes(1))

    watcher.stop()
    watcher.start()
    await vi.waitFor(() => expect(onUpdateAvailable).toHaveBeenCalledTimes(2))
    watcher.stop()
  })

  test('默认取数复用统一 API base：VITE_API_BASE_URL 覆盖时探测路径跟随（P2-8）', async () => {
    const originalFetch = globalThis.fetch
    const urls = []
    const stubFetch = vi.fn(async (url) => {
      urls.push(url)
      return { ok: true, json: async () => ({ success: true, data: { buildId: 'build-aaa' } }) }
    })

    try {
      globalThis.fetch = stubFetch
      for (const [env, expected] of [
        ['/sub/api', '/sub/api/version'],
        ['https://api.example.com/api', 'https://api.example.com/api/version'],
        [undefined, '/api/version'],
      ]) {
        vi.resetModules()
        if (env === undefined) vi.stubEnv('VITE_API_BASE_URL', '')
        else vi.stubEnv('VITE_API_BASE_URL', env)
        const mod = await import('@/utils/versionWatcher')
        const watcher = mod.createVersionWatcher({ localBuildId: 'build-aaa', intervalMs: 1000 })
        watcher.start()
        await watcher.checkNow()
        watcher.stop()
        expect(urls.at(-1), String(env)).toBe(expected)
      }
    } finally {
      globalThis.fetch = originalFetch
      vi.unstubAllEnvs()
      vi.resetModules()
    }
  })

  test('标签页重新可见时补查一次（切回页面能立刻发现换版）', async () => {
    const fetchVersion = vi.fn(async () => ({ buildId: 'build-aaa' }))
    const watcher = createVersionWatcher({
      localBuildId: 'build-aaa',
      fetchVersion,
      intervalMs: DEFAULT_INTERVAL_MS,
    })

    setVisibility('hidden')
    watcher.start()
    await vi.waitFor(() => expect(fetchVersion).not.toHaveBeenCalled())

    setVisibility('visible')
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.waitFor(() => expect(fetchVersion).toHaveBeenCalledTimes(1))

    watcher.stop()
  })
})
