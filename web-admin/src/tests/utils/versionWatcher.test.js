/**
 * 版本探测（热升级的感知层）
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
