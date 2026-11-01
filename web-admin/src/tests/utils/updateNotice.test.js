/**
 * 「有新版本」共享状态与刷新动作
 *
 * 这里的失败形态是「用户点了按钮但什么都没发生」——比不提示更糟：
 * 此时页面已经处在新旧混合状态，用户以为修好了，实际还在旧代码上。
 */

import { afterEach, describe, expect, test, vi } from 'vitest'
import {
  UPDATE_RELOAD_FALLBACK_MS,
  applyUpdate,
  markUpdateAvailable,
  resetUpdateNotice,
  setUpdateApplier,
  updateAvailable,
  updateReason,
} from '@/utils/updateNotice'

/**
 * 用可观测的 reload 顶替 window.location（jsdom 的 location.reload 不可 spy）。
 * 返回值即 reload 的调用记录；用例结束时由 afterEach 还原。
 */
const installReloadSpy = () => {
  const original = window.location
  const reload = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...original, reload },
  })
  restoreLocation = () => {
    Object.defineProperty(window, 'location', { configurable: true, value: original })
    restoreLocation = null
  }
  return { reload, original }
}

let restoreLocation = null

describe('updateNotice', () => {
  afterEach(() => {
    resetUpdateNotice()
    setUpdateApplier(null)
    restoreLocation?.()
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  test('置位一次即可，重复置位保留第一次的原因', () => {
    markUpdateAvailable('service-worker')
    markUpdateAvailable('version')

    expect(updateAvailable.value).toBe(true)
    expect(updateReason.value).toBe('service-worker')
  })

  test('reset 清空状态（登出/换账号后不应继续提示）', () => {
    markUpdateAvailable('version')
    resetUpdateNotice()

    expect(updateAvailable.value).toBe(false)
    expect(updateReason.value).toBe('')
  })

  test('applyUpdate 走注入的 applier（先激活等待中的 SW 再 reload）', async () => {
    const applier = vi.fn(async () => {})
    setUpdateApplier(applier)

    await applyUpdate()

    expect(applier).toHaveBeenCalledTimes(1)
  })

  /**
   * A2 回归：applier 正常返回 ≠ 页面已经刷新。
   *
   * vite-plugin-pwa 的 updateSW(true) 在**没有 waiting SW** 时只发一条
   * SKIP_WAITING 就 resolve（register.js 的 updateServiceWorker 分支），
   * 而版本探测（GET /api/version 的 buildId 不一致）恰恰常在这种形态下置位提示。
   * 修复前的实现 resolve 后直接 return、跳过兜底 reload ⇒ 用户点「立即刷新」
   * 页面毫无反应，而页面正处于新旧混合状态（提示条存在的唯一理由）。
   *
   * 判据（可证伪）：applier 空转 resolve ⇒ 兜底窗口过后必须发生一次 reload。
   * 修复前该断言为 0 次。
   */
  test('applier 空转 resolve（无 waiting SW）：兜底窗口后必须 reload，不能点了没反应', async () => {
    const { reload } = installReloadSpy()
    setUpdateApplier(async () => {})

    vi.useFakeTimers()
    try {
      await applyUpdate()
      // 先给 SW 路径一个时间窗：不得在 resolve 的同一拍里立刻重刷
      expect(reload).toHaveBeenCalledTimes(0)

      await vi.advanceTimersByTimeAsync(UPDATE_RELOAD_FALLBACK_MS)
      expect(reload).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  test('对照：未注入 applier 时立即 reload（无 SW 场景仍可刷新）', async () => {
    const { reload } = installReloadSpy()
    setUpdateApplier(null)

    await applyUpdate()

    expect(reload).toHaveBeenCalledTimes(1)
  })

  test('applier 抛错时仍要刷新页面：不能点了没反应', async () => {
    const original = window.location
    const reload = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...original, reload },
    })

    try {
      setUpdateApplier(async () => {
        throw new Error('SW 激活失败')
      })

      await expect(applyUpdate()).resolves.toBeUndefined()
      // 抛错路径必须**立即**刷新（不走兜底窗口）：SW 激活已失败，再等只是让用户干瞪眼
      expect(reload).toHaveBeenCalledTimes(1)
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })
})
