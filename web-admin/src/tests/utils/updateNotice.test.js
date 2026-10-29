/**
 * 「有新版本」共享状态与刷新动作
 *
 * 这里的失败形态是「用户点了按钮但什么都没发生」——比不提示更糟：
 * 此时页面已经处在新旧混合状态，用户以为修好了，实际还在旧代码上。
 */

import { afterEach, describe, expect, test, vi } from 'vitest'
import {
  applyUpdate,
  markUpdateAvailable,
  resetUpdateNotice,
  setUpdateApplier,
  updateAvailable,
  updateReason,
} from '@/utils/updateNotice'

describe('updateNotice', () => {
  afterEach(() => {
    resetUpdateNotice()
    setUpdateApplier(null)
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
      expect(reload).toHaveBeenCalledTimes(1)
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })
})
