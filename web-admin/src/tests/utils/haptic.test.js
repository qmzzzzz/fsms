/**
 * haptic.js 行为测试（移动端触觉反馈的降级路径）
 *
 * 模块契约（源码 12 行，三条可证伪行为）：
 *  1. 支持 Vibration API 时：调用 navigator.vibrate，pattern 原样透传，默认 10ms；
 *  2. vibrate 抛错（个别浏览器权限受限场景）：静默吞掉，不冒泡给调用方——
 *     登录/注册等处的 haptic 是「锦上添花」，抛错会炸掉主流程；
 *  3. 不支持时（桌面 / iOS Safari）：静默跳过。iOS 不支持 Vibration API，
 *     因此该路径是 iOS 上的**默认路径**，必须真的不抛错。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import haptic, { haptic as namedHaptic } from '@/utils/haptic'

/** jsdom 无 navigator.vibrate；defineProperty 注入/摘除，避免污染其他用例 */
const setVibrate = (impl) => {
  Object.defineProperty(navigator, 'vibrate', {
    value: impl,
    configurable: true,
    writable: true,
  })
}

afterEach(() => {
  delete navigator.vibrate
  vi.restoreAllMocks()
})

describe('haptic 触觉反馈', () => {
  test('支持 Vibration API：默认 10ms，自定义 pattern 原样透传', () => {
    const vibrate = vi.fn()
    setVibrate(vibrate)
    haptic()
    expect(vibrate).toHaveBeenCalledWith(10)
    haptic(30)
    expect(vibrate).toHaveBeenLastCalledWith(30)
    haptic([20, 40, 20])
    expect(vibrate).toHaveBeenLastCalledWith([20, 40, 20])
    // 默认导出与命名导出必须是同一个函数（调用方两种引入方式都可能用）
    expect(namedHaptic).toBe(haptic)
  })

  test('vibrate 抛错：静默吞掉，不冒泡给调用方', () => {
    setVibrate(() => {
      throw new Error('blocked by permissions policy')
    })
    expect(() => haptic()).not.toThrow()
  })

  test('不支持 Vibration API（iOS/桌面默认路径）：静默跳过，不抛错', () => {
    // jsdom 默认没有 navigator.vibrate，此处即为「不支持」环境
    expect(navigator.vibrate).toBeUndefined()
    expect(() => haptic()).not.toThrow()
    expect(() => namedHaptic(50)).not.toThrow()
  })

  test('navigator.vibrate 存在但不是函数：不调用、不抛错', () => {
    setVibrate('not-a-function')
    expect(() => haptic()).not.toThrow()
  })
})
