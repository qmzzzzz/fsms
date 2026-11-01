/**
 * 审计读取二次验证的本地时间戳测试（utils/reauthTicket.js）
 *
 * 模块只留一个「刚验证过」的本地时间戳（2026-10-31 审计一-3 改造后客户端不再
 * 持有任何凭据），唯一职责是抑制「刚输完口令、页面重放首屏读取」与「重新弹框」
 * 之间的重复弹框竞态。它不是凭据——丢了、被改了都不产生权限，最坏只是多弹一次框。
 *
 * 本测试钉住两个口径，防止后续重构无声漂移：
 *   · 空态短路：verifiedAt 从未置位时 must 返回 false（Boolean(null) 短路，
 *     不得把 null 当 0 号时间戳参与减法）；
 *   · 窗口是**严格小于** 3000ms：恰好 3000ms 整已过期（与 step-up 的抑制
 *     定位一致——宁可多弹一次框，不能把过期当有效）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { markReauthVerified, justReauthVerified, clearReauthTicket } from '@/utils/reauthTicket'

const BASE = 1_700_000_000_000

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(BASE)
  clearReauthTicket()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('justReauthVerified 三秒窗口', () => {
  test('从未置位时恒为 false（空态短路）', () => {
    expect(justReauthVerified()).toBe(false)
  })

  test('置位后窗口内为 true，且不随调用次数衰减', () => {
    markReauthVerified()
    expect(justReauthVerified()).toBe(true)
    expect(justReauthVerified()).toBe(true)
  })

  test('窗口是严格小于：2999ms 内有效，恰好 3000ms 整已过期', () => {
    markReauthVerified()
    vi.setSystemTime(BASE + 2999)
    expect(justReauthVerified()).toBe(true)
    vi.setSystemTime(BASE + 3000)
    expect(justReauthVerified()).toBe(false)
  })

  test('clearReauthTicket 立即失效（登出、窗口被服务端拒绝路径）', () => {
    markReauthVerified()
    clearReauthTicket()
    expect(justReauthVerified()).toBe(false)
  })

  test('重新置位覆盖旧时间戳（二次 step-up 后窗口重新计时）', () => {
    markReauthVerified()
    vi.setSystemTime(BASE + 2500)
    markReauthVerified()
    vi.setSystemTime(BASE + 4000)
    // 距第二次置位 1500ms < 3000，窗口按新时间戳计
    expect(justReauthVerified()).toBe(true)
  })
})
