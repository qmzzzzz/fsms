/**
 * 竞态守卫 composable 测试（useLatestRequest）
 * 核心断言：只有最新一次请求的门票有效，旧请求回包被丢弃
 */
import { describe, test, expect } from 'vitest'
import { useLatestRequest } from '@/composables/useLatestRequest'

describe('useLatestRequest', () => {
  test('单次请求：门票始终有效', () => {
    const guard = useLatestRequest()
    const isCurrent = guard()
    expect(isCurrent()).toBe(true)
  })

  test('连续两次请求：第一张门票失效，第二张有效（模拟慢旧响应晚回）', () => {
    const guard = useLatestRequest()
    const first = guard()
    const second = guard()
    expect(first()).toBe(false)
    expect(second()).toBe(true)
  })

  test('多请求并发：仅最后一张门票有效', () => {
    const guard = useLatestRequest()
    const tickets = [guard(), guard(), guard(), guard()]
    expect(tickets.map((t) => t())).toEqual([false, false, false, true])
  })

  test('守卫互不干扰：各视图独立实例', () => {
    const guardA = useLatestRequest()
    const guardB = useLatestRequest()
    const a1 = guardA()
    const b1 = guardB() // B 的新请求不应影响 A 的门票
    expect(a1()).toBe(true)
    expect(b1()).toBe(true)
  })
})
