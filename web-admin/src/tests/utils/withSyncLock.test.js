import { describe, test, expect, vi } from 'vitest'
import { withSyncLock } from '@/utils/withSyncLock'

describe('withSyncLock 同步重入锁（P2-29）', () => {
  test('首个 await 前同步判定：在途期间的同 tick 二次调用不执行原函数', async () => {
    let resolveA
    const body = vi.fn(
      () =>
        new Promise((r) => {
          resolveA = r
        })
    )
    const locked = withSyncLock(body)
    const p1 = locked('x')
    const p2 = locked('y')
    expect(body).toHaveBeenCalledTimes(1)
    expect(body.mock.calls[0]).toEqual(['x'])
    resolveA('done')
    await Promise.all([p1, p2])
    expect(await p2).toBeUndefined()
  })

  test('Promise 落定后解锁：后续调用可再次执行', async () => {
    const body = vi.fn(async (v) => v * 2)
    const locked = withSyncLock(body)
    expect(await locked(2)).toBe(4)
    expect(await locked(3)).toBe(6)
    expect(body).toHaveBeenCalledTimes(2)
  })

  test('async 抛错也解锁（finally 语义），下一次调用重新执行', async () => {
    const body = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce('ok')
    const locked = withSyncLock(body)
    await expect(locked()).rejects.toThrow('boom')
    await expect(locked()).resolves.toBe('ok')
    expect(body).toHaveBeenCalledTimes(2)
  })

  test('同步抛错同样解锁并透传异常', () => {
    const body = vi.fn(() => {
      throw new Error('sync-boom')
    })
    const locked = withSyncLock(body)
    expect(() => locked()).toThrow('sync-boom')
    expect(body).toHaveBeenCalledTimes(1)
  })

  test('同步返回值不被包装成 Promise（非 thenable 直接透传）', () => {
    const body = vi.fn(() => 42)
    const locked = withSyncLock(body)
    expect(locked()).toBe(42)
  })
})
