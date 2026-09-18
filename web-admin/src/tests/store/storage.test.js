/**
 * Store 存储工具行为测试（safeStorage / safeLocal / readSessionState）
 *
 * 这三个工具是所有会话状态读写的唯一出口（authStore / appStore 都经它们落盘），
 * 设计承诺是「存储不可用时降级而不是抛错」——隐私模式、配额写满、企业策略禁用
 * 存储时，页面必须继续可用。每条用例对应一种真实退化：
 *
 *  1. 读写往返：get/set、getJSON/setJSON 必须对称，否则刷新后状态静默丢失；
 *  2. 读取失败返回 fallback 而非 undefined：调用方普遍用 `|| 默认值` 兜底，
 *     静默 undefined 会掩盖存储损坏；
 *  3. 写入/删除失败必须被吞掉：一旦向上抛，登录、主题切换等同步流程会在用户
 *     毫无预期时炸掉（jsdom 默认存储可用，故用 spy 精确模拟「某个介质抛错」，
 *     并用「抛错方法确实被调用过」证明用例打到了目标路径而不是什么都没发生）；
 *  4. getJSON 遇到坏数据（半截 JSON、空串）返回 fallback 而不是抛 SyntaxError；
 *  5. readSessionState 的介质优先级与一次性迁移：localStorage 优先；回退到
 *     sessionStorage 时把值写回 localStorage 并清掉旧副本——但**写回失败时
 *     绝不能删旧副本**，否则唯一的会话副本丢失，用户刷新即被登出（这正是迁移
 *     本身要避免的故障，用「只让 localStorage 抛错」的用例钉住）。
 *
 * safeStorage 与 safeLocal 是两段各自独立的实现（复制而非共享），任一侧的
 * 回归不会被另一侧的用例发现，故两侧都各自完整覆盖，不做「只测一个」的省略。
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { safeStorage, safeLocal, readSessionState } from '@/store/storage'

/**
 * 让指定 Storage 实例的某个方法抛错，其余实例照常工作。
 * 真实隐私模式正是「某个介质不可用」而非全部不可用，只有按实例区分才能
 * 同时验证「不可用的一侧降级」与「可用的一侧仍写入」。
 */
const breakMethod = (storage, method) => {
  const original = Storage.prototype[method]
  return vi.spyOn(Storage.prototype, method).mockImplementation(function (...args) {
    if (this === storage) throw new Error(method + ' unavailable')
    return original.apply(this, args)
  })
}

afterEach(() => {
  vi.restoreAllMocks()
  sessionStorage.clear()
  localStorage.clear()
})

describe('safeStorage（sessionStorage 出口）', () => {
  test('set/get 往返；缺失键返回 null，显式 fallback 生效', () => {
    safeStorage.set('k', 'v')
    expect(safeStorage.get('k')).toBe('v')
    expect(safeStorage.get('missing')).toBeNull()
    expect(safeStorage.get('missing', 'FB')).toBe('FB')
  })

  test('setJSON/getJSON 往返保持类型（数组/对象/数字 0）', () => {
    safeStorage.setJSON('arr', ['a:b', 'c:d'])
    safeStorage.setJSON('obj', { _id: 'u1', nested: { n: 1 } })
    safeStorage.setJSON('num', 0)
    expect(safeStorage.getJSON('arr')).toEqual(['a:b', 'c:d'])
    expect(safeStorage.getJSON('obj')).toEqual({ _id: 'u1', nested: { n: 1 } })
    // 0 是合法值：空权限数组/零计数不能被当成「无值」而走 fallback
    expect(safeStorage.getJSON('num')).toBe(0)
  })

  test('getJSON 缺失键/空串/坏 JSON 一律返回 fallback，不抛 SyntaxError', () => {
    expect(safeStorage.getJSON('missing')).toBeNull()
    expect(safeStorage.getJSON('missing', [])).toEqual([])
    // 半截 JSON（上次写入被中断、人工改坏）不能让整个页面崩掉
    sessionStorage.setItem('broken', '{"a":')
    expect(safeStorage.getJSON('broken', 'FB')).toBe('FB')
    // 空串：无值语义，走 fallback
    sessionStorage.setItem('empty', '')
    expect(safeStorage.getJSON('empty', 'FB')).toBe('FB')
  })

  test('介质不可用时 get 返回 fallback、set/remove 静默降级', () => {
    const getSpy = breakMethod(window.sessionStorage, 'getItem')
    expect(safeStorage.get('k', 'FB')).toBe('FB')
    expect(safeStorage.getJSON('k', 'FB')).toBe('FB')
    expect(getSpy.mock.calls.length).toBeGreaterThan(0)
    getSpy.mockRestore()

    const setSpy = breakMethod(window.sessionStorage, 'setItem')
    expect(() => safeStorage.set('k', 'v')).not.toThrow()
    expect(() => safeStorage.setJSON('k', { a: 1 })).not.toThrow()
    expect(setSpy.mock.calls.length).toBeGreaterThan(0)
    setSpy.mockRestore()

    safeStorage.set('k', 'v')
    const rmSpy = breakMethod(window.sessionStorage, 'removeItem')
    expect(() => safeStorage.remove('k')).not.toThrow()
    expect(rmSpy.mock.calls.length).toBeGreaterThan(0)
    rmSpy.mockRestore()
    // remove 未生效：值仍在（证明前面确实打在抛错路径上，而不是「没调用所以没抛」）
    expect(safeStorage.get('k')).toBe('v')
  })
})

describe('safeLocal（localStorage 出口）', () => {
  test('set/get 往返；缺失键返回 null，显式 fallback 生效', () => {
    safeLocal.set('k', 'v')
    expect(safeLocal.get('k')).toBe('v')
    expect(safeLocal.get('missing')).toBeNull()
    expect(safeLocal.get('missing', 'FB')).toBe('FB')
  })

  test('setJSON/getJSON 往返保持类型（数组/对象/布尔 false）', () => {
    safeLocal.setJSON('arr', ['device:read'])
    safeLocal.setJSON('obj', { _id: 'u1', roles: ['ADMIN'] })
    safeLocal.setJSON('flag', false)
    expect(safeLocal.getJSON('arr')).toEqual(['device:read'])
    expect(safeLocal.getJSON('obj')).toEqual({ _id: 'u1', roles: ['ADMIN'] })
    expect(safeLocal.getJSON('flag')).toBe(false)
  })

  test('getJSON 缺失键/坏 JSON 返回 fallback，不抛 SyntaxError', () => {
    expect(safeLocal.getJSON('missing')).toBeNull()
    expect(safeLocal.getJSON('missing', {})).toEqual({})
    localStorage.setItem('broken', '[1,')
    expect(safeLocal.getJSON('broken', 'FB')).toBe('FB')
  })

  test('介质不可用时 get 返回 fallback、set/remove 静默降级', () => {
    const getSpy = breakMethod(window.localStorage, 'getItem')
    expect(safeLocal.get('k', 'FB')).toBe('FB')
    expect(safeLocal.getJSON('k', 'FB')).toBe('FB')
    expect(getSpy.mock.calls.length).toBeGreaterThan(0)
    getSpy.mockRestore()

    const setSpy = breakMethod(window.localStorage, 'setItem')
    expect(() => safeLocal.set('k', 'v')).not.toThrow()
    expect(() => safeLocal.setJSON('k', { a: 1 })).not.toThrow()
    expect(setSpy.mock.calls.length).toBeGreaterThan(0)
    setSpy.mockRestore()

    safeLocal.set('k', 'v')
    const rmSpy = breakMethod(window.localStorage, 'removeItem')
    expect(() => safeLocal.remove('k')).not.toThrow()
    expect(rmSpy.mock.calls.length).toBeGreaterThan(0)
    rmSpy.mockRestore()
    expect(safeLocal.get('k')).toBe('v')
  })
})

describe('readSessionState（介质优先级与一次性迁移）', () => {
  test('localStorage 有值时优先返回，且不动 sessionStorage 副本（迁移只在回退路径发生）', () => {
    safeLocal.setJSON('currentUser', { userId: 'new' })
    safeStorage.setJSON('currentUser', { userId: 'legacy' })
    expect(readSessionState('currentUser')).toEqual({ userId: 'new' })
    expect(sessionStorage.getItem('currentUser')).not.toBeNull()
  })

  test('localStorage 缺失时回退 sessionStorage：返回旧值、写回新介质、清掉旧副本', () => {
    safeStorage.setJSON('permissions', ['device:read'])
    expect(readSessionState('permissions')).toEqual(['device:read'])
    expect(safeLocal.getJSON('permissions')).toEqual(['device:read'])
    expect(sessionStorage.getItem('permissions')).toBeNull()
  })

  test('回退路径的 falsy 值同样要迁移（判据是 !== null 而非真值）', () => {
    // 旧标签页里存的 0 / false 是**有效状态**而非「无值」：若回退判据写成
    // `if (legacy)`，这些值会被静默丢弃且旧副本永不清除（迁移永远不完成）
    safeStorage.setJSON('zero', 0)
    safeStorage.setJSON('flag', false)
    expect(readSessionState('zero')).toBe(0)
    expect(readSessionState('flag')).toBe(false)
    // 迁移必须真正落地：写回新介质 + 清掉旧副本
    expect(safeLocal.getJSON('zero')).toBe(0)
    expect(safeLocal.getJSON('flag')).toBe(false)
    expect(sessionStorage.getItem('zero')).toBeNull()
    expect(sessionStorage.getItem('flag')).toBeNull()
  })

  test('两处都没有时返回 null（未登录/无偏好）', () => {
    expect(readSessionState('currentUser')).toBeNull()
    expect(readSessionState('permissions')).toBeNull()
  })

  test('falsy 值（0/false/空数组）不算「无状态」：判据是 !== null 而非真值', () => {
    safeLocal.setJSON('zero', 0)
    safeLocal.setJSON('flag', false)
    safeLocal.setJSON('list', [])
    expect(readSessionState('zero')).toBe(0)
    expect(readSessionState('flag')).toBe(false)
    expect(readSessionState('list')).toEqual([])
  })

  test('写回新介质失败时不删旧副本：会话仍可继续使用（避免刷新即登出）', () => {
    safeStorage.setJSON('currentUser', { userId: 'u1' })
    breakMethod(window.localStorage, 'setItem')
    expect(readSessionState('currentUser')).toEqual({ userId: 'u1' })
    // 关键：localStorage 没写成，sessionStorage 里的唯一副本必须保留
    expect(sessionStorage.getItem('currentUser')).not.toBeNull()
    // 且下次读取仍能拿到（迁移是「尽力而为」，不是「一次性机会」）
    expect(readSessionState('currentUser')).toEqual({ userId: 'u1' })
  })
})
