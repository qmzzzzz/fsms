/**
 * 列表加载三态契约测试（useListLoadState）
 *
 * 为何需要它：这是 P1③/P1④ 的**共用判据**。修复前 6 个列表视图各自实现
 * 「catch 里清表 + total=0」，失败与「真的没有数据」在界面上完全一致；
 * 若每个视图各写一套，下一轮必然变成 6 份互相漂移的实现。这里先把契约钉死，
 * 六个视图只允许接线，不允许重写判据。
 *
 * 契约（三条，缺一不可）：
 *   1. 失败 ⇒ phase='failed'，且 hasData=false 时**不得**渲染成空表（表格要让位于错误块）
 *   2. 失败且有旧数据 ⇒ phase='stale'，保留旧数据但必须显式标注「上次数据」
 *   3. 成功 ⇒ phase='ready'；真实空结果 ⇒ phase='empty'（与 failed 严格区分）
 */
import { describe, test, expect } from 'vitest'
import { useListLoadState } from '@/composables/useListLoadState'

// 测试侧的装载器：把「成功提交 / 失败 / 取消」三条出口接到契约的三个方法上。
// 视图侧的真实写法见各视图 loadData（同样是 begin → commit / fail / abort）。
const load = async (state, thunk) => {
  state.begin()
  try {
    return await thunk()
  } catch (e) {
    if (e && e.__CANCEL__) return state.abort()
    return state.fail()
  }
}

describe('useListLoadState · 三态契约', () => {
  test('初始态：phase=idle，没有数据，没有失败', () => {
    const s = useListLoadState()
    expect(s.phase.value).toBe('idle')
    expect(s.failed.value).toBe(false)
    expect(s.stale.value).toBe(false)
    expect(s.isEmpty.value).toBe(false)
  })

  test('成功且有数据：phase=ready，失败标记清除', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: 42, count: 10 }))
    expect(s.phase.value).toBe('ready')
    expect(s.failed.value).toBe(false)
    expect(s.isEmpty.value).toBe(false)
  })

  test('成功但结果为空：phase=empty（这是「真的没有」，允许渲染空表）', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: 0, count: 0 }))
    expect(s.phase.value).toBe('empty')
    expect(s.failed.value).toBe(false)
    expect(s.isEmpty.value).toBe(true)
  })

  test('失败且此前无数据：phase=failed，必须让位于错误块（不得渲染成空表）', async () => {
    const s = useListLoadState()
    await load(s, async () => {
      throw new Error('boom')
    })
    expect(s.phase.value).toBe('failed')
    expect(s.failed.value).toBe(true)
    expect(s.isEmpty.value).toBe(false) // 关键：不得被当成「空」
    expect(s.stale.value).toBe(false)
    expect(s.showErrorBlock.value).toBe(true) // 表格让位
    expect(s.showTable.value).toBe(false)
  })

  test('先成功后失败：phase=stale，保留旧数据但标注为上次数据', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: 5, count: 5 }))
    await load(s, async () => {
      throw new Error('boom')
    })
    expect(s.phase.value).toBe('stale')
    expect(s.failed.value).toBe(true)
    expect(s.stale.value).toBe(true)
    expect(s.isEmpty.value).toBe(false)
    expect(s.showErrorBlock.value).toBe(true)
    expect(s.showTable.value).toBe(true) // 旧数据仍可见
  })

  test('失败后再成功：错误态必须清除（不是永久错误态）', async () => {
    const s = useListLoadState()
    await load(s, async () => {
      throw new Error('boom')
    })
    expect(s.failed.value).toBe(true)
    await load(s, async () => s.commit({ total: 1, count: 1 }))
    expect(s.phase.value).toBe('ready')
    expect(s.failed.value).toBe(false)
    expect(s.showErrorBlock.value).toBe(false)
    expect(s.showTable.value).toBe(true)
  })

  test('取消不算失败：路由切换 abort 不得留下错误态', async () => {
    const s = useListLoadState()
    const cancelError = new Error('canceled')
    cancelError.__CANCEL__ = true
    await load(s, async () => {
      throw cancelError
    })
    expect(s.failed.value).toBe(false)
    expect(s.phase.value).toBe('idle')
  })

  test('总数缺失不得回退成当前页长度：total 未知时给 null（P1④）', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: undefined, count: 10 }))
    // 关键：不能拿 count 顶替 total，否则分页器显示「共 10 条/1 页」，第 2 页永不出现
    expect(s.total.value).toBeNull()
    expect(s.totalKnown.value).toBe(false)
  })

  test('总数为 0 是合法已知值，不得当成「未知」', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: 0, count: 0 }))
    expect(s.total.value).toBe(0)
    expect(s.totalKnown.value).toBe(true)
  })

  test('末页 clamp：请求页超出结果总页数时给出应回退的页码（P1④）', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: 5, count: 0 }))
    // 每页 10 条、共 5 条 ⇒ 只有 1 页；请求第 3 页应回退到 1
    expect(s.clampPage(3, 10)).toBe(1)
    // 正常范围内的页码原样返回
    expect(s.clampPage(1, 10)).toBe(1)
    await load(s, async () => s.commit({ total: 25, count: 10 }))
    expect(s.clampPage(3, 10)).toBe(3)
    expect(s.clampPage(9, 10)).toBe(3)
  })

  test('total 未知时不做 clamp（不能凭空把用户送回第 1 页）', async () => {
    const s = useListLoadState()
    await load(s, async () => s.commit({ total: undefined, count: 10 }))
    expect(s.clampPage(3, 10)).toBe(3)
  })
})
