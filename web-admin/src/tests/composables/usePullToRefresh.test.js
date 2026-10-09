/**
 * usePullToRefresh 行为测试（移动端下拉刷新手势）
 *
 * 契约：
 *  1. 阻尼与上限：位移按 RESISTANCE=0.55 阻尼，封顶 MAX_PULL=120；
 *  2. 触发门槛：松手时 y ≥ 80 才触发 onRefresh（先 haptic 15 再置 refreshing，
 *     期间 y 锁在 80），刷新落定后 y 归零、refreshing 复位；
 *  3. 未达门槛：松手回弹，不触发刷新、不震动；
 *  4. 顶部判定：滚动源可能是 window，el.scrollTop 与 window.scrollY 任一不在顶部
 *     都不启动（防与纵向滚动/浏览器返回手势冲突）；
 *  5. 多指/上滑/滚动中途离开顶部：放弃本轮下拉；
 *  6. 刷新中新下拉被忽略；touchcancel 按取消处理，不误触发刷新；
 *  7. 卸载摘监听（onMounted 记住绑定节点——onUnmounted 时模板 ref 已被置 null）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { mountComponent, flush } from '../helpers/componentHarness'

const hapticMock = vi.fn()
vi.mock('@/utils/haptic', () => ({ haptic: (...a) => hapticMock(...a) }))

import { usePullToRefresh } from '@/composables/usePullToRefresh'

let active = null

afterEach(() => {
  active?.handle.unmount()
  active = null
  vi.restoreAllMocks()
  hapticMock.mockReset()
})

/** jsdom 无 TouchEvent：自造带 touches 的事件对象 */
const touch = (type, clientY, fingers = 1) => {
  const e = new window.Event(type, { bubbles: true, cancelable: true })
  const list = []
  for (let i = 0; i < fingers; i += 1) list.push({ clientY: clientY + i * 10 })
  Object.defineProperty(e, 'touches', { value: list })
  return e
}

const mountPull = async (onRefresh) => {
  const elRef = ref(null)
  let api = null
  const Host = defineComponent({
    setup() {
      api = usePullToRefresh(elRef, onRefresh)
      return () => h('div', { ref: elRef, class: 'pull-target' })
    },
  })
  active = mountComponent(Host)
  await flush(2)
  return { el: active.find('.pull-target'), api: () => api }
}

/** 可控的 onRefresh：刷新状态持续到用例手动落定 */
const deferredRefresh = () => {
  let resolve
  const fn = vi.fn(
    () =>
      new Promise((r) => {
        resolve = r
      })
  )
  return { fn, settle: () => resolve() }
}

describe('usePullToRefresh 下拉刷新', () => {
  test('下拉阻尼、封顶与触发：y 按 0.55 阻尼且封顶 120，过门槛触发刷新', async () => {
    const { fn, settle } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 200)) // dy=100 → 55
    expect(api().y.value).toBeCloseTo(55, 6)
    el.dispatchEvent(touch('touchmove', 300)) // dy=200 → 110
    expect(api().y.value).toBeCloseTo(110, 6)
    el.dispatchEvent(touch('touchmove', 500)) // dy=400 → 220 → 封顶 120
    expect(api().y.value).toBe(120)

    el.dispatchEvent(touch('touchend', 500))
    expect(fn).toHaveBeenCalledTimes(1)
    expect(hapticMock).toHaveBeenCalledWith(15)
    expect(api().refreshing.value).toBe(true)
    expect(api().y.value).toBe(80) // 刷新期间指示条锁在门槛处

    await settle()
    await flush(4)
    expect(api().refreshing.value).toBe(false)
    expect(api().y.value).toBe(0)
  })

  test('未达门槛：松手回弹，不触发刷新、不震动', async () => {
    const { fn } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 130)) // dy=30 → 16.5
    expect(api().y.value).toBe(16.5)
    el.dispatchEvent(touch('touchend', 130))
    expect(fn).not.toHaveBeenCalled()
    expect(hapticMock).not.toHaveBeenCalled()
    expect(api().y.value).toBe(0)
    expect(api().refreshing.value).toBe(false)
  })

  test('不在顶部不启动：el.scrollTop 与 window.scrollY 任一越界都忽略', async () => {
    const { fn } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    el.scrollTop = 10 // 主内容区自己滚动中
    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 300))
    el.dispatchEvent(touch('touchend', 300))
    expect(fn).not.toHaveBeenCalled()
    expect(api().y.value).toBe(0)

    el.scrollTop = 0
    Object.defineProperty(window, 'scrollY', { value: 50, configurable: true })
    try {
      el.dispatchEvent(touch('touchstart', 100))
      el.dispatchEvent(touch('touchmove', 300))
      el.dispatchEvent(touch('touchend', 300))
      expect(fn).not.toHaveBeenCalled()
      expect(api().y.value).toBe(0)
    } finally {
      Object.defineProperty(window, 'scrollY', { value: 0, configurable: true })
    }
  })

  test('多指放弃本轮；上滑与中途离开顶部同样放弃', async () => {
    const { fn } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    el.dispatchEvent(touch('touchstart', 100, 2)) // 多指：resetPull
    el.dispatchEvent(touch('touchmove', 300))
    el.dispatchEvent(touch('touchend', 300))
    expect(api().y.value).toBe(0)
    expect(fn).not.toHaveBeenCalled()

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 80)) // dy<0：上滑
    expect(api().y.value).toBe(0)

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 200))
    expect(api().y.value).toBeCloseTo(55, 6)
    el.scrollTop = 10 // 滚动中途离开顶部
    el.dispatchEvent(touch('touchmove', 300))
    expect(api().y.value).toBe(0)
  })

  test('下拉进行中第二指落下：重置本轮（y 归零且不再跟手）', async () => {
    // 变异实测（M15，2026-10-09）暴露的缺口：上面那条「多指放弃本轮」用例把多指
    // **当作首个事件**发出——此时 y 本就是 0、isPulling 本就是 false，
    // 于是 `resetPull()` 删掉与否完全看不出来（该变异在旧用例下存活）。
    // 真正要守的不变量是「多指介入会**中断进行中的**下拉」：第二指落在已经拉出的
    // 手势上时必须把 y 复位并清掉 isPulling，否则指示条会停在半途、后续 move 继续跟手。
    const { fn } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    // 单指先拉出一段（dy=100 → 55）
    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 200))
    expect(api().y.value).toBeCloseTo(55, 6)

    // 第二指落下：必须重置本轮
    el.dispatchEvent(touch('touchstart', 100, 2))
    expect(api().y.value).toBe(0)

    // 且 isPulling 已复位：后续 move 不再跟手
    el.dispatchEvent(touch('touchmove', 400))
    expect(api().y.value).toBe(0)
    el.dispatchEvent(touch('touchend', 400))
    expect(fn).not.toHaveBeenCalled()
  })

  test('刷新中的新下拉被忽略；touchcancel 按取消处理不触发刷新', async () => {
    const { fn, settle } = deferredRefresh()
    const { el, api } = await mountPull(fn)

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 300))
    el.dispatchEvent(touch('touchend', 300))
    expect(api().refreshing.value).toBe(true)

    el.dispatchEvent(touch('touchstart', 100)) // 刷新中：忽略
    el.dispatchEvent(touch('touchmove', 400))
    expect(api().y.value).toBe(80) // 不被新手势改写

    el.dispatchEvent(touch('touchcancel', 400)) // refreshing 中：不 reset
    expect(api().y.value).toBe(80)
    await settle()
    await flush(4)

    // 刷新落定后 cancel 才恢复 reset 语义
    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 300))
    expect(api().y.value).toBeCloseTo(110, 6)
    el.dispatchEvent(touch('touchcancel', 300))
    expect(api().y.value).toBe(0)
  })

  test('卸载：监听被摘掉（onMounted 记住节点），离开后手势不再改写 y', async () => {
    const { fn } = deferredRefresh()
    const { el, api } = await mountPull(fn)
    const removeSpy = vi.spyOn(el, 'removeEventListener')

    el.dispatchEvent(touch('touchstart', 100))
    el.dispatchEvent(touch('touchmove', 200))
    expect(api().y.value).toBeCloseTo(55, 6)

    active.handle.unmount()
    active = null
    expect(removeSpy).toHaveBeenCalledWith('touchstart', expect.any(Function))
    expect(removeSpy).toHaveBeenCalledWith('touchmove', expect.any(Function))

    el.dispatchEvent(touch('touchmove', 400)) // 监听若在，会写到 165→120
    expect(api().y.value).toBeCloseTo(55, 6)
  })
})
