/**
 * useCountUp 行为测试（统计卡数字滚动）
 *
 * 模块级 SKIP_ANIMATION = import.meta.env.MODE === 'test' || prefers-reduced-motion
 * 在**导入时**求值，因此两条分支必须用「stubEnv/stub matchMedia + resetModules +
 * 动态 import」的方式单独覆盖，静态 import 只能覆盖 test 模式那条。
 *
 * 覆盖的行为：
 *  1. test 模式：数值/非数值（'-' 占位）变化直给终值，不建 rAF（断言确定性文本）；
 *  2. development 模式：数值变化走 rAF 动画，中间值符合 easeOutCubic（钉死
 *     performance.now 与时间戳，断言中间值 88、终值 100），达标后自动停；
 *  3. development 模式：原显示值是非数字时从 0 起滚；
 *  4. 同值跳过：新旧值相等时不建 rAF（语言切换整体重建数组不得重复滚动）；
 *  5. reduced-motion：直给终值；
 *  6. 卸载：pending 的 rAF 被 cancel（不向已卸载组件继续写 display）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, ref } from 'vue'
import { mountComponent, flush } from '../helpers/componentHarness'
import { useCountUp } from '@/composables/useCountUp'

let active = null

afterEach(() => {
  active?.handle.unmount()
  active = null
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.resetModules()
  vi.restoreAllMocks()
  if (window.matchMedia) delete window.matchMedia
})

/**
 * 全文件唯一的 defineComponent（vue/one-component-per-file）：把任意组合式函数
 * 装进真实组件，onMounted/onUnmounted/watch 才会真的跑。
 */
const mountComposable = async (setup) => {
  const Host = defineComponent({ setup, render: () => null })
  active = mountComponent(Host)
  await flush(2)
  return active
}

/** rAF 手动队列：id 可 cancel，回调由用例按时间戳驱动 */
const installRafQueue = () => {
  const frames = []
  let seq = 0
  vi.stubGlobal('requestAnimationFrame', (cb) => {
    seq += 1
    frames.push({ id: seq, cb })
    return seq
  })
  const cancelSpy = vi.fn((id) => {
    const i = frames.findIndex((f) => f.id === id)
    if (i > -1) frames.splice(i, 1)
  })
  vi.stubGlobal('cancelAnimationFrame', cancelSpy)
  const drive = async (now) => {
    const pending = frames.splice(0, frames.length)
    pending.forEach((f) => f.cb(now))
    await flush(2)
  }
  return { frames, cancelSpy, drive }
}

describe('useCountUp 数字滚动', () => {
  test('test 模式（默认）：数值与占位符变化都直给终值，不建 rAF', async () => {
    const rafSpy = vi.fn()
    vi.stubGlobal('requestAnimationFrame', rafSpy)
    const stats = ref([{ value: '-' }, { value: 5 }])
    let display = null
    await mountComposable(() => {
      display = useCountUp(stats)
    })
    expect(display.value).toEqual(['-', 5])

    stats.value = [{ value: 10 }, { value: 7 }, { value: '-' }]
    await flush(2)
    expect(display.value).toEqual([10, 7, '-'])
    expect(rafSpy).not.toHaveBeenCalled()
  })

  test('development 模式：走 rAF 动画，中间值符合 easeOutCubic，达标自动停', async () => {
    vi.resetModules()
    vi.stubEnv('MODE', 'development')
    const { useCountUp: devUseCountUp } = await import('@/composables/useCountUp')
    const stats = ref([{ value: '-' }])
    let display = null
    await mountComposable(() => {
      display = devUseCountUp(stats, { duration: 600 })
    })
    const { frames, drive } = installRafQueue()
    vi.spyOn(performance, 'now').mockReturnValue(1000)

    stats.value = [{ value: 100 }] // 原显示值 '-' 非数字 → 从 0 起滚
    await flush(2)
    expect(frames).toHaveLength(1)

    await drive(1300) // p=0.5 → eased=0.875 → round(87.5)
    expect(display.value).toEqual([88])

    await drive(1600) // p=1 → 终值，且不再排帧
    expect(display.value).toEqual([100])
    expect(frames).toHaveLength(0)
  })

  test('development 模式：新旧值相等时不建 rAF（数组整体重建不得重复滚动）', async () => {
    vi.resetModules()
    vi.stubEnv('MODE', 'development')
    const { useCountUp: devUseCountUp } = await import('@/composables/useCountUp')
    const stats = ref([{ value: 42 }])
    let display = null
    await mountComposable(() => {
      display = devUseCountUp(stats, { duration: 600 })
    })
    const { frames } = installRafQueue()

    stats.value = [{ value: 42 }] // 新数组、同值
    await flush(2)
    expect(frames).toHaveLength(0)
    expect(display.value).toEqual([42])
  })

  test('prefers-reduced-motion：development 模式下也直给终值，不建 rAF', async () => {
    vi.resetModules()
    vi.stubEnv('MODE', 'development')
    window.matchMedia = vi.fn(() => ({ matches: true }))
    const { useCountUp: devUseCountUp } = await import('@/composables/useCountUp')
    expect(typeof devUseCountUp).toBe('function')
    const rafSpy = vi.fn()
    vi.stubGlobal('requestAnimationFrame', rafSpy)
    const stats = ref([{ value: 0 }])
    let display = null
    await mountComposable(() => {
      display = devUseCountUp(stats, { duration: 600 })
    })

    stats.value = [{ value: 100 }]
    await flush(2)
    expect(display.value).toEqual([100])
    expect(rafSpy).not.toHaveBeenCalled()
  })

  test('卸载：pending 的 rAF 被 cancel，不再有回调残留', async () => {
    vi.resetModules()
    vi.stubEnv('MODE', 'development')
    const { useCountUp: devUseCountUp } = await import('@/composables/useCountUp')
    const stats = ref([{ value: 0 }])
    let display = null
    await mountComposable(() => {
      display = devUseCountUp(stats, { duration: 600 })
    })
    const { frames, cancelSpy, drive } = installRafQueue()
    vi.spyOn(performance, 'now').mockReturnValue(1000)

    stats.value = [{ value: 100 }]
    await flush(2)
    expect(frames).toHaveLength(1)
    const pendingId = frames[0].id

    active.handle.unmount()
    active = null
    // watch 起步时也会 cancel 一次 undefined 的 rafs[i]，故按 id 断言而非总次数
    expect(cancelSpy).toHaveBeenCalledWith(pendingId)
    expect(frames).toHaveLength(0)
    await drive(1600) // 队列已空：没有回调能再写 display
    expect(display.value).toEqual([0])
  })
})
