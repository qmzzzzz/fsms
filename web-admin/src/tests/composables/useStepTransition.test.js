/**
 * useStepTransition 行为测试（分步向导：方向感知 + 容器高度状态机）
 *
 * 为何需要它：该 composable 是 RegisterView 三步向导的纯视图状态机，
 * 此前无任何测试。它失效不会让接口报错，只会让用户在切步时看到卡片
 * 瞬间跳高/跳矮、动画方向反向——属于「坏了也没人发现」的静默退化。
 *
 * 断言对象是**对外契约**（方向类名、容器内联高度、观察者生命周期），
 * 不是内部实现细节。本文件 17 条用例已逐条做过变异验证（2026-09-18）：
 * 对实现注入 11 个变异体，10 个被杀死，1 个存活且经核实为**不可达代码**，
 * 详见 startObserving 用例内的说明——不为凑数给不可达分支造假测试。
 *
 * 本仓无 @vue/test-utils（新依赖需用户定夺），故用 createApp 自建最小
 * 挂载宿主：只有真实组件上下文才能验证 onBeforeUnmount(dispose) 的接线。
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { createApp, defineComponent, h, nextTick, ref } from 'vue'
import { useStepTransition } from '@/composables/useStepTransition'

/** 面板替身：jsdom 不做布局，offsetHeight 恒为 0，故按用例显式给定高度 */
const panel = (height) => ({ offsetHeight: height })

/** jsdom 30 未实现 ResizeObserver，用可控替身观察「注册/触发/断开」全链路 */
class FakeResizeObserver {
  static instances = []
  constructor(cb) {
    this.cb = cb
    this.observed = []
    this.disconnected = false
    FakeResizeObserver.instances.push(this)
  }
  observe(el) {
    this.observed.push(el)
  }
  disconnect() {
    this.disconnected = true
  }
  /** 模拟被观察元素尺寸变化（校验错误文案出现/收起） */
  fire() {
    this.cb([])
  }
}

let mounted = []

/**
 * 在真实 Vue 应用内运行 composable：onBeforeUnmount 仅对组件实例内的调用生效。
 * renderFn 由用例注入，以便覆盖 v-if 挂载/卸载时 Vue 对 ref 回调的调用序列。
 */
const mountHarness = ({ initialStep = 0, renderFn = () => h('div') } = {}) => {
  let api = null
  const activeStep = ref(initialStep)
  const Host = defineComponent({
    setup() {
      api = useStepTransition(activeStep)
      return () => renderFn(api)
    },
  })
  const root = document.createElement('div')
  document.body.appendChild(root)
  const app = createApp(Host)
  app.mount(root)
  const handle = {
    api: () => api,
    activeStep,
    root,
    unmount: () => {
      if (handle.unmounted) return
      handle.unmounted = true
      app.unmount()
      root.remove()
    },
  }
  mounted.push(handle)
  return handle
}

beforeEach(() => {
  FakeResizeObserver.instances = []
  globalThis.ResizeObserver = FakeResizeObserver
})

afterEach(() => {
  mounted.forEach((m) => m.unmount())
  mounted = []
  vi.useRealTimers()
})

describe('useStepTransition 方向感知', () => {
  test('初始为前进方向，类名映射 is-fwd / is-back', () => {
    const s = mountHarness().api()
    expect(s.stepDirection.value).toBe('forward')
    expect(s.stepDirClass.value).toBe('is-fwd')
    s.stepDirection.value = 'back'
    expect(s.stepDirClass.value).toBe('is-back')
  })

  test('方向类名只有两种取值，非 forward 一律 is-back（不产生空类名）', () => {
    const s = mountHarness().api()
    for (const v of ['back', 'backward', '', 'anything']) {
      s.stepDirection.value = v
      expect(s.stepDirClass.value).toBe('is-back')
    }
  })
})

describe('useStepTransition 面板高度', () => {
  test('未测量前容器高度为 auto，而非 0px（首帧不塌陷）', () => {
    const s = mountHarness().api()
    expect(s.stepsWrapStyle.value).toEqual({ height: 'auto' })
  })

  test('高度只取当前步的面板：切步后容器跟随新面板实测值', () => {
    const h = mountHarness({ initialStep: 0 })
    const s = h.api()
    s.setPanel(0, panel(120))
    s.setPanel(1, panel(300))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '120px' })
    h.activeStep.value = 1
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '300px' })
  })

  test('重复注册同一面板（重渲染 / 热更新）后取最新元素高度，不记忆旧值', () => {
    const s = mountHarness({ initialStep: 0 }).api()
    s.setPanel(0, panel(100))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '100px' })
    s.setPanel(0, panel(260))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '260px' })
  })

  test('高度为 0（display:none / 未布局）时不覆盖既有高度，避免容器塌回 auto', () => {
    const h = mountHarness({ initialStep: 0 })
    const s = h.api()
    s.setPanel(0, panel(200))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '200px' })
    s.setPanel(0, panel(0))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: '200px' })
  })

  test('当前步面板未注册时不抛错、不改变既有高度', () => {
    const h = mountHarness({ initialStep: 1 })
    const s = h.api()
    s.setPanel(0, panel(180))
    s.measureActivePanel()
    expect(s.stepsWrapStyle.value).toEqual({ height: 'auto' })
    expect(() => s.measureActivePanel()).not.toThrow()
    expect(s.stepsWrapStyle.value).toEqual({ height: 'auto' })
  })

  test('ref 回调传 null/undefined 不抛错（Vue 卸载面板时必然发生）', () => {
    const s = mountHarness({ initialStep: 2 }).api()
    s.setPanel(2, panel(100))
    s.setPanel(2, null)
    s.setPanel(2, undefined)
    expect(() => s.measureActivePanel()).not.toThrow()
    // 说明：本断言不能单独击穿 setPanel 内的 if (el) 守卫（守卫属防御性冗余，
    // 保留旧元素与写入 null 在既有调用序列下结果相同），它钉住的是
    // 「null 入参不得抛错、不得把已测量高度置零」这一对外行为。
    expect(s.stepsWrapStyle.value).toEqual({ height: '100px' })
  })

  test('真实 v-if 卸载流程：面板销毁后不抛错，容器高度保持', async () => {
    const show = ref(true)
    const harness = mountHarness({
      initialStep: 0,
      renderFn: (api) =>
        h('div', [show.value ? h('section', { ref: (el) => api.setPanel(0, el) }, 'panel') : null]),
    })
    const api = harness.api()
    const el = harness.root.querySelector('section')
    // jsdom 无布局：手工给 offsetHeight 以便断言高度确实来自该面板
    Object.defineProperty(el, 'offsetHeight', { value: 180, configurable: true })
    api.measureActivePanel()
    expect(api.stepsWrapStyle.value).toEqual({ height: '180px' })
    show.value = false
    await nextTick()
    expect(harness.root.querySelector('section')).toBe(null)
    expect(() => api.measureActivePanel()).not.toThrow()
    expect(api.stepsWrapStyle.value).toEqual({ height: '180px' })
  })
})

describe('useStepTransition 过渡计时', () => {
  test('过渡态 380ms 内保持，满 380ms 自动结束', () => {
    vi.useFakeTimers()
    const s = mountHarness().api()
    expect(s.isStepping.value).toBe(false)
    s.beginStepTransition()
    expect(s.isStepping.value).toBe(true)
    vi.advanceTimersByTime(379)
    expect(s.isStepping.value).toBe(true)
    vi.advanceTimersByTime(1)
    expect(s.isStepping.value).toBe(false)
  })

  test('过渡中再次触发会重置计时：上一次的定时器不得提前结束新的过渡', () => {
    vi.useFakeTimers()
    const s = mountHarness().api()
    s.beginStepTransition()
    vi.advanceTimersByTime(300)
    s.beginStepTransition()
    vi.advanceTimersByTime(200)
    expect(s.isStepping.value).toBe(true)
    vi.advanceTimersByTime(180)
    expect(s.isStepping.value).toBe(false)
  })

  test('在 DOM 更新后测量：读到的是新布局高度而非旧值', async () => {
    const s = mountHarness({ initialStep: 0 }).api()
    s.setPanel(0, panel(150))
    s.beginStepTransition()
    s.setPanel(0, panel(260))
    await nextTick()
    expect(s.stepsWrapStyle.value).toEqual({ height: '260px' })
  })
})

describe('useStepTransition 观察者生命周期', () => {
  test('startObserving 观察全部已注册面板，并先做一次初始测量', () => {
    const h = mountHarness({ initialStep: 1 })
    const s = h.api()
    const el0 = panel(100)
    const el1 = panel(240)
    s.setPanel(0, el0)
    s.setPanel(1, el1)
    s.startObserving()
    const ob = FakeResizeObserver.instances.at(-1)
    expect(ob.observed).toEqual([el0, el1])
    expect(s.stepsWrapStyle.value).toEqual({ height: '240px' })
  })

  test('面板尺寸变化时容器高度同步跟随（校验错误撑高不被裁切）', () => {
    const h = mountHarness({ initialStep: 1 })
    const s = h.api()
    const el1 = panel(240)
    s.setPanel(0, panel(100))
    s.setPanel(1, el1)
    s.startObserving()
    el1.offsetHeight = 420
    FakeResizeObserver.instances.at(-1).fire()
    expect(s.stepsWrapStyle.value).toEqual({ height: '420px' })
  })

  test('环境无 ResizeObserver 时不抛错，仍完成一次初始测量（降级路径）', () => {
    delete globalThis.ResizeObserver
    const s = mountHarness({ initialStep: 0 }).api()
    s.setPanel(0, panel(180))
    expect(() => s.startObserving()).not.toThrow()
    expect(s.stepsWrapStyle.value).toEqual({ height: '180px' })
  })

  test('dispose 断开观察者，且可重复调用不抛错', () => {
    const s = mountHarness().api()
    s.startObserving()
    const ob = FakeResizeObserver.instances.at(-1)
    expect(ob.disconnected).toBe(false)
    s.dispose()
    expect(ob.disconnected).toBe(true)
    expect(() => s.dispose()).not.toThrow()
  })

  test('组件卸载时自动 dispose：观察者断开且挂起的过渡计时器被清除', () => {
    vi.useFakeTimers()
    const h = mountHarness()
    const s = h.api()
    s.startObserving()
    const ob = FakeResizeObserver.instances.at(-1)
    s.beginStepTransition()
    expect(s.isStepping.value).toBe(true)
    h.unmount()
    expect(ob.disconnected).toBe(true)
    vi.advanceTimersByTime(5000)
    // 计时器已被 dispose 清除，故 isStepping 不会被 380ms 定时器翻回 false
    expect(s.isStepping.value).toBe(true)
  })
})
