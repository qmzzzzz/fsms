/**
 * vSegGlass × 真实 Element Plus：`.is-active` 契约（行为级审计补齐）
 *
 * 为什么单开一个文件、而不并入 segGlass.test.js：
 * 那边**刻意**不挂组件——它造一个 el-radio-group 形态的手工 DOM，直接驱动
 * 指令对象，理由是「指令与组件无关」。这个理由对**指令自身**的逻辑成立，
 * 但留下了一个没人守的接缝：指令用 `el.querySelector('.el-radio-button.is-active')`
 * 定位当前段，而 `is-active` 是 **Element Plus 生成的**，不是本仓生成的。
 * 手工 DOM 里的 `is-active` 是测试自己写上去的，所以「EP 不再产出这个类名」
 * 这类退化在那套用例里**永远不会红**——而它的后果是静默的：滑块 opacity 恒 0，
 * 界面上就是「分段控件没有滑块」，不抛错、不报错、控制台干净。
 *
 * 取证（EP 2.14.5，node_modules/element-plus/es/components/radio/src/
 * radio-button.vue_vue_type_script_setup_true_lang.mjs）：
 *   class: normalizeClass([ ns.b('button'),
 *     ns.is('active', modelValue === actualValue), ... ])
 * 即 `el-radio-button` + 条件类 `is-active`（useNamespace('radio') ⇒ 前缀 el-radio）。
 * 上游换类名（或改成 `is-checked`）时本文件会红，手工 DOM 那套不会。
 *
 * 断言口径受 jsdom 限制：jsdom 里 offsetWidth/offsetLeft **恒为 0 且只读**，
 * 所以这里不断言几何量，只断言「指令在**真实 EP DOM** 里找到了选中段」——
 * 判据就是 opacity 从 0 变 1（update() 只在找到 `.is-active` 时才置 1）。
 * 这一条恰好就是「EP 契约还在不在」的可证伪信号。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h, ref, withDirectives } from 'vue'
import { ElRadioGroup, ElRadioButton } from 'element-plus'
import { mountComponent, flush } from '../helpers/componentHarness'
import vSegGlass from '@/directives/segGlass'

let rafQueue = []
let rafSpy

beforeEach(() => {
  rafQueue = []
  rafSpy = vi.spyOn(globalThis, 'requestAnimationFrame').mockImplementation((cb) => {
    rafQueue.push(cb)
    return rafQueue.length
  })
})

afterEach(() => {
  rafSpy.mockRestore()
})

/** 手动执行本帧收集到的 rAF 回调（指令靠它做首帧定位 + 开 live 类） */
const runRaf = () => {
  const callbacks = rafQueue
  rafQueue = []
  callbacks.forEach((cb) => cb(0))
}

let active = null
/** 分段控件的 v-model（测试里直接改它来模拟用户切换，避免依赖 jsdom 的 label→input 点击链） */
let rangeRef = null

/** 与 ReportView/InspectionView 同形：el-radio-group 挂 class="seg-glass" + v-seg-glass */
const makeHost = () =>
  defineComponent({
    setup() {
      rangeRef = ref(7)
      return () =>
        withDirectives(
          h(
            ElRadioGroup,
            {
              modelValue: rangeRef.value,
              'onUpdate:modelValue': (v) => {
                rangeRef.value = v
              },
              class: 'seg-glass',
            },
            () => [7, 30, 90].map((d) => h(ElRadioButton, { key: d, value: d }, () => `${d}天`))
          ),
          [[vSegGlass]]
        )
    },
  })

const open = async () => {
  rangeRef = null
  active = mountComponent(makeHost(), { initialRoute: '/reports' })
  await flush(10)
  return active
}

const thumb = () => active.find('.seg-glass__thumb')

describe('vSegGlass 在真实 Element Plus DOM 上', () => {
  test('EP 真的产出 .el-radio-button.is-active（指令定位所依赖的类名）', async () => {
    const c = await open()
    // 这是**上游契约**的直接断言：EP 换类名时这里先红，而不是界面上静默没有滑块
    const actives = c.findAll('.el-radio-button.is-active')
    expect(actives).toHaveLength(1)
    // v-model=7 ⇒ 第 1 段（7天）选中
    expect(actives[0].textContent).toContain('7天')
    // 且它确实是 el-radio-group 的子节点（offsetLeft 才是相对容器的）
    expect(c.find('.el-radio-group.seg-glass')).not.toBeNull()
    active?.handle.unmount()
    active = null
  })

  test('挂载后首帧：滑块被追加、opacity 置 1（= 在真实 EP DOM 里找到了选中段）', async () => {
    const c = await open()

    // 滑块是真实容器 appendChild 进去的
    expect(thumb()).not.toBeNull()
    expect(c.find('.seg-glass__thumb').getAttribute('aria-hidden')).toBe('true')

    // 首帧前 opacity 仍是初始 0；rAF 后必须变 1
    expect(thumb().style.opacity).not.toBe('1')
    runRaf()
    expect(thumb().style.opacity).toBe('1')
    expect(c.find('.el-radio-group').classList.contains('seg-glass--live')).toBe(true)

    active?.handle.unmount()
    active = null
  })

  test('切换选中段：EP 迁移 is-active 后滑块仍在（MutationObserver 在真实 DOM 上生效）', async () => {
    const c = await open()
    runRaf()
    expect(thumb().style.opacity).toBe('1')

    // 模拟用户点选「90天」：EP 只改 class，不重建节点
    rangeRef.value = 90
    await flush(6)
    // MutationObserver 回调走微任务，让出一轮宏任务确保投递
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(c.findAll('.el-radio-button.is-active')).toHaveLength(1)
    expect(c.find('.el-radio-button.is-active').textContent).toContain('90天')
    // 关键：滑块没有因为 is-active 迁移而消失
    expect(thumb().style.opacity).toBe('1')

    active?.handle.unmount()
    active = null
  })

  test('正对照：摘掉真实 EP DOM 里选中段的 is-active，滑块立刻回落隐藏', async () => {
    // 这是上面「opacity === 1」断言的**正对照**：证明该断言确实取决于
    // `.el-radio-button.is-active` 是否出现在真实 EP DOM 里，而不是恒真。
    //
    // 上游若把类名换掉（例如改成 is-checked），真实 DOM 里就不再有 is-active，
    // 指令找不到选中段 ⇒ opacity 恒 0 ⇒ 上面那条断言必然红。
    //
    // 这里**只摘除、不补替代类**：补一个 is-checked 会让本用例对「源码选择器被改」
    // 也敏感，从而与它要隔离的那个变量纠缠在一起（实测：补类时改选择器的变异会连带
    // 把本用例杀掉）。只摘不补，本用例就只回答一个问题——「类不在时会不会隐藏」。
    const c = await open()
    runRaf()
    expect(thumb().style.opacity).toBe('1')

    const activeBtn = c.find('.el-radio-button.is-active')
    expect(activeBtn).not.toBeNull()
    activeBtn.classList.remove('is-active')
    await flush(4)
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(thumb().style.opacity).toBe('0')

    active.handle.unmount()
    active = null
  })

  test('v-model 不匹配任何段（真实 EP 下无 is-active）：滑块隐藏，不残留错位滑块', async () => {
    const c = await open()
    // 把模型置成一个没有任何分段承载的值：EP 于是不给任何段 is-active
    rangeRef.value = 999
    await flush(6)
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(c.findAll('.el-radio-button.is-active')).toHaveLength(0)
    // 找不到选中段时必须隐藏（设计说明第 3 条），而不是停在左上角
    expect(thumb().style.opacity).toBe('0')

    active?.handle.unmount()
    active = null
  })

  test('卸载：滑块从真实 EP DOM 里移除、观察者断开', async () => {
    const c = await open()
    runRaf()
    const group = c.find('.el-radio-group.seg-glass')
    const ctx = group.__segGlass
    const moDisconnect = vi.spyOn(ctx.mo, 'disconnect')

    active.handle.unmount()
    active = null

    // 卸载后容器已脱离文档，滑块随之不可见；上下文清空、观察者断开
    expect(ctx.mo.disconnect).toHaveBeenCalledTimes(1)
    expect(moDisconnect).toHaveBeenCalled()
    expect(group.__segGlass).toBeUndefined()
    expect(group.querySelector('.seg-glass__thumb')).toBeNull()
  })

  test('容器在卸载前已脱离（v-if 快速切换）：挂载/卸载配对不抛错', async () => {
    const c = await open()
    // 未跑 rAF 就卸载：rAF 回调与 fonts.ready 仍在队列里
    expect(() => active.handle.unmount()).not.toThrow()
    active = null
    // 补跑那次迟到的 rAF：不得抛错（回调里只是写已移除元素的样式）
    expect(() => runRaf()).not.toThrow()
    expect(c.find('.seg-glass__thumb')).toBeNull()
  })
})
