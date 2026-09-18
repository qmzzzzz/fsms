/**
 * GlassSegmented 行为测试（分段控件 + 滑动透镜滑块）
 *
 * 组件定位：AlarmView / IpListView 的筛选控件。两条真实契约：
 *  1. 点击未选中项 → 先 emit update:modelValue 再 emit change；点击已选中项必须静默
 *     （否则父视图会重复发起筛选请求）。
 *  2. 滑块尺寸/位移由真实布局测量（offsetWidth/offsetLeft）驱动；jsdom 无布局恒为 0，
 *     故用 defineProperty 给激活项注入真值，再断言 style.width / style.transform 真被写入。
 *
 * ResizeObserver 在 jsdom 30 中不存在（本套件 before/afterEach 已实测确认），
 * 因此 window resize 降级是**默认路径**；注入 RO 替身只用于验证 RO 分支的注册与清理。
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import GlassSegmented from '@/components/GlassSegmented.vue'
import { defineComponent, h, ref, unref } from 'vue'

let active = null
const mount = (props, options = {}) => {
  active = mountComponent(GlassSegmented, { props, ...options })
  return active
}

const options = [
  { label: '全部', value: 'all' },
  { label: '待处理', value: 'pending' },
  { label: '已处理', value: 'done' },
]

/**
 * 受控宿主：把 v-model 接回本地 ref，才能验证「点击 → 更新 → 重新对位」的完整链路。
 * 全文件只保留这一处 defineComponent（避免 vue/one-component-per-file 告警）。
 */
const makeHost = (opts, model, onChange) =>
  defineComponent({
    setup() {
      return () =>
        h(GlassSegmented, {
          options: unref(opts),
          modelValue: model.value,
          'onUpdate:modelValue': (v) => {
            model.value = v
          },
          onChange,
        })
    },
  })

/** 给元素注入布局真值：jsdom 不做布局，offset* 恒 0，不注入就无法验证滑块定位 */
const defineMetrics = (el, width, left) => {
  Object.defineProperty(el, 'offsetWidth', { value: width, configurable: true })
  Object.defineProperty(el, 'offsetLeft', { value: left, configurable: true })
}

beforeEach(() => {
  // vitest jsdom 环境下 window === globalThis（实测），挂 globalThis 即挂 window
  delete globalThis.ResizeObserver
})

afterEach(() => {
  active?.handle.unmount()
  active = null
  delete globalThis.ResizeObserver
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('GlassSegmented 选择事件契约', () => {
  test('点击未选中项：先 update:modelValue 后 change，两事件同一值', async () => {
    const calls = []
    const c = mount({
      options,
      modelValue: 'all',
      'onUpdate:modelValue': (v) => calls.push(['update:modelValue', v]),
      onChange: (v) => calls.push(['change', v]),
    })
    await flush(2)
    click(c.findAll('.glass-segmented__item')[1])
    expect(calls).toEqual([
      ['update:modelValue', 'pending'],
      ['change', 'pending'],
    ])
    expect(c.errors).toEqual([])
  })

  test('点击当前已选中项：不 emit 任何事件（幂等守卫，防父视图重复筛选）', async () => {
    const onUpdate = vi.fn()
    const onChange = vi.fn()
    const c = mount({
      options,
      modelValue: 'pending',
      'onUpdate:modelValue': onUpdate,
      onChange,
    })
    await flush(2)
    const activeBtn = c.find('.glass-segmented__item.is-active')
    expect(activeBtn.getAttribute('data-value')).toBe('pending')
    click(activeBtn)
    click(activeBtn)
    expect(onUpdate).not.toHaveBeenCalled()
    expect(onChange).not.toHaveBeenCalled()
  })

  test('点击每一项都回传该项自己的 value（不是下标、不是邻项）', async () => {
    const values = []
    const model = ref('all')
    const c = mountComponent(
      makeHost(options, model, (v) => values.push(v)),
      {}
    )
    active = c
    await flush(3)
    const items = c.findAll('.glass-segmented__item')
    click(items[2])
    await flush(2)
    click(items[1])
    await flush(2)
    click(items[0])
    await flush(2)
    expect(values).toEqual(['done', 'pending', 'all'])
    expect(model.value).toBe('all')
  })

  test('数字 value 原样回传（不被字符串化）', async () => {
    const values = []
    const c = mount({
      options: [
        { label: '一级', value: 1 },
        { label: '二级', value: 2 },
      ],
      modelValue: 1,
      onChange: (v) => values.push(v),
    })
    await flush(2)
    click(c.findAll('.glass-segmented__item')[1])
    expect(values).toEqual([2])
    expect(typeof values[0]).toBe('number')
  })
})

describe('GlassSegmented 选中态与计数徽标', () => {
  test('is-active 类与 aria-selected 随 modelValue 变化（单选项）', async () => {
    const c = mount({ options, modelValue: 'pending' })
    await flush(2)
    const items = c.findAll('.glass-segmented__item')
    expect(items.map((el) => el.classList.contains('is-active'))).toEqual([false, true, false])
    expect(items.map((el) => el.getAttribute('aria-selected'))).toEqual(['false', 'true', 'false'])
  })

  test('modelValue 缺省为空串：不会自动选中任何选项（受控语义）', async () => {
    const c = mount({ options })
    await flush(2)
    expect(c.findAll('.glass-segmented__item.is-active')).toEqual([])
    expect(c.findAll('.glass-segmented__item[aria-selected="true"]')).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('modelValue 不在 options 中：无任何项被标记选中，滑块保持原样不抛错', async () => {
    const c = mount({ options, modelValue: 'ghost' })
    await flush(2)
    expect(c.findAll('.glass-segmented__item.is-active')).toEqual([])
    expect(c.findAll('.glass-segmented__item[aria-selected="true"]')).toEqual([])
    expect(c.find('.glass-segmented__thumb').getAttribute('style')).toBe(null)
    expect(c.errors).toEqual([])
  })

  test('count 存在时渲染徽标；count=0 也必须渲染（判据是 !== undefined && !== null）', async () => {
    const c = mount({
      options: [
        { label: '全部', value: 'all', count: 12 },
        { label: '待处理', value: 'pending', count: 0 },
        { label: '已处理', value: 'done' },
      ],
      modelValue: 'all',
    })
    await flush(2)
    const badges = c.findAll('.glass-segmented__count')
    expect(badges.map((el) => el.textContent.trim())).toEqual(['12', '0'])
    // 无 count 的项不带徽标
    expect(c.findAll('.glass-segmented__item')[2].querySelector('.glass-segmented__count')).toBe(
      null
    )
  })

  test('count 为 null 不渲染徽标（与 0 区别对待）', async () => {
    const c = mount({
      options: [
        { label: 'A', value: 'a', count: null },
        { label: 'B', value: 'b', count: 0 },
      ],
      modelValue: 'a',
    })
    await flush(2)
    const badges = c.findAll('.glass-segmented__count')
    expect(badges).toHaveLength(1)
    expect(badges[0].textContent.trim()).toBe('0')
    expect(badges[0].closest('.glass-segmented__item').getAttribute('data-value')).toBe('b')
  })

  test('尺寸变体：仅 size=sm 加 --sm 类，缺省与非 sm 值都不加；ariaLabel 为空时不输出属性', async () => {
    const c = mount({ options, modelValue: 'all', size: 'sm' })
    await flush(2)
    expect(c.element.className).toContain('glass-segmented--sm')
    expect(c.element.getAttribute('aria-label')).toBe(null)
    c.handle.unmount()
    active = null
    // 缺省：不加类
    const plain = mount({ options, modelValue: 'all' })
    await flush(2)
    expect(plain.element.className).not.toContain('glass-segmented--sm')
    plain.handle.unmount()
    active = null
    // 非空但非 sm 的值（未来新增尺寸档）不得误加 sm 类
    const md = mount({ options, modelValue: 'all', size: 'md' })
    await flush(2)
    expect(md.element.className).not.toContain('glass-segmented--sm')
  })

  test('ariaLabel 传入时输出到 tablist；role / aria-hidden / 原生 button 齐备', async () => {
    const c = mount({ options, modelValue: 'all', ariaLabel: '报警状态筛选' })
    await flush(2)
    expect(c.element.getAttribute('role')).toBe('tablist')
    expect(c.element.getAttribute('aria-label')).toBe('报警状态筛选')
    expect(c.find('.glass-segmented__thumb').getAttribute('aria-hidden')).toBe('true')
    expect(c.findAll('.glass-segmented__item').map((el) => el.getAttribute('role'))).toEqual([
      'tab',
      'tab',
      'tab',
    ])
    // 原生 button：避免在 form 内触发隐式提交
    expect(c.findAll('.glass-segmented__item').map((el) => el.getAttribute('type'))).toEqual([
      'button',
      'button',
      'button',
    ])
  })
})

describe('GlassSegmented 滑块定位', () => {
  test('resize 时按激活项测量值写入 width 与 translateX', async () => {
    const c = mount({ options, modelValue: 'pending' })
    await flush(2)
    const btn = c.find('.glass-segmented__item.is-active')
    const thumb = c.find('.glass-segmented__thumb')
    defineMetrics(btn, 88, 120)
    window.dispatchEvent(new window.Event('resize'))
    await flush(2)
    expect(thumb.style.width).toBe('88px')
    expect(thumb.style.transform).toBe('translateX(120px)')
  })

  test('modelValue 变化后重新对位到新的激活项', async () => {
    const model = ref('all')
    const c = mountComponent(makeHost(options, model), {})
    active = c
    await flush(3)
    const items = c.findAll('.glass-segmented__item')
    defineMetrics(items[0], 60, 0)
    defineMetrics(items[2], 100, 200)
    const thumb = c.find('.glass-segmented__thumb')
    window.dispatchEvent(new window.Event('resize'))
    await flush(2)
    expect(thumb.style.width).toBe('60px')
    expect(thumb.style.transform).toBe('translateX(0px)')
    model.value = 'done'
    await flush(3)
    expect(c.find('.glass-segmented__item.is-active').getAttribute('data-value')).toBe('done')
    expect(thumb.style.width).toBe('100px')
    expect(thumb.style.transform).toBe('translateX(200px)')
  })

  test('options 内部字段被就地改写（deep watch）后重新对位', async () => {
    const opts = ref([
      { label: 'A', value: 'a' },
      { label: 'B', value: 'b' },
    ])
    const c = mountComponent(makeHost(opts, ref('a')), {})
    active = c
    await flush(3)
    const btn = c.find('.glass-segmented__item.is-active')
    defineMetrics(btn, 150, 20)
    const thumb = c.find('.glass-segmented__thumb')
    opts.value[0].count = 9
    await flush(3)
    expect(c.find('.glass-segmented__count').textContent.trim()).toBe('9')
    expect(thumb.style.width).toBe('150px')
    expect(thumb.style.transform).toBe('translateX(20px)')
  })

  test('首次定位延后到下一帧才加 is-ready（避免从 0 滑入），且只调度一次', async () => {
    const rafCbs = []
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      rafCbs.push(cb)
      return rafCbs.length
    })
    const opts = ref([
      { label: 'A', value: 'a' },
      { label: 'B', value: 'b' },
    ])
    const c = mountComponent(makeHost(opts, ref('a')), {})
    active = c
    await flush(3)
    const thumb = c.find('.glass-segmented__thumb')
    expect(rafCbs).toHaveLength(1)
    expect(thumb.classList.contains('is-ready')).toBe(false)
    rafCbs[0](0)
    await flush()
    expect(thumb.classList.contains('is-ready')).toBe(true)
    // is-ready 后即使再次对位也不再重复调度
    opts.value = [
      { label: 'A', value: 'a' },
      { label: 'B', value: 'b', count: 2 },
    ]
    await flush(4)
    expect(rafCbs).toHaveLength(1)
    expect(thumb.classList.contains('is-ready')).toBe(true)
  })

  test('无激活项时滑块不被改写（保留初始样式）且不抛错', async () => {
    const c = mount({ options, modelValue: 'ghost' })
    await flush(2)
    const thumb = c.find('.glass-segmented__thumb')
    expect(thumb.getAttribute('style')).toBe(null)
    window.dispatchEvent(new window.Event('resize'))
    await flush(2)
    expect(thumb.getAttribute('style')).toBe(null)
    expect(c.errors).toEqual([])
    expect(c.warnings).toEqual([])
  })
})

describe('GlassSegmented 观察者生命周期', () => {
  test('无 ResizeObserver 时降级为 window resize 监听，卸载时移除同一函数', async () => {
    const added = []
    const removed = []
    vi.spyOn(window, 'addEventListener').mockImplementation((type, fn) => {
      added.push([type, fn])
    })
    vi.spyOn(window, 'removeEventListener').mockImplementation((type, fn) => {
      removed.push([type, fn])
    })
    const c = mount({ options, modelValue: 'all' })
    await flush(2)
    const addedResize = added.filter(([type]) => type === 'resize')
    expect(addedResize).toHaveLength(1)
    expect(typeof addedResize[0][1]).toBe('function')
    c.handle.unmount()
    active = null
    const removedResize = removed.filter(([type]) => type === 'resize')
    expect(removedResize).toHaveLength(1)
    // 必须移除注册时的同一个引用，否则监听泄漏
    expect(removedResize[0][1]).toBe(addedResize[0][1])
  })

  test('ResizeObserver 可用时改用它：observe 容器、回调驱动对位、卸载 disconnect', async () => {
    class FakeResizeObserver {
      static instances = []
      constructor(cb) {
        this.cb = cb
        this.disconnected = false
        FakeResizeObserver.instances.push(this)
      }

      observe(el) {
        this.observed = el
      }

      disconnect() {
        this.disconnected = true
      }
    }
    globalThis.ResizeObserver = FakeResizeObserver
    const addSpy = vi.spyOn(window, 'addEventListener')
    const c = mount({ options, modelValue: 'done' })
    await flush(2)
    expect(FakeResizeObserver.instances).toHaveLength(1)
    expect(FakeResizeObserver.instances[0].observed).toBe(c.find('.glass-segmented'))
    // RO 分支下不应注册 window resize 监听
    expect(addSpy.mock.calls.filter(([type]) => type === 'resize')).toEqual([])
    const btn = c.find('.glass-segmented__item.is-active')
    defineMetrics(btn, 77, 154)
    FakeResizeObserver.instances[0].cb([])
    await flush(2)
    const thumb = c.find('.glass-segmented__thumb')
    expect(thumb.style.width).toBe('77px')
    expect(thumb.style.transform).toBe('translateX(154px)')
    c.handle.unmount()
    active = null
    expect(FakeResizeObserver.instances[0].disconnected).toBe(true)
  })

  test('卸载后再派发 resize 不抛错（监听已移除）', async () => {
    const c = mount({ options, modelValue: 'all' })
    await flush(2)
    c.handle.unmount()
    active = null
    expect(() => window.dispatchEvent(new window.Event('resize'))).not.toThrow()
    expect(c.errors).toEqual([])
  })
})
