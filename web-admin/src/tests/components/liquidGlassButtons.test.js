/**
 * LiquidGlassButtons 行为测试
 *
 * 该组件是登录/注册页主操作按钮（提交、返回、下一步）的渲染器。
 * 关键契约：每个按钮把**自己的 id** 通过 press 事件回传——父视图靠这个 id
 * 分发动作。若 id 传错或事件不发，用户点击「提交」会执行别的动作。
 * 此前无测试覆盖，属高风险静默缺陷区。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import LiquidGlassButtons from '@/components/LiquidGlassButtons.vue'

let active = null
const mount = (props, options = {}) => {
  active = mountComponent(LiquidGlassButtons, { props, ...options })
  return active
}

afterEach(() => {
  active?.handle.unmount()
  active = null
})

describe('LiquidGlassButtons', () => {
  test('按 buttons 顺序渲染，标签与文案一一对应', async () => {
    const c = mount({
      buttons: [
        { id: 'back', label: '返回' },
        { id: 'submit', label: '提交', type: 'primary' },
      ],
    })
    await flush()
    const buttons = c.findAll('button')
    expect(buttons.map((b) => b.textContent.trim())).toEqual(['返回', '提交'])
    expect(buttons.map((b) => b.className)).toEqual([
      'glass-btn glass-btn--default',
      'glass-btn glass-btn--primary',
    ])
  })

  test('点击第 N 个按钮时 press 回传它自己的 id（不是下标、不是别人的 id）', async () => {
    const onPress = vi.fn()
    const c = mount({
      buttons: [
        { id: 'cancel', label: '取消' },
        { id: 'ok', label: '确定' },
      ],
      onPress,
    })
    await flush()
    click(c.findAll('button')[1])
    click(c.findAll('button')[0])
    expect(onPress.mock.calls.map((x) => x[0])).toEqual(['ok', 'cancel'])
  })

  test('幂等点击同一按钮：每次点击都派发事件（不得去重）', async () => {
    const onPress = vi.fn()
    const c = mount({ buttons: [{ id: 'retry', label: '重试' }], onPress })
    await flush()
    const btn = c.findAll('button')[0]
    click(btn)
    click(btn)
    expect(onPress).toHaveBeenCalledTimes(2)
  })

  test('type 缺省时为 default 类；height 同时作用于容器与按钮内联样式', async () => {
    const c = mount({ buttons: [{ id: 'a', label: 'A' }], height: 56 })
    await flush()
    expect(c.find('button').className).toContain('glass-btn--default')
    expect(c.element.style.height).toBe('56px')
    expect(c.find('button').style.height).toBe('56px')
  })

  test('buttons 缺省为空数组：不渲染按钮也不抛错', async () => {
    const c = mount({})
    await flush()
    expect(c.findAll('button')).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('按钮为原生 button，禁止触发表单隐式提交以外行为的类型漂移', async () => {
    const c = mount({ buttons: [{ id: 'a', label: 'A' }] })
    await flush()
    expect(c.find('button').getAttribute('type')).toBe('button')
  })
})
