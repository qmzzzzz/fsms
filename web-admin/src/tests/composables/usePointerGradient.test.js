/**
 * usePointerGradient 行为测试（鼠标追踪径向渐变）
 *
 * 契约：
 *  1. 仅 (pointer: fine) 启用：精确指针设备才绑 pointermove，触屏（coarse）不绑；
 *  2. pointermove 把指针相对元素**中心**的偏移写入 CSS 变量 --posX/--posY
 *     （取整，无小数——calc() 里的长度不需要亚像素精度）；
 *  3. 卸载摘监听：onUnmounted 里 targetRef.value 已被 Vue 置 null，故实现在
 *     onMounted 时记住绑定节点；摘不掉的话路由离开后移动鼠标仍在写已卸载节点的样式。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { mountComponent, flush } from '../helpers/componentHarness'
import { usePointerGradient } from '@/composables/usePointerGradient'

let active = null

afterEach(() => {
  active?.handle.unmount()
  active = null
  vi.restoreAllMocks()
  if (window.matchMedia) delete window.matchMedia
})

/**
 * 全文件唯一的 defineComponent（vue/one-component-per-file）：渲染一个带 ref 的 div
 * 供 composable 绑定。matchMedia 替身由用例通过参数注入。
 */
const mountGradient = async (matchMediaImpl) => {
  if (matchMediaImpl) window.matchMedia = matchMediaImpl
  const elRef = ref(null)
  const Host = defineComponent({
    setup() {
      usePointerGradient(elRef)
      return () => h('div', { ref: elRef, class: 'pg-target' })
    },
  })
  active = mountComponent(Host)
  await flush(2)
  return active.find('.pg-target')
}

/** jsdom 无布局：给元素注入矩形真值，否则中心偏移恒为 0，断言恒真 */
const stubRect = (el, rect) => {
  el.getBoundingClientRect = () => rect
}

const move = (el, clientX, clientY) => {
  el.dispatchEvent(new window.MouseEvent('pointermove', { clientX, clientY }))
}

describe('usePointerGradient 指针渐变', () => {
  test('pointer: fine：pointermove 把相对中心的偏移（取整）写入 CSS 变量', async () => {
    const el = await mountGradient(vi.fn(() => ({ matches: true })))
    stubRect(el, { left: 100, top: 50, width: 200, height: 100 })

    move(el, 250, 120)
    expect(el.style.getPropertyValue('--posX')).toBe('50') // 250-100-100
    expect(el.style.getPropertyValue('--posY')).toBe('20') // 120-50-50

    move(el, 99, 49) // 负方向同样要走变量
    expect(el.style.getPropertyValue('--posX')).toBe('-101')
    expect(el.style.getPropertyValue('--posY')).toBe('-51')

    move(el, 251.6, 120.4) // toFixed(0) 取整
    expect(el.style.getPropertyValue('--posX')).toBe('52')
    expect(el.style.getPropertyValue('--posY')).toBe('20')
  })

  test('非精确指针（触屏/默认无 matchMedia）：不绑监听，指针事件不写变量', async () => {
    const el = await mountGradient(null)
    stubRect(el, { left: 0, top: 0, width: 200, height: 100 })
    move(el, 50, 50)
    expect(el.style.getPropertyValue('--posX')).toBe('')
    expect(el.style.getPropertyValue('--posY')).toBe('')
  })

  test('matchMedia 抛错：安全降级为不启用，不冒泡', async () => {
    const el = await mountGradient(
      vi.fn(() => {
        throw new Error('blocked')
      })
    )
    stubRect(el, { left: 0, top: 0, width: 200, height: 100 })
    move(el, 50, 50)
    expect(el.style.getPropertyValue('--posX')).toBe('')
  })

  test('卸载：监听被摘掉，离开后移动鼠标不再写样式', async () => {
    const el = await mountGradient(vi.fn(() => ({ matches: true })))
    stubRect(el, { left: 0, top: 0, width: 200, height: 100 })
    move(el, 150, 50)
    expect(el.style.getPropertyValue('--posX')).toBe('50') // 150-0-100

    const removeSpy = vi.spyOn(el, 'removeEventListener')
    active.handle.unmount()
    active = null
    // behavioral 之外直侦 removeEventListener：onUnmounted 里 bound=null 会让处理器
    // 提前返回（行为等价），但监听不摘意味着节点一直被闭钩着，属真实泄漏
    expect(removeSpy).toHaveBeenCalledWith('pointermove', expect.any(Function))

    move(el, 10, 5) // 若监听未摘，这里会写成 -90
    expect(el.style.getPropertyValue('--posX')).toBe('50') // 未被改写
  })
})
