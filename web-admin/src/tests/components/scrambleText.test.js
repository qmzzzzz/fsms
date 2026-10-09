/**
 * ScrambleText 行为测试（悬停扰码动画）
 *
 * 组件契约：
 *  1. 初始为完成态直接显示原文；mouseenter 启表逐帧扰码，字符按 resolveStep 递增解析；
 *  2. 迭代达到文本长度后自动停表回原文（不无限空转）；
 *  3. mouseleave / text 变化立即停表回原文；
 *  4. prefers-reduced-motion: reduce 时不启动扰码（可访问性降级）；
 *  5. 悬停途中卸载必须清定时器（第 34 轮 L10 修复点）：路由离开不会补发 mouseleave，
 *     不清表的话 interval 会靠 props.speed 累计继续空转直到迭代自然结束。
 *
 * 环境事实（实测）：
 *  - 定时器行为一律用假定时器推进；advanceTimersByTimeAsync 与 harness 的
 *    flush/waitFor 兼容（后者在假定时器下走 advanceTimersByTimeAsync(0)）。
 *  - 扰动字符用 Math.random 钉死（0.9 → CHARS[39] = '$'），断言才是确定值。
 *  - jsdom 无 window.matchMedia，组件用可选调用兜底；reduce 分支用替身注入验证。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { mountComponent, flush } from '../helpers/componentHarness'
import ScrambleText from '@/components/ScrambleText.vue'

let active = null

const mountText = (props) => {
  active = mountComponent(ScrambleText, { props })
  return active
}

const span = (c) => c.find('.scramble-text')
const hover = (c) => span(c).dispatchEvent(new window.MouseEvent('mouseenter'))
const unhover = (c) => span(c).dispatchEvent(new window.MouseEvent('mouseleave'))

afterEach(() => {
  active?.handle.unmount()
  active = null
})

describe('ScrambleText 悬停扰码', () => {
  test('悬停：逐帧扰码、字符递增解析，迭代达标自动停表回原文', async () => {
    vi.useFakeTimers()
    try {
      vi.spyOn(Math, 'random').mockReturnValue(0.9) // CHARS[39] = '$'
      const setSpy = vi.spyOn(globalThis, 'setInterval')
      const clearSpy = vi.spyOn(globalThis, 'clearInterval')
      const c = mountText({ text: 'abc', speed: 30, resolveStep: 1 / 3 })
      await flush(2)
      expect(c.text()).toBe('abc') // 初始完成态
      setSpy.mockClear()
      clearSpy.mockClear()

      hover(c)
      await flush(2)
      expect(setSpy).toHaveBeenCalledTimes(1)
      expect(c.text()).toBe('$$$') // iteration=0：全扰码

      await vi.advanceTimersByTimeAsync(90) // 3 帧 → iteration=1
      await flush(2)
      expect(c.text()).toBe('a$$') // 仅首字符解析

      await vi.advanceTimersByTimeAsync(30) // 4 帧 → iteration=4/3
      await flush(2)
      expect(c.text()).toBe('ab$')

      await vi.advanceTimersByTimeAsync(150) // 9 帧 → iteration=3 ≥ 长度
      await flush(2)
      expect(c.text()).toBe('abc')

      clearSpy.mockClear()
      await vi.advanceTimersByTimeAsync(60) // 第 10 帧命中达标分支 → 停表
      await flush(2)
      expect(c.text()).toBe('abc')
      expect(clearSpy).toHaveBeenCalledTimes(1)
    } finally {
      vi.restoreAllMocks()
      vi.useRealTimers()
    }
  })

  test('悬停途中卸载：onUnmounted 清掉定时器，卸载后推进时间不再有回调（L10）', async () => {
    vi.useFakeTimers()
    try {
      vi.spyOn(Math, 'random').mockReturnValue(0.9)
      const setSpy = vi.spyOn(globalThis, 'setInterval')
      const clearSpy = vi.spyOn(globalThis, 'clearInterval')
      const c = mountText({ text: 'abcdef', speed: 30 })
      await flush(2)
      setSpy.mockClear()
      clearSpy.mockClear()

      hover(c)
      await flush(2)
      expect(setSpy).toHaveBeenCalledTimes(1)
      const timerId = setSpy.mock.results[0].value
      await vi.advanceTimersByTimeAsync(60) // 扰码进行中，迭代远未到长度
      await flush(2)
      expect(c.text()).not.toBe('abcdef')

      // 悬停途中路由离开：不补发 mouseleave，stopScramble 不会执行
      c.handle.unmount()
      active = null
      expect(clearSpy).toHaveBeenCalledWith(timerId)

      // 定时器若未清，回调会继续跑并在迭代达标时再调一次 clear——
      // 推进远超自然结束所需时间，出现任何 clear 即说明卸载没收尸
      clearSpy.mockClear()
      await vi.advanceTimersByTimeAsync(5000)
      expect(clearSpy).not.toHaveBeenCalled()
    } finally {
      vi.restoreAllMocks()
      vi.useRealTimers()
    }
  })

  test('mouseleave：中途退出立即回原文并停表', async () => {
    vi.useFakeTimers()
    try {
      vi.spyOn(Math, 'random').mockReturnValue(0.9)
      const clearSpy = vi.spyOn(globalThis, 'clearInterval')
      const c = mountText({ text: 'abcdef', speed: 30 })
      await flush(2)
      clearSpy.mockClear()

      hover(c)
      await vi.advanceTimersByTimeAsync(30) // 1 帧 → iteration=1/3
      await flush(2)
      expect(c.text()).toBe('a$$$$$')

      unhover(c)
      await flush(2)
      expect(c.text()).toBe('abcdef')
      expect(clearSpy).toHaveBeenCalledTimes(1)

      clearSpy.mockClear()
      await vi.advanceTimersByTimeAsync(1000) // 已停表：不该再有任何回调
      expect(clearSpy).not.toHaveBeenCalled()
      expect(c.text()).toBe('abcdef')
    } finally {
      vi.restoreAllMocks()
      vi.useRealTimers()
    }
  })

  test('text 变化：watch 停掉进行中的扰码并显示新文本', async () => {
    vi.useFakeTimers()
    try {
      vi.spyOn(Math, 'random').mockReturnValue(0.9)
      const text = ref('abc')
      const Host = defineComponent({
        setup() {
          return () => h(ScrambleText, { text: text.value, speed: 30 })
        },
      })
      active = mountComponent(Host)
      await flush(2)

      hover(active)
      await vi.advanceTimersByTimeAsync(30)
      await flush(2)
      expect(active.text()).toBe('a$$')

      text.value = 'xy'
      await flush(2)
      expect(active.text()).toBe('xy')

      // 旧定时器已随 watch 停掉：推进时间不会把新文本也扰码
      await vi.advanceTimersByTimeAsync(300)
      await flush(2)
      expect(active.text()).toBe('xy')
    } finally {
      vi.restoreAllMocks()
      vi.useRealTimers()
    }
  })

  test('prefers-reduced-motion：悬停不建定时器，直接显示原文', async () => {
    vi.useFakeTimers()
    try {
      const setSpy = vi.spyOn(globalThis, 'setInterval')
      const mm = vi.fn(() => ({ matches: true }))
      window.matchMedia = mm
      const c = mountText({ text: 'abc', speed: 30 })
      await flush(2)
      setSpy.mockClear()

      hover(c)
      await flush(2)
      expect(mm).toHaveBeenCalledWith('(prefers-reduced-motion: reduce)')
      expect(setSpy).not.toHaveBeenCalled()
      expect(c.text()).toBe('abc')
    } finally {
      delete window.matchMedia
      vi.restoreAllMocks()
      vi.useRealTimers()
    }
  })
})
