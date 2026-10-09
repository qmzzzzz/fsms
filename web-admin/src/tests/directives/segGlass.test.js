/**
 * vSegGlass 指令行为测试
 *
 * 该指令是「液态玻璃分段控件」的视觉层：在 el-radio-group 内追加一个绝对定位
 * 滑块，靠测量当前 .is-active 段的 offset* 做平移。它此前零测试，而它的四类
 * 退化都只静默出错、不会抛异常：
 *  1. 不追加滑块 / 不记录上下文 -> 视觉上「没有滑块」，用户看不出坏了；
 *  2. 首帧不定位 -> 滑块停在左上角，遮住第一个分段；
 *  3. 无 is-active 时不隐藏 -> 滑块以 0 尺寸/错位残留在界面上；
 *  4. is-active 迁移后不重定位 -> 滑块永远停在旧位置（EP 是改 class 而非重建节点，
 *     所以只有 MutationObserver 这条路径能发现）。
 *
 * 测试策略：直接驱动指令对象（mounted/unmounted），不挂载组件——指令与组件无关，
 * 直接测 DOM 更贴近其真实契约。rAF 用受控替身收集回调手动执行，避免依赖 jsdom
 * 的帧调度（真 rAF 在 CI 高负载下会让「首帧定位」断言时序不确定）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
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
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

/** 手动执行本帧收集到的 rAF 回调 */
const runRaf = () => {
  const callbacks = rafQueue
  rafQueue = []
  callbacks.forEach((cb) => cb(0))
}

/**
 * 造一个 el-radio-group 形态的容器：三个 .el-radio-button，其中一个带 is-active。
 * offset* 在 jsdom 下恒为 0 且只读，故逐元素 defineProperty 出可断言的量。
 */
const makeGroup = (activeIndex = 0) => {
  const group = document.createElement('div')
  const segs = [0, 1, 2].map((i) => {
    const btn = document.createElement('label')
    btn.className = 'el-radio-button' + (i === activeIndex ? ' is-active' : '')
    Object.defineProperty(btn, 'offsetWidth', { value: 80 + i, configurable: true })
    Object.defineProperty(btn, 'offsetHeight', { value: 32, configurable: true })
    Object.defineProperty(btn, 'offsetLeft', { value: i * 84, configurable: true })
    Object.defineProperty(btn, 'offsetTop', { value: 0, configurable: true })
    btn.textContent = `seg${i}`
    group.appendChild(btn)
    return btn
  })
  document.body.appendChild(group)
  return { group, segs }
}

const thumbOf = (group) => group.querySelector('.seg-glass__thumb')

describe('vSegGlass 挂载与首帧定位', () => {
  test('挂载：追加 aria-hidden 的滑块并记录上下文；live 类只在首帧后出现', () => {
    const { group } = makeGroup()
    vSegGlass.mounted(group)

    const thumb = thumbOf(group)
    expect(thumb).toBeTruthy()
    expect(thumb.getAttribute('aria-hidden')).toBe('true')
    expect(group.__segGlass).toBeTruthy()
    expect(group.__segGlass.thumb).toBe(thumb)

    // 首帧定位前不得开启动画类，否则挂载时会从左侧滑入（设计说明第 2 条）
    expect(group.classList.contains('seg-glass--live')).toBe(false)
    runRaf()
    expect(group.classList.contains('seg-glass--live')).toBe(true)

    vSegGlass.unmounted(group)
  })

  test('首帧定位：滑块尺寸/位移取自 is-active 段的 offset*', () => {
    const { group } = makeGroup(1)
    vSegGlass.mounted(group)
    runRaf()

    const thumb = thumbOf(group)
    expect(thumb.style.opacity).toBe('1')
    expect(thumb.style.width).toBe('81px') // 80 + 1
    expect(thumb.style.height).toBe('32px')
    expect(thumb.style.transform).toBe('translate(84px, 0px)') // 1 * 84

    vSegGlass.unmounted(group)
  })

  test('无 is-active 段：滑块隐藏（opacity 0），不做 0 尺寸残留定位', () => {
    const { group, segs } = makeGroup(0)
    segs[0].classList.remove('is-active')

    vSegGlass.mounted(group)
    runRaf()

    expect(thumbOf(group).style.opacity).toBe('0')

    vSegGlass.unmounted(group)
  })
})

describe('vSegGlass is-active 迁移', () => {
  test('EP 改 class 触发的迁移被 MutationObserver 捕获并重定位', async () => {
    const { group, segs } = makeGroup(0)
    vSegGlass.mounted(group)
    runRaf()
    expect(thumbOf(group).style.transform).toBe('translate(0px, 0px)')

    // 模拟 EP：把 is-active 从第 0 段挪到第 2 段（只改 class，不重建节点）
    segs[0].classList.remove('is-active')
    segs[2].classList.add('is-active')
    // MutationObserver 回调走微任务；让出一轮宏任务确保已投递
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(thumbOf(group).style.transform).toBe('translate(168px, 0px)') // 2 * 84
    expect(thumbOf(group).style.width).toBe('82px')

    vSegGlass.unmounted(group)
  })
})

describe('vSegGlass ResizeObserver 守卫', () => {
  test('存在 ResizeObserver 时挂载到容器、卸载时断开', () => {
    const observe = vi.fn()
    const disconnect = vi.fn()
    class FakeResizeObserver {
      observe(...args) {
        observe(...args)
      }
      disconnect() {
        disconnect()
      }
    }
    vi.stubGlobal('ResizeObserver', FakeResizeObserver)

    const { group } = makeGroup()
    vSegGlass.mounted(group)
    expect(observe).toHaveBeenCalledWith(group)

    runRaf()
    vSegGlass.unmounted(group)
    expect(disconnect).toHaveBeenCalled()
  })

  test('缺失 ResizeObserver（jsdom 默认）时不抛错，其余能力照常', () => {
    vi.stubGlobal('ResizeObserver', undefined)
    const { group } = makeGroup()
    expect(() => vSegGlass.mounted(group)).not.toThrow()
    runRaf()
    expect(group.__segGlass.ro).toBeNull()
    expect(thumbOf(group).style.opacity).toBe('1')
    vSegGlass.unmounted(group)
  })
})

describe('vSegGlass 卸载', () => {
  test('卸载：滑块移除、上下文清空、观察者断开，且重复卸载幂等', () => {
    const { group } = makeGroup()
    vSegGlass.mounted(group)
    runRaf()
    const ctx = group.__segGlass
    const moDisconnect = vi.spyOn(ctx.mo, 'disconnect')

    vSegGlass.unmounted(group)

    expect(thumbOf(group)).toBeNull()
    expect(group.__segGlass).toBeUndefined()
    expect(moDisconnect).toHaveBeenCalled()
    // 重复卸载不得抛（指令在无上下文时必须直接返回）
    expect(() => vSegGlass.unmounted(group)).not.toThrow()
  })
})
