/**
 * UpdateNoticeBar 行为测试（G8）
 *
 * 三条可观测行为，各对应一个真实退化：
 *  1. updateAvailable 置位 → 提示条渲染；点 ×（dismiss）→ 消失。
 *     退化形态：标记了新版本但界面无任何提示，用户不知道刷新才能切到新版。
 *  2. 内存语义（核心）：dismiss 只对**本次置位**有效——重新 mount（模拟刷新
 *     后的新一轮置位）必须重新出现。若把 dismissed 落进 localStorage，
 *     用户点过一次「稍后」之后下一版的提示会被永久吞掉。
 *  3. 点「立即刷新」调用 applyUpdate（SW 激活 + reload 的统一入口）。
 *
 * mock 边界：@/utils/updateNotice 整体替换——updateAvailable 用 { value } 形态
 * （组件 computed 读 .value；重挂载即重新求值，满足「刷新后重新出现」断言），
 * resetUpdateNotice 同步清态防用例串味。源码零改动。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'

const m = vi.hoisted(() => ({
  updateAvailable: { value: false },
  updateReason: { value: '' },
  applyUpdate: vi.fn(),
}))

vi.mock('@/utils/updateNotice', () => ({
  updateAvailable: m.updateAvailable,
  updateReason: m.updateReason,
  applyUpdate: (...a) => m.applyUpdate(...a),
  resetUpdateNotice: () => {
    m.updateAvailable.value = false
    m.updateReason.value = ''
  },
}))

import UpdateNoticeBar from '@/components/UpdateNoticeBar.vue'

let active = null

const mountBar = async () => {
  active = mountComponent(UpdateNoticeBar)
  await flush(4)
  return active
}

const bar = () => active.find('.update-bar')

afterEach(() => {
  active?.unmount()
  active = null
  m.updateAvailable.value = false
  m.updateReason.value = ''
  m.applyUpdate.mockClear()
})

describe('UpdateNoticeBar 提示条渲染与消失', () => {
  test('updateAvailable=true：提示条出现，文案含刷新/稍后入口', async () => {
    m.updateAvailable.value = true
    await mountBar()
    expect(bar()).toBeTruthy()
    expect(bar().textContent).toContain('系统已更新到新版本，刷新后生效')
    expect(bar().textContent).toContain('立即刷新')
    // 无障碍语义：role=status + aria-live
    expect(bar().getAttribute('role')).toBe('status')
  })

  test('updateAvailable=false（默认态）：不渲染', async () => {
    await mountBar()
    expect(bar()).toBe(null)
  })

  test('dismiss 后消失，且只是组件内状态（不落任何存储）', async () => {
    m.updateAvailable.value = true
    await mountBar()
    const dismiss = Array.from(bar().querySelectorAll('button')).find((b) =>
      (b.getAttribute('title') || '').includes('稍后再说')
    )
    expect(dismiss).toBeTruthy()
    click(dismiss)
    await flush(4)
    expect(bar()).toBe(null)
  })
})

describe('UpdateNoticeBar 内存语义（G8 核心）', () => {
  test('dismiss 后重新置位并重挂（模拟刷新后新版本）：提示条必须重新出现', async () => {
    // 第一轮：置位 → 出现 → 用户点「稍后再说」→ 消失
    m.updateAvailable.value = true
    await mountBar()
    expect(bar()).toBeTruthy()
    const dismiss = Array.from(bar().querySelectorAll('button')).find((b) =>
      (b.getAttribute('title') || '').includes('稍后再说')
    )
    click(dismiss)
    await flush(4)
    expect(bar()).toBe(null)
    active.unmount()
    active = null

    // 第二轮：模拟「页面刷新后又发现新版本」——同样的置位重新挂载
    m.updateAvailable.value = true
    await mountBar()
    expect(bar()).toBeTruthy()
    expect(bar().textContent).toContain('系统已更新到新版本，刷新后生效')
  })
})

describe('UpdateNoticeBar 立即刷新', () => {
  test('点「立即刷新」调用 applyUpdate（SW 激活 + reload 统一入口）', async () => {
    m.updateAvailable.value = true
    await mountBar()
    const refresh = Array.from(bar().querySelectorAll('button')).find((b) =>
      b.textContent.includes('立即刷新')
    )
    expect(refresh).toBeTruthy()
    click(refresh)
    await flush(4)
    expect(m.applyUpdate).toHaveBeenCalledTimes(1)
  })
})
