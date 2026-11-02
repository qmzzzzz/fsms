/**
 * 安全分析工作台组件测试
 *
 * 钉住四件事：三个工具共用一个读权限面、tab 按需挂载、访问过的 tab 切走不丢现场、
 * 切 tab 不把上一个工具的深链判据带过去（画像会监听 ?ip= 自动开查）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, click, waitFor } from '../helpers/componentHarness'
import i18n from '@/i18n'

vi.mock('@/views/AttackProfileView.vue', async () => {
  const { h } = await import('vue')
  return {
    // defineAsyncComponent 以 __esModule / Symbol.toStringTag 判定模块命名空间；
    // vitest 的 mock proxy 对这两个键返回 undefined，不显式声明会把命名空间当组件渲染
    __esModule: true,
    default: {
      name: 'AttackProfileStub',
      setup: () => () => h('div', { 'data-test': 'pane-attack' }, 'attack'),
    },
  }
})
vi.mock('@/views/StuffingProfileView.vue', async () => {
  const { h } = await import('vue')
  return {
    __esModule: true,
    default: {
      name: 'StuffingProfileStub',
      setup: () => () => h('div', { 'data-test': 'pane-stuffing' }, 'stuffing'),
    },
  }
})
vi.mock('@/views/ForensicTraceView.vue', async () => {
  const { h } = await import('vue')
  return {
    __esModule: true,
    default: {
      name: 'ForensicTraceStub',
      setup: () => () => h('div', { 'data-test': 'pane-forensic' }, 'forensic'),
    },
  }
})

import SecurityAnalysisView from '@/views/SecurityAnalysisView.vue'

let active = null

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  active?.handle.unmount()
  active = null
})

const mountWorkbench = (initialRoute = '/security-analysis') => {
  active = mountComponent(SecurityAnalysisView, { initialRoute })
  return active
}

const tabByText = (c, key) =>
  c.findAll('.el-tabs__item').find((el) => el.textContent.trim() === i18n.global.t(key))

describe('SecurityAnalysisView · tab 切换', () => {
  test('默认只挂载 IP 画像；三个 tab 的标题来自全局词表', async () => {
    const c = mountWorkbench()
    await waitFor(() => !!c.find('[data-test="pane-attack"]'), { message: '默认 tab 挂载' })
    expect(c.find('[data-test="pane-stuffing"]')).toBeNull()
    expect(c.find('[data-test="pane-forensic"]')).toBeNull()
    expect(c.findAll('.el-tabs__item').map((el) => el.textContent.trim())).toEqual([
      i18n.global.t('nav.attackProfile'),
      i18n.global.t('nav.stuffingProfile'),
      i18n.global.t('nav.forensic'),
    ])
  })

  test('切到撞库再切回：两次访问的 tab 都保活，未访问的仍不加载', async () => {
    const c = mountWorkbench()
    await waitFor(() => !!c.find('[data-test="pane-attack"]'), { message: '默认 tab 挂载' })
    const attackPane = c.find('[data-test="pane-attack"]')

    click(tabByText(c, 'nav.stuffingProfile'))
    await waitFor(() => c.router.currentRoute.value.query.tab === 'stuffing', {
      message: '撞库 tab 写入 URL',
    })
    await waitFor(() => !!c.find('[data-test="pane-stuffing"]'), { message: '撞库 tab 挂载' })
    expect(c.find('[data-test="pane-forensic"]')).toBeNull()

    click(tabByText(c, 'nav.attackProfile'))
    await waitFor(() => c.router.currentRoute.value.query.tab === 'attack', {
      message: '切回画像 tab',
    })
    // 保活的是同一个实例（不是重新挂载出一个新的）
    expect(c.find('[data-test="pane-attack"]')).toBe(attackPane)
    expect(c.find('[data-test="pane-attack"]').style.display).not.toBe('none')
    expect(c.find('[data-test="pane-stuffing"]').style.display).toBe('none')
  })

  test('切 tab 时丢弃上一个工具的深链判据，避免下一工具自动开查', async () => {
    const c = mountWorkbench('/security-analysis?tab=forensic&ip=203.0.113.10&limit=50')
    await waitFor(() => !!c.find('[data-test="pane-forensic"]'), { message: '取证 tab 挂载' })

    click(tabByText(c, 'nav.stuffingProfile'))
    await waitFor(() => c.router.currentRoute.value.query.tab === 'stuffing', {
      message: '撞库 tab 写入 URL',
    })
    expect(c.router.currentRoute.value.query).toEqual({ tab: 'stuffing' })
  })

  test('URL 里的非法 tab 回落到 IP 画像（不白屏、不加载别的工具）', async () => {
    const c = mountWorkbench('/security-analysis?tab=bogus')
    await waitFor(() => !!c.find('[data-test="pane-attack"]'), { message: '回落默认 tab' })
    expect(c.find('[data-test="pane-stuffing"]')).toBeNull()
    expect(c.find('[data-test="pane-forensic"]')).toBeNull()
  })

  test('路由驱动的 tab 变化（深链/前进后退）也切换面板', async () => {
    const c = mountWorkbench('/security-analysis?tab=attack')
    await waitFor(() => !!c.find('[data-test="pane-attack"]'), { message: '画像 tab 挂载' })

    await c.router.push('/security-analysis?tab=forensic')
    await waitFor(() => !!c.find('[data-test="pane-forensic"]'), { message: '取证 tab 挂载' })
    expect(c.find('[data-test="pane-forensic"]').style.display).not.toBe('none')
    expect(c.find('[data-test="pane-attack"]').style.display).toBe('none')
    // route 驱动的切换不回写 URL：深链里的 tab 不能被表单 watcher 改掉
    expect(c.router.currentRoute.value.query).toEqual({ tab: 'forensic' })
  })
})
