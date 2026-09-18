/**
 * 布局主框架（src/layout/index.vue）行为测试
 *
 * 组件定位：登录后所有页面的外壳 —— 侧边菜单（权限过滤）、折叠/移动端抽屉、
 * 主题与语言入口、用户菜单与登出、面包屑与 router-view 容器。
 *
 * 每条用例防的真实退化（写在用例名与就近注释里），归纳为七类：
 *  1. 菜单权限过滤：无权限项不得出现；子项全无权限时父级不得留下空壳；
 *     permissions 为 null（会话被清）时必须按「无权限」渲染，而不是抛错或全放行。
 *  2. 折叠/抽屉：桌面折叠只动 store，移动端只开抽屉（两者不得互相串台）；
 *     移动端选菜单后抽屉必须自动收起；打开抽屉后切到桌面宽度不得残留遮罩。
 *  3. 主题/语言：三态图标与「跟随系统」偏好后缀；切换后必须落到 store、DOM
 *     （html.dark / html lang）与持久化存储。
 *  4. 用户信息与登出：用户名/头像兜底不得因 currentUser 为空而抛错；登出必须
 *     服务端吊销成功后才清本地；503（令牌未吊销）必须保持登录态；取消确认不得
 *     产生未处理 Promise 拒绝。
 *  5. 路由联动：高亮取 route.path（query 不干扰）、面包屑文案与兜底、
 *     router-view 以 fullPath 为 key（同路径不同 query 必须重挂载页面组件）。
 *  6. 能力探测：环境无全屏 API 时不渲染全屏入口；刷新按钮真实触发 reload。
 *  7. 权限热同步接线：登录才建连、卸载释放引用、推送到达后菜单即时收敛。
 *
 * 断言口径：图标用真实 @element-plus/icons-vue 渲染出的 svg path 做 oracle，
 * 不硬编码 path 数据；文案用 i18n 实例按期望键取值（键写错即红），跨语言断言
 * 用词表字面量。真实定时器一律用 setTimeout 等待（harness 的 waitFor 只推 nextTick）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createApp, h, onMounted, onUnmounted } from 'vue'
import { Expand, Fold, FullScreen, Monitor, Moon, Refresh, Sunny } from '@element-plus/icons-vue'
import { mountComponent, click, flush, settleRouter } from '../helpers/componentHarness'
import { useAppStore, useAuthStore } from '@/store'
import i18n from '@/i18n'

// ── 依赖替身 ────────────────────────────────────────────────────────────────
// 登出接口与 /auth/me 用可编程替身：本套件要断言的是「什么时候调、失败怎么办」，
// 不是 axios 行为本身。
const logoutApi = vi.fn()
const getMeApi = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      logout: (...args) => logoutApi(...args),
      getMe: (...args) => getMeApi(...args),
    },
  },
  isCanceledError: () => false,
}))

const acquireWs = vi.fn()
const releaseWs = vi.fn()
const disconnectWs = vi.fn()
vi.mock('@/utils/websocket', () => ({
  acquireWebSocket: (...args) => acquireWs(...args),
  releaseWebSocket: (...args) => releaseWs(...args),
  disconnectWebSocket: (...args) => disconnectWs(...args),
}))

vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
const confirmBox = vi.fn()
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...args) => confirmBox(...args) },
}))
vi.mock('element-plus/es/components/notification/index.mjs', () => ({
  ElNotification: vi.fn(),
}))

import AppLayout from '@/layout/index.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

// ── 期望值口径 ──────────────────────────────────────────────────────────────
/** 布局声明的菜单项（含子项）按渲染顺序：直挂项与子菜单子项都渲染成 .el-menu-item */
const MENU_KEYS = [
  'nav.dashboard',
  'nav.devices',
  'nav.alarms',
  'nav.inspections',
  'nav.users',
  'nav.roles',
  'nav.auditLogs',
  'nav.ipList',
  'nav.reports',
  'nav.profile',
  'nav.about',
]
/** 无需权限即可见的公开项（声明中 perm 为空字符串） */
const PUBLIC_KEYS = ['nav.dashboard', 'nav.profile', 'nav.about']

const label = (key) => i18n.global.t(key)

// ── 交互辅助 ────────────────────────────────────────────────────────────────
/** 真实定时器 + nextTick 轮询；超时抛出「在等什么」，不做静默兜底 */
const pollUntil = async (predicate, message) => {
  for (let i = 0; i < 60; i += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 20))
    await flush(2)
  }
  if (predicate()) return
  throw new Error('轮询超时：' + message)
}

const poppers = () => Array.from(document.body.querySelectorAll('.el-popper'))
const visiblePopper = () => poppers().find((el) => el.getAttribute('aria-hidden') === 'false')
const dropdownItemLabels = (popper) =>
  Array.from(popper.querySelectorAll('.el-dropdown-menu__item')).map((el) => el.textContent.trim())
const dropdownItem = (popper, text) => {
  const item = Array.from(popper.querySelectorAll('.el-dropdown-menu__item')).find(
    (el) => el.textContent.trim() === text
  )
  if (!item) {
    throw new Error('下拉项不存在：' + text + '；实际为 ' + dropdownItemLabels(popper).join(' | '))
  }
  return item
}

/** click 触发的下拉（语言/主题）：等浮层真正可见再返回 */
const openByClick = async (trigger, message) => {
  await pollUntil(() => !visiblePopper(), '等待上一个浮层关闭')
  click(trigger)
  await pollUntil(() => !!visiblePopper(), message)
  return visiblePopper()
}
/** hover 触发的下拉（用户菜单）：Element Plus 有 150ms show-after，必须等真实定时器 */
const openByHover = async (trigger, message) => {
  await pollUntil(() => !visiblePopper(), '等待上一个浮层关闭')
  trigger.dispatchEvent(new window.MouseEvent('mouseenter', { bubbles: true }))
  await pollUntil(() => !!visiblePopper(), message)
  return visiblePopper()
}

const iconByTitle = (c, key) =>
  c.findAll('.action-icon').find((el) => el.getAttribute('title') === label(key))

const menuLabels = (c) => c.findAll('.el-menu-item').map((el) => el.textContent.trim())
const submenuTitles = (c) => c.findAll('.el-sub-menu__title').map((el) => el.textContent.trim())
const breadcrumbs = (c) =>
  c.findAll('.el-breadcrumb__item .el-breadcrumb__inner').map((el) => el.textContent.trim())
/** navbar 直挂的独立操作图标（语言/主题是 el-dropdown，不计入） */
const standaloneIcons = (c) => c.findAll('.navbar-right > .el-icon.action-icon')

/** 图标 oracle：用真实图标组件渲染出的 <path d> 比对，避免硬编码 path 数据 */
const iconPathCache = new Map()
const iconPath = (icon) => {
  if (!iconPathCache.has(icon)) {
    const host = document.createElement('div')
    document.body.appendChild(host)
    const app = createApp({ render: () => h(icon) })
    app.mount(host)
    iconPathCache.set(icon, host.querySelector('path').getAttribute('d'))
    app.unmount()
    host.remove()
  }
  return iconPathCache.get(icon)
}
const renderedIconPath = (el) => el.querySelector('svg path').getAttribute('d')

/**
 * 等待路由过渡结束。fade 过渡是 CSS 动画，jsdom 不会自动触发 animationend，
 * 必须手动派发，否则旧组件不会被卸载（实测：只等 nextTick 时旧页面仍在 DOM）。
 */
const settleTransition = async (c, predicate) => {
  for (let i = 0; i < 50; i += 1) {
    if (predicate()) return
    c.findAll('[class*="fade-"]').forEach((el) => {
      el.dispatchEvent(new window.Event('animationend', { bubbles: true }))
      el.dispatchEvent(new window.Event('transitionend', { bubbles: true }))
    })
    await new Promise((resolve) => setTimeout(resolve, 20))
    await flush(2)
  }
  if (predicate()) return
  throw new Error('过渡未结束：' + c.find('.main-content').innerHTML.slice(0, 200))
}

// ── 页面替身与路由表 ────────────────────────────────────────────────────────
let pageSeq = 0
const pageEvents = []
/** 记录 setup/mount/unmount 的页面替身，用于断言「是否真的重挂载」 */
const makePage = (name) => ({
  name: 'Page' + name,
  setup() {
    const id = (pageSeq += 1)
    pageEvents.push('setup:' + name + '#' + id)
    onMounted(() => pageEvents.push('mount:' + name + '#' + id))
    onUnmounted(() => pageEvents.push('unmount:' + name + '#' + id))
    return () => h('div', { class: 'page-' + name, 'data-instance': String(id) })
  },
})

const page = (name, meta) => ({
  path: '/' + name,
  name,
  component: makePage(name),
  ...(meta ? { meta } : {}),
})

const ROUTES = [
  { path: '/', redirect: '/dashboard' },
  page('dashboard', { titleKey: 'nav.dashboard' }),
  page('devices', { titleKey: 'nav.devices' }),
  page('alarms', { titleKey: 'nav.alarms' }),
  page('inspections', { titleKey: 'nav.inspections' }),
  page('users', { titleKey: 'nav.users' }),
  page('roles', { titleKey: 'nav.roles' }),
  page('audit-logs', { titleKey: 'nav.auditLogs' }),
  page('ip-list', { titleKey: 'nav.ipList' }),
  page('reports', { titleKey: 'nav.reports' }),
  page('profile', { titleKey: 'nav.profile' }),
  page('about', { titleKey: 'nav.about' }),
  page('legacy-title', { title: 'Legacy Title' }),
  page('no-meta'),
  { path: '/login', name: 'login', component: makePage('login') },
]

// ── 挂载与清理 ──────────────────────────────────────────────────────────────
let active = null
let currentAuth = null
let currentApp = null

const mountLayout = (options = {}) => {
  const {
    perms = ['*:*'],
    user = { username: 'alice' },
    initialRoute = '/dashboard',
    themeMode,
    collapsed,
    language = 'zh-CN',
  } = options
  active = mountComponent(AppLayout, {
    routes: ROUTES,
    initialRoute,
    setupStore: (pinia) => {
      const auth = useAuthStore(pinia)
      auth.currentUser = user
      auth.permissions = perms
      const app = useAppStore(pinia)
      // 语言显式给定：store 初值取自 sessionStorage/浏览器语言，jsdom 下
      // navigator.language 与 mountComponent 设定的 i18n locale 可能不一致
      app.language = language
      if (themeMode !== undefined) app.themeMode = themeMode
      if (collapsed !== undefined) app.sidebarCollapsed = collapsed
      currentAuth = auth
      currentApp = app
    },
  })
  return active
}

beforeEach(() => {
  vi.clearAllMocks()
  window.localStorage.clear()
  window.sessionStorage.clear()
  window.innerWidth = 1024
  document.documentElement.classList.remove('dark')
  logoutApi.mockImplementation(() => Promise.resolve({ data: { success: true } }))
  getMeApi.mockImplementation(() =>
    Promise.resolve({
      data: {
        success: true,
        data: { user: { id: 'u1', username: 'alice' }, permissions: ['*:*'] },
      },
    })
  )
  confirmBox.mockImplementation(() => Promise.resolve())
  acquireWs.mockImplementation(() => ({ on: vi.fn(), off: vi.fn() }))
  pageEvents.length = 0
})

afterEach(() => {
  if (active) {
    active.handle.unmount()
    active = null
  }
  i18n.global.locale.value = 'zh-CN'
  document.documentElement.classList.remove('dark')
  window.localStorage.clear()
  window.sessionStorage.clear()
  window.innerWidth = 1024
  delete document.documentElement.requestFullscreen
  delete document.documentElement.webkitRequestFullscreen
  delete document.documentElement.mozRequestFullScreen
  delete document.documentElement.msRequestFullscreen
  delete document.exitFullscreen
  delete document.webkitExitFullscreen
  delete document.mozCancelFullScreen
  delete document.msExitFullscreen
  delete document.fullscreenElement
  delete document.webkitFullscreenElement
  delete document.mozFullScreenElement
  delete document.msFullscreenElement
  vi.unstubAllGlobals()
  currentAuth = null
  currentApp = null
})

// ── 用例 ────────────────────────────────────────────────────────────────────
describe('布局 · 菜单渲染与权限过滤', () => {
  test('超级通配 *:*：渲染全部菜单项，顺序与声明一致，系统管理含 4 个子项', async () => {
    const c = mountLayout({ perms: ['*:*'] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(MENU_KEYS.map(label))
    expect(submenuTitles(c)).toEqual([label('nav.system')])
    expect(c.errors).toEqual([])
  })

  test('精确权限 device:read：只出现设备管理；系统管理子项全无权限时父级整体隐藏', async () => {
    const c = mountLayout({ perms: ['device:read'] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(
      ['nav.dashboard', 'nav.devices', 'nav.profile', 'nav.about'].map(label)
    )
    // 若父级过滤被删，这里会残留一个「系统管理」空壳
    expect(submenuTitles(c)).toEqual([])
  })

  test('模块通配 device:* 视同拥有该模块权限；未授权模块不得出现', async () => {
    const c = mountLayout({ perms: ['device:*'] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(
      ['nav.dashboard', 'nav.devices', 'nav.profile', 'nav.about'].map(label)
    )
  })

  test('权限列表为空：只剩无需权限的公开项', async () => {
    const c = mountLayout({ perms: [] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(PUBLIC_KEYS.map(label))
  })

  test('permissions 为 null（会话被清）：按无权限渲染且不抛错', async () => {
    const c = mountLayout({ perms: null })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(PUBLIC_KEYS.map(label))
    expect(c.errors).toEqual([])
  })

  test('系统管理只渲染有权限的子项：不显示未授权入口', async () => {
    const c = mountLayout({ perms: ['user:read', 'security:audit'] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(
      ['nav.dashboard', 'nav.users', 'nav.auditLogs', 'nav.profile', 'nav.about'].map(label)
    )
    expect(submenuTitles(c)).toEqual([label('nav.system')])
  })
})

describe('布局 · 折叠与展开', () => {
  test('桌面点击折叠：写 store、收窄到 64px、logo 文案隐藏、图标切为 Expand、菜单进入折叠态', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    expect(c.find('.sidebar').getAttribute('style')).toContain('width: 220px')
    expect(c.find('.logo-text').style.display).not.toBe('none')
    expect(renderedIconPath(c.find('.collapse-btn'))).toBe(iconPath(Fold))

    click(c.find('.collapse-btn'))
    await pollUntil(() => currentApp.sidebarCollapsed === true, 'store 折叠态')
    await pollUntil(
      () => c.find('.sidebar').getAttribute('style').includes('width: 64px'),
      '侧栏宽度'
    )
    expect(c.find('.logo-text').style.display).toBe('none')
    await pollUntil(
      () => renderedIconPath(c.find('.collapse-btn')) === iconPath(Expand),
      '折叠态图标为 Expand'
    )
    await pollUntil(
      () => c.find('.el-menu').className.includes('el-menu--collapse'),
      '菜单折叠态 class'
    )
  })

  test('store 初始 collapsed=true：挂载即为 64px 折叠态（状态源是 store 而非组件内 ref）', async () => {
    const c = mountLayout({ collapsed: true })
    await settleRouter(c.router)
    await flush(10)
    expect(c.find('.sidebar').getAttribute('style')).toContain('width: 64px')
    expect(c.find('.logo-text').style.display).toBe('none')
    expect(renderedIconPath(c.find('.collapse-btn'))).toBe(iconPath(Expand))
  })

  test('再次点击恢复展开：220px + Fold 图标', async () => {
    const c = mountLayout({ collapsed: true })
    await settleRouter(c.router)
    await flush(10)
    click(c.find('.collapse-btn'))
    await pollUntil(() => currentApp.sidebarCollapsed === false, 'store 恢复展开')
    await pollUntil(
      () => c.find('.sidebar').getAttribute('style').includes('width: 220px'),
      '侧栏宽度'
    )
    expect(renderedIconPath(c.find('.collapse-btn'))).toBe(iconPath(Fold))
  })
})

describe('布局 · 移动端抽屉', () => {
  test('宽度 768（含边界）判定为移动端：抽屉样式 + 强制展开侧栏（清零折叠态）', async () => {
    window.innerWidth = 768
    const c = mountLayout({ collapsed: true })
    await flush(10)
    expect(c.find('.sidebar').className).toContain('sidebar-mobile')
    expect(c.find('.sidebar').getAttribute('style')).toContain('width: 240px')
    expect(c.find('.sidebar').getAttribute('style')).toContain('translateX(-100%)')
    // 若移动端分支被删，折叠态会保留 true，抽屉里的菜单是收起状态
    expect(currentApp.sidebarCollapsed).toBe(false)
  })

  test('宽度 769 判定为桌面端（边界另一侧）', async () => {
    window.innerWidth = 769
    const c = mountLayout()
    await flush(10)
    expect(c.find('.sidebar').className).not.toContain('sidebar-mobile')
    expect(c.find('.sidebar').getAttribute('style')).toContain('width: 220px')
  })

  test('移动端点击折叠按钮：打开抽屉（遮罩 + translateX(0)），不改动 store 折叠态', async () => {
    window.innerWidth = 500
    const c = mountLayout()
    await flush(10)
    expect(c.find('.mobile-overlay')).toBeFalsy()

    click(c.find('.collapse-btn'))
    await pollUntil(() => !!c.find('.mobile-overlay'), '遮罩出现')
    expect(c.find('.app-wrapper').className).toContain('mobile-sidebar-open')
    expect(c.find('.sidebar').getAttribute('style')).toContain('translateX(0)')
    // 移动端开关是抽屉，不应把桌面折叠态写进 store
    expect(currentApp.sidebarCollapsed).toBe(false)
  })

  test('点击遮罩关闭抽屉：遮罩移除、侧栏移出可视区', async () => {
    window.innerWidth = 500
    const c = mountLayout()
    await flush(10)
    click(c.find('.collapse-btn'))
    await pollUntil(() => !!c.find('.mobile-overlay'), '遮罩出现')

    click(c.find('.mobile-overlay'))
    await pollUntil(() => !c.find('.mobile-overlay'), '遮罩消失')
    expect(c.find('.sidebar').getAttribute('style')).toContain('translateX(-100%)')
  })

  test('移动端选择菜单项：抽屉自动收起并完成路由跳转', async () => {
    window.innerWidth = 500
    const c = mountLayout()
    await flush(10)
    click(c.find('.collapse-btn'))
    await pollUntil(() => !!c.find('.mobile-overlay'), '遮罩出现')

    const item = c
      .findAll('.el-menu-item')
      .find((el) => el.textContent.trim() === label('nav.devices'))
    click(item)
    await pollUntil(() => c.router.currentRoute.value.path === '/devices', '菜单跳转')
    expect(c.router.currentRoute.value.path).toBe('/devices')
    await pollUntil(() => !c.find('.mobile-overlay'), '抽屉自动收起')
  })

  test('打开抽屉后切到桌面宽度：遮罩消失、侧栏回到桌面布局（不留全屏遮罩）', async () => {
    window.innerWidth = 500
    const c = mountLayout()
    await flush(10)
    click(c.find('.collapse-btn'))
    await pollUntil(() => !!c.find('.mobile-overlay'), '遮罩出现')

    window.innerWidth = 1024
    window.dispatchEvent(new window.Event('resize'))
    await pollUntil(() => !c.find('.mobile-overlay'), '遮罩消失')
    expect(c.find('.sidebar').className).not.toContain('sidebar-mobile')
    expect(c.find('.sidebar').getAttribute('style')).toContain('width: 220px')
  })

  test('卸载后 resize 监听解除：改窗口宽度不再改动 store', async () => {
    const c = mountLayout({ collapsed: true })
    await flush(10)
    c.handle.unmount()
    active = null
    expect(currentApp.sidebarCollapsed).toBe(true)

    window.innerWidth = 400
    window.dispatchEvent(new window.Event('resize'))
    await flush(10)
    // 监听器若未移除，checkMobile 会把折叠态清零
    expect(currentApp.sidebarCollapsed).toBe(true)
  })
})

describe('布局 · 主题切换', () => {
  test('主题图标随 themeMode 三态切换（system → Monitor / light → Sunny / dark → Moon）', async () => {
    for (const [mode, icon] of [
      ['system', Monitor],
      ['light', Sunny],
      ['dark', Moon],
    ]) {
      const c = mountLayout({ themeMode: mode })
      await settleRouter(c.router)
      await flush(10)
      expect(renderedIconPath(iconByTitle(c, 'common.theme'))).toBe(iconPath(icon))
      c.handle.unmount()
      active = null
    }
  })

  test('「跟随系统」项展示系统当前偏好后缀（systemPrefersDark=true → 暗色模式）', async () => {
    const c = mountLayout({ themeMode: 'system' })
    await settleRouter(c.router)
    await flush(10)
    currentApp.systemPrefersDark = true
    await flush(4)

    const popper = await openByClick(iconByTitle(c, 'common.theme'), '主题下拉')
    expect(dropdownItemLabels(popper)).toEqual([
      label('common.autoMode') + ' · ' + label('common.darkMode'),
      label('common.lightMode'),
      label('common.darkMode'),
    ])
  })

  test('选择暗色模式：store 落地 + html.dark + localStorage 持久化 + 图标跟随', async () => {
    const c = mountLayout({ themeMode: 'light' })
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByClick(iconByTitle(c, 'common.theme'), '主题下拉')

    click(dropdownItem(popper, label('common.darkMode')))
    await pollUntil(() => currentApp.themeMode === 'dark', 'themeMode=dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(window.localStorage.getItem('themeMode')).toBe('dark')
    await pollUntil(
      () => renderedIconPath(iconByTitle(c, 'common.theme')) === iconPath(Moon),
      '图标切为 Moon'
    )
  })

  test('当前主题项带 is-active 标记（用户能看出当前选择）', async () => {
    const c = mountLayout({ themeMode: 'dark' })
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByClick(iconByTitle(c, 'common.theme'), '主题下拉')
    const active = Array.from(popper.querySelectorAll('.el-dropdown-menu__item.is-active')).map(
      (el) => el.textContent.trim()
    )
    expect(active).toEqual([label('common.darkMode')])
  })
})

describe('布局 · 用户信息与登出', () => {
  test('展示用户名与首字母大写头像；currentUser 为空时兜底且不抛错', async () => {
    const c = mountLayout({ user: { username: 'alice' } })
    await flush(10)
    expect(c.find('.user-name').textContent.trim()).toBe('alice')
    expect(c.find('.user-avatar').textContent.trim()).toBe('A')
    c.handle.unmount()
    active = null

    const c2 = mountLayout({ user: null })
    await flush(10)
    expect(c2.find('.user-name').textContent.trim()).toBe(label('common.notLoggedIn'))
    expect(c2.find('.user-avatar').textContent.trim()).toBe('')
    expect(c2.errors).toEqual([])
  })

  test('用户名缺失的回退文案随语言切换：中文显示「未登录」，英文显示「Not signed in」且不含中文', async () => {
    const c = mountLayout({ user: null })
    await flush(10)
    expect(c.find('.user-name').textContent.trim()).toBe('未登录')

    const popper = await openByClick(iconByTitle(c, 'common.language'), '语言下拉')
    click(dropdownItem(popper, 'English'))
    await pollUntil(() => i18n.global.locale.value === 'en-US', 'i18n 切到 en-US')
    await flush(10)
    const english = c.find('.user-name').textContent.trim()
    expect(english).toBe('Not signed in')
    // 硬编码中文会让英文界面出现中英混排；这条断言把「回退文案绕过 i18n」钉死
    expect(/[\u4e00-\u9fa5]/.test(english)).toBe(false)

    const popper2 = await openByClick(iconByTitle(c, 'common.language'), '语言下拉（第二次）')
    click(dropdownItem(popper2, '中文'))
    await pollUntil(() => i18n.global.locale.value === 'zh-CN', 'i18n 切回 zh-CN')
    await flush(10)
    // 反向断言：防「恒英文」的实现（如把回退文案写死为英文常量）
    expect(c.find('.user-name').textContent.trim()).toBe('未登录')
    expect(c.errors).toEqual([])
  })

  test('用户菜单命令：个人资料 / 修改密码 均跳转 /profile', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)

    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')
    expect(dropdownItemLabels(popper)).toEqual([
      label('nav.profile'),
      label('auth.changePassword'),
      label('auth.logout'),
    ])
    click(dropdownItem(popper, label('nav.profile')))
    await pollUntil(() => c.router.currentRoute.value.path === '/profile', '个人资料跳转')
    expect(c.router.currentRoute.value.path).toBe('/profile')

    await c.router.push('/dashboard')
    await flush(20)
    const popper2 = await openByHover(c.find('.user-dropdown'), '用户菜单（第二次）')
    click(dropdownItem(popper2, label('auth.changePassword')))
    await pollUntil(() => c.router.currentRoute.value.path === '/profile', '修改密码命令跳转')
    expect(c.router.currentRoute.value.path).toBe('/profile')
  })

  test('登出确认框：文案与按钮口径正确（warning 类型，确认/取消都本地化）', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')

    click(dropdownItem(popper, label('auth.logout')))
    await pollUntil(() => confirmBox.mock.calls.length === 1, '弹出确认框')
    expect(confirmBox).toHaveBeenCalledWith(label('auth.logoutConfirm'), label('common.confirm'), {
      confirmButtonText: label('common.confirm'),
      cancelButtonText: label('common.cancel'),
      type: 'warning',
    })
  })

  test('登出成功：服务端吊销成功后才清本地，随后断开 ws 并跳登录页、提示成功', async () => {
    let userDuringLogout = 'unset'
    logoutApi.mockImplementationOnce(() => {
      // 服务端登出使 token 进入黑名单，成功后才清本地状态
      userDuringLogout = currentAuth.currentUser
      return Promise.resolve({ data: { success: true } })
    })
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')

    click(dropdownItem(popper, label('auth.logout')))
    await pollUntil(() => c.router.currentRoute.value.path === '/login', '跳转登录页')
    expect(userDuringLogout).toEqual({ username: 'alice' })
    expect(currentAuth.currentUser).toBeNull()
    expect(currentAuth.permissions).toEqual([])
    // 残留连接仍携带旧身份 cookie，会继续接收上一个账号的推送
    expect(disconnectWs).toHaveBeenCalledTimes(1)
    expect(ElMessage.success).toHaveBeenCalledWith(label('auth.logoutSuccess'))
  })

  test('登出遇 503（令牌未吊销）：保持登录态、不跳转、不断开 ws、不提示成功', async () => {
    logoutApi.mockImplementationOnce(() =>
      Promise.reject(Object.assign(new Error('revoke failed'), { response: { status: 503 } }))
    )
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')

    click(dropdownItem(popper, label('auth.logout')))
    await pollUntil(() => logoutApi.mock.calls.length === 1, '调用登出接口')
    await new Promise((resolve) => setTimeout(resolve, 150))
    await flush(20)

    expect(c.router.currentRoute.value.path).toBe('/dashboard')
    expect(currentAuth.currentUser).toEqual({ username: 'alice' })
    expect(disconnectWs).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('登出遇网络失败（非 503）：按设计完成本地登出，避免卡在不可操作的已登录态', async () => {
    logoutApi.mockImplementationOnce(() => Promise.reject(new Error('network down')))
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')

    click(dropdownItem(popper, label('auth.logout')))
    await pollUntil(() => c.router.currentRoute.value.path === '/login', '跳转登录页')
    expect(currentAuth.currentUser).toBeNull()
    expect(disconnectWs).toHaveBeenCalledTimes(1)
  })

  test('取消确认：不发登出请求、不登出、不产生未处理 Promise 拒绝', async () => {
    const unhandled = []
    const onUnhandled = (reason) => unhandled.push(String(reason))
    process.on('unhandledRejection', onUnhandled)
    confirmBox.mockImplementationOnce(() => Promise.reject(new Error('cancel')))
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByHover(c.find('.user-dropdown'), '用户菜单')

    click(dropdownItem(popper, label('auth.logout')))
    await pollUntil(() => confirmBox.mock.calls.length === 1, '弹出确认框')
    await new Promise((resolve) => setTimeout(resolve, 150))
    await flush(20)
    process.off('unhandledRejection', onUnhandled)

    expect(logoutApi).not.toHaveBeenCalled()
    expect(c.router.currentRoute.value.path).toBe('/dashboard')
    expect(currentAuth.currentUser).toEqual({ username: 'alice' })
    expect(unhandled).toEqual([])
  })
})

describe('布局 · 路由联动与面包屑', () => {
  test('高亮跟随 route.path：初始路由与程序化跳转都正确', async () => {
    const c = mountLayout({ initialRoute: '/dashboard' })
    await settleRouter(c.router)
    await flush(10)
    expect(c.findAll('.el-menu-item.is-active').map((el) => el.textContent.trim())).toEqual([
      label('nav.dashboard'),
    ])

    await c.router.push('/devices')
    await pollUntil(
      () =>
        c
          .findAll('.el-menu-item.is-active')
          .map((el) => el.textContent.trim())
          .join() === label('nav.devices'),
      '高亮跟随跳转'
    )
    expect(c.findAll('.el-menu-item.is-active').map((el) => el.textContent.trim())).toEqual([
      label('nav.devices'),
    ])
  })

  test('桌面端选择菜单项：不出现遮罩，也不改动折叠态（抽屉逻辑不得串台）', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const item = c
      .findAll('.el-menu-item')
      .find((el) => el.textContent.trim() === label('nav.alarms'))
    click(item)
    await pollUntil(() => c.router.currentRoute.value.path === '/alarms', '菜单跳转')
    expect(c.find('.mobile-overlay')).toBeFalsy()
    expect(currentApp.sidebarCollapsed).toBe(false)
  })

  test('带 query 的路由高亮不丢（高亮取 path 而非 fullPath）', async () => {
    const c = mountLayout({ initialRoute: '/devices?page=2' })
    await settleRouter(c.router)
    await flush(10)
    expect(c.router.currentRoute.value.fullPath).toBe('/devices?page=2')
    expect(c.findAll('.el-menu-item.is-active').map((el) => el.textContent.trim())).toEqual([
      label('nav.devices'),
    ])
  })

  test('面包屑：首页 + 当前页标题（meta.titleKey 经 i18n 翻译）', async () => {
    const c = mountLayout({ initialRoute: '/devices' })
    await settleRouter(c.router)
    await flush(10)
    expect(breadcrumbs(c)).toEqual([label('nav.home'), label('nav.devices')])
  })

  test('面包屑兜底：无 titleKey 时用 meta.title；两者都缺时为空串', async () => {
    const c = mountLayout({ initialRoute: '/legacy-title' })
    await settleRouter(c.router)
    await flush(10)
    expect(breadcrumbs(c)).toEqual([label('nav.home'), 'Legacy Title'])

    await c.router.push('/no-meta')
    await flush(20)
    expect(breadcrumbs(c)).toEqual([label('nav.home'), ''])
  })

  test('面包屑首页项可点击，跳转 /dashboard', async () => {
    const c = mountLayout({ initialRoute: '/devices' })
    await settleRouter(c.router)
    await flush(10)
    const home = c.findAll('.el-breadcrumb__item')[0]
    click(home.querySelector('.el-breadcrumb__inner') || home)
    await pollUntil(() => c.router.currentRoute.value.path === '/dashboard', '面包屑跳转')
    expect(c.router.currentRoute.value.path).toBe('/dashboard')
  })

  test('router-view 以 fullPath 为 key：仅 query 变化也重挂载页面组件', async () => {
    const c = mountLayout({ initialRoute: '/devices' })
    await settleRouter(c.router)
    await settleTransition(c, () => !!c.find('.page-devices'))
    const firstInstance = c.find('.page-devices').dataset.instance
    pageEvents.length = 0

    await c.router.push('/devices?page=2')
    await settleTransition(
      c,
      () => c.find('.page-devices') && c.find('.page-devices').dataset.instance !== firstInstance
    )
    // 若 key 改为 route.path，同路径不同 query 不会重挂载：
    // 这里既不会出现旧实例的 unmount，也不会出现新实例的 setup/mount
    expect(pageEvents.filter((e) => e.startsWith('unmount:devices'))).toHaveLength(1)
    expect(pageEvents.filter((e) => e.startsWith('setup:devices'))).toHaveLength(1)
    expect(pageEvents.filter((e) => e.startsWith('mount:devices'))).toHaveLength(1)
    // 顺序：旧实例先卸载，新实例再 setup/mount（in-out 过渡不重叠）
    expect(pageEvents.map((e) => e.split(':')[0])).toEqual(['unmount', 'setup', 'mount'])
  })
})

describe('布局 · 语言切换', () => {
  test('切到 English：i18n / store / sessionStorage / html lang / 菜单与面包屑文案全部跟随', async () => {
    const c = mountLayout({ initialRoute: '/devices' })
    await settleRouter(c.router)
    await flush(10)
    // 先切到中文：jsdom 的 navigator.language 是 en-US，若直接从「已是 en-US」
    // 的初始态出发，断言 html lang / sessionStorage 时会与初始值重合而掩盖
    // 「切换链路被拆掉」这类退化。必须先切到非默认语言，再切回英文。
    const first = await openByClick(iconByTitle(c, 'common.language'), '语言下拉')
    expect(dropdownItemLabels(first)).toEqual(['中文', 'English'])
    click(dropdownItem(first, '中文'))
    await pollUntil(() => i18n.global.locale.value === 'zh-CN', 'i18n 切到 zh-CN')
    expect(document.documentElement.getAttribute('lang')).toBe('zh-CN')
    expect(window.sessionStorage.getItem('locale')).toBe('zh-CN')
    expect(menuLabels(c)).toEqual(MENU_KEYS.map(label))

    const popper = await openByClick(iconByTitle(c, 'common.language'), '语言下拉（第二次）')
    click(dropdownItem(popper, 'English'))
    await pollUntil(() => i18n.global.locale.value === 'en-US', 'i18n 切到 en-US')
    expect(currentApp.language).toBe('en-US')
    expect(window.sessionStorage.getItem('locale')).toBe('en-US')
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
    // 用词表字面量断言，避免「用 t() 比 t()」的恒真比较
    expect(menuLabels(c)).toEqual([
      'Dashboard',
      'Devices',
      'Alarms',
      'Inspections',
      'Users',
      'Roles',
      'Audit Logs',
      'IP List',
      'Reports',
      'Profile',
      'About',
    ])
    expect(breadcrumbs(c)).toEqual(['Home', 'Devices'])
  })

  test('语言下拉当前语言带 is-active 标记', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const popper = await openByClick(iconByTitle(c, 'common.language'), '语言下拉')
    const active = Array.from(popper.querySelectorAll('.el-dropdown-menu__item.is-active')).map(
      (el) => el.textContent.trim()
    )
    expect(active).toEqual(['中文'])
  })
})

describe('布局 · 全屏入口与刷新', () => {
  test('环境无全屏 API：不渲染全屏入口，仅保留刷新（提示文案为「刷新」）', async () => {
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    expect(icons).toHaveLength(1)
    expect(renderedIconPath(icons[0])).toBe(iconPath(Refresh))
    const popper = await openByHover(icons[0], '刷新提示')
    expect(popper.textContent.trim()).toBe(label('common.refresh'))
  })

  test('支持全屏 API：渲染入口；点击进入全屏，已在全屏时点击退出', async () => {
    const enterCalls = []
    const exitCalls = []
    document.documentElement.requestFullscreen = () => {
      enterCalls.push('enter')
      return Promise.resolve()
    }
    document.exitFullscreen = () => {
      exitCalls.push('exit')
      return Promise.resolve()
    }
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    expect(icons).toHaveLength(2)
    expect(renderedIconPath(icons[1])).toBe(iconPath(FullScreen))

    click(icons[1])
    expect(enterCalls).toEqual(['enter'])
    expect(exitCalls).toEqual([])

    Object.defineProperty(document, 'fullscreenElement', {
      value: document.body,
      configurable: true,
    })
    click(icons[1])
    expect(exitCalls).toEqual(['exit'])
  })

  test('仅有 webkit 前缀全屏 API 时：入口仍渲染，点击走 webkit 分支', async () => {
    const calls = []
    document.documentElement.webkitRequestFullscreen = () => {
      calls.push('webkit-enter')
      return Promise.resolve()
    }
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    expect(icons).toHaveLength(2)
    click(icons[1])
    expect(calls).toEqual(['webkit-enter'])
    expect(c.errors).toEqual([])
  })

  test('全屏 API 返回被拒 Promise：拒绝被吞掉，不冒泡成未处理拒绝', async () => {
    const unhandled = []
    const onUnhandled = (reason) => unhandled.push(String(reason))
    process.on('unhandledRejection', onUnhandled)
    document.documentElement.requestFullscreen = () =>
      Promise.reject(new Error('fullscreen denied'))
    document.exitFullscreen = () => Promise.reject(new Error('exit denied'))
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    click(icons[1])
    await new Promise((resolve) => setTimeout(resolve, 60))
    Object.defineProperty(document, 'fullscreenElement', {
      value: document.body,
      configurable: true,
    })
    click(icons[1])
    await new Promise((resolve) => setTimeout(resolve, 60))
    process.off('unhandledRejection', onUnhandled)
    expect(unhandled).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('仅有 moz/ms 前缀全屏 API 时：能力探测与调用都走对应前缀分支', async () => {
    const calls = []
    // 老 Firefox / 老 Edge 只提供前缀 API，且不带标准 requestFullscreen
    document.documentElement.mozRequestFullScreen = () => {
      calls.push('moz-enter')
      return Promise.resolve()
    }
    document.mozCancelFullScreen = () => {
      calls.push('moz-exit')
      return Promise.resolve()
    }
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    expect(icons).toHaveLength(2)
    click(icons[1])
    expect(calls).toEqual(['moz-enter'])

    Object.defineProperty(document, 'mozFullScreenElement', {
      value: document.body,
      configurable: true,
    })
    click(icons[1])
    expect(calls).toEqual(['moz-enter', 'moz-exit'])
    expect(c.errors).toEqual([])
  })

  test('仅有 ms 前缀全屏 API 时：能力探测与调用都走 ms 分支', async () => {
    const calls = []
    document.documentElement.msRequestFullscreen = () => {
      calls.push('ms-enter')
      return Promise.resolve()
    }
    document.msExitFullscreen = () => {
      calls.push('ms-exit')
      return Promise.resolve()
    }
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    const icons = standaloneIcons(c)
    expect(icons).toHaveLength(2)
    click(icons[1])
    expect(calls).toEqual(['ms-enter'])

    Object.defineProperty(document, 'msFullscreenElement', {
      value: document.body,
      configurable: true,
    })
    click(icons[1])
    expect(calls).toEqual(['ms-enter', 'ms-exit'])
    expect(c.errors).toEqual([])
  })

  test('刷新按钮触发整页 reload', async () => {
    const reload = vi.fn()
    vi.stubGlobal('location', { ...window.location, reload })
    const c = mountLayout()
    await settleRouter(c.router)
    await flush(10)
    click(standaloneIcons(c)[0])
    expect(reload).toHaveBeenCalledTimes(1)
  })
})

describe('布局 · 权限热同步接线', () => {
  test('已登录挂载：建立连接并订阅 permission-sync；卸载时解除订阅并释放引用', async () => {
    const handlers = new Map()
    acquireWs.mockImplementationOnce(() => ({
      on: vi.fn((evt, fn) => handlers.set(evt, fn)),
      off: vi.fn((evt) => handlers.delete(evt)),
    }))
    const c = mountLayout()
    await flush(10)
    expect(acquireWs).toHaveBeenCalledTimes(1)
    expect(handlers.has('permission-sync')).toBe(true)

    c.handle.unmount()
    active = null
    expect(releaseWs).toHaveBeenCalledTimes(1)
    expect(handlers.has('permission-sync')).toBe(false)
  })

  test('未登录挂载：不建立连接（避免无身份连接白占配额）', async () => {
    mountLayout({ user: null })
    await flush(10)
    expect(acquireWs).not.toHaveBeenCalled()
  })

  test('收到 permission-sync 推送：菜单即时收敛到新权限集', async () => {
    const handlers = new Map()
    acquireWs.mockImplementationOnce(() => ({
      on: vi.fn((evt, fn) => handlers.set(evt, fn)),
      off: vi.fn(),
    }))
    const c = mountLayout({ perms: ['*:*'] })
    await settleRouter(c.router)
    await flush(10)
    expect(menuLabels(c)).toEqual(MENU_KEYS.map(label))

    // 服务端在推送后由 /auth/me 给出同一份权威权限集（两段式：乐观替换 + 权威核对）
    getMeApi.mockImplementationOnce(() =>
      Promise.resolve({
        data: {
          success: true,
          data: { user: { id: 'u1', username: 'alice' }, permissions: ['report:read'] },
        },
      })
    )
    handlers.get('permission-sync')({ permissionCodes: ['report:read'] })
    await pollUntil(
      () =>
        menuLabels(c).join() ===
        ['nav.dashboard', 'nav.reports', 'nav.profile', 'nav.about'].map(label).join(),
      '菜单收敛到新权限'
    )
    expect(menuLabels(c)).toEqual(
      ['nav.dashboard', 'nav.reports', 'nav.profile', 'nav.about'].map(label)
    )
    expect(c.errors).toEqual([])
  })
})
