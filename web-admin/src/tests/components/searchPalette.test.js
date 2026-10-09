/**
 * SearchPalette 行为测试（⌘K 全局搜索面板）
 *
 * 组件契约：
 *  1. 全局热键开合：Ctrl+K（或 ⌘K）打开/关闭；打开时重置查询与高亮位、
 *     锁 body 滚动、聚焦输入框；
 *  2. 检索范围：当前语言标题 + 另一语言标题 + 路由路径（中文界面搜 "users" 也命中），
 *     命中片段用 <mark> 高亮（模板插值渲染，无 v-html）；无结果显示空态；
 *  3. 键盘导航：↑↓ 在扁平列表上循环移动，is-active 与 aria-activedescendant 同步；
 *  4. 执行：回车跑当前项、点击跑所点项——视图走 router.push，动作走 run()
 *     （切主题/切语言等），执行后关闭并给一次 haptic；
 *  5. 关闭：ESC 或点遮罩空白处；点面板内部不关闭；
 *  6. 卸载：摘掉全局热键监听，打开状态下还原 body 滚动锁。
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { mountComponent, flush, click } from '../helpers/componentHarness'
import { useAppStore } from '@/store'
import SearchPalette from '@/components/SearchPalette.vue'
import { User, Setting, Odometer } from '@element-plus/icons-vue'

let active = null
let store = null

/** jsdom 未实现 scrollIntoView（键盘导航会调到），缺失时补一个可调用替身 */
let addedScrollIntoView = false
beforeEach(() => {
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = vi.fn()
    addedScrollIntoView = true
  }
})

afterEach(() => {
  active?.handle.unmount()
  active = null
  store = null
  if (addedScrollIntoView) {
    delete Element.prototype.scrollIntoView
    addedScrollIntoView = false
  }
})

const pollUntil = async (predicate, message) => {
  for (let i = 0; i < 60; i += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 20))
    await flush(2)
  }
  if (predicate()) return
  throw new Error('轮询超时：' + message)
}

const palette = () => document.body.querySelector('.search-palette')
const input = () => document.body.querySelector('.search-palette__input')
const items = () => Array.from(document.body.querySelectorAll('.search-palette__item'))
const itemTitles = () =>
  Array.from(document.body.querySelectorAll('.search-palette__item-title')).map((el) =>
    el.textContent.trim()
  )

/** 同时带 ctrl/meta：isMac 分支在两种判定下都成立，测试不依赖运行平台 */
const hotkey = () =>
  window.dispatchEvent(
    new window.KeyboardEvent('keydown', {
      key: 'k',
      ctrlKey: true,
      metaKey: true,
      cancelable: true,
    })
  )
const keyOnInput = (key) =>
  input().dispatchEvent(
    new window.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })
  )
const typeInto = async (text) => {
  input().value = text
  input().dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(4)
}

const MENU = [
  {
    i18nKey: 'nav.system',
    path: '/system',
    icon: Setting,
    children: [
      { i18nKey: 'nav.users', path: '/system/users', icon: User },
      { i18nKey: 'nav.roles', path: '/system/roles', icon: Setting },
    ],
  },
  { i18nKey: 'nav.dashboard', path: '/dashboard', icon: Odometer },
]

const mountPalette = async () => {
  active = mountComponent(SearchPalette, {
    props: { menu: MENU },
    setupStore: (pinia) => {
      store = useAppStore(pinia)
      store.setThemeMode('system')
      store.setLanguage('zh-CN')
    },
  })
  await flush(4)
  return active
}

describe('SearchPalette 全局搜索面板', () => {
  test('热键开合：打开时重置状态、锁滚动、聚焦输入；再次按下关闭并解锁', async () => {
    const c = await mountPalette()
    expect(palette()).toBeNull()

    hotkey()
    await pollUntil(() => !!palette(), '面板打开')
    expect(document.body.style.overflow).toBe('hidden')
    await pollUntil(() => document.activeElement === input(), '输入框聚焦')
    expect(items()).toHaveLength(8) // 3 视图 + 主题三态/语言/刷新 5 个动作

    hotkey()
    await pollUntil(() => !palette(), '面板关闭')
    expect(document.body.style.overflow).toBe('')
    expect(c.errors).toEqual([])
  })

  test('检索：中文标题、跨语言标题与路由路径都命中，命中片段高亮，无结果出空态', async () => {
    await mountPalette()
    hotkey()
    await pollUntil(() => !!palette(), '面板打开')

    await typeInto('用户') // 当前语言标题
    expect(itemTitles()).toEqual(['用户管理'])
    expect(document.body.querySelector('.search-palette__mark').textContent).toBe('用户')

    await typeInto('users') // 路由路径（中文界面输英文）
    expect(itemTitles()).toEqual(['用户管理'])

    // 只可能经「另一语言标题」命中：动作的中文标题是「主题 · 暗色模式」，
    // 无 path，英文别名 Theme · Dark Mode 是唯一命中源——少了 altTitle 这条断言就红
    await typeInto('dark mode')
    expect(itemTitles()).toEqual(['主题 · 暗色模式'])

    await typeInto('') // 清空恢复全量
    expect(items()).toHaveLength(8)

    await typeInto('zzzz不存在')
    expect(items()).toHaveLength(0)
    expect(document.body.querySelector('.search-palette__empty')).toBeTruthy()
  })

  test('键盘导航：↑↓ 循环移动，is-active 与 aria-activedescendant 同步', async () => {
    await mountPalette()
    hotkey()
    await pollUntil(() => !!palette(), '面板打开')
    await flush(2)

    expect(items()[0].className).toContain('is-active')
    expect(input().getAttribute('aria-activedescendant')).toBe('sp-item-0')

    keyOnInput('ArrowDown')
    await flush(2)
    expect(items()[1].className).toContain('is-active')
    expect(input().getAttribute('aria-activedescendant')).toBe('sp-item-1')

    keyOnInput('ArrowUp') // 回到 0
    keyOnInput('ArrowUp') // 向上越界 → 末项（循环）
    await flush(2)
    expect(items()[7].className).toContain('is-active')
    expect(input().getAttribute('aria-activedescendant')).toBe('sp-item-7')

    for (let i = 0; i < 8; i += 1) keyOnInput('ArrowDown') // 走满一圈回到原项（循环）
    await flush(2)
    expect(items()[7].className).toContain('is-active')
    keyOnInput('ArrowDown') // 再进一步才回到首项
    await flush(2)
    expect(items()[0].className).toContain('is-active')
  })

  test('回车执行当前项：视图走 router.push，动作走 run()，执行后关闭', async () => {
    const c = await mountPalette()
    hotkey()
    await pollUntil(() => !!palette(), '面板打开')

    await typeInto('用户')
    keyOnInput('Enter')
    await pollUntil(() => c.router.currentRoute.value.path === '/system/users', '视图跳转')
    await pollUntil(() => !palette(), '执行后关闭')

    hotkey()
    await pollUntil(() => !!palette(), '面板再次打开')
    await typeInto('暗色') // 动作：主题 · 暗色模式
    keyOnInput('Enter')
    await pollUntil(() => store.themeMode === 'dark', '主题切到暗色')
    await pollUntil(() => !palette(), '动作执行后关闭')
  })

  test('点击条目执行；点面板内部不关闭；ESC 与点遮罩关闭', async () => {
    const c = await mountPalette()
    hotkey()
    await pollUntil(() => !!palette(), '面板打开')

    click(items()[1]) // 角色权限
    await pollUntil(() => c.router.currentRoute.value.path === '/system/roles', '点击跳转')
    await pollUntil(() => !palette(), '点击后关闭')

    hotkey()
    await pollUntil(() => !!palette(), '面板再次打开')
    click(document.body.querySelector('.search-palette')) // 点面板内部
    await flush(6)
    expect(palette()).toBeTruthy() // 不关闭

    keyOnInput('Escape')
    await pollUntil(() => !palette(), 'ESC 关闭')

    hotkey()
    await pollUntil(() => !!palette(), '面板再次打开')
    click(document.body.querySelector('.search-palette__overlay')) // 点遮罩空白
    await pollUntil(() => !palette(), '遮罩点击关闭')
    expect(c.errors).toEqual([])
  })

  test('卸载：摘掉全局热键监听，打开状态下还原 body 滚动锁', async () => {
    await mountPalette()
    hotkey()
    await pollUntil(() => !!palette(), '面板打开')
    expect(document.body.style.overflow).toBe('hidden')

    active.handle.unmount()
    active = null
    expect(palette()).toBeNull()
    expect(document.body.style.overflow).toBe('')

    // 监听已摘：再按热键不应把面板唤回（也不会抛错）
    expect(() => hotkey()).not.toThrow()
    await flush(4)
    expect(palette()).toBeNull()
  })
})
