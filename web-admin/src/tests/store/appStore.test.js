/**
 * 应用 Store 主题模式测试（三态：system / light / dark）
 * 核心断言：默认跟随系统、手动选择持久化 localStorage（登出/关页不失效）、
 * isDarkMode 在 system 模式下随系统偏好计算、DOM 应用（html.dark + color-scheme + theme-color）
 */
import { describe, test, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAppStore } from '@/store'

const setMetaThemeColor = (content) => {
  let meta = document.querySelector('meta[name="theme-color"]')
  if (!meta) {
    meta = document.createElement('meta')
    meta.setAttribute('name', 'theme-color')
    document.head.appendChild(meta)
  }
  meta.setAttribute('content', content)
}

describe('useAppStore 主题模式', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    sessionStorage.clear()
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    document.documentElement.style.colorScheme = ''
    setMetaThemeColor('#c1121f')
  })

  test('默认 themeMode=system，且不写任何持久化', () => {
    const store = useAppStore()
    expect(store.themeMode).toBe('system')
    expect(localStorage.getItem('themeMode')).toBeNull()
  })

  test('setThemeMode("dark") 生效并持久化到 localStorage（非 sessionStorage）', () => {
    const store = useAppStore()
    store.setThemeMode('dark')
    expect(store.themeMode).toBe('dark')
    expect(localStorage.getItem('themeMode')).toBe('dark')
    expect(sessionStorage.getItem('themeMode')).toBeNull()
  })

  test('isDarkMode：显式 light 时即使系统暗色也为亮', () => {
    const store = useAppStore()
    store.systemPrefersDark = true // 模拟系统暗色
    store.setThemeMode('light')
    expect(store.isDarkMode).toBe(false)
  })

  test('isDarkMode：system 模式跟随 systemPrefersDark', () => {
    const store = useAppStore()
    store.setThemeMode('system')
    store.systemPrefersDark = true
    expect(store.isDarkMode).toBe(true)
    store.systemPrefersDark = false
    expect(store.isDarkMode).toBe(false)
  })

  test('_applyTheme：暗色写 html.dark + color-scheme + theme-color 深色', () => {
    const store = useAppStore()
    store.setThemeMode('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(document.documentElement.style.colorScheme).toBe('dark')
    expect(document.querySelector('meta[name="theme-color"]').getAttribute('content')).toBe(
      '#0a0f1a'
    )
  })

  test('_applyTheme：亮色移除 html.dark 并恢复亮色 theme-color', () => {
    const store = useAppStore()
    store.setThemeMode('dark')
    store.setThemeMode('light')
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    expect(document.documentElement.style.colorScheme).toBe('light')
    expect(document.querySelector('meta[name="theme-color"]').getAttribute('content')).toBe(
      '#c1121f'
    )
  })

  test('toggleDarkMode 兼容语义：在亮暗间切换并视为手动选择', () => {
    const store = useAppStore()
    store.setThemeMode('system')
    store.toggleDarkMode() // system 且当前亮 → dark
    expect(store.themeMode).toBe('dark')
    store.toggleDarkMode() // dark → light
    expect(store.themeMode).toBe('light')
  })

  test('刷新页面恢复：localStorage 中的选择重建主题状态', () => {
    localStorage.setItem('themeMode', 'dark')
    const store = useAppStore()
    expect(store.themeMode).toBe('dark')
    expect(store.isDarkMode).toBe(true)
  })
})
