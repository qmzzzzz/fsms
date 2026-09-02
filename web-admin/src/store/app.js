import { defineStore } from 'pinia'
import { safeStorage, safeLocal } from './storage'

// 应用设置 Store
export const useAppStore = defineStore('app', {
  state: () => ({
    userCount: parseInt(safeStorage.get('userCount') || '0'),
    // 主题模式三态：system=跟随系统（默认）/ light / dark
    // 持久化到 localStorage，关闭网页与登出后保留
    themeMode: safeLocal.get('themeMode') || 'system',
    // 系统当前是否偏好暗色（由 matchMedia 监听实时更新，system 模式下生效）
    systemPrefersDark:
      typeof window !== 'undefined' &&
      !!window.matchMedia?.('(prefers-color-scheme: dark)').matches,
    sidebarCollapsed: false,
    language:
      safeStorage.get('locale') || (navigator.language?.startsWith('zh') ? 'zh-CN' : 'en-US'),
  }),

  getters: {
    getUserCount: (state) => state.userCount,
    // 实际生效的主题：显式选择优先，system 模式看系统偏好
    isDarkMode: (state) =>
      state.themeMode === 'dark' || (state.themeMode === 'system' && state.systemPrefersDark),
  },

  actions: {
    incrementUserCount() {
      this.userCount++
      safeStorage.set('userCount', this.userCount.toString())
    },

    decrementUserCount() {
      if (this.userCount > 0) {
        this.userCount--
        safeStorage.set('userCount', this.userCount.toString())
      }
    },

    setUserCount(count) {
      this.userCount = count
      safeStorage.set('userCount', count.toString())
    },

    toggleSidebar() {
      this.sidebarCollapsed = !this.sidebarCollapsed
    },

    // 将当前生效主题应用到 DOM：html.dark 类、原生 color-scheme、
    // 移动端浏览器地址栏 theme-color（暗色用页面深色底，避免白条突兀）
    _applyTheme() {
      const dark = this.isDarkMode
      document.documentElement.classList.toggle('dark', dark)
      document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
      const meta = document.querySelector('meta[name="theme-color"]')
      if (meta) meta.setAttribute('content', dark ? '#0a0f1a' : '#c1121f')
    },

    // 启动时调用：迁移旧版 sessionStorage 偏好，应用主题并监听系统切换
    initTheme() {
      // 旧版本把 darkMode(true/false) 存在 sessionStorage，一次性迁移为三态
      if (!safeLocal.get('themeMode')) {
        try {
          const legacy = sessionStorage.getItem('darkMode')
          if (legacy === 'true') safeLocal.set('themeMode', 'dark')
          else if (legacy === 'false') safeLocal.set('themeMode', 'light')
        } catch (_) {}
        this.themeMode = safeLocal.get('themeMode') || 'system'
      }
      this.systemPrefersDark = !!window.matchMedia?.('(prefers-color-scheme: dark)').matches
      this._applyTheme()

      const mq = window.matchMedia?.('(prefers-color-scheme: dark)')
      if (mq) {
        const onChange = (e) => {
          this.systemPrefersDark = e.matches
          this._applyTheme()
        }
        // Safari < 14 只支持 addListener
        if (mq.addEventListener) mq.addEventListener('change', onChange)
        else if (mq.addListener) mq.addListener(onChange)
      }
    },

    setThemeMode(mode) {
      this.themeMode = mode
      safeLocal.set('themeMode', mode)
      this._applyTheme()
    },

    // 兼容旧调用：亮暗互切（视为手动选择，脱离跟随系统）
    toggleDarkMode() {
      this.setThemeMode(this.isDarkMode ? 'light' : 'dark')
    },

    setDarkMode(enabled) {
      this.setThemeMode(enabled ? 'dark' : 'light')
    },

    setLanguage(lang) {
      this.language = lang
      safeStorage.set('locale', lang)
    },
  },
})
