import { defineStore } from 'pinia'
import { safeStorage, safeLocal } from './storage'

// P2-59 修复（2026-09-17）：initTheme 可能被重复调用（热重载、未来新增的
// 重新初始化入口），原实现每次都新建 matchMedia 监听器且从不移除——
// 旧监听器闭包持有 store 实例，系统主题每切换一次就会叠加一次 _applyTheme。
// 这里在模块级持有「当前监听器 + 所属 MediaQueryList」的引用，重入时先摘除。
let systemThemeListener = null
let systemThemeQuery = null

// 应用设置 Store
export const useAppStore = defineStore('app', {
  state: () => ({
    // L-12：原 userCount 状态与 increment/decrement/setUserCount 三个 action
    // 全仓无任何消费方（RoleListPanel 的 role.userCount 是接口字段，非此状态），
    // 却每次登录自增并持久化到 sessionStorage——冗余状态且与接口同名字段易误导。已删除。
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
    // 实际生效的主题：显式选择优先，system 模式看系统偏好
    isDarkMode: (state) =>
      state.themeMode === 'dark' || (state.themeMode === 'system' && state.systemPrefersDark),
  },

  actions: {
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
        // 重入保护：若上一轮 initTheme 已注册过监听器，先摘除再注册，
        // 避免热重载或重复初始化在同一 MediaQueryList 上叠加多个 change 回调。
        if (systemThemeQuery && systemThemeListener) {
          if (systemThemeQuery.removeEventListener) {
            systemThemeQuery.removeEventListener('change', systemThemeListener)
          } else if (systemThemeQuery.removeListener) {
            // Safari < 14 只支持 removeListener
            systemThemeQuery.removeListener(systemThemeListener)
          }
        }
        const onChange = (e) => {
          this.systemPrefersDark = e.matches
          this._applyTheme()
        }
        // Safari < 14 只支持 addListener
        if (mq.addEventListener) mq.addEventListener('change', onChange)
        else if (mq.addListener) mq.addListener(onChange)
        // 记录本轮注册的监听器及其宿主对象，供下次重入时摘除
        systemThemeQuery = mq
        systemThemeListener = onChange
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
