import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
// Element Plus 按需引入：不再全量注册插件与全量样式，
// 组件/指令由 unplugin-vue-components + ElementPlusResolver 自动注册并按需加载对应样式。
// 这里仅保留全局基础 CSS 变量（所有组件样式依赖 :root 变量）与暗色模式变量。
import 'element-plus/theme-chalk/base.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
// 命令式 API（ElMessage/ElMessageBox/ElNotification）在各文件中均为显式导入。
// 注意：必须从具体组件路径 `element-plus/es/components/xxx` 导入，不能写 `from 'element-plus'`。
// 后者会解析到全量入口 es/index.mjs，使「任何地方用到的组件」全部汇聚进首屏 chunk——
// 实测 date-picker + time-picker 约 217KB（minify 前）就是这样被拖进首屏的，
// 即便它们只被懒加载视图使用。深路径导入可切断这条链。
// 显式导入不会触发 AutoImport resolver 的样式注入，故手动补齐这几个小体积样式。
import 'element-plus/theme-chalk/el-message.css'
import 'element-plus/theme-chalk/el-message-box.css'
import 'element-plus/theme-chalk/el-notification.css'
import i18n from './i18n'
import { useAppStore, useAuthStore } from './store'
import { initSessionSync } from './utils/sessionSync'
import { initErrorHandling } from './utils/errorReporter'

// 全局样式
import '@/assets/styles/global.css'
import '@/assets/styles/dark.css'
// Apple 风格全局打磨层：只叠加交互反馈与过渡质感，不改布局；须在 global/dark 之后引入
import '@/assets/styles/apple-polish.css'

// 开发端口可能与生产 preview 共用。旧的生产 Service Worker 会拦截 Vite 模块和
// HMR 请求，造成资源读取失败；开发启动时先清理，刷新一次后即恢复干净状态。
if (import.meta.env.DEV && 'serviceWorker' in navigator) {
  ;(async () => {
    try {
      const registrations = await navigator.serviceWorker.getRegistrations()
      await Promise.all(registrations.map((registration) => registration.unregister()))
      if (typeof caches !== 'undefined') {
        const cacheNames = await caches.keys()
        await Promise.all(cacheNames.map((cacheName) => caches.delete(cacheName)))
      }
    } catch (_) {
      // 清理失败不应阻塞本地开发页面加载。
    }
  })()
}

// 创建 Pinia 实例
const pinia = createPinia()

// 创建 Vue 应用
const app = createApp(App)

// 全局错误兜底：组件/资源/未处理 Promise 三路错误收敛留档（G-1）
initErrorHandling(app)

// Element Plus locale follows i18n via el-config-provider in App.vue

app.use(pinia)

// 初始化主题（默认跟随系统，用户手动选择持久化于 localStorage；
// 首帧防闪烁由 index.html 内联脚本完成，这里负责状态初始化与系统主题监听）
useAppStore().initTheme()

// 跨标签页会话同步：其他标签页登录了不同账号（httpOnly cookie 被覆盖）
// 或同账号登出时，本标签页的界面身份与请求身份会错位，须立即失效本地会话
initSessionSync((event) => {
  useAuthStore().handleRemoteAuthEvent(event)
})

app.use(router)
app.use(i18n)

// 挂载应用
app.mount('#app')
