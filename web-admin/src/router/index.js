import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { cancelAllPendingRequests } from '@/utils/api'
import { useAuthStore } from '@/store'
import { matchPermission } from '@/utils/permission'
import i18n from '@/i18n'

const Layout = () => import('@/layout/index.vue')

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { requiresAuth: false, hidden: true },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('../views/RegisterView.vue'),
    meta: { requiresAuth: false, hidden: true },
  },
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('@/views/DashboardView.vue'),
        meta: { titleKey: 'nav.dashboard', icon: 'Odometer' },
      },
      {
        path: 'devices',
        name: 'devices',
        component: () => import('@/views/DeviceView.vue'),
        meta: { titleKey: 'nav.devices', icon: 'Cpu', permission: 'device:read' },
      },
      {
        path: 'alarms',
        name: 'alarms',
        component: () => import('@/views/AlarmView.vue'),
        meta: { titleKey: 'nav.alarms', icon: 'Bell', permission: 'alarm:read' },
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('@/views/UserView.vue'),
        meta: { titleKey: 'nav.users', icon: 'User', permission: 'user:read' },
      },
      {
        path: 'roles',
        name: 'roles',
        component: () => import('@/views/RoleView.vue'),
        meta: { titleKey: 'nav.roles', icon: 'Key', permission: 'role:read' },
      },
      {
        path: 'inspections',
        name: 'inspections',
        component: () => import('@/views/InspectionView.vue'),
        meta: { titleKey: 'nav.inspections', icon: 'Tickets', permission: 'inspection:read' },
      },
      {
        path: 'reports',
        name: 'reports',
        component: () => import('@/views/ReportView.vue'),
        meta: { titleKey: 'nav.reports', icon: 'DataAnalysis', permission: 'report:read' },
      },
      {
        path: 'audit-logs',
        name: 'audit-logs',
        component: () => import('@/views/AuditLogView.vue'),
        meta: { titleKey: 'nav.auditLogs', icon: 'Document', permission: 'security:audit' },
      },
      {
        path: 'ip-list',
        name: 'ip-list',
        component: () => import('@/views/IpListView.vue'),
        meta: { titleKey: 'nav.ipList', icon: 'Lock', permission: 'security:config' },
      },
      {
        path: 'profile',
        name: 'profile',
        component: () => import('@/views/ProfileView.vue'),
        meta: { titleKey: 'nav.profile', icon: 'UserFilled' },
      },
      {
        path: 'about',
        name: 'about',
        component: () => import('@/views/AboutView.vue'),
        meta: { titleKey: 'nav.about', icon: 'InfoFilled' },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

// 损坏的浏览器磁盘缓存会让动态导入失败。先强制从网络刷新对应模块，
// 再对当前路由做一次恢复性加载；短时间窗口避免服务器异常时反复刷新。
const CHUNK_LOAD_ERROR =
  /Failed to fetch dynamically imported module|Importing a module script failed/i
const ROUTE_RETRY_WINDOW_MS = 15 * 1000

router.onError(async (error, to) => {
  if (!CHUNK_LOAD_ERROR.test(error.message)) return

  const target = to?.fullPath || '/'
  const retryKey = `router:chunkRetry:${target}`
  let lastRetryAt = 0
  try {
    lastRetryAt = Number(sessionStorage.getItem(retryKey)) || 0
    if (Date.now() - lastRetryAt >= ROUTE_RETRY_WINDOW_MS) {
      sessionStorage.setItem(retryKey, String(Date.now()))
    }
  } catch (_) {}
  if (Date.now() - lastRetryAt < ROUTE_RETRY_WINDOW_MS) return

  const [failedUrl] = error.message.match(/https?:\/\/\S+/) || []
  if (failedUrl) {
    try {
      const url = new URL(failedUrl)
      if (url.origin === window.location.origin) {
        await fetch(url, { cache: 'reload' })
      }
    } catch (_) {
      // 即使强制刷新失败，仍允许浏览器执行一次常规路由恢复。
    }
  }

  // FE-L3：子路径部署（BASE_URL ≠ '/'）下必须带部署基路径，与 auth.js 同口径
  const base = String(import.meta.env.BASE_URL || '/').replace(/\/+$/, '')
  window.location.replace(base + target)
})

// 全局前置守卫 - 跨浏览器兼容
router.beforeEach(async (to, from, next) => {
  // 路由切换时取消所有在途请求，避免状态更新到已卸载组件
  if (from.name !== null) {
    cancelAllPendingRequests()
  }

  // I-01：登录态以 store 中的 currentUser 判断（令牌走 httpOnly cookie，JS 不可读）
  const authStore = useAuthStore()
  let authenticated = authStore.isAuthenticated

  // 会话恢复：本地无身份状态但浏览器可能仍持有有效 cookie（新标签页首次进入、
  // 复制 URL 直达子路径、localStorage 被清等）。此时先用 /auth/me 探测一次，
  // 探测成功即复用同一会话，避免把已登录用户误踢到登录页。
  // 仅在「本地无身份」时探测，已登录路径零额外请求。
  if (!authenticated) {
    authenticated = await authStore.restoreSession()
  }

  // 已登录用户访问登录页 -> 跳首页
  if (to.name === 'login' && authenticated) {
    next('/dashboard')
    return
  }

  // 未登录访问需要认证的页面 -> 登录页
  if (to.meta.requiresAuth !== false && !authenticated) {
    next('/login')
    return
  }

  // 权限校验：路由 meta.permission 声明所需权限
  const requiredPermission = to.meta.permission
  if (requiredPermission && authenticated) {
    if (!matchPermission(authStore.permissions || [], requiredPermission)) {
      ElMessage.error(i18n.global.t('messages.permissionDenied'))
      next('/dashboard')
      return
    }
  }

  next()
})

export default router
