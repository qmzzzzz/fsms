import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { cancelAllPendingRequests } from '@/utils/api'
import { useAuthStore } from '@/store'
import { matchPermission } from '@/utils/permission'
import { watch } from 'vue'
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
        // 取证溯源（T5/T6）：读溯源 security:audit；页内封段按钮另按 security:config 门控
        path: 'forensic-trace',
        name: 'forensic-trace',
        component: () => import('@/views/ForensicTraceView.vue'),
        meta: { titleKey: 'nav.forensic', icon: 'Search', permission: 'security:audit' },
      },
      {
        path: 'privilege-grants',
        name: 'privilege-grants',
        component: () => import('@/views/PrivilegeGrantView.vue'),
        meta: {
          titleKey: 'nav.privilegeGrants',
          icon: 'Stamp',
          permission: 'privilege:read',
        },
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
  // 导航后回到顶部：各页都是长列表/长表单，停留在旧滚动位会让用户以为页面没变
  // （筛选变化导致同路径重渲染时尤其明显）。浏览器前进/后退沿用保存的位置，
  // hash 锚点优先——三者互斥的优先级即下面的分支顺序。
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) return savedPosition
    if (to.hash) return { el: to.hash }
    return { top: 0 }
  },
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
  // P2-58 修复（2026-09-17）：判据改为 `!== undefined`。
  // 首屏进入时 from 是 vue-router 的 START_LOCATION（name === undefined），
  // 而 `!== null` 对 undefined 同样成立 —— 条件恒真，注释声称的「仅路由切换时」
  // 从未成立过。改后首屏不再误触发取消（虽然此时本就没有在途请求，属行为收敛）。
  if (from.name !== undefined) {
    cancelAllPendingRequests()
  }

  // I-01：登录态以 store 中的 currentUser 判断（令牌走 httpOnly cookie，JS 不可读）
  const authStore = useAuthStore()
  let authenticated = authStore.isAuthenticated

  // P-2：公开路由（登录/注册）在本地无身份时**不再**探测 /auth/me。
  // 匿名用户访问 /login 是最高频入口，此前每开一个新标签页都先吃一发 401/网络往返，
  // 只为处理「cookie 仍有效但 localStorage 被清」这一种少数场景；而该场景在进入任何
  // 受保护页时仍会走下面的恢复逻辑，不会把会话丢掉。
  const isPublicRoute = to.meta.requiresAuth === false

  // 会话恢复：本地无身份状态但浏览器可能仍持有有效 cookie（新标签页首次进入、
  // 复制 URL 直达子路径、localStorage 被清等）。此时先用 /auth/me 探测一次，
  // 探测成功即复用同一会话，避免把已登录用户误踢到登录页。
  //
  // 身份校验（P3-38 / 无 id 用户对象）：localStorage 里的 currentUser 只是**界面缓存**，
  // 不是登录凭证——它可以被手工写入、也可能是旧版本留下的脏形状。仅当本页生命周期内
  // 已向服务端核实过（sessionVerified）才直接放行；否则即便本地有身份也要探测一次，
  // 由服务端确认该会话真实存在。公开路由仍不探测（匿名入口不做无谓往返）。
  if (!isPublicRoute && (!authenticated || !authStore.sessionVerified)) {
    authenticated = await authStore.restoreSession()
  }

  // P1-2：临时口令账户在完成改密前只允许停留在个人资料页。
  // 服务端 authenticate 对所有业务接口返回 403 PASSWORD_CHANGE_REQUIRED，
  // 前端守卫提前收敛，避免用户点一圈菜单全是 403。
  const mustChangePassword = authStore.currentUser?.mustChangePassword === true

  // 已登录用户访问登录页 -> 跳首页（强制改密账户先去改密）
  if (to.name === 'login' && authenticated) {
    next(mustChangePassword ? '/profile' : '/dashboard')
    return
  }

  if (authenticated && mustChangePassword && to.name !== 'profile') {
    next('/profile')
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

/**
 * 标签页标题（H6）：登录后永停「…- 用户登录」的修法。
 *
 * LoginView 只在进入登录页时写一次 document.title（并 watch(locale) 重写），
 * 之后无论跳到哪个页面都不再更新 ⇒ 用户整天看着「用户登录」。
 * layout/index.vue:386 的 route.meta.titleKey 只服务菜单/面包屑，
 * 与 document.title 是两件事，那边改了这边不会跟着动。
 *
 * 取值口径与 layout:386 逐字一致（titleKey 优先、meta.title 兜底）：
 * 两处对同一条 route 必须读出同一个标题，否则菜单与标签页各说各话。
 * login/register 是 hidden 路由、不带 meta，由各自视图自己管标题，这里不覆盖。
 */
let titledRoute = null
const applyDocumentTitle = () => {
  const meta = titledRoute?.meta
  // hidden 路由（login/register）不带 meta，标题由各自视图自己管，这里不覆盖
  if (!meta?.titleKey && !meta?.title) return
  const page = meta.titleKey ? i18n.global.t(meta.titleKey) : meta.title
  document.title = `${page} - ${i18n.global.t('common.appTitle')}`
}

router.afterEach((to) => {
  titledRoute = to
  applyDocumentTitle()
})

// 首屏（含刷新后直接落在某路由）没有 afterEach 可触发，用当前路由补一次
titledRoute = router.currentRoute.value
applyDocumentTitle()

// 切语言后标题要跟着重写：文案物化在 document.title 里，不会随 locale 自愈
watch(() => i18n.global.locale.value, applyDocumentTitle)

export default router
