<template>
  <!--
    inert：退出遮罩显示期间，把整块应用内容移出可访问性树并禁止聚焦——遮罩盖住的是
    「正在登出」，此时下层菜单/按钮仍可 Tab 到并触发操作（读屏也会念到它们）。
    遮罩自身已 Teleport 到 body，不会被这行一起 inert 掉（它的 aria-live 播报依赖这一点）。
    取值用 '' / null 而非布尔：Vue 对不在 isSpecialBooleanAttr 里的属性走 setAttribute，
    传 false 会写上 "false" 字面量（对布尔属性仍是「生效」）；'' 与 null 在浏览器属性
    赋值与 jsdom setAttribute 两条路径下语义一致（测试可断言 hasAttribute）。
  -->
  <div
    class="app-wrapper"
    :class="{ 'mobile-sidebar-open': mobileSidebarOpen }"
    :inert="showExit ? '' : null"
    @keydown.esc="mobileSidebarOpen = false"
  >
    <!-- 键盘跳转链接（a11y）：Tab 键的第一个停靠点，回车后焦点直达主内容区，
         免去逐个 Tab 穿过整条侧边栏菜单。平时视觉隐藏，获得焦点时浮现
         （纯 CSS 实现，参考研读 2026-11-01 §二 P1-2）。 -->
    <a class="skip-link" href="#main-content">{{ t('layout.skipToContent') }}</a>

    <!-- 移动端遮罩：用原生 button 承载点击/键盘关闭，避免只有一个不可聚焦的 div -->
    <button
      v-if="isMobile && mobileSidebarOpen"
      type="button"
      class="mobile-overlay"
      :aria-label="t('layout.closeSidebar')"
      @click="mobileSidebarOpen = false"
    />

    <!-- 侧边栏 -->
    <aside
      class="sidebar"
      :class="{ 'sidebar-mobile': isMobile, 'sidebar-collapsed': isCollapse }"
      :style="sidebarStyle"
    >
      <div class="logo">
        <el-icon class="logo-icon">
          <Flag />
        </el-icon>
        <span v-show="!isCollapse" class="logo-text">{{ t('auth.loginTitle') }}</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="isCollapse"
        :collapse-transition="true"
        background-color="transparent"
        text-color="#94a3b8"
        active-text-color="#ffffff"
        router
        class="sidebar-menu"
        @select="onMenuSelect"
      >
        <template v-for="item in menuItems" :key="item.path">
          <el-sub-menu v-if="item.children" :index="item.path">
            <template #title>
              <el-icon><component :is="item.icon" /></el-icon>
              <span>{{ t(item.i18nKey) }}</span>
            </template>
            <el-menu-item
              v-for="child in item.children"
              :key="child.path"
              :index="child.path"
              @mouseenter="prefetchRoute(child.path)"
            >
              <el-icon><component :is="child.icon" /></el-icon>
              <template #title>
                {{ t(child.i18nKey) }}
              </template>
            </el-menu-item>
          </el-sub-menu>
          <el-menu-item v-else :index="item.path" @mouseenter="prefetchRoute(item.path)">
            <el-icon><component :is="item.icon" /></el-icon>
            <template #title>
              {{ t(item.i18nKey) }}
            </template>
          </el-menu-item>
        </template>
      </el-menu>
    </aside>

    <!-- 主区域 -->
    <div class="main-container">
      <header class="navbar">
        <div class="navbar-left">
          <el-icon
            class="collapse-btn"
            role="button"
            tabindex="0"
            :aria-label="isCollapse ? t('layout.expandSidebar') : t('layout.collapseSidebar')"
            @click="handleToggleSidebar"
            @keydown.enter.prevent="handleToggleSidebar"
            @keydown.space.prevent="handleToggleSidebar"
          >
            <Expand v-if="isCollapse" /><Fold v-else />
          </el-icon>
          <el-breadcrumb separator="/" class="tech-hide-mobile">
            <el-breadcrumb-item :to="{ path: '/dashboard' }">
              {{ t('nav.home') }}
            </el-breadcrumb-item>
            <el-breadcrumb-item>{{ currentTitle }}</el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="navbar-right">
          <!-- 举报异常：人人可用的安全出口（无权限码），入口在搜索左侧 -->
          <el-tooltip :content="t('security.report')" placement="bottom">
            <el-icon
              class="action-icon"
              role="button"
              tabindex="0"
              :aria-label="t('security.report')"
              @click="reportDialogVisible = true"
              @keydown.enter.prevent="reportDialogVisible = true"
              @keydown.space.prevent="reportDialogVisible = true"
            >
              <Warning />
            </el-icon>
          </el-tooltip>

          <!-- ⌘K 全局搜索（移动端同样可点按触发） -->
          <el-tooltip :content="searchTooltip" placement="bottom">
            <el-icon
              class="action-icon"
              role="button"
              tabindex="0"
              :aria-label="t('common.searchPalette')"
              @click="searchPaletteRef?.open()"
              @keydown.enter.prevent="searchPaletteRef?.open()"
              @keydown.space.prevent="searchPaletteRef?.open()"
            >
              <Search />
            </el-icon>
          </el-tooltip>

          <!-- 语言切换 -->
          <!-- 提示走 el-tooltip 而非原生 title：title 的样式与出现时机都由浏览器
               决定，与搜索/刷新/全屏不是一套观感。展开期间禁用提示——菜单浮层与
               提示浮层同位叠放会互相盖住，且此时指针停在图标上不产生 mouseleave，
               提示不会自行消失 -->
          <el-tooltip :content="t('common.language')" placement="bottom" :disabled="prefMenuOpen">
            <el-dropdown
              trigger="click"
              @command="handleLanguageChange"
              @visible-change="onPrefMenuVisible"
            >
              <el-icon
                class="action-icon"
                role="button"
                tabindex="0"
                :aria-label="t('common.language')"
                @keydown.enter.prevent="$event.currentTarget.click()"
                @keydown.space.prevent="$event.currentTarget.click()"
              >
                <Operation />
              </el-icon>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="zh-CN" :class="{ 'is-active': language === 'zh-CN' }">
                    中文
                  </el-dropdown-item>
                  <el-dropdown-item command="en-US" :class="{ 'is-active': language === 'en-US' }">
                    English
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </el-tooltip>

          <!-- 主题切换：下拉选择，与语言切换交互一致 -->
          <el-tooltip :content="t('common.theme')" placement="bottom" :disabled="prefMenuOpen">
            <el-dropdown
              trigger="click"
              @command="handleThemeChange"
              @visible-change="onPrefMenuVisible"
            >
              <el-icon
                class="action-icon"
                role="button"
                tabindex="0"
                :aria-label="t('common.theme')"
                @keydown.enter.prevent="$event.currentTarget.click()"
                @keydown.space.prevent="$event.currentTarget.click()"
              >
                <Monitor v-if="themeMode === 'system'" />
                <Sunny v-else-if="themeMode === 'light'" />
                <Moon v-else />
              </el-icon>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item
                    command="system"
                    :class="{ 'is-active': themeMode === 'system' }"
                  >
                    {{ t('common.autoMode')
                    }}{{
                      appStore.systemPrefersDark
                        ? ' · ' + t('common.darkMode')
                        : ' · ' + t('common.lightMode')
                    }}
                  </el-dropdown-item>
                  <el-dropdown-item command="light" :class="{ 'is-active': themeMode === 'light' }">
                    {{ t('common.lightMode') }}
                  </el-dropdown-item>
                  <el-dropdown-item command="dark" :class="{ 'is-active': themeMode === 'dark' }">
                    {{ t('common.darkMode') }}
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </el-tooltip>

          <el-tooltip :content="t('common.refresh')" placement="bottom">
            <el-icon
              class="action-icon"
              role="button"
              tabindex="0"
              :aria-label="t('common.refresh')"
              @click="refresh"
              @keydown.enter.prevent="refresh"
              @keydown.space.prevent="refresh"
            >
              <Refresh />
            </el-icon>
          </el-tooltip>
          <el-tooltip
            v-if="canToggleFullScreen"
            :content="$t('layout.fullscreen')"
            placement="bottom"
            class="tech-hide-mobile"
          >
            <el-icon
              class="action-icon"
              role="button"
              tabindex="0"
              :aria-label="$t('layout.fullscreen')"
              @click="toggleFullScreen"
              @keydown.enter.prevent="toggleFullScreen"
              @keydown.space.prevent="toggleFullScreen"
            >
              <FullScreen />
            </el-icon>
          </el-tooltip>
          <el-dropdown @command="handleCommand">
            <span class="user-dropdown">
              <UserAvatar
                :src="currentUser?.avatar"
                :name="currentUser?.username"
                :size="32"
                class="user-avatar"
              />
              <span class="user-name tech-hide-mobile">{{
                currentUser?.username || t('common.notLoggedIn')
              }}</span>
              <el-icon class="tech-hide-mobile"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">
                  <el-icon><UserFilled /></el-icon>{{ t('nav.profile') }}
                </el-dropdown-item>
                <el-dropdown-item command="password">
                  <el-icon><Lock /></el-icon>{{ t('auth.changePassword') }}
                </el-dropdown-item>
                <el-dropdown-item divided command="logout">
                  <el-icon><SwitchButton /></el-icon>{{ t('auth.logout') }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <div
        class="pull-indicator"
        :style="{ transform: `translate(-50%, ${pullY}px)`, opacity: pullOpacity }"
      >
        <div class="pull-indicator__spinner" :class="{ 'is-spinning': pullRefreshing }" />
        <span class="pull-indicator__text">{{
          pullRefreshing ? t('common.refreshing') : t('common.pullToRefresh')
        }}</span>
      </div>

      <!-- tabindex="-1"：skip-link 的 href 定位目标必须可编程聚焦，
           否则部分浏览器点击跳转链接后焦点仍停在原地（URL hash 变了但 Tab 序不变） -->
      <main id="main-content" ref="mainContentRef" class="main-content" tabindex="-1">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <!-- 默认同路径不同 query 重挂载；工作台把 tab 放 query 里且需保活，
                 由 meta.keepOnQuery 显式豁免（否则每次切 tab 都丢三个工具的现场） -->
            <component
              :is="Component"
              :key="route.meta.keepOnQuery ? route.path : route.fullPath"
            />
          </transition>
        </router-view>
      </main>
    </div>

    <!-- 优雅退出遮罩 -->
    <ExitOverlay :visible="showExit" />

    <!-- ⌘K 全局搜索面板 -->
    <SearchPalette ref="searchPaletteRef" :menu="menuItems" />

    <!-- 举报异常对话框（顶栏入口，人人可用） -->
    <ReportDialog v-model:visible="reportDialogVisible" />
  </div>
</template>

<script setup>
defineOptions({ name: 'AppLayout' })
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import {
  Flag,
  Odometer,
  Cpu,
  Bell,
  Tickets,
  Setting,
  User,
  Key,
  DataAnalysis,
  Fold,
  Expand,
  Refresh,
  FullScreen,
  ArrowDown,
  UserFilled,
  Lock,
  Stamp,
  SwitchButton,
  Document,
  Sunny,
  Moon,
  Monitor,
  Operation,
  Search,
  Aim,
  Warning,
} from '@element-plus/icons-vue'
import { useAuthStore, useAppStore } from '@/store'
import { matchPermission } from '@/utils/permission'
import { api } from '@/utils/api'
import { setLocale } from '@/i18n'
import { usePermissionSync } from '@/composables/usePermissionSync'
import { usePullToRefresh } from '@/composables/usePullToRefresh'
import { prefetchRoute } from '@/utils/routePrefetch'
import { disconnectWebSocket } from '@/utils/websocket'
import ExitOverlay from '@/components/ExitOverlay.vue'
import SearchPalette from '@/components/SearchPalette.vue'
import ReportDialog from '@/components/ReportDialog.vue'
import UserAvatar from '@/components/UserAvatar.vue'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const appStore = useAppStore()

// 权限热同步：挂在布局层而非某个具体页面 —— 需要收到推送的是「权限被改的人」，
// 他此刻可能在任意页面（多半不在角色管理页，那页还需要 role:read 权限）。
// 内部自行管理 socket 生命周期与引用计数。
usePermissionSync()

const isCollapse = computed(() => appStore.sidebarCollapsed)
const currentUser = computed(() => authStore.currentUser)
const permissions = computed(() => authStore.permissions || [])
const themeMode = computed(() => appStore.themeMode)
const language = computed(() => appStore.language)
// iPhone Safari 不提供元素全屏 API；隐藏入口比点击后无响应更符合跨端预期。
const canToggleFullScreen = computed(() => {
  const el = document.documentElement
  return !!(
    el.requestFullscreen ||
    el.webkitRequestFullscreen ||
    el.mozRequestFullScreen ||
    el.msRequestFullscreen
  )
})

const handleThemeChange = (mode) => {
  appStore.setThemeMode(mode)
}

// 语言/主题下拉展开期间禁用悬停提示（el-tooltip 的 disabled）：菜单浮层与提示
// 浮层同位叠放会互相遮挡，而展开时指针停在图标上不会触发 mouseleave，提示
// 不会自行消失。两个入口互斥，共用一个状态即可
const prefMenuOpen = ref(false)
const onPrefMenuVisible = (visible) => {
  prefMenuOpen.value = visible
}

// 移动端检测
const isMobile = ref(false)
const mobileSidebarOpen = ref(false)

const checkMobile = () => {
  isMobile.value = window.innerWidth <= 768
  if (isMobile.value) {
    appStore.sidebarCollapsed = false
  }
}

// ===== 移动端下拉刷新 =====
const mainContentRef = ref(null)
const { y: pullY, refreshing: pullRefreshing } = usePullToRefresh(mainContentRef, async () => {
  // 下拉刷新等价于点击刷新按钮：整页重载，各视图自行重新拉取
  window.location.reload()
  // reload 完成后页面已重建，无需手动复位 refreshing。
  // 兜底（审计 2026-11-02 D-F5）：reload 可能被宿主环境阻止（部分内嵌 WebView
  // 的策略）——返回永不 resolve 的 Promise 加上 onTouchCancel 在 refreshing 态
  // 的短路，会让指示器永久转圈且无恢复路径。3 秒后仍未离开页面就本地复位；
  // reload 正常发生时定时器随页面销毁，无副作用。
  setTimeout(() => {
    pullRefreshing.value = false
    pullY.value = 0
  }, 3000)
  return new Promise(() => {})
})

const pullOpacity = computed(() => Math.min(pullY.value / 60, 1))

// ===== 移动端侧栏边缘滑动手势 =====
// 从左缘 24px 热区右滑打开侧栏；侧栏打开时任意位置左滑关闭。
// 判定要求水平位移 ≥50px 且明显大于垂直位移，避免与纵向滚动、浏览器返回手势冲突。
const EDGE_SWIPE_WIDTH = 24
const EDGE_SWIPE_THRESHOLD = 50
let swipeStartX = 0
let swipeStartY = 0
let swipeTracking = false

const onSwipeStart = (e) => {
  if (!isMobile.value || e.touches.length !== 1) return
  const x = e.touches[0].clientX
  if (mobileSidebarOpen.value || x <= EDGE_SWIPE_WIDTH) {
    swipeTracking = true
    swipeStartX = x
    swipeStartY = e.touches[0].clientY
  }
}

const onSwipeEnd = (e) => {
  if (!swipeTracking) return
  swipeTracking = false
  const touch = e.changedTouches[0]
  const dx = touch.clientX - swipeStartX
  const dy = touch.clientY - swipeStartY
  if (Math.abs(dx) < EDGE_SWIPE_THRESHOLD || Math.abs(dx) <= Math.abs(dy)) return
  if (dx > 0 && swipeStartX <= EDGE_SWIPE_WIDTH) {
    mobileSidebarOpen.value = true
  } else if (dx < 0 && mobileSidebarOpen.value) {
    mobileSidebarOpen.value = false
  }
}

onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)
  window.addEventListener('touchstart', onSwipeStart, { passive: true })
  window.addEventListener('touchend', onSwipeEnd, { passive: true })
})

onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
  window.removeEventListener('touchstart', onSwipeStart)
  window.removeEventListener('touchend', onSwipeEnd)
  // 登出延迟跳转的定时器：组件若在其触发前卸载，必须清掉，
  // 否则回调会把用户刚进入的页面强行拽回 /login 并弹出假的"已登出"
  if (exitTimer) clearTimeout(exitTimer)
})

// 折叠宽度不硬编码 64px，而是复用 Element Plus 自身的折叠宽度公式：
// .el-menu--collapse { width: calc(var(--el-menu-icon-width)
//   + var(--el-menu-base-level-padding) * 2) }（默认 24 + 2×20 = 64px）。
// 两个变量定义在 el-menu.css 的 :root 上，侧栏内联样式可直接引用；
// aside 与内部 el-menu 由同一公式驱动，主题调整 el 变量或后续版本改
// 默认值时二者不会脱节。若 Element Plus 连公式本身都改了，静态不变量
// 测试会红（对比 node_modules 里的 el-menu.css），提醒同步这里。
const SIDEBAR_COLLAPSED_WIDTH =
  'calc(var(--el-menu-icon-width) + var(--el-menu-base-level-padding) * 2)'

const sidebarStyle = computed(() => {
  if (isMobile.value) {
    return {
      transform: mobileSidebarOpen.value ? 'translateX(0)' : 'translateX(-100%)',
      width: '240px',
    }
  }
  return { width: isCollapse.value ? SIDEBAR_COLLAPSED_WIDTH : '220px' }
})

const activeMenu = computed(() => route.path)
const currentTitle = computed(() =>
  route.meta.titleKey ? t(route.meta.titleKey) : route.meta.title || ''
)

const hasPerm = (perm) => matchPermission(permissions.value, perm)

const baseMenu = [
  { path: '/dashboard', i18nKey: 'nav.dashboard', icon: Odometer, perm: '' },
  { path: '/devices', i18nKey: 'nav.devices', icon: Cpu, perm: 'device:read' },
  { path: '/alarms', i18nKey: 'nav.alarms', icon: Bell, perm: 'alarm:read' },
  { path: '/inspections', i18nKey: 'nav.inspections', icon: Tickets, perm: 'inspection:read' },
  {
    path: '/system',
    i18nKey: 'nav.system',
    icon: Setting,
    children: [
      { path: '/users', i18nKey: 'nav.users', icon: User, perm: 'user:read' },
      { path: '/roles', i18nKey: 'nav.roles', icon: Key, perm: 'role:read' },
      { path: '/audit-logs', i18nKey: 'nav.auditLogs', icon: Document, perm: 'security:audit' },
      { path: '/ip-list', i18nKey: 'nav.ipList', icon: Lock, perm: 'security:config' },
      {
        // 安全分析工作台：画像 → 撞库 → 取证在同一读权限面下用 tab 切换
        path: '/security-analysis',
        i18nKey: 'nav.securityAnalysis',
        icon: Aim,
        perm: 'security:audit',
      },
      {
        path: '/privilege-grants',
        i18nKey: 'nav.privilegeGrants',
        icon: Stamp,
        perm: 'privilege:read',
      },
    ],
  },
  { path: '/reports', i18nKey: 'nav.reports', icon: DataAnalysis, perm: 'report:read' },
  { path: '/profile', i18nKey: 'nav.profile', icon: UserFilled, perm: '' },
  { path: '/about', i18nKey: 'nav.about', icon: Flag, perm: '' },
]

const menuItems = computed(() => {
  return baseMenu
    .filter((item) => {
      if (!item.perm) return true
      return hasPerm(item.perm)
    })
    .map((item) => {
      if (item.children) {
        const filteredChildren = item.children.filter((child) => hasPerm(child.perm))
        return { ...item, children: filteredChildren }
      }
      return item
    })
    .filter((item) => !(item.children && item.children.length === 0))
})

const handleToggleSidebar = () => {
  if (isMobile.value) {
    mobileSidebarOpen.value = !mobileSidebarOpen.value
  } else {
    appStore.toggleSidebar()
  }
}

const onMenuSelect = () => {
  if (isMobile.value) {
    mobileSidebarOpen.value = false
  }
}

const handleLanguageChange = (lang) => {
  setLocale(lang)
  appStore.setLanguage(lang)
  locale.value = lang
}

const refresh = () => {
  window.location.reload()
}

const toggleFullScreen = () => {
  const docEl = document.documentElement
  const isFullscreen = !!(
    document.fullscreenElement ||
    document.webkitFullscreenElement ||
    document.mozFullScreenElement ||
    document.msFullscreenElement
  )
  if (!isFullscreen) {
    const requestFS =
      docEl.requestFullscreen ||
      docEl.webkitRequestFullscreen ||
      docEl.mozRequestFullScreen ||
      docEl.msRequestFullscreen
    const result = requestFS?.call(docEl)
    result?.catch?.(() => {})
  } else {
    const exitFS =
      document.exitFullscreen ||
      document.webkitExitFullscreen ||
      document.mozCancelFullScreen ||
      document.msExitFullscreen
    const result = exitFS?.call(document)
    result?.catch?.(() => {})
  }
}

const searchPaletteRef = ref(null)
const searchTooltip = computed(() => {
  const k = /mac/i.test(navigator.platform || navigator.userAgent || '') ? '⌘K' : 'Ctrl K'
  return `${t('common.search')} (${k})`
})
// 举报对话框开关：组件自身不持有状态，由布局层控制
const reportDialogVisible = ref(false)
const showExit = ref(false)
// 登出遮罩动画结束后跳转登录页的延迟句柄（onUnmounted 里清理）
let exitTimer = null

const handleCommand = (command) => {
  switch (command) {
    case 'profile':
      router.push('/profile')
      break
    case 'password':
      router.push('/profile')
      break
    case 'logout':
      ElMessageBox.confirm(t('auth.logoutConfirm'), t('common.confirm'), {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      })
        .then(async () => {
          // 显示优雅退出遮罩
          showExit.value = true

          // 服务端登出使 token 进入黑名单，成功后才清本地状态。
          //
          // 令牌在 httpOnly Cookie 中，JS 无法自行清除：只有服务端明确答复
          // 「会话已不可用」（401/403）时，本地登出才不会留下仍可恢复的服务端会话。
          // 网络错误 / 5xx（含 503）时令牌可能仍然有效，若清本地并提示成功，
          // 用户会误以为已登出，刷新页面后 Cookie 又会让会话复活。
          try {
            await api.auth.logout()
          } catch (err) {
            const status = err?.response?.status
            if (status !== 401 && status !== 403) {
              // 提示已由 api 响应拦截器按错误码本地化输出，此处仅中止登出
              showExit.value = false
              return
            }
          }
          authStore.clearAuth()
          // 登出必须强制断开 WebSocket 并清零引用计数：残留连接仍携带旧身份的
          // cookie，会继续接收上一个账号的权限推送
          disconnectWebSocket()

          // 等待遮罩动画完成后跳转
          exitTimer = setTimeout(() => {
            router.push('/login')
            ElMessage.success(t('auth.logoutSuccess'))
          }, 600)
        })
        .catch(() => {
          showExit.value = false
        })
      break
  }
}
</script>

<style scoped>
.app-wrapper {
  position: relative;
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
}

/* ===== 侧边栏 ===== */
.sidebar {
  background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
  background-image: linear-gradient(180deg, #0f172a 0%, #1e293b 100%), var(--xf-tech-grid);
  background-size:
    100% 100%,
    var(--xf-tech-grid-size) var(--xf-tech-grid-size);
  transition: width 0.35s var(--xf-ease-glass);
  display: flex;
  flex-direction: column;
  overflow-x: hidden;
  overflow-y: auto;
  scrollbar-width: none;
  -ms-overflow-style: none;
  position: sticky;
  /* 悬浮面板：四周离屏一圈，不与视口贴边 */
  top: var(--xf-spacing-lg);
  margin: var(--xf-spacing-lg);
  height: calc(100vh - 2 * var(--xf-spacing-lg));
  height: calc(100dvh - 2 * var(--xf-spacing-lg));
  z-index: 100;
  box-shadow: var(--xf-shadow-lg);
  /* 圆角与主区 el-card 面板同规格（--xf-radius-lg） */
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: var(--xf-radius-lg);
}

.sidebar::-webkit-scrollbar {
  display: none;
}

/* 平板横屏（769–1024px）：这一段没有侧栏中间态，折叠态 64px 侧栏加
   双侧 16px 离屏边距共占 96px，追求紧凑的用户空间利用一般。此段把
   边距收到 10px（找回 12px 宽度与高度）；悬浮观感主要来自 box-shadow
   与圆角而非边距大小，视觉不受影响。 */
@media (min-width: 769px) and (max-width: 1024px) {
  .sidebar {
    top: var(--xf-spacing-md);
    margin: var(--xf-spacing-md);
    height: calc(100vh - 2 * var(--xf-spacing-md));
    height: calc(100dvh - 2 * var(--xf-spacing-md));
  }
}

/* 移动端侧边栏：抽屉式 */
.sidebar-mobile {
  position: fixed;
  left: 0;
  top: 0;
  /* 抽屉保持贴左全高：避免 translateX(-100%) 因外边距露出侧边残影 */
  margin: 0;
  height: 100vh;
  height: 100dvh;
  border: none;
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 0 var(--xf-radius-lg) var(--xf-radius-lg) 0;
  z-index: 200;
  transition: transform 0.3s var(--xf-ease-glass);
  box-shadow: 4px 0 32px rgba(0, 0, 0, 0.4);
}

.mobile-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 150;
  backdrop-filter: blur(2px);
  /* 原生 button 只借语义，不借外观 */
  border: 0;
  padding: 0;
  cursor: pointer;
}

.mobile-overlay:focus-visible {
  outline: 2px solid var(--xf-primary);
  outline-offset: -4px;
}

/* ===== Logo ===== */
.logo {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: flex-start;
  /* 与菜单项内容起点对齐：margin-inline + padding-inline = 12px */
  gap: var(--xf-spacing-sm);
  padding-inline: calc(var(--xf-spacing-sm) * 2) var(--xf-spacing-sm);
  color: #fff;
  background: linear-gradient(135deg, #c1121f 0%, #7d0c14 100%);
  flex-shrink: 0;
  position: relative;
  overflow: hidden;
}

.sidebar-collapsed .logo {
  justify-content: center;
  padding-inline: 0;
}

.logo::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.12) 0%, transparent 50%);
  pointer-events: none;
}

.logo-icon {
  font-size: var(--xf-font-size-lg);
  filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
  z-index: 1;
}

.logo-text {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-base);
  font-weight: 700;
  white-space: nowrap;
  letter-spacing: var(--xf-tracking-wide);
  text-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  z-index: 1;
}

/* ===== 菜单 ===== */
.sidebar-menu {
  border-right: none;
  flex: 1;
  min-height: 0;
  /* 首行/末行与面板边缘留白 */
  padding-block: var(--xf-spacing-sm);
  background: transparent !important;
}

/* 展开态内边距改由组件库变量驱动：Element Plus 竖向菜单的 padding-left 规则
   .el-menu--vertical:not(.el-menu--collapse):not(.el-menu--popup-container) .el-menu-item
   特异性 (0,4,0) 高于本文件任何 :deep 选择器（(0,3,0)，且 --el-menu-level 由组件
   内联样式提供），直接声明 padding 会被盖掉——修复前实际渲染为左 20px、右 6px，
   图标起点比 logo 右移 14px。改为赋值变量后组件库 calc() 产出我们的值：
   顶层 padding-left = 6px，与 margin-inline 6px 合计 12px，与 logo 内容起点对齐；
   子项每级缩进 10px（图标起点 22px，较父项内缩 10px）；子菜单标题右内边距
   calc(6px + 24px) 恰好给绝对定位箭头（right 同步变为 6px）留出位置。
   折叠态刻意不挂这两个变量：--el-menu-base-level-padding 还参与 .el-menu--collapse
   宽度公式（aside 折叠宽度与其同源），改动会让折叠 rail 与菜单宽度脱节。 */
.sidebar-menu:not(.el-menu--collapse) {
  --el-menu-base-level-padding: var(--xf-spacing-sm);
  --el-menu-level-padding: var(--xf-spacing-md);
}

.sidebar-menu :deep(.el-menu-item),
.sidebar-menu :deep(.el-sub-menu__title) {
  /* 上下留白保证点击空间（行高 56px + 上下各 6px 间隔）；分组节奏见下方两条规则 */
  margin-block: var(--xf-spacing-sm);
  margin-inline: var(--xf-spacing-sm);
  /* 同心圆角：内层 = 外层(侧栏 lg 16px) − 内边距(sm 6px) = 10px，
     与外层圆角同圆心收敛，拐角处不"打架" */
  border-radius: calc(var(--xf-radius-lg) - var(--xf-spacing-sm));
  font-size: var(--xf-font-size-base);
  color: #94a3b8;
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
}

/* 顶层项与子项的右内边距：组件库只在低特异性混合器里给了 20px 默认值，
   左内边距已由上方变量产出 6px/16px，这里补齐右侧使水平留白对称 */
.sidebar-menu:not(.el-menu--collapse) :deep(.el-menu-item) {
  padding-right: var(--xf-spacing-sm);
}

/* 图标略小于文字，并保留图文间隙；不影响子菜单展开箭头 */
.sidebar-menu :deep(.el-menu-item .el-icon:not(.el-sub-menu__icon-arrow)),
.sidebar-menu :deep(.el-sub-menu__title .el-icon:not(.el-sub-menu__icon-arrow)) {
  font-size: var(--xf-font-size-sm);
  width: var(--xf-font-size-lg);
  margin-right: var(--xf-spacing-sm);
}

/* 同组收紧：子项纵向间隔 2px（顶层项为 6px）；缩进由 --el-menu-level-padding
   驱动（子项 padding-left 16px），不再单独声明——旧值特异性不足从未生效 */
.sidebar-menu :deep(.el-sub-menu .el-menu-item) {
  margin-block: calc(var(--xf-spacing-xs) / 2);
}

/* 不同组拉大：子菜单组与相邻项之间 10px（> 常规 6px），组边界一眼可辨。
   兄弟纵向外边距折叠取较大者，组内子项的 2px 不会抵消这里的 10px */
.sidebar-menu :deep(.el-menu-item + .el-sub-menu),
.sidebar-menu :deep(.el-sub-menu + .el-menu-item),
.sidebar-menu :deep(.el-sub-menu + .el-sub-menu) {
  margin-top: var(--xf-spacing-md);
}

/* 折叠态：仅剩图标，去掉内外边距并居中 */
.sidebar-menu.el-menu--collapse :deep(.el-menu-item),
.sidebar-menu.el-menu--collapse :deep(.el-sub-menu__title) {
  margin-inline: 0;
  padding-inline: 0;
  justify-content: center;
}

/* 折叠态图标：去掉图文间隙、恢复 18px 图标 / 24px 图标盒（折叠后无文字，
   "图标略小于文字"不适用；24px 与折叠宽度公式里的 icon-width 同源）。
   选择器必须带 .el-menu-item/.el-sub-menu__title 抬到与上方图标规则相同的
   (0,5,0) 且位置靠后才能覆盖——裸 :deep(.el-icon) 只有 (0,4,0)，
   margin-right: 6px 会残留，图标偏离中线 3px */
.sidebar-menu.el-menu--collapse :deep(.el-menu-item .el-icon),
.sidebar-menu.el-menu--collapse :deep(.el-sub-menu__title .el-icon) {
  margin-right: 0;
  width: var(--el-menu-icon-width);
  font-size: var(--xf-font-size-lg);
}

/* 折叠态图标经由 tooltip 触发层渲染：去掉其默认左内边距并居中 */
.sidebar-menu.el-menu--collapse :deep(.el-menu-tooltip__trigger) {
  padding: 0;
  justify-content: center;
}

.sidebar-menu :deep(.el-menu-item:hover),
.sidebar-menu :deep(.el-sub-menu__title:hover) {
  background: rgba(255, 255, 255, 0.06) !important;
  color: #e2e8f0;
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  background: linear-gradient(
    135deg,
    rgba(193, 18, 31, 0.25) 0%,
    rgba(193, 18, 31, 0.1) 100%
  ) !important;
  color: #fff !important;
  box-shadow:
    inset 3px 0 0 var(--xf-primary),
    0 0 20px rgba(193, 18, 31, 0.15);
}

/* ===== 移动端下拉刷新指示器 ===== */
.pull-indicator {
  position: absolute;
  top: 64px;
  left: 50%;
  transform: translateX(-50%) translateY(0);
  z-index: 40;
  display: flex;
  align-items: center;
  gap: 8px;
  pointer-events: none;
  opacity: 0;
  will-change: transform, opacity;
}

@media (max-width: 768px) {
  .pull-indicator {
    top: 56px;
  }
}

.pull-indicator__spinner {
  width: 20px;
  height: 20px;
  border: 2px solid var(--xf-border-color);
  border-top-color: var(--xf-primary);
  border-radius: 50%;
  flex-shrink: 0;
}

.pull-indicator__spinner.is-spinning {
  animation: pull-spin 0.7s linear infinite;
}

.pull-indicator__text {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  background: var(--xf-bg-card);
  padding: 6px 12px;
  border-radius: 999px;
  box-shadow: var(--xf-shadow-sm);
  border: 1px solid var(--xf-border-color);
}

@keyframes pull-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .pull-indicator__spinner.is-spinning {
    animation: none !important;
  }
}

/* ===== 主容器 ===== */
.main-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

/* ===== 导航栏 ===== */
.navbar {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  box-shadow: 0 1px 3px rgba(0, 21, 41, 0.06);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  height: 64px;
  flex-shrink: 0;
  border-bottom: 1px solid var(--xf-border-color);
  z-index: 50;
}

.navbar-left {
  display: flex;
  align-items: center;
  gap: 24px;
}

/*
   box-sizing 必须显式 content-box：element-plus 的 .el-icon 是 width/height:1em 的
   定尺寸盒，而 global.css 的 * 重置是 border-box——padding 会连内容盒一起吃掉
   （20px 图标 + 2×6px padding 后内容盒只剩 8px），svg 作为 flex 子项被 flex-shrink
   压成窄条，热区也永远停在 1em 而不是 1em + 2×padding。content-box 下 1em 指内容盒，
   padding 才真正长在图标外围（触屏 2×13 = 46×46）。
 */
.collapse-btn {
  font-size: var(--xf-font-size-xl);
  cursor: pointer;
  color: var(--xf-gray-500);
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
  box-sizing: content-box;
  padding: 6px;
  border-radius: var(--xf-radius-sm);
}

.collapse-btn:hover {
  color: var(--xf-primary);
  background: var(--xf-primary-alpha-8);
}

.collapse-btn:focus-visible,
.action-icon:focus-visible {
  outline: 2px solid var(--xf-primary);
  outline-offset: 2px;
  color: var(--xf-primary);
}

.navbar-right {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-lg);
}

/* 同 .collapse-btn：content-box 才能让 padding 长在 1em 图标外围而不是吃掉它 */
.action-icon {
  font-size: var(--xf-font-size-lg);
  cursor: pointer;
  color: var(--xf-gray-500);
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
  box-sizing: content-box;
  padding: 6px;
  border-radius: var(--xf-radius-sm);
}

.action-icon:hover {
  color: var(--xf-primary);
  background: var(--xf-primary-alpha-8);
  transform: scale(1.05);
}

/* 下拉菜单当前选中项高亮（语言/主题菜单共用） */
:global(.el-dropdown-menu__item.is-active) {
  color: var(--xf-primary);
  font-weight: 600;
  background: var(--xf-primary-alpha-8);
}

.user-dropdown {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-md);
  cursor: pointer;
  outline: none;
  padding: 4px 12px 4px 4px;
  border-radius: 999px;
  transition: background var(--xf-duration-base) var(--xf-ease-standard);
}

.user-dropdown:hover {
  background: var(--xf-gray-100);
}

.user-avatar {
  background: linear-gradient(135deg, #c1121f 0%, #7d0c14 100%);
  color: #fff;
  font-weight: 700;
  font-family: var(--xf-font-display);
  box-shadow: 0 2px 8px rgba(193, 18, 31, 0.3);
}

.user-name {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-base);
  color: var(--xf-gray-700);
  font-weight: 600;
}

/* ===== 键盘跳转链接（a11y） ===== */
/* 平时移出屏幕隐藏；获得键盘焦点时浮现在左上角。纯 CSS、无 JS。
   z-index 需压过遮罩与侧边栏；outline 用系统焦点环，不自定义颜色。 */
.skip-link {
  position: fixed;
  top: -48px;
  left: 16px;
  z-index: 3000;
  padding: 8px 16px;
  border-radius: 8px;
  background: var(--xf-gray-900, #0f172a);
  color: #fff;
  font-size: var(--xf-font-size-base);
  text-decoration: none;
  transition: top 0.15s var(--xf-ease-glass, ease);
}
.skip-link:focus-visible {
  top: 12px;
}
/* focus 兜底（不支持 :focus-visible 的旧浏览器同样要能看见） */
.skip-link:focus {
  top: 12px;
}

/* ===== 主内容区 ===== */
.main-content {
  padding: 24px;
  background: var(--xf-gray-50);
  background-image: var(--xf-tech-grid);
  background-size: var(--xf-tech-grid-size) var(--xf-tech-grid-size);
  min-height: calc(100vh - 64px);
  min-height: calc(100dvh - 64px);
  flex: 1;
}

/* ===== 路由过渡 ===== */
.fade-enter-active {
  animation: fade-in 0.3s var(--xf-ease-glass);
}
.fade-leave-active {
  animation: fade-out 0.15s var(--xf-ease-standard);
}

/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .navbar {
    padding: 0 12px;
    height: 56px;
  }
  .navbar-left {
    gap: 12px;
  }
  .navbar-right {
    gap: 8px;
  }
  .main-content {
    padding: 12px;
    min-height: calc(100vh - 56px);
    min-height: calc(100dvh - 56px);
    padding-bottom: calc(12px + env(safe-area-inset-bottom, 0px));
  }
  .user-avatar {
    width: 28px !important;
    height: 28px !important;
  }
}

@media (max-width: 480px) {
  .navbar {
    padding: 0 8px;
  }
  .main-content {
    padding: 8px;
    padding-bottom: calc(8px + env(safe-area-inset-bottom, 0px));
  }
  .navbar-right .action-icon {
    font-size: 16px;
    padding: 4px;
  }
}

/* 触屏设备：扩大导航操作图标点击热区（含主题/语言切换），满足 Apple 44×44pt 触控标准
   action-icon 18px 图标 + 2×13 = 44px；collapse-btn 20px 图标 + 2×13 = 46px
   选择器必须带上 .navbar-right / .navbar-left 把特异性抬到 (0,3,0)：裸 .action-icon
   只有 (0,2,0)，会被同文件 max-width:480px 断点里的 .navbar-right .action-icon 盖掉，
   手机（≤480px，恰是最需要大热区的设备）上 44×44 会静默退回 24×24。 */
@media (hover: none) and (pointer: coarse) {
  .navbar-right .action-icon {
    padding: 13px;
  }
  .navbar-left .collapse-btn {
    padding: 13px;
  }
}

@keyframes fade-in {
  from {
    opacity: 0;
    transform: translateY(6px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
@keyframes fade-out {
  from {
    opacity: 1;
  }
  to {
    opacity: 0;
  }
}

/* ===== 响应式 ===== */
@media (max-width: 768px) {
  .navbar {
    padding: 0 16px;
  }
  .navbar-left {
    gap: 12px;
  }
  .main-content {
    padding: 16px;
  }
}

/* ===== Apple 风格增量（侧边栏 & 导航栏交互手感层） ===== */

/* 菜单项：hover 用弹簧感曲线（可中断），active 状态柔和发光过渡 */
.sidebar-menu :deep(.el-menu-item),
.sidebar-menu :deep(.el-sub-menu__title) {
  transition:
    background-color 200ms cubic-bezier(0.32, 0.72, 0, 1),
    color 200ms cubic-bezier(0.32, 0.72, 0, 1),
    box-shadow 240ms cubic-bezier(0.32, 0.72, 0, 1);
}

/* 菜单项按下即时缩放反馈（pointer-down，非松开） */
.sidebar-menu :deep(.el-menu-item:active),
.sidebar-menu :deep(.el-sub-menu__title:active) {
  transform: scale(0.97);
  transition: transform 100ms ease-out;
}

/* 激活项：左侧指示条用渐变宽度动画（而非硬切），外发光平滑过渡 */
.sidebar-menu :deep(.el-menu-item.is-active) {
  box-shadow:
    inset 3px 0 0 var(--xf-primary),
    0 0 20px rgba(193, 18, 31, 0.15);
  transition:
    background-color 280ms cubic-bezier(0.32, 0.72, 0, 1),
    color 200ms cubic-bezier(0.32, 0.72, 0, 1),
    box-shadow 300ms cubic-bezier(0.32, 0.72, 0, 1);
}

/* 侧边栏宽度折叠/展开：更顺滑的 cubic-bezier 曲线（替代原有 ease-glass） */
.sidebar {
  transition: width 0.4s cubic-bezier(0.32, 0.72, 0, 1);
}

/* Logo 区域：材质化入场（blur+scale，非纯淡入） */
.logo {
  animation: logo-material-enter 0.5s cubic-bezier(0.32, 0.72, 0, 1) both;
}
@keyframes logo-material-enter {
  from {
    opacity: 0;
    filter: blur(6px);
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    filter: blur(0);
    transform: translateY(0);
  }
}

/* 折叠按钮 / action-icon 按压反馈 */
.collapse-btn:active,
.action-icon:active {
  transform: scale(0.92) !important; /* 覆盖 hover 的 scale(1.05) */
  transition: transform 100ms ease-out;
}

/* 导航栏 navbar 已有 backdrop-filter 材质；补 hover 阴影过渡 */
.navbar {
  transition: box-shadow 240ms cubic-bezier(0.32, 0.72, 0, 1);
}

/* 移动端侧边栏抽屉：材质化滑入（blur+translateX，非纯位移） */
.sidebar-mobile {
  transition:
    transform 0.35s cubic-bezier(0.32, 0.72, 0, 1),
    opacity 0.25s ease;
}

/* 移动端遮罩：材质化淡入 */
.mobile-overlay {
  backdrop-filter: blur(8px);
  animation: overlay-fade-in 0.3s ease both;
}
@keyframes overlay-fade-in {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

/* 悬浮面板没有 prefers-reduced-transparency 降级，是权衡后的决定而非遗漏：
   面板背景本身是不透明渐变，仅有的半透明元素（1px 边框、hover/激活底色、
   阴影、0.03 alpha 的网格纹理）全部叠在不透明底上，不存在内容透过面板
   造成可读性损失；真正含 backdrop-filter 的 navbar / 抽屉遮罩 / 弹层已由
   全局降级（apple-refine.css §19）覆盖。日后若把面板改成磨砂材质，必须
   在此补 @media (prefers-reduced-transparency: reduce) 换不透明实底。 */

/* 无障碍降级 */
@media (prefers-reduced-motion: reduce) {
  .logo {
    animation: none !important;
  }
  .sidebar,
  .sidebar-mobile {
    transition: none !important;
  }
  .sidebar-menu :deep(.el-menu-item:active),
  .sidebar-menu :deep(.el-sub-menu__title:active),
  .collapse-btn:active,
  .action-icon:active {
    transform: none !important;
  }
  .mobile-overlay {
    animation: none !important;
  }
}
</style>
