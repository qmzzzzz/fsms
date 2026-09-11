<template>
  <div class="app-wrapper" :class="{ 'mobile-sidebar-open': mobileSidebarOpen }">
    <!-- 移动端遮罩 -->
    <div
      v-if="isMobile && mobileSidebarOpen"
      class="mobile-overlay"
      @click="mobileSidebarOpen = false"
    />

    <!-- 侧边栏 -->
    <aside class="sidebar" :class="{ 'sidebar-mobile': isMobile }" :style="sidebarStyle">
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
            <el-menu-item v-for="child in item.children" :key="child.path" :index="child.path">
              <el-icon><component :is="child.icon" /></el-icon>
              <template #title>
                {{ t(child.i18nKey) }}
              </template>
            </el-menu-item>
          </el-sub-menu>
          <el-menu-item v-else :index="item.path">
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
          <el-icon class="collapse-btn" @click="handleToggleSidebar">
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
          <!-- 语言切换 -->
          <el-dropdown trigger="click" @command="handleLanguageChange">
            <el-icon class="action-icon" :title="t('common.language')">
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

          <!-- 主题切换：下拉选择，与语言切换交互一致 -->
          <el-dropdown trigger="click" @command="handleThemeChange">
            <el-icon class="action-icon" :title="t('common.theme')">
              <Monitor v-if="themeMode === 'system'" />
              <Sunny v-else-if="themeMode === 'light'" />
              <Moon v-else />
            </el-icon>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="system" :class="{ 'is-active': themeMode === 'system' }">
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

          <el-tooltip :content="t('common.refresh')" placement="bottom">
            <el-icon class="action-icon" @click="refresh">
              <Refresh />
            </el-icon>
          </el-tooltip>
          <el-tooltip
            v-if="canToggleFullScreen"
            :content="$t('全屏')"
            placement="bottom"
            class="tech-hide-mobile"
          >
            <el-icon class="action-icon" @click="toggleFullScreen">
              <FullScreen />
            </el-icon>
          </el-tooltip>
          <el-dropdown @command="handleCommand">
            <span class="user-dropdown">
              <el-avatar :size="32" class="user-avatar">{{ avatarText }}</el-avatar>
              <span class="user-name tech-hide-mobile">{{
                currentUser?.username || '未登录'
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

      <main class="main-content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" :key="route.fullPath" />
          </transition>
        </router-view>
      </main>
    </div>
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
  SwitchButton,
  Document,
  Sunny,
  Moon,
  Monitor,
  Operation,
} from '@element-plus/icons-vue'
import { useAuthStore, useAppStore } from '@/store'
import { matchPermission } from '@/utils/permission'
import { api } from '@/utils/api'
import { setLocale } from '@/i18n'
import { usePermissionSync } from '@/composables/usePermissionSync'
import { disconnectWebSocket } from '@/utils/websocket'

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

// 移动端检测
const isMobile = ref(false)
const mobileSidebarOpen = ref(false)

const checkMobile = () => {
  isMobile.value = window.innerWidth <= 768
  if (isMobile.value) {
    appStore.sidebarCollapsed = false
  }
}

onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)
})

onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
})

const sidebarStyle = computed(() => {
  if (isMobile.value) {
    return {
      transform: mobileSidebarOpen.value ? 'translateX(0)' : 'translateX(-100%)',
      width: '240px',
    }
  }
  return { width: isCollapse.value ? '64px' : '220px' }
})

const activeMenu = computed(() => route.path)
const currentTitle = computed(() =>
  route.meta.titleKey ? t(route.meta.titleKey) : route.meta.title || ''
)

const avatarText = computed(() => {
  const name = currentUser.value?.username || ''
  return name.slice(0, 1).toUpperCase()
})

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
          // 服务端登出使 token 进入黑名单，成功后才清本地状态。
          //
          // 后端 P2-26 起，令牌吊销未落库会返回 503/LOGOUT_REVOKE_FAILED——
          // 此时**不能**清本地状态并跳登录页：那会让用户以为已登出，
          // 而服务端令牌在其剩余有效期内仍然可用（被窃取即持续可用）。
          // 保持登录态并提示重试，是把「未完成」如实呈现给用户。
          // 其余失败（网络不可达、令牌已过期的 401）仍完成本地登出，
          // 避免用户卡在无法操作的已登录态。
          try {
            await api.auth.logout()
          } catch (err) {
            if (err?.response?.status === 503) {
              // 提示已由 api 响应拦截器按错误码本地化输出，此处仅中止登出
              return
            }
          }
          authStore.clearAuth()
          // 登出必须强制断开 WebSocket 并清零引用计数：残留连接仍携带旧身份的
          // cookie，会继续接收上一个账号的权限推送
          disconnectWebSocket()
          router.push('/login')
          ElMessage.success(t('auth.logoutSuccess'))
        })
        .catch(() => {})
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
  overflow-x: hidden;
  overflow-y: auto;
  scrollbar-width: none;
  -ms-overflow-style: none;
  position: sticky;
  top: 0;
  height: 100vh;
  height: 100dvh;
  z-index: 100;
  box-shadow: 4px 0 24px rgba(0, 0, 0, 0.15);
  border-right: 1px solid rgba(255, 255, 255, 0.06);
}

.sidebar::-webkit-scrollbar {
  display: none;
}

/* 移动端侧边栏：抽屉式 */
.sidebar-mobile {
  position: fixed;
  left: 0;
  top: 0;
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
}

/* ===== Logo ===== */
.logo {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: #fff;
  background: linear-gradient(135deg, #c1121f 0%, #7d0c14 100%);
  flex-shrink: 0;
  position: relative;
  overflow: hidden;
}

.logo::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.12) 0%, transparent 50%);
  pointer-events: none;
}

.logo-icon {
  font-size: 24px;
  filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
  z-index: 1;
}

.logo-text {
  font-family: var(--xf-font-display);
  font-size: 15px;
  font-weight: 700;
  white-space: nowrap;
  letter-spacing: var(--xf-tracking-wide);
  text-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  z-index: 1;
}

/* ===== 菜单 ===== */
.sidebar-menu {
  border-right: none;
  height: calc(100vh - 64px);
  height: calc(100dvh - 64px);
  border-radius: 0;
  background: transparent !important;
}

.sidebar-menu :deep(.el-menu-item),
.sidebar-menu :deep(.el-sub-menu__title) {
  margin: 2px 8px;
  border-radius: var(--xf-radius-sm);
  color: #94a3b8;
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
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

.collapse-btn {
  font-size: 20px;
  cursor: pointer;
  color: var(--xf-gray-500);
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
  padding: 6px;
  border-radius: var(--xf-radius-sm);
}

.collapse-btn:hover {
  color: var(--xf-primary);
  background: var(--xf-primary-alpha-8);
}

.navbar-right {
  display: flex;
  align-items: center;
  gap: 16px;
}

.action-icon {
  font-size: 18px;
  cursor: pointer;
  color: var(--xf-gray-500);
  transition: all var(--xf-duration-base) var(--xf-ease-standard);
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
  gap: 10px;
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
  font-size: 14px;
  color: var(--xf-gray-700);
  font-weight: 600;
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

/* 触屏设备：扩大导航操作图标点击热区（含主题/语言切换），满足 ≥40px 触控标准 */
@media (hover: none) and (pointer: coarse) {
  .action-icon {
    padding: 9px;
  }
  .collapse-btn {
    padding: 9px;
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
