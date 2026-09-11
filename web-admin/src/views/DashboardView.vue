<template>
  <div class="dashboard" :class="loading ? 'is-loading' : 'is-loaded'">
    <!-- ===== 骨架屏：与真实布局同构，内容到达后直接替换（零位移） ===== -->
    <template v-if="loading">
      <el-card class="welcome-card" shadow="never">
        <GlassSkeleton variant="welcome" :avatar-size="64" />
      </el-card>

      <el-row :gutter="20" class="stat-row">
        <el-col v-for="i in 4" :key="i" :xs="12" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <GlassSkeleton variant="stat" />
          </el-card>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <el-col :xs="24" :md="16">
          <el-card shadow="never" class="chart-card">
            <template #header>
              <div class="card-header">
                <span class="sk-block sk-text" style="width: 120px" />
              </div>
            </template>
            <GlassSkeleton variant="chart" />
          </el-card>
        </el-col>
        <el-col :xs="24" :md="8">
          <el-card shadow="never" class="chart-card">
            <template #header>
              <div class="card-header">
                <span class="sk-block sk-text" style="width: 100px" />
              </div>
            </template>
            <GlassSkeleton variant="chart" />
          </el-card>
        </el-col>
      </el-row>

      <el-card shadow="never" class="alarm-card">
        <template #header>
          <div class="card-header">
            <span class="sk-block sk-text" style="width: 100px" />
          </div>
        </template>
        <GlassSkeleton variant="table" :rows="5" />
      </el-card>
    </template>

    <!-- ===== 真实内容 ===== -->
    <template v-else>
      <!-- 欢迎卡片（D-2 拆为 DashboardWelcome 组件，时钟生命周期组件自理） -->
      <DashboardWelcome :current-user="currentUser" />

      <!-- 数据卡片（P3-39：无 report:read 时整块不渲染，避免显示一排「-」占位） -->
      <el-row v-if="canReadReport" :gutter="20" class="stat-row">
        <el-col v-for="item in stats" :key="item.title" :xs="12" :sm="12" :md="6">
          <el-card shadow="hover" class="stat-card">
            <div class="stat-body">
              <div class="stat-info">
                <div class="stat-title">
                  {{ item.title }}
                </div>
                <div class="stat-value">
                  {{ item.value }}
                </div>
                <div class="stat-trend">
                  <el-icon :class="item.trend > 0 ? 'up' : 'down'">
                    <CaretTop v-if="item.trend > 0" />
                    <CaretBottom v-else />
                  </el-icon>
                  <span :class="item.trend > 0 ? 'up' : 'down'">
                    {{ item.trendLabel || '' }}
                  </span>
                </div>
              </div>
              <div class="stat-icon" :style="{ background: item.color }">
                <el-icon><component :is="item.icon" /></el-icon>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- 图表区（D-2 拆为 DashboardCharts 组件；P3-39：无 report:read 不渲染） -->
      <DashboardCharts v-if="canShowCharts" ref="chartsRef" />

      <!-- 最近报警（D-2 拆为 RecentAlarmsCard 纯渲染组件；P3-39：无 alarm:read 不渲染） -->
      <RecentAlarmsCard v-if="canReadAlarm" :rows="recentAlarms" />
    </template>
  </div>
</template>

<script setup>
import {
  ref,
  computed,
  onMounted,
  onUnmounted,
  markRaw,
  nextTick,
  watch,
  defineAsyncComponent,
  h,
} from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useI18n } from 'vue-i18n'
import { CaretTop, CaretBottom, Cpu, Bell, UserFilled } from '@element-plus/icons-vue'

import { useAuthStore } from '@/store'
import { usePermission } from '@/composables/usePermission'
import { api, isCanceledError } from '@/utils/api'
// 类型/状态 → i18n 标签映射（O-1 抽取的单一事实来源，与 ReportView 共用）
import { makeAlarmTypeLabels, makeAlarmStatusLabels } from '@/utils/labelMaps'
// D-2：欢迎卡/图表区/最近报警拆为子组件（echarts 与图表数据加载随之迁出）
// 注：DashboardCharts 改为异步组件（见下方 canShowCharts 之后的定义），
// 不再在此静态引入 —— 否则 echarts 会被打进本视图 chunk，阻塞首屏渲染。
import DashboardWelcome from '@/components/DashboardWelcome.vue'
import RecentAlarmsCard from '@/components/RecentAlarmsCard.vue'
import GlassSkeleton from '@/components/GlassSkeleton.vue'

const authStore = useAuthStore()
const { hasPerm } = usePermission()
const currentUser = computed(() => authStore.currentUser)
const { t, locale } = useI18n()

/**
 * 首页各数据块对应的后端权限（P3-39）
 *
 * 原实现无差别请求全部接口：仅有 device 权限的用户一进首页就连吃 2-3 个
 * 403 红框，且 5 分钟自动刷新会周期性重复 —— 用户没做错任何事，
 * 却被反复告知"无权访问"。更糟的是这训练用户忽略红框，
 * 真正的权限异常也会被当成噪音划过去。
 *
 * 路由 /dashboard 本身不带 permission（首页必须对所有登录用户可达），
 * 所以门控只能落在数据块粒度：有权限才请求、无权限则整块不渲染。
 * 权限码与后端路由逐一核对：
 *   reports.getDashboard / getAlarms / getDevices → report:read
 *   users.getStats                               → user:read
 *   alarms.getList                               → alarm:read
 */
const canReadReport = computed(() => hasPerm('report:read'))
const canReadUserStats = computed(() => hasPerm('user:read'))
const canReadAlarm = computed(() => hasPerm('alarm:read'))
// 图表数据全部来自 report 接口，无该权限时整个图表区不渲染（而非渲染空图表）
const canShowCharts = canReadReport

// 图表区异步化：echarts（约 583KB / gzip 193KB）不再阻塞 Dashboard 首屏。
// 关键点在于立即触发一次 prefetch —— 让 echarts chunk 与 Dashboard 的数据请求
// 并行下载。若只在组件渲染时才加载，会退化成「等数据返回 → 才开始下载 echarts」
// 的串行等待，反而比同步引入更慢。import() 返回同一 Promise，不会重复下载。
const loadChartsComponent = () => import('@/components/DashboardCharts.vue')
if (canShowCharts.value) loadChartsComponent()

const DashboardCharts = defineAsyncComponent({
  loader: loadChartsComponent,
  // 数据已就绪、echarts 仍在下载时用骨架占位，避免图表区塌陷造成布局抖动
  loadingComponent: {
    render: () =>
      h('div', { class: 'charts-async-skeleton' }, [
        h(GlassSkeleton, { variant: 'chart' }),
        h(GlassSkeleton, { variant: 'chart' }),
      ]),
  },
  delay: 0,
  timeout: 20000,
})

// 问候语与实时时钟已迁入 DashboardWelcome.vue（D-2）

// 图表组件引用：定时/可见性恢复/语言切换时经 load() 触发刷新
const chartsRef = ref(null)

const stats = ref([
  {
    title: t('dashboard.totalDevices'),
    value: '-',
    trend: 0,
    color: 'linear-gradient(135deg,#c1121f,#16a34a)',
    icon: markRaw(Cpu),
  },
  {
    title: t('dashboard.onlineDevices'),
    value: '-',
    trend: 0,
    color: 'linear-gradient(135deg,#15803d,#16a34a)',
    icon: markRaw(Cpu),
  },
  {
    title: t('dashboard.pendingAlarms'),
    value: '-',
    trend: 0,
    color: 'linear-gradient(135deg,#b91c1c,#d97706)',
    icon: markRaw(Bell),
  },
  {
    title: t('dashboard.systemUsers'),
    value: '-',
    trend: 0,
    color: 'linear-gradient(135deg,#e63946,#c1121f)',
    icon: markRaw(UserFilled),
  },
])

const recentAlarms = ref([])
const loading = ref(true)

// 图表实例/初始化/配色/窗口 resize 已迁入 DashboardCharts.vue（D-2）

let refreshTimer = null

// 自动刷新数据（每5分钟）
const startAutoRefresh = () => {
  refreshTimer = setInterval(
    () => {
      if (document.visibilityState === 'visible') {
        loadDashboardData()
        loadRecentAlarms()
        chartsRef.value?.load?.()
      }
    },
    5 * 60 * 1000
  )
}

const handleVisibilityChange = () => {
  if (document.visibilityState === 'visible') {
    loadDashboardData()
    loadRecentAlarms()
    chartsRef.value?.load?.()
  }
}

const stopAutoRefresh = () => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

const loadDashboardData = async () => {
  // P3-39：无 report:read 时整个统计卡片区不渲染，也就不必请求
  if (!canReadReport.value) return
  try {
    const [reportRes, userRes] = await Promise.all([
      api.reports.getDashboard(),
      // 用户统计单独门控：只有 report:read 没有 user:read 的角色很常见
      canReadUserStats.value
        ? api.users.getStats().catch(() => ({ data: { data: {} } }))
        : Promise.resolve({ data: { data: {} } }),
    ])

    if (reportRes.data.success) {
      const d = reportRes.data.data
      const userStats = userRes.data?.data || {}

      stats.value = [
        {
          title: t('dashboard.totalDevices'),
          value: d.devices?.total || 0,
          trend: 0,
          color: 'linear-gradient(135deg,#c1121f,#16a34a)',
          icon: markRaw(Cpu),
        },
        {
          title: t('dashboard.onlineDevices'),
          value: d.devices?.online || 0,
          trend: 0,
          color: 'linear-gradient(135deg,#15803d,#16a34a)',
          icon: markRaw(Cpu),
        },
        {
          title: t('dashboard.pendingAlarms'),
          value: d.alarms?.pending || 0,
          trend: 0,
          color: 'linear-gradient(135deg,#b91c1c,#d97706)',
          icon: markRaw(Bell),
        },
        {
          title: t('dashboard.systemUsers'),
          value: userStats.active || userStats.total || 0,
          trend: 0,
          color: 'linear-gradient(135deg,#e63946,#c1121f)',
          icon: markRaw(UserFilled),
        },
      ]
    }
  } catch (e) {
    // B-3：失败给一次非阻断式提示，避免骨架屏消失后页面静默显示 0 值；
    // FE-L1：路由切换取消（abort）不提示——用户已到达新页面，假错误训练用户忽略红框
    if (isCanceledError(e)) return
    ElMessage.error(t('messages.loadFailed'))
  }
}

const loadRecentAlarms = async () => {
  // P3-39：无 alarm:read 时「最近报警」整块不渲染
  if (!canReadAlarm.value) return
  try {
    const res = await api.alarms.getList({ limit: 5 })
    const list = res?.data?.data || []
    recentAlarms.value = list
      .map((a) => ({
        time: a.occurredAt
          ? new Date(a.occurredAt).toLocaleString(locale.value, { hour12: false })
          : '',
        location: formatLocation(a.location),
        type: alarmTypeLabel(a.alarmType),
        tagType:
          a.level === 'critical' || a.level === 'emergency'
            ? 'danger'
            : a.level === 'warning'
              ? 'warning'
              : 'info',
        status: statusText(a.status),
        statusType:
          a.status === 'resolved'
            ? 'success'
            : a.status === 'processing'
              ? 'warning'
              : a.status === 'pending'
                ? 'danger'
                : 'info',
      }))
      .slice(0, 5)
  } catch (e) {
    // B-3：失败给一次非阻断式提示；FE-L1：取消不提示
    if (isCanceledError(e)) return
    ElMessage.error(t('messages.loadFailed'))
  }
}

const formatLocation = (loc) => {
  if (!loc) return ''
  return [loc.building, loc.floor, loc.room].filter(Boolean).join(' ')
}

const alarmTypeLabel = (type) => makeAlarmTypeLabels(t)[type] || type

const statusText = (s) => makeAlarmStatusLabels(t)[s] || s

// 图表数据加载（loadChartData）已迁入 DashboardCharts.vue，经 load() 暴露（D-2）

onMounted(() => {
  // 时钟与窗口 resize 监听已分别迁入 DashboardWelcome / DashboardCharts（D-2）
  document.addEventListener('visibilitychange', handleVisibilityChange)
  startAutoRefresh()

  nextTick(async () => {
    // 首屏：骨架屏占位 → 数据到达后直接替换（v-if/v-else 同构布局，无位移）
    try {
      await Promise.allSettled([loadDashboardData(), loadRecentAlarms()])
    } finally {
      loading.value = false
      // 图表容器随内容分支挂载，待 DOM 就绪后再初始化图表
      await nextTick()
      chartsRef.value?.load?.()
    }
  })
})

// 语言切换时重新加载数据与图表标签
watch(locale, () => {
  loadDashboardData()
  loadRecentAlarms()

  // 骨架屏阶段图表容器尚未挂载，跳过图表重建（首屏加载完成后会另行初始化）；
  // DashboardCharts 内部也有 locale watch，但容器不存在时不会发请求
  if (!loading.value) chartsRef.value?.load?.()
})

onUnmounted(() => {
  document.removeEventListener('visibilitychange', handleVisibilityChange)
  stopAutoRefresh()
  // 时钟定时器与 echarts 实例销毁由各自组件卸载时自理（D-2）
})
</script>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* 骨架屏阶段与内容直换阶段均禁用入场动画：
   占位块 → 真实内容为原地直接替换，无淡入/位移，页面不跳 */
.dashboard.is-loading .stat-card,
.dashboard.is-loading .chart-card,
.dashboard.is-loading .alarm-card,
.dashboard.is-loaded .stat-card,
.dashboard.is-loaded .chart-card,
.dashboard.is-loaded .alarm-card {
  animation: none;
}

/* ===== 欢迎卡片 ===== */
.welcome-card {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  border: none;
  position: relative;
  overflow: hidden;
}

.welcome-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: var(--xf-tech-grid);
  background-size: var(--xf-tech-grid-size) var(--xf-tech-grid-size);
  opacity: 0.5;
  pointer-events: none;
}

.welcome-card::after {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  width: 40%;
  height: 100%;
  background: radial-gradient(ellipse at right center, rgba(193, 18, 31, 0.15) 0%, transparent 70%);
  pointer-events: none;
}

.welcome-card :deep(.el-card__body) {
  padding: 28px 32px;
  position: relative;
  z-index: 1;
}

/* 欢迎卡内容样式（文案/头像/时钟）已随组件迁入 DashboardWelcome.vue（D-2）。
   .welcome-card 本体样式保留：骨架屏分支仍使用该类的深色底卡片 */

/* ===== 数据统计卡片 ===== */
.stat-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.stat-card:nth-child(1) {
  animation-delay: 0.05s;
}
.stat-card:nth-child(2) {
  animation-delay: 0.1s;
}
.stat-card:nth-child(3) {
  animation-delay: 0.15s;
}
.stat-card:nth-child(4) {
  animation-delay: 0.2s;
}

.stat-card :deep(.el-card__body) {
  padding: 20px 24px;
}

.stat-body {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-title {
  font-family: var(--xf-font-body);
  font-weight: 500;
  color: var(--xf-gray-500);
  font-size: var(--xf-font-size-xs);
  margin-bottom: var(--xf-spacing-xs);
  letter-spacing: var(--xf-tracking-wide);
  text-transform: uppercase;
}

.stat-value {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-2xl);
  font-weight: 700;
  color: var(--xf-gray-900);
  margin-bottom: var(--xf-spacing-xs);
  letter-spacing: var(--xf-tracking-tight);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.stat-trend {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-xs);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  font-family: var(--xf-font-mono);
}

.stat-trend .up {
  color: var(--xf-success);
}
.stat-trend .down {
  color: var(--xf-danger);
}

.stat-icon {
  width: 52px;
  height: 52px;
  border-radius: var(--xf-radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 24px;
  flex-shrink: 0;
  position: relative;
  overflow: hidden;
}

.stat-icon::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.25) 0%, transparent 50%);
}

/* ===== 图表卡片 ===== */
.chart-card {
  height: 380px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.25s;
}

.chart-card :deep(.el-card__body) {
  height: calc(100% - 56px);
  padding: 16px 20px;
}

/* chart-container 已随图表迁入 DashboardCharts.vue（D-2） */

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-base);
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-gray-800);
}

/* ===== 报警记录卡片 ===== */
.alarm-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.3s;
}

/* ===== 移动端适配 =====
   欢迎卡内容的降级规则已随组件迁入 DashboardWelcome.vue（D-2）；
   此处只保留骨架屏仍用到的图表卡高度与欢迎卡 body 收紧 */
@media (max-width: 768px) {
  .chart-card {
    height: 300px;
  }
  .stat-value {
    font-size: var(--xf-font-size-xl);
  }
}

@media (max-width: 480px) {
  .welcome-card :deep(.el-card__body) {
    padding: 18px 16px;
  }
}

/* ===== Apple 风格增量（交互手感层：只叠反馈与过渡，不改布局） ===== */

/* 可交互元素按压即时反馈（pointer-down，非松开） */
.el-button:active {
  transform: scale(0.97);
  transition: transform 100ms ease-out;
}

/* 卡片 hover 轻浮起（可中断阴影过渡，无弹跳，克制） */
.el-card {
  transition: box-shadow 280ms cubic-bezier(0.32, 0.72, 0, 1);
}
.el-card:hover {
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
}

/* 表格行背景平滑渐变，避免斑马纹/状态色跳变 */
:deep(.el-table .el-table__row td.el-table__cell) {
  transition: background-color 150ms ease;
}

/* 标签（el-tag）hover 轻微加深，仅提示可读性 */
:deep(.el-tag) {
  transition: opacity 150ms ease;
}

/* 异步图表区加载中的占位骨架：与 DashboardCharts 的 16/8 分栏保持一致，
   避免 echarts 下载期间图表区塌陷导致整页跳动 */
.charts-async-skeleton {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 20px;
}

@media (max-width: 768px) {
  .charts-async-skeleton {
    grid-template-columns: 1fr;
  }
}

/* 无障碍降级：本页新增动效全部纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .el-button:active {
    transform: none !important;
  }
  .el-card {
    transition: opacity 150ms ease !important;
  }
  .el-card:hover {
    box-shadow: none !important;
  }
  :deep(.el-table .el-table__row td.el-table__cell) {
    transition: none !important;
  }
}
</style>
