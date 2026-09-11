<template>
  <div class="page">
    <el-card shadow="never">
      <div class="about-header">
        <el-icon class="about-icon">
          <Flag />
        </el-icon>
        <div>
          <h2>{{ $t('login.brandTitle') }}</h2>
          <p class="version">v{{ APP_VERSION }}</p>
        </div>
      </div>
      <el-divider />
      <el-descriptions :column="2" border>
        <el-descriptions-item :label="$t('about.systemName')">
          {{ $t('about.description') }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('about.versionLabel')">
          {{ APP_VERSION }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('about.backendTech')">
          Node.js + Express + MongoDB
        </el-descriptions-item>
        <el-descriptions-item :label="$t('about.frontendTech')">
          Vue 3 + Vite + Element Plus
        </el-descriptions-item>
        <el-descriptions-item :label="$t('about.permissionModel')"> RBAC </el-descriptions-item>
        <el-descriptions-item :label="$t('about.license')"> MIT </el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">
        {{ $t('about.coreFeatures') }}
      </el-divider>
      <el-row :gutter="16">
        <el-col v-for="f in features" :key="f.title" :xs="12" :md="8">
          <div class="feature-item">
            <el-icon :size="28" :color="f.color">
              <component :is="f.icon" />
            </el-icon>
            <div>
              <h4>{{ f.title }}</h4>
              <p>{{ f.desc }}</p>
            </div>
          </div>
        </el-col>
      </el-row>
    </el-card>

    <!-- 系统运行指标（O-8：/api/metrics snapshot，security:audit 门控） -->
    <el-card v-if="canViewMetrics" shadow="never" class="metrics-card">
      <template #header>
        <div class="card-header">
          <span>{{ $t('about.metrics.title') }}</span>
          <el-tag size="small" type="info">
            {{ $t('about.metrics.live') }}
          </el-tag>
        </div>
      </template>
      <div v-if="metricsSnap" class="metrics-body">
        <div class="metrics-stats">
          <div class="metrics-stat">
            <div class="metrics-stat-value">
              {{ metricsSnap.summary.totalRequests }}
            </div>
            <div class="metrics-stat-label">
              {{ $t('about.metrics.totalRequests') }}
            </div>
          </div>
          <div class="metrics-stat">
            <div class="metrics-stat-value">
              {{ metricsSnap.summary.totalErrors }}
            </div>
            <div class="metrics-stat-label">
              {{ $t('about.metrics.totalErrors') }}
            </div>
          </div>
          <div class="metrics-stat">
            <div class="metrics-stat-value">
              {{ (metricsSnap.summary.errorRate * 100).toFixed(2) }}%
            </div>
            <div class="metrics-stat-label">
              {{ $t('about.metrics.errorRate') }}
            </div>
          </div>
          <div class="metrics-stat">
            <div class="metrics-stat-value">{{ metricsSnap.latency.avgSeconds }}s</div>
            <div class="metrics-stat-label">
              {{ $t('about.metrics.avgLatency') }}
            </div>
          </div>
          <div class="metrics-stat">
            <div class="metrics-stat-value">
              {{ formatUptime(metricsSnap.process.uptimeSeconds) }}
            </div>
            <div class="metrics-stat-label">
              {{ $t('about.metrics.uptime') }}
            </div>
          </div>
        </div>
        <div v-if="topRoutes.length" class="metrics-routes">
          <div v-for="r in topRoutes" :key="r.route" class="metrics-route">
            <span class="route-name">{{ r.route }}</span>
            <div class="route-bar">
              <div class="route-bar-fill" :style="{ width: routeBarWidth(r) }" />
            </div>
            <span class="route-count">{{ r.requests }}</span>
          </div>
        </div>
        <div v-if="metricsAlerts.length" class="metrics-alerts">
          <el-tag
            v-for="a in metricsAlerts"
            :key="a.type + a.level"
            type="warning"
            size="small"
            class="metrics-alert-tag"
          >
            {{ a.type }}({{ $t('about.metrics.level.' + a.level) }}) × {{ a.count }}
          </el-tag>
        </div>
      </div>
      <el-empty v-else :description="$t('common.noData')" :image-size="80" />
    </el-card>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Flag, Cpu, Bell, Key, Document, Lock } from '@element-plus/icons-vue'
import { usePermission } from '@/composables/usePermission'
import { api } from '@/utils/api'

const { t } = useI18n()
const { hasPerm } = usePermission()

// 版本号统一常量：两处展示共用，与 package.json 的 version 字段同步维护
const APP_VERSION = '1.0.0'

const features = computed(() => [
  {
    title: t('about.featureDevice'),
    desc: t('about.featureDeviceDesc'),
    icon: Cpu,
    color: '#475569',
  },
  {
    title: t('about.featureAlarm'),
    desc: t('about.featureAlarmDesc'),
    icon: Bell,
    color: '#e63946',
  },
  {
    title: t('about.featurePermission'),
    desc: t('about.featurePermissionDesc'),
    icon: Key,
    color: '#c1121f',
  },
  {
    title: t('about.featureAudit'),
    desc: t('about.featureAuditDesc'),
    icon: Document,
    color: '#16a34a',
  },
  {
    title: t('about.featureEncryption'),
    desc: t('about.featureEncryptionDesc'),
    icon: Lock,
    color: '#d97706',
  },
])

// ================= 系统运行指标（O-8：/api/metrics snapshot） =================

/**
 * 权限门控（P3-39 同思路）：后端 /api/metrics 要求 security:audit，
 * 无权限时整卡不渲染也不发请求——否则用户每次进「关于」页都会吃一个 403。
 * 这张卡是管理面数据（QPS/延迟/告警计数），权限模型里与审计日志同级。
 */
const canViewMetrics = computed(() => hasPerm('security:audit'))

const metricsSnap = ref(null)

/** 请求数 Top 路由条数：条形图太多会占满整卡且失去对比意义 */
const TOP_ROUTES_COUNT = 8

/** 后端 routes 已按 requests 降序，直接切片即可，无需前端重排 */
const topRoutes = computed(() => (metricsSnap.value?.routes || []).slice(0, TOP_ROUTES_COUNT))

const metricsAlerts = computed(() => metricsSnap.value?.alerts || [])

/**
 * 条形图宽度：按 Top 路由中的最大请求数归一化。
 * 基准取「本批最大值」而非 totalRequests——后者会把所有条都压成细线，
 * 图形失去对比作用。max 为 0（无数据）时固定 0%。
 */
const routeBarWidth = (r) => {
  const max = Math.max(...topRoutes.value.map((x) => x.requests), 0)
  if (!max) return '0%'
  return `${Math.round((r.requests / max) * 100)}%`
}

/**
 * 运行时长人类可读化。
 * 超过一天却显示「86400 秒」或「1440 分钟」都读不懂；
 * 不到 1 分钟才用秒，避免刚启动时显示「0 分钟」。
 */
const formatUptime = (seconds) => {
  const s = Math.max(0, Math.floor(Number(seconds) || 0))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

/**
 * 拉取指标快照。
 * 失败静默：卡片显示空态（el-empty）而非红框——此页是「关于系统」，
 * 指标是附属信息，不能因为附属数据不可用就让整页报错。
 * 静默时保留上一次数据（若有）：轮询过程中瞬时失败不该把面板清空。
 */
const loadMetrics = async () => {
  if (!canViewMetrics.value) return
  try {
    const { data: resp } = await api.reports.getMetrics()
    if (!resp?.success || !resp.data) return
    // FE-L2：形状归一化兜底——后端契约调整时卡片降级显示 0 值而非 NaN/渲染异常
    const d = resp.data
    metricsSnap.value = {
      ...d,
      summary: { totalRequests: 0, totalErrors: 0, errorRate: 0, ...(d.summary || {}) },
      latency: { avgSeconds: 0, byRoute: {}, ...(d.latency || {}) },
      routes: Array.isArray(d.routes) ? d.routes : [],
      alerts: Array.isArray(d.alerts) ? d.alerts : [],
      process: { uptimeSeconds: 0, rssMB: 0, heapUsedMB: 0, ...(d.process || {}) },
    }
  } catch (_) {
    // 静默：保留上一次数据
  }
}

/**
 * 30s 轮询刷新。
 * 取 30s 而非更短：指标是进程内计数器快照，非趋势数据；
 * 更快轮询只会给认证接口加压，且面板上的数字变化肉眼也读不出差异。
 * 页面隐藏时暂停（visibilitychange）与 DashboardView 时钟同思路。
 */
const METRICS_POLL_MS = 30 * 1000
let metricsTimer = null

onMounted(() => {
  loadMetrics()
  metricsTimer = setInterval(() => {
    // 隐藏时暂停；不以上次成败为条件——首次失败后不重试，
    // 卡片就会一直停在空态直到用户重新进入本页
    if (document.visibilityState === 'visible') loadMetrics()
  }, METRICS_POLL_MS)
})

onUnmounted(() => {
  if (metricsTimer) {
    clearInterval(metricsTimer)
    metricsTimer = null
  }
})
</script>

<style scoped>
.page {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.about-header {
  display: flex;
  align-items: center;
  gap: 16px;
}

.about-icon {
  font-size: 48px;
  color: #c1121f;
  filter: drop-shadow(0 2px 8px rgba(193, 18, 31, 0.2));
}

.about-header h2 {
  margin: 0;
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-xl);
  font-weight: 700;
  letter-spacing: var(--xf-tracking-tight);
}

.version {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-600);
  margin: 4px 0 0;
}

.feature-item {
  display: flex;
  gap: 12px;
  padding: 16px;
  background: var(--xf-gray-50);
  border-radius: var(--xf-radius-sm);
  margin-bottom: 16px;
  transition:
    transform var(--xf-duration-base) var(--xf-ease-glass),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.feature-item:hover {
  transform: translateY(-2px);
  box-shadow: var(--xf-shadow-md);
}

.el-col:nth-child(1) .feature-item {
  animation-delay: 0.05s;
}
.el-col:nth-child(2) .feature-item {
  animation-delay: 0.1s;
}
.el-col:nth-child(3) .feature-item {
  animation-delay: 0.15s;
}
.el-col:nth-child(4) .feature-item {
  animation-delay: 0.2s;
}
.el-col:nth-child(5) .feature-item {
  animation-delay: 0.25s;
}

.feature-item h4 {
  margin: 0 0 4px;
  font-family: var(--xf-font-display);
  font-weight: 600;
}

.feature-item p {
  margin: 0;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
}

/* ===== 系统运行指标卡（O-8） ===== */
.metrics-card {
  margin-top: 16px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.15s;
}

.metrics-card .card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-base);
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-gray-800);
}

.metrics-body {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* 指标数字行：五格等宽，mono + tabular-nums 保证数字宽度恒定，
   卡片间不会因位数不同错落 */
.metrics-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.metrics-stat {
  flex: 1 1 140px;
  min-width: 140px;
  padding: 12px 16px;
  border-radius: var(--xf-radius-md);
  background: var(--xf-gray-50);
  border: 1px solid var(--xf-border-color);
}

.metrics-stat-value {
  font-family: var(--xf-font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--xf-font-size-xl);
  font-weight: 700;
  color: var(--xf-gray-900);
  line-height: 1.2;
}

.metrics-stat-label {
  margin-top: 4px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  letter-spacing: var(--xf-tracking-wide);
}

/* Top 路由条形图：名称定宽截断，条形按最大值归一化 */
.metrics-routes {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.metrics-route {
  display: flex;
  align-items: center;
  gap: 12px;
}

.route-name {
  flex-shrink: 0;
  width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-700);
}

.route-bar {
  flex: 1;
  height: 8px;
  border-radius: 4px;
  background: var(--xf-gray-100);
  overflow: hidden;
}

/* 条形填充色走主题主色：亮暗两套变量各自定义，不写死色值 */
.route-bar-fill {
  height: 100%;
  border-radius: 4px;
  background: var(--xf-primary);
  transition: width var(--xf-duration-base) var(--xf-ease-standard);
}

.route-count {
  flex-shrink: 0;
  min-width: 56px;
  text-align: right;
  font-family: var(--xf-font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
}

.metrics-alerts {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.metrics-alert-tag {
  font-family: var(--xf-font-mono);
}

@media (max-width: 768px) {
  .metrics-stat {
    flex: 1 1 calc(50% - 6px);
  }
  .route-name {
    /* 窄屏与条形图共享一行：名称列收窄，给条形图留出可读宽度 */
    width: 120px;
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
