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
            :title="a.type"
            type="warning"
            size="small"
            class="metrics-alert-tag"
          >
            {{ metricsAlertLabel(a.type) }}({{ metricsLevelLabel(a.level) }}) × {{ a.count }}
          </el-tag>
        </div>
      </div>
      <el-empty
        v-else
        :image-size="80"
        :description="$t(metricsFailed ? 'messages.loadFailed' : 'common.noData')"
      >
        <button
          v-if="metricsFailed"
          type="button"
          class="glass-btn glass-btn--sm"
          @click="loadMetrics"
        >
          {{ $t('common.refresh') }}
        </button>
      </el-empty>
    </el-card>

    <!-- 版本概况 + 一键升级入口（security:config 可见；触发按钮仅唯一超管） -->
    <el-card v-if="canViewUpgrade" shadow="never" class="version-card">
      <template #header>
        <div class="card-header">
          <span>{{ $t('about.upgrade.title') }}</span>
          <div class="version-card-actions">
            <button
              v-if="isSuperAdmin"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--sm"
              data-testid="upgrade-open"
              @click="upgradeDialogVisible = true"
            >
              {{ upgradeButtonLabel }}
            </button>
            <button
              type="button"
              class="glass-btn glass-btn--default glass-btn--sm"
              :disabled="upgradeLoading"
              @click="loadUpgradeOverview"
            >
              {{ $t('about.upgrade.refresh') }}
            </button>
          </div>
        </div>
      </template>

      <div v-if="upgradeSnap" class="version-body">
        <!-- 刷新失败但有旧快照：必须明说「可能已过期」+ 给重试入口。
             原实现只置 upgradeFailed，而模板仅在无快照空态用它 ⇒ 失败不可见 -->
        <div v-if="upgradeStale" class="version-stale" role="alert" data-testid="upgrade-stale">
          <span>{{ $t('about.upgrade.staleSnapshot') }}</span>
          <button type="button" class="glass-btn glass-btn--sm" @click="loadUpgradeOverview">
            {{ $t('common.refresh') }}
          </button>
        </div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item :label="$t('about.upgrade.serverVersion')">
            {{ upgradeSnap.server.version || '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.color')">
            <el-tag size="small" :type="serverColorTag">{{ serverColorLabel }}</el-tag>
            <span class="version-port">{{ serverPortText }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.buildId')">
            <span class="version-mono">{{ upgradeSnap.server.buildId || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.localBuild')">
            <span class="version-mono">{{ localBuild || '-' }}</span>
            <el-tag size="small" :type="buildMatch.tag">{{ buildMatch.text }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.buildTime')">
            {{ formatTime(upgradeSnap.server.buildTime) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.startedAt')">
            {{ formatTime(upgradeSnap.server.startedAt) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.uptime')">
            {{ serverUptimeText }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.agent')">
            <el-tag size="small" :type="agentStatus.tag">{{ agentStatus.text }}</el-tag>
            <span v-if="upgradeSnap.upgrade.heartbeat" class="version-heartbeat">
              {{ formatTime(upgradeSnap.upgrade.heartbeat.lastSeenAt) }}
            </span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('about.upgrade.allowlist')" :span="2">
            <template v-if="allowlist.length">
              <el-tag
                v-for="item in allowlist"
                :key="item"
                size="small"
                class="version-allowlist-tag"
              >
                {{ item }}
              </el-tag>
            </template>
            <span v-else class="version-empty">
              {{ $t('about.upgrade.allowlistEmpty') }}
            </span>
          </el-descriptions-item>
        </el-descriptions>

        <el-alert
          v-if="!upgradeSnap.upgrade.ready"
          type="warning"
          :closable="false"
          class="version-alert"
          :title="$t('about.upgrade.notReady')"
        >
          <ul class="version-reasons">
            <li v-for="(reason, index) in upgradeSnap.upgrade.reasons" :key="index">
              {{ upgradeReason(reason, upgradeSnap.upgrade.reasonCodes?.[index]) }}
            </li>
          </ul>
          <p class="version-raw-note">{{ $t('about.upgrade.serverTextNote') }}</p>
        </el-alert>

        <div class="version-job">
          <template v-if="activeUpgradeJob">
            <span class="version-job-label">{{ $t('about.upgrade.activeJob') }}</span>
            <el-tag size="small" :type="jobStateTag(activeUpgradeJob.state)">
              {{ jobStateLabel(activeUpgradeJob.state) }}
            </el-tag>
            <span v-if="activeUpgradeJob.targetColor" class="version-job-target">
              → {{ colorLabel(activeUpgradeJob.targetColor) }}
            </span>
            <span class="version-job-message">
              {{ activeUpgradeJob.message || activeUpgradeJob.id }}
            </span>
          </template>
          <template v-else-if="latestUpgradeJob">
            <span class="version-job-label">{{ $t('about.upgrade.latestJob') }}</span>
            <el-tag size="small" :type="jobStateTag(latestUpgradeJob.state)">
              {{ jobStateLabel(latestUpgradeJob.state) }}
            </el-tag>
            <span class="version-job-time">{{ formatTime(latestUpgradeJob.finishedAt) }}</span>
          </template>
          <span v-else class="version-empty">{{ $t('about.upgrade.noHistory') }}</span>
        </div>

        <!-- 落位通道（inbox → bundles）：只在有动静时显示。
             没有这一段时，「包传上去了但下拉里没有」只能 SSH 上目标机查 inbox——
             那正是单文件传包这个功能要消掉的步骤。 -->
        <div
          v-if="intakePending.length || intakeRejected.length"
          class="version-intake"
          data-testid="version-intake"
        >
          <template v-if="intakePending.length">
            <span class="version-job-label">{{ $t('about.upgrade.intakeTitle') }}</span>
            <el-tag size="small" type="info">
              {{ $t('about.upgrade.intakePending', { count: intakePending.length }) }}
            </el-tag>
            <span class="version-job-message version-mono">{{ intakePending.join('、') }}</span>
          </template>
          <template v-for="item in intakeRejected" :key="item.archive || item.outcome">
            <span class="version-job-label">{{ $t('about.upgrade.intakeTitle') }}</span>
            <el-tag size="small" type="danger">
              {{ $t('about.upgrade.intakeRejected', { archive: item.archive || '—' }) }}
            </el-tag>
            <span class="version-job-message">{{ item.reason }}</span>
          </template>
          <p class="version-raw-note">{{ $t('about.upgrade.serverTextNote') }}</p>
        </div>
      </div>

      <el-empty
        v-else
        :image-size="80"
        :description="
          upgradeLoading
            ? $t('common.loading')
            : upgradeFailed
              ? $t('about.upgrade.loadFailed')
              : $t('common.noData')
        "
      >
        <button
          v-if="!upgradeLoading"
          type="button"
          class="glass-btn glass-btn--sm"
          @click="loadUpgradeOverview"
        >
          {{ $t('common.refresh') }}
        </button>
      </el-empty>
    </el-card>

    <UpgradeDialog
      v-model="upgradeDialogVisible"
      :overview="upgradeSnap"
      @started="loadUpgradeOverview"
      @completed="loadUpgradeOverview"
    />
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSystemLabels } from '@/i18n/systemLabels'
import { Flag, Cpu, Bell, Key, Document, Lock } from '@element-plus/icons-vue'
import { usePermission } from '@/composables/usePermission'
import { api, isCanceledError } from '@/utils/api'
import { formatTime } from '@/utils/datetime'
import { LOCAL_BUILD_ID, isComparableBuildId, isPageHidden } from '@/utils/versionWatcher'
import UpgradeDialog from '@/components/UpgradeDialog.vue'

const { t } = useI18n()
const { upgradeReason } = useSystemLabels()
const { permissions, hasPerm } = usePermission()

// 版本号：构建期由 vite define 注入（单一事实来源 = package.json 的 version）。
// 此前是手抄的字面量，发版后页面会永久显示旧版本（实测 2026-09-18）。
// 非 Vite 构建环境（如直接 vitest 单测的极简转译）下退化为占位，避免 ReferenceError。
const APP_VERSION = typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : '0.0.0-dev'

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

// 空态要能区分「真的没有数据」与「没拿到数据」。整页不报错、不弹红框的原口径保留
// （本卡是附属信息），改的只有文案与重试入口。
const metricsFailed = ref(false)

/** 请求数 Top 路由条数：条形图太多会占满整卡且失去对比意义 */
const TOP_ROUTES_COUNT = 8

/** 后端 routes 已按 requests 降序，直接切片即可，无需前端重排 */
const topRoutes = computed(() => (metricsSnap.value?.routes || []).slice(0, TOP_ROUTES_COUNT))

const metricsAlerts = computed(() => metricsSnap.value?.alerts || [])

/**
 * 告警等级标签（WF-12，2026-11-02）：动态拼接键在缺键时会渲染裸键
 * （`about.metrics.level.info`），与 UpgradeDialog.stepLabel/outcomeLabel 的
 * 「未知码回退显示原码而非裸键」纪律不一致。回退方向取原码——运维一眼能认出
 * 是后端新增档位，而不是页面上冒出一串点分键。
 */
const metricsLevelLabel = (level) => {
  const key = `about.metrics.level.${level}`
  const text = t(key)
  return text === key ? String(level || '') : text
}
/**
 * 告警类型标签（2026-11-04）：与 metricsLevelLabel 同一纪律——词条缺失时回退原码，
 * 不在页面上渲染 `about.metrics.alertTypes.xxx` 这种裸键。码表与词条由
 * tests/i18n/metricsAlertTypesCoverage.test.js 双向钉住（后端新增类型未登记会红）。
 */
const metricsAlertLabel = (type) => {
  const code = String(type || '')
  const key = `about.metrics.alertTypes.${code}`
  const text = t(key)
  return text === key ? code : text
}

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
    if (!resp?.success) {
      metricsFailed.value = true
      return
    }
    // success 但 data 缺失 ⇒ 那是「暂无数据」而不是「没拿到数据」，两种空态必须可区分
    if (!resp.data) {
      metricsFailed.value = false
      return
    }
    // FE-L2：形状归一化兜底——后端契约调整时卡片降级显示 0 值而非 NaN/渲染异常
    const d = resp.data
    metricsFailed.value = false
    metricsSnap.value = {
      ...d,
      summary: { totalRequests: 0, totalErrors: 0, errorRate: 0, ...(d.summary || {}) },
      latency: { avgSeconds: 0, byRoute: {}, ...(d.latency || {}) },
      routes: Array.isArray(d.routes) ? d.routes : [],
      alerts: Array.isArray(d.alerts) ? d.alerts : [],
      process: { uptimeSeconds: 0, rssMB: 0, heapUsedMB: 0, ...(d.process || {}) },
    }
  } catch (_) {
    // 静默：有快照时保留上一次数据；一次都没拿到时空态要说「加载失败」而非「暂无数据」
    metricsFailed.value = true
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

// ================= 版本概况与一键升级入口 =================

/**
 * 权限门控：后端 /api/security/upgrade 要求 security:config。
 * 无权限时整卡不渲染也不发请求（避免每进一次「关于」页吃一个 403）。
 * 触发升级的要求更高（唯一超管 *:*），在按钮层面单独门控；后端仍会再验一次。
 */
const canViewUpgrade = computed(() => hasPerm('security:config'))
const isSuperAdmin = computed(() => (permissions.value || []).includes('*:*'))

const upgradeSnap = ref(null)
/** 落位通道：传完未落位 / 落位失败的归档——「传了却没出现在下拉」要在这页能看懂。 */
const intakePending = computed(() => {
  const list = upgradeSnap.value?.upgrade?.intake?.pending
  return Array.isArray(list) ? list.filter((n) => typeof n === 'string' && n) : []
})
const intakeRejected = computed(() => {
  const list = upgradeSnap.value?.upgrade?.intake?.rejected
  if (!Array.isArray(list)) return []
  return list.filter((r) => r && (typeof r.archive === 'string' || typeof r.outcome === 'string'))
})
const upgradeLoading = ref(false)
const upgradeFailed = ref(false)
/** 有快照但最近一次刷新没拿到数据：数据可能已过期（P2-9） */
const upgradeStale = ref(false)
const upgradeDialogVisible = ref(false)

/**
 * 任务形状归一化。
 *
 * 必须保留**完整结构**（P2-10）：UpgradeDialog 打开 activeJob 时要展示
 * steps / requestedAt / requestedBy / activeColor，原先只留 id/state/image/
 * message/targetColor/finishedAt，弹窗里步骤、操作人、请求时间全是空的。
 * 口径与 UpgradeDialog 的 adoptJob 保持一致（两处形状相同，缺字段一律兜底）。
 */
const normalizeJob = (raw) => {
  if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || !raw.id) return null
  return {
    id: raw.id,
    state: typeof raw.state === 'string' ? raw.state : 'unknown',
    image: typeof raw.image === 'string' ? raw.image : '',
    mode: raw.mode === 'offline' ? 'offline' : 'registry',
    message: typeof raw.message === 'string' ? raw.message : '',
    outcome: typeof raw.outcome === 'string' ? raw.outcome : '',
    activeColor: typeof raw.activeColor === 'string' ? raw.activeColor : '',
    targetColor: typeof raw.targetColor === 'string' ? raw.targetColor : '',
    requestedAt: raw.requestedAt || null,
    startedAt: raw.startedAt || null,
    finishedAt: raw.finishedAt || null,
    requestedBy:
      raw.requestedBy && typeof raw.requestedBy === 'object'
        ? {
            userId: typeof raw.requestedBy.userId === 'string' ? raw.requestedBy.userId : '',
            username: typeof raw.requestedBy.username === 'string' ? raw.requestedBy.username : '',
          }
        : null,
    steps: Array.isArray(raw.steps)
      ? raw.steps
          .filter((step) => step && typeof step === 'object')
          .map((step) => ({
            name: typeof step.name === 'string' ? step.name : '',
            detail: typeof step.detail === 'string' ? step.detail : '',
            at: step.at || null,
          }))
      : [],
  }
}

/** 离线包候选（代理心跳携带）的白名单式归一：坏形状折成空结构，不让坏心跳炸整卡 */
const normalizeBundles = (raw) => {
  const empty = { available: [], invalid: [] }
  if (!raw || typeof raw !== 'object') return empty
  const take = (list, map) =>
    Array.isArray(list) ? list.map(map).filter(Boolean).slice(0, 10) : []
  return {
    available: take(raw.available, (b) => {
      if (!b || typeof b !== 'object' || typeof b.ref !== 'string' || !b.ref) return null
      return {
        dirName: typeof b.dirName === 'string' ? b.dirName : '',
        ref: b.ref,
        digest: typeof b.digest === 'string' ? b.digest : '',
        repository: typeof b.repository === 'string' ? b.repository : '',
        version: typeof b.version === 'string' ? b.version : '',
        buildId: typeof b.buildId === 'string' ? b.buildId : '',
        createdAt: typeof b.createdAt === 'string' ? b.createdAt : '',
      }
    }),
    invalid: take(raw.invalid, (b) => {
      if (!b || typeof b !== 'object' || typeof b.dirName !== 'string' || !b.dirName) return null
      return { dirName: b.dirName, error: typeof b.error === 'string' ? b.error : '' }
    }),
  }
}

/**
 * 落位通道状态（代理心跳携带）的归一：pending = 已传完待落位的归档名，
 * rejected = 落位失败及原因。与 bundles 同纪律——坏形状折成空结构，不让坏心跳炸整卡。
 */
const normalizeIntake = (raw) => {
  const empty = { pending: [], rejected: [], landed: '' }
  if (!raw || typeof raw !== 'object') return empty
  const clip = (v) => (typeof v === 'string' ? v : '')
  return {
    pending: Array.isArray(raw.pending) ? raw.pending.map(clip).filter(Boolean).slice(0, 10) : [],
    rejected: Array.isArray(raw.rejected)
      ? raw.rejected
          .map((r) => {
            if (!r || typeof r !== 'object') return null
            return {
              archive: clip(r.archive),
              outcome: clip(r.outcome),
              reason: clip(r.reason),
            }
          })
          .filter((r) => r && (r.archive || r.outcome))
          .slice(0, 10)
      : [],
    landed: clip(raw.landed),
  }
}

/** 快照形状归一化：字段漂移时渲染 0/'-'，不让整卡因 undefined 崩掉 */
const normalizeUpgrade = (d) => {
  const server = d.server && typeof d.server === 'object' ? d.server : {}
  const upgrade = d.upgrade && typeof d.upgrade === 'object' ? d.upgrade : {}
  return {
    server: {
      version: typeof server.version === 'string' ? server.version : '',
      buildId: typeof server.buildId === 'string' ? server.buildId : '',
      buildTime: server.buildTime || null,
      startedAt: server.startedAt || null,
      // 缺失保持 null（渲染 '-'），不归一成 0：0s / :0 是**看起来像真值**的
      // 假数据，比 '-' 更容易被当成"服务刚重启"（P3-15）
      uptimeSec: Number.isFinite(server.uptimeSec) ? server.uptimeSec : null,
      color: typeof server.color === 'string' ? server.color : 'unknown',
      port: Number.isFinite(server.port) ? server.port : null,
    },
    upgrade: {
      ready: upgrade.ready === true,
      enabled: upgrade.enabled === true,
      reasons: Array.isArray(upgrade.reasons)
        ? upgrade.reasons.filter((r) => typeof r === 'string')
        : [],
      // 稳定原因码（与 reasons 同序）；老后端没有该字段时为空数组，
      // upgradeReason 会退回按已知原文映射，不会把中文原样漏到英文界面
      reasonCodes: Array.isArray(upgrade.reasonCodes)
        ? upgrade.reasonCodes.map((c) => (typeof c === 'string' ? c : ''))
        : [],
      allowlist: Array.isArray(upgrade.allowlist)
        ? upgrade.allowlist.filter((a) => typeof a === 'string')
        : [],
      heartbeat:
        upgrade.heartbeat && typeof upgrade.heartbeat === 'object' ? upgrade.heartbeat : null,
      // 离线包候选：仅用于展示与下拉，不是完整性背书（全量校验在代理执行时做）
      bundles: normalizeBundles(upgrade.bundles),
      intake: normalizeIntake(upgrade.intake),
      activeJob: normalizeJob(upgrade.activeJob),
      latestJob: normalizeJob(upgrade.latestJob),
    },
  }
}

/**
 * 请求令牌 + 中断器（P2-9）：@started/@completed 与手动刷新会并发触发本函数，
 * 没有序号时「慢的那一发后到」会用旧数据覆盖新快照（升级刚完成又被显示回
 * 进行中）；关闭/离开页面后回来的响应同样不该落地。
 */
let upgradeToken = 0
let upgradeCtrl = null

/**
 * 标记「这次刷新没拿到数据」。
 *
 * 有快照 ⇒ 保留数据但**显式标注可能过期**并可重试；原实现只置 upgradeFailed，
 * 而模板仅在无快照的空态里用这个标志 ⇒ 失败对用户完全不可见，
 * 他看到的是一份还带着旧 activeJob 的"当前"面板。
 */
const markUpgradeStale = () => {
  upgradeFailed.value = true
  upgradeStale.value = !!upgradeSnap.value
}

/**
 * 读取版本概况。失败静默为空态 + 重试入口（附属信息不可用不该让整页报错），
 * 与指标卡同口径；成功后保留快照，刷新期间不清空面板。
 */
const loadUpgradeOverview = async () => {
  if (!canViewUpgrade.value) return
  const token = (upgradeToken += 1)
  if (upgradeCtrl) {
    try {
      upgradeCtrl.abort()
    } catch (_) {
      // 上一发已结束时的 abort 失败无需处理
    }
  }
  upgradeCtrl = typeof AbortController === 'function' ? new AbortController() : null
  upgradeLoading.value = true
  try {
    const config = upgradeCtrl ? { signal: upgradeCtrl.signal } : undefined
    const { data: resp } = await api.security.getUpgradeOverview(config)
    if (token !== upgradeToken) return
    if (!resp?.success || !resp.data) {
      markUpgradeStale()
      return
    }
    upgradeSnap.value = normalizeUpgrade(resp.data)
    upgradeFailed.value = false
    upgradeStale.value = false
  } catch (e) {
    // 被自己取消（并发刷新/离页）不是失败，也不该改状态
    if (token !== upgradeToken || isCanceledError(e)) return
    markUpgradeStale()
  } finally {
    if (token === upgradeToken) upgradeLoading.value = false
  }
}

const allowlist = computed(() => upgradeSnap.value?.upgrade.allowlist || [])
const activeUpgradeJob = computed(() => upgradeSnap.value?.upgrade.activeJob || null)
const latestUpgradeJob = computed(() => upgradeSnap.value?.upgrade.latestJob || null)

const upgradeButtonLabel = computed(() =>
  activeUpgradeJob.value ? t('about.upgrade.viewProgress') : t('about.upgrade.oneClick')
)

const colorLabel = (color) => {
  if (color === 'blue') return t('about.upgrade.colorBlue')
  if (color === 'green') return t('about.upgrade.colorGreen')
  return t('about.upgrade.colorUnknown')
}

const serverColorLabel = computed(() => colorLabel(upgradeSnap.value?.server.color))
/** 缺失保持 null ⇒ 显示 '-'（与服务端真的返回 0 区分开，P3-15） */
const serverPortText = computed(() => {
  const port = upgradeSnap.value?.server.port
  return Number.isFinite(port) ? `:${port}` : '-'
})
const serverUptimeText = computed(() => {
  const seconds = upgradeSnap.value?.server.uptimeSec
  return Number.isFinite(seconds) ? formatUptime(seconds) : '-'
})
const serverColorTag = computed(() => {
  const color = upgradeSnap.value?.server.color
  if (color === 'blue') return 'primary'
  if (color === 'green') return 'success'
  return 'info'
})

const agentStatus = computed(() => {
  const heartbeat = upgradeSnap.value?.upgrade.heartbeat
  if (!heartbeat) return { tag: 'info', text: t('about.upgrade.agentNever') }
  // 只有真正的布尔 true 才算心跳过期：原实现是 truthy 判断，
  // 后端把 stale 传成字符串 'false' / 1 时会把在线代理显示成"心跳过期"（P3-15）
  if (heartbeat.stale === true) return { tag: 'danger', text: t('about.upgrade.agentStale') }
  return { tag: 'success', text: t('about.upgrade.agentReady') }
})

/**
 * 本页构建 vs 服务端构建：版本概况最有用的判断之一。
 * 任一侧不可比对时一律显示「无法比对」——拿 'unknown'/'dev' 相比只会恒假。
 */
const localBuild = LOCAL_BUILD_ID
const buildMatch = computed(() => {
  const remote = upgradeSnap.value?.server.buildId || ''
  if (!isComparableBuildId(localBuild) || !isComparableBuildId(remote)) {
    return { tag: 'info', text: t('about.upgrade.buildUnknown') }
  }
  if (remote === localBuild) {
    return { tag: 'success', text: t('about.upgrade.buildMatch') }
  }
  return { tag: 'warning', text: t('about.upgrade.buildMismatch') }
})

const jobStateLabel = (state) => {
  const key = `about.upgrade.state.${state || 'unknown'}`
  const text = t(key)
  return text === key ? t('about.upgrade.state.unknown') : text
}

const jobStateTag = (state) =>
  ({ queued: 'info', running: 'warning', succeeded: 'success', failed: 'danger' })[state] || 'info'

onMounted(() => {
  loadMetrics()
  loadUpgradeOverview()
  metricsTimer = setInterval(() => {
    // 隐藏时暂停；不以上次成败为条件——首次失败后不重试，
    // 卡片就会一直停在空态直到用户重新进入本页。
    // 判据走全仓统一实现（isPageHidden）：原实现自己写了 === 'visible'，
    // 与升级弹窗的 === 'hidden' 各说各话，'prerender' 两边都漏（P2-6）
    if (!isPageHidden()) loadMetrics()
  }, METRICS_POLL_MS)
})

onUnmounted(() => {
  if (metricsTimer) {
    clearInterval(metricsTimer)
    metricsTimer = null
  }
  // 离页即中止在途的概况请求：响应回来时组件已不在，不应再改状态
  upgradeToken += 1
  if (upgradeCtrl) {
    try {
      upgradeCtrl.abort()
    } catch (_) {
      // 忽略：组件正在卸载
    }
    upgradeCtrl = null
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

/* ===== 版本概况卡与一键升级入口 ===== */
.version-card {
  margin-top: 16px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.2s;
}

.version-card .card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-base);
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-gray-800);
}

.version-card-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.version-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.version-mono {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  word-break: break-all;
}

.version-port {
  margin-left: 8px;
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

.version-heartbeat {
  margin-left: 8px;
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

.version-allowlist-tag {
  margin-right: 6px;
  margin-bottom: 4px;
}

.version-empty {
  color: var(--xf-text-secondary);
  font-size: var(--xf-font-size-xs);
}

/* 数据可能过期：常驻可见的告警条 + 重试（P2-9） */
.version-stale {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  padding: 8px 12px;
  border-radius: var(--xf-radius-sm);
  border: 1px solid var(--xf-danger);
  background: var(--xf-gray-50);
  color: var(--xf-danger);
  font-size: var(--xf-font-size-xs);
}

/* 后端原文（message / step.detail / reasons）的标注：原文不本地化，只标来源 */
.version-raw-note {
  margin: 6px 0 0;
  color: var(--xf-text-secondary);
  font-size: var(--xf-font-size-xs);
}

.version-alert {
  margin-top: 2px;
}

.version-reasons {
  margin: 6px 0 0;
  padding-left: 18px;
  font-size: var(--xf-font-size-xs);
  line-height: 1.7;
}

/* 任务行：进行中/最近一次升级共用一行式摘要 */
.version-job {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding-top: 10px;
  border-top: 1px dashed var(--xf-border-color);
}

.version-job-label {
  font-weight: 600;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-800);
}

.version-job-target,
.version-job-time {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
}

.version-job-message {
  flex: 1 1 100%;
  min-width: 0;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
  word-break: break-all;
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
