<template>
  <div class="page">
    <!-- 查询判据：IP / 指纹 / 网段 至少一项。缺判据时前端就拦住，不发请求 -->
    <div class="glass glass-card">
      <div class="card-header">
        <span>{{ $t('forensic.criteriaCard') }}</span>
      </div>
      <p class="card-hint">{{ $t('forensic.criteriaHint') }}</p>
      <el-form :inline="true" :model="criteria" class="criteria-form">
        <el-form-item :label="$t('forensic.ipLabel')">
          <el-input
            v-model="criteria.ip"
            :placeholder="$t('forensic.ipPlaceholder')"
            style="width: 190px"
            clearable
            maxlength="64"
            @keyup.enter="handleTrace"
          />
        </el-form-item>
        <el-form-item :label="$t('forensic.fingerprintLabel')">
          <el-input
            v-model="criteria.fingerprint"
            :placeholder="$t('forensic.fingerprintPlaceholder')"
            style="width: 210px"
            clearable
            maxlength="128"
            @keyup.enter="handleTrace"
          />
        </el-form-item>
        <el-form-item :label="$t('forensic.segmentLabel')">
          <el-input
            v-model="criteria.ipSegment"
            :placeholder="$t('forensic.segmentPlaceholder')"
            style="width: 160px"
            clearable
            maxlength="64"
            @keyup.enter="handleTrace"
          />
        </el-form-item>
        <el-form-item :label="$t('forensic.timeRangeLabel')">
          <el-date-picker
            v-model="criteria.dateRange"
            type="daterange"
            range-separator="-"
            :start-placeholder="$t('report.startDate')"
            :end-placeholder="$t('report.endDate')"
            value-format="YYYY-MM-DD"
            style="width: 260px"
          />
        </el-form-item>
        <el-form-item :label="$t('forensic.limitLabel')">
          <el-input-number v-model="criteria.limit" :min="1" :max="1000" :step="100" />
        </el-form-item>
        <el-form-item class="glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            :disabled="tracing"
            @click="handleTrace"
          >
            {{ tracing ? $t('forensic.searching') : $t('forensic.search') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="resetCriteria">
            {{ $t('forensic.reset') }}
          </button>
          <!-- 导出与查询同权限码（security:audit）；会话期内权限被热回收时按钮随之消失 -->
          <button
            v-if="hasPerm('security:audit')"
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="exporting || tracing"
            @click="handleExport"
          >
            {{ exporting ? $t('forensic.exporting') : $t('forensic.exportAction') }}
          </button>
        </el-form-item>
      </el-form>
      <p class="capability-note">{{ $t('forensic.exportBoundary') }}</p>
    </div>

    <!-- 溯源结果：时间线 + 触发原因分布 + 网段分布 + 「他的 ip 池」 -->
    <div v-if="hasQueried" class="glass glass-card">
      <div class="card-header">
        <span>{{ $t('forensic.resultCard') }}</span>
        <span v-if="result" class="card-meta">{{ resultSummary }}</span>
      </div>

      <el-alert
        v-if="traceError"
        :title="hasResult ? $t('forensic.staleData') : $t('forensic.loadError')"
        type="warning"
        :closable="false"
        show-icon
        class="load-error"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="tracing"
            @click="handleTrace"
          >
            {{ $t('common.retry') }}
          </button>
        </template>
      </el-alert>

      <el-alert
        v-if="result && result.truncated"
        :title="$t('forensic.truncated', { count: result.count || 0 })"
        type="warning"
        :closable="false"
        show-icon
        class="truncated-alert"
      />

      <template v-if="result">
        <!-- 时间线：统一走 utils/datetime.formatTime（本地时区 + 定长口径） -->
        <h3 class="section-title">{{ $t('forensic.timelineTitle') }}</h3>
        <el-table
          :data="timelineRows"
          border
          stripe
          class="forensic-timeline"
          style="width: 100%"
          max-height="420"
        >
          <template #empty>
            <div class="empty-tip">{{ $t('forensic.emptyResult') }}</div>
          </template>
          <el-table-column :label="$t('forensic.colTime')" width="170">
            <template #default="{ row }">
              {{ formatTime(row.createdAt) }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colIp')" min-width="130">
            <template #default="{ row }">
              <span class="mono">{{ row.ip || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colSegment')" width="110">
            <template #default="{ row }">
              <span class="mono">{{ row.ipSegment || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colMethod')" width="90">
            <template #default="{ row }">
              {{ row.method || '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colPath')" min-width="200" show-overflow-tooltip>
            <template #default="{ row }">
              <span class="mono">{{ row.path || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colAction')" min-width="140">
            <template #default="{ row }">
              {{ row.action || '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colUsername')" width="120">
            <template #default="{ row }">
              {{ row.username || '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colTrigger')" width="130">
            <template #default="{ row }">
              <el-tag v-if="row.trigger" type="warning" size="small" effect="plain">
                {{ row.trigger }}
              </el-tag>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colReason')" min-width="150" show-overflow-tooltip>
            <template #default="{ row }">
              {{ row.reason || '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.colStatus')" width="90">
            <template #default="{ row }">
              <el-tag v-if="row.status" :type="statusTagType(row.status)" size="small">
                {{ row.status }}
              </el-tag>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('forensic.colFingerprint')"
            min-width="140"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span class="mono">{{ row.fingerprint || '-' }}</span>
            </template>
          </el-table-column>
        </el-table>

        <!-- 分布：触发原因 / 网段 -->
        <div class="dist-row">
          <div class="dist-col">
            <h3 class="section-title">{{ $t('forensic.triggerTitle') }}</h3>
            <el-table
              :data="triggerRows"
              border
              size="small"
              class="forensic-trigger"
              style="width: 100%"
            >
              <template #empty>
                <div class="empty-tip">{{ $t('forensic.emptyTrigger') }}</div>
              </template>
              <el-table-column prop="name" :label="$t('forensic.colTrigger')" min-width="140" />
              <el-table-column prop="count" :label="$t('forensic.poolHits')" width="100" />
            </el-table>
          </div>
          <div class="dist-col">
            <h3 class="section-title">{{ $t('forensic.segmentTitle') }}</h3>
            <el-table
              :data="segmentRows"
              border
              size="small"
              class="forensic-segment"
              style="width: 100%"
            >
              <template #empty>
                <div class="empty-tip">{{ $t('forensic.emptySegment') }}</div>
              </template>
              <el-table-column prop="name" :label="$t('forensic.colSegment')" min-width="140" />
              <el-table-column prop="count" :label="$t('forensic.poolHits')" width="100" />
            </el-table>
          </div>
        </div>

        <!-- 「他的 ip 池」：运维最想要的那一屏。只有传了指纹才有内容 -->
        <h3 class="section-title">{{ $t('forensic.poolTitle') }}</h3>
        <p class="card-hint">{{ $t('forensic.poolHint') }}</p>
        <el-table :data="poolRows" border stripe class="forensic-pool" style="width: 100%">
          <template #empty>
            <div class="empty-tip">
              {{
                criteria.fingerprint
                  ? $t('forensic.poolEmpty')
                  : $t('forensic.poolOnlyWithFingerprint')
              }}
            </div>
          </template>
          <el-table-column :label="$t('forensic.poolSegment')" min-width="140">
            <template #default="{ row }">
              <span class="mono">{{ row.segment || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="hits" :label="$t('forensic.poolHits')" width="110" />
          <el-table-column prop="distinctIps" :label="$t('forensic.poolDistinctIps')" width="130" />
          <el-table-column :label="$t('forensic.poolFirstSeen')" width="170">
            <template #default="{ row }">
              {{ formatTime(row.firstSeen) }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('forensic.poolLastSeen')" width="170">
            <template #default="{ row }">
              {{ formatTime(row.lastSeen) }}
            </template>
          </el-table-column>
        </el-table>
      </template>
    </div>

    <!-- IP 池聚类 + 封段入口（security:config） -->
    <div class="glass glass-card">
      <div class="card-header">
        <span>{{ $t('forensic.clustersCard') }}</span>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          :disabled="clustersLoading"
          @click="loadClusters"
        >
          {{ clustersLoading ? $t('forensic.clustersLoading') : $t('forensic.clustersRefresh') }}
        </button>
      </div>
      <p class="card-hint">{{ $t('forensic.clustersHint') }}</p>

      <el-alert
        v-if="clustersError"
        :title="$t('forensic.clustersError')"
        type="warning"
        :closable="false"
        show-icon
        class="load-error"
      />

      <div class="cluster-controls">
        <span class="control-item">
          {{ $t('forensic.clustersWindow') }}
          <el-input-number v-model="clusterQuery.windowHours" :min="1" :max="720" :step="12" />
        </span>
        <span class="control-item">
          {{ $t('forensic.clustersMinHits') }}
          <el-input-number v-model="clusterQuery.minHits" :min="1" :max="100000" :step="10" />
        </span>
        <span class="control-item">
          {{ $t('forensic.clustersMinIps') }}
          <el-input-number v-model="clusterQuery.minIps" :min="1" :max="1000" :step="1" />
        </span>
      </div>

      <el-table :data="clusterRows" border stripe class="forensic-clusters" style="width: 100%">
        <template #empty>
          <div class="empty-tip">
            {{
              !canSeeClusters
                ? $t('forensic.clustersForbidden')
                : clustersError
                  ? $t('forensic.clustersError')
                  : $t('forensic.clustersEmpty')
            }}
          </div>
        </template>
        <el-table-column :label="$t('forensic.colCidr')" min-width="150">
          <template #default="{ row }">
            <span class="mono">{{ row.cidr || row.segment || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="hits" :label="$t('forensic.colHits')" width="100" />
        <el-table-column prop="distinctIps" :label="$t('forensic.colDistinctIps')" width="120" />
        <el-table-column
          prop="distinctFingerprints"
          :label="$t('forensic.colDistinctFingerprints')"
          width="130"
        />
        <el-table-column :label="$t('forensic.colFirstSeen')" width="170">
          <template #default="{ row }">
            {{ formatTime(row.firstSeen) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('forensic.colLastSeen')" width="170">
          <template #default="{ row }">
            {{ formatTime(row.lastSeen) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('forensic.colVerdict')" min-width="150">
          <template #default="{ row }">
            <el-tag :type="verdictTagType(row.verdict)" size="small">
              {{ verdictText(row.verdict) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('forensic.colRecommend')" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.recommendBan" type="danger" size="small" effect="dark">
              {{ $t('forensic.recommendBan') }}
            </el-tag>
            <span v-else class="muted">{{ $t('forensic.noRecommendBan') }}</span>
          </template>
        </el-table-column>
        <!-- 封段按钮：与路由 meta / 后端同一权限码；无可封 CIDR 时不给入口 -->
        <el-table-column :label="$t('common.operation')" width="150" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('security:config') && row.cidr"
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              :disabled="banSubmitting"
              @click="openBanDialog(row)"
            >
              {{ $t('forensic.banAction') }}
            </button>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 封禁确认框：先看 cidr / 命中数 / 影响面，再填理由，然后才是「确认封禁」 -->
    <el-dialog
      v-model="banDialogVisible"
      :title="$t('forensic.banDialogTitle')"
      width="560px"
      :close-on-click-modal="false"
    >
      <div v-if="banTarget" class="ban-summary">
        <div class="ban-row">
          <span class="ban-label">{{ $t('forensic.banCidr') }}</span>
          <span class="mono ban-value">{{ banTarget.cidr || '-' }}</span>
        </div>
        <div class="ban-row">
          <span class="ban-label">{{ $t('forensic.banHits') }}</span>
          <span class="ban-value">{{ banTarget.hits ?? '-' }}</span>
        </div>
        <div class="ban-row">
          <span class="ban-label">{{ $t('forensic.banDistinctIps') }}</span>
          <span class="ban-value">{{ banTarget.distinctIps ?? '-' }}</span>
        </div>
        <div class="ban-row">
          <span class="ban-label">{{ $t('forensic.banDistinctFingerprints') }}</span>
          <span class="ban-value">{{ banTarget.distinctFingerprints ?? '-' }}</span>
        </div>
        <el-alert type="warning" :closable="false" show-icon class="ban-impact">
          <template #title>
            {{ $t('forensic.banImpact') }}
          </template>
          <template #default>
            {{
              $t('forensic.banImpactText', {
                cidr: banTarget.cidr || '',
                ips: banTarget.distinctIps ?? 0,
              })
            }}
          </template>
        </el-alert>
        <el-form-item :label="$t('forensic.banReasonLabel')" class="ban-reason">
          <el-input
            v-model="banReason"
            type="textarea"
            :rows="2"
            maxlength="200"
            show-word-limit
            :placeholder="$t('forensic.banReasonPlaceholder')"
          />
        </el-form-item>
        <!-- 打字确认：后端对 hostCount ≥ 256 的段（即 UI 能封的每个 /24）要求逐字敲出 CIDR。
             不在这里收，第二步必然 400 typed_confirmation_required——功能等于不可用。 -->
        <el-form-item v-if="banNeedTypedConfirm" :label="$t('forensic.banTypedLabel')">
          <el-input
            v-model="banTypedConfirm"
            :placeholder="$t('forensic.banTypedPlaceholder', { cidr: banTarget.cidr || '' })"
            class="ban-typed-confirm"
          />
        </el-form-item>
        <el-form-item :label="$t('forensic.banDurationLabel')">
          <el-select v-model="banDurationHours" style="width: 240px">
            <el-option :label="$t('forensic.banDuration24h')" :value="24" />
            <el-option :label="$t('forensic.banDuration7d')" :value="168" />
            <el-option :label="$t('forensic.banDuration30d')" :value="720" />
            <el-option :label="$t('forensic.banDurationPermanent')" :value="0" />
          </el-select>
        </el-form-item>

        <!-- 被拒原因必须落在页面上（不只是弹一条一闪而过的 toast） -->
        <el-alert
          v-if="banRefusalText"
          :title="$t('forensic.banRefusedTitle')"
          type="error"
          :closable="false"
          show-icon
          class="ban-refusal"
        >
          <template #default>
            {{ banRefusalText }}
          </template>
        </el-alert>
      </div>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          :disabled="banSubmitting"
          @click="banDialogVisible = false"
        >
          {{ $t('forensic.banCancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--danger"
          :disabled="banSubmitting"
          @click="handleConfirmBan"
        >
          {{
            banSubmitting
              ? banStage === 'confirm'
                ? $t('forensic.banConfirming')
                : $t('forensic.banRequesting')
              : $t('forensic.banConfirm')
          }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { formatTime } from '@/utils/datetime'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'

const { t } = useI18n()
const { hasPerm } = usePermission()

// 默认时间范围：最近 7 天（与后端 DEFAULT_WINDOW_MS 同口径）
const DAY_MS = 24 * 60 * 60 * 1000
const defaultDateRange = () => {
  const until = new Date()
  const since = new Date(until.getTime() - 7 * DAY_MS)
  // value-format=YYYY-MM-DD，这里必须给本地日期串（toISOString 在东八区 0-8 点会早一天）
  const wall = (d) => {
    const p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
  }
  return [wall(since), wall(until)]
}

const criteria = reactive({
  ip: '',
  fingerprint: '',
  ipSegment: '',
  dateRange: defaultDateRange(),
  limit: 200,
})

const tracing = ref(false)
const hasQueried = ref(false)
const result = ref(null)
const traceError = ref(false)

// 重入锁：与 tracing 分开、**同步**置位。tracing 要等 DOM 重渲染才对按钮生效，
// 同一 tick 连点会全部进入 handler 并发出多个请求。
let traceSubmitting = false
const traceGuard = useLatestRequest()

const hasCriteria = () =>
  Boolean(criteria.ip.trim() || criteria.fingerprint.trim() || criteria.ipSegment.trim())

/** 时间范围 → ISO 边界。结束日按「当天最后一毫秒」收口，否则当天记录全被排除 */
const buildTimeWindow = () => {
  const range = criteria.dateRange
  if (!Array.isArray(range) || range.length !== 2 || !range[0] || !range[1]) return null
  const since = new Date(`${range[0]}T00:00:00`)
  const until = new Date(`${range[1]}T23:59:59.999`)
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime())) return null
  if (since.getTime() > until.getTime()) return null
  return { since: since.toISOString(), until: until.toISOString() }
}

/** 查询参数：空判据不下发空串（后端 optional({values:'falsy'}) 会忽略，但空串会先撞 length 校验） */
const buildParams = () => {
  const params = {}
  if (criteria.ip.trim()) params.ip = criteria.ip.trim()
  if (criteria.fingerprint.trim()) params.fingerprint = criteria.fingerprint.trim()
  if (criteria.ipSegment.trim()) params.ipSegment = criteria.ipSegment.trim()
  const win = buildTimeWindow()
  if (win) {
    params.since = win.since
    params.until = win.until
  }
  params.limit = Number(criteria.limit) || 200
  return params
}

const resultSummary = computed(() => {
  if (!result.value) return ''
  const parts = [t('forensic.resultSummary', { count: result.value.count ?? 0 })]
  if (result.value.since && result.value.until) {
    parts.push(
      t('forensic.resultWindow', {
        since: formatTime(result.value.since),
        until: formatTime(result.value.until),
      })
    )
  }
  return parts.join(' · ')
})

const hasResult = computed(() => Boolean(result.value))

const timelineRows = computed(() => result.value?.timeline || [])
const poolRows = computed(() => result.value?.pools || [])

/** 分布对象 → 表格行（按次数倒序；Object.entries 顺序不可依赖） */
const distRows = (obj) =>
  Object.entries(obj || {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
const triggerRows = computed(() => distRows(result.value?.triggers))
const segmentRows = computed(() => distRows(result.value?.segments))

const statusTagType = (status) => {
  const n = Number(status)
  if (!Number.isFinite(n)) return 'info'
  if (n >= 500) return 'danger'
  if (n >= 400) return 'warning'
  return 'success'
}

const handleTrace = async () => {
  if (traceSubmitting) return
  // 无判据：前端直接拦住并提示，**不发请求**（后端也要求至少一个维度）
  if (!hasCriteria()) {
    ElMessage.warning(t('forensic.noCriteria'))
    return
  }
  const win = buildTimeWindow()
  if (Array.isArray(criteria.dateRange) && criteria.dateRange.length === 2 && !win) {
    ElMessage.warning(t('forensic.invalidTimeRange'))
    return
  }

  traceSubmitting = true
  tracing.value = true
  const isCurrent = traceGuard()
  try {
    const res = await api.security.getForensicTrace(buildParams())
    if (!isCurrent()) return
    // 信封：res.data 是 { success, message, data }，业务负载在内层 data。
    // 200 但内层 data 为空 = 契约漂移：导出路径对同一形态会明确报错（见 exportForensic 注释），
    // 这里若静默渲染一张只有标题的空卡片，"查询失败"与"这段时间没有记录"就分不开了。
    const payload = res?.data?.data || null
    if (payload === null) {
      result.value = null
      traceError.value = true
      hasQueried.value = true
      return
    }
    result.value = payload
    traceError.value = false
    hasQueried.value = true
    // 空结果不是错误：表格走 empty 插槽，不弹提示
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // 失败必须可见：保留上次结果并标注为上次数据，绝不把失败画成「没有记录」
    traceError.value = true
    hasQueried.value = true
  } finally {
    if (isCurrent()) tracing.value = false
    traceSubmitting = false
  }
}

const resetCriteria = () => {
  criteria.ip = ''
  criteria.fingerprint = ''
  criteria.ipSegment = ''
  criteria.dateRange = defaultDateRange()
  criteria.limit = 200
  result.value = null
  traceError.value = false
  hasQueried.value = false
}

// ===== IP 池聚类 =====
const clusterQuery = reactive({ windowHours: 24, minHits: 20, minIps: 4 })
const clustersLoading = ref(false)
const clustersError = ref(false)
// 聚类端点后端要 security:config（forensicRoutes.js 的 checkPermission），而本页路由只要
// security:audit：不先过这道判据就发请求，只有 audit 的用户会拿到一个注定 403 的响应，
// 面板先把"没权限"渲染成 loading、再渲染成"聚类查询失败"——把权限差距伪装成后端故障。
const canSeeClusters = computed(() => hasPerm('security:config'))
const clusters = ref(null)
const clusterRows = computed(() => clusters.value?.segments || [])
let clustersSubmitting = false
const clusterGuard = useLatestRequest()

const loadClusters = async () => {
  if (clustersSubmitting) return
  clustersSubmitting = true
  clustersLoading.value = true
  const isCurrent = clusterGuard()
  try {
    const res = await api.security.getForensicClusters({
      windowHours: Number(clusterQuery.windowHours) || 24,
      minHits: Number(clusterQuery.minHits) || 20,
      minIps: Number(clusterQuery.minIps) || 4,
      limit: 50,
    })
    if (!isCurrent()) return
    clusters.value = res?.data?.data || null
    clustersError.value = false
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    clustersError.value = true
  } finally {
    if (isCurrent()) clustersLoading.value = false
    clustersSubmitting = false
  }
}

// 进页面即拉一次聚类：聚类面板是封段的入口，空着等用户点「重新聚类」
// 会让人以为「没有可封的网段」。失败由 clustersError 显式可见；无 security:config 时不发。
onMounted(() => {
  if (canSeeClusters.value) loadClusters()
})

const verdictText = (verdict) => {
  const map = {
    rotate_pool: t('forensic.verdictRotatePool'),
    shared_egress: t('forensic.verdictSharedEgress'),
    too_few_ips: t('forensic.verdictTooFewIps'),
    unparsable_segment: t('forensic.verdictUnparsableSegment'),
  }
  // hasOwnProperty 而非裸下标：verdict 来自响应体，'constructor' 等原型键会取到函数
  if (typeof verdict === 'string' && Object.prototype.hasOwnProperty.call(map, verdict)) {
    return map[verdict]
  }
  return verdict || '-'
}

const verdictTagType = (verdict) => {
  if (verdict === 'rotate_pool') return 'danger'
  if (verdict === 'shared_egress') return 'warning'
  if (verdict === 'unparsable_segment') return 'info'
  return 'info'
}

// ===== 封段两步走：request 拿票 → confirm 落库 =====
const banDialogVisible = ref(false)
const banTarget = ref(null)
const banReason = ref('')
const banDurationHours = ref(24)
const banNeedTypedConfirm = ref(false)
const banTypedConfirm = ref('')
// 第一步拿到的票据：存在即说明"只差落库这一步"，第二次点击不再重复申请
const banToken = ref('')
const banSubmitting = ref(false)
const banStage = ref('request')
const banRefusalText = ref('')

let banSubmittingLock = false

const openBanDialog = (row) => {
  banTarget.value = row
  banReason.value = ''
  banDurationHours.value = 24
  banNeedTypedConfirm.value = false
  banTypedConfirm.value = ''
  banToken.value = ''
  banRefusalText.value = ''
  banStage.value = 'request'
  banDialogVisible.value = true
}

/**
 * 契约 §4 的拒绝原因 → 专属文案。
 * 具体原因在 **errors.reason**（不是 data.reason、也不是顶层 reason），
 * 只认 errorCode 会把五种完全不同的处境说成同一句「操作失败」。
 */
// 拒绝原因码是后端的枚举（单一事实来源 src/constants/banRefusalReason.js）。这里逐码映射到
// i18n 键：漏一个，界面就把英文枚举暴露给运维；多一个，说明后端已经删掉该码而这里没人清。
// 两个方向都由 src/tests/ci/banRefusalEnumSingleSource.test.js 对账。
const BAN_REFUSAL_KEYS = {
  unparsable_cidr: 'forensic.banRefusedUnparsable',
  full_range_cidr: 'forensic.banRefusedFullRange',
  whitelist_covers: 'forensic.banRefusedWhitelist',
  union_covers_family: 'forensic.banRefusedUnionCovers',
  operator_inside: 'forensic.banRefusedOperatorInside',
  live_traffic_inside: 'forensic.banRefusedLiveTraffic',
  reason_required: 'forensic.banRefusedReasonRequired',
  typed_confirmation_required: 'forensic.banRefusedTypedConfirm',
  no_rescue_path: 'forensic.banRefusedNoRescuePath',
  unknown_token: 'forensic.banRefusedUnknownToken',
  token_expired: 'forensic.banRefusedTokenExpired',
}

const refusalTextOf = (e) => {
  const reason = e?.response?.data?.errors?.reason
  if (
    typeof reason === 'string' &&
    Object.prototype.hasOwnProperty.call(BAN_REFUSAL_KEYS, reason)
  ) {
    return t(BAN_REFUSAL_KEYS[reason])
  }
  // 原因未知（后端新增 reason / 前端未跟上）：如实把原因码带上，不吞成笼统文案
  return t('forensic.banRefusedUnknown', { reason: reason || '-' })
}

const handleConfirmBan = async () => {
  if (banSubmittingLock) return
  if (!banTarget.value?.cidr) return
  const reason = banReason.value.trim()
  if (!reason) {
    ElMessage.warning(t('forensic.banReasonRequired'))
    return
  }

  banSubmittingLock = true
  banSubmitting.value = true
  banRefusalText.value = ''
  try {
    // 第一步：申请确认票据（不落库）。silentErrors：拒绝原因由本页渲染，
    // 不希望同一次失败再弹一条更笼统的拦截器提示。
    // 已有票据时跳过这步：**打字确认必须是真的两次交互**——首次点击只拿票并露出输入框，
    // 用户敲完再点第二次才落库。否则 needTypedConfirm 为真时 typedConfirm 只能是空串，
    // 后端一律 400 typed_confirmation_required，界面等于不可用（第 18 轮实测）。
    let token = banToken.value
    if (!token) {
      banStage.value = 'request'
      const reqRes = await api.security.requestPoolBan(
        { cidr: banTarget.value.cidr, reason },
        { silentErrors: true }
      )
      const ticket = reqRes?.data?.data || {}
      token = ticket.token
      if (!token) {
        // 拿到 200 却没有 token = 契约漂移，不能当成功继续往下走
        banRefusalText.value = t('forensic.banFailed')
        ElMessage.error(t('forensic.banFailed'))
        return
      }
      // needTypedConfirm 由后端按 hostCount 判定（≥256 或解析不出规模），前端不自己算：
      // 两边各算一次就是两份事实，一旦漂移，界面会以为不用确认而服务端一律拒。
      banNeedTypedConfirm.value = Boolean(ticket.needTypedConfirm)
      banToken.value = token
      if (banNeedTypedConfirm.value) {
        // 必须打字：停在「请逐字输入网段」这一步，不替用户做确认
        banStage.value = 'confirm'
        return
      }
    }

    // 第二步：持票落库（token 一次性、10 分钟失效，原样提交）
    banStage.value = 'confirm'
    const confirmRes = await api.security.confirmPoolBan(
      {
        token,
        durationHours: Number(banDurationHours.value) || 0,
        // 只有后端明确要求时才带；带空串会被判成"打字不匹配"
        ...(banNeedTypedConfirm.value ? { typedConfirm: banTypedConfirm.value.trim() } : {}),
      },
      { silentErrors: true }
    )
    const payload = confirmRes?.data?.data || {}
    // 成功依据**只有 bannedCount**：addToBlacklist 从不抛错，
    // 「await 返回了」不等于「封上了」，必须按真实写入条数报结果。
    const bannedCount = Number(payload.bannedCount)
    const total = Array.isArray(payload.results) ? payload.results.length : bannedCount
    const cidr = payload.cidr || banTarget.value.cidr

    if (!Number.isFinite(bannedCount) || bannedCount <= 0) {
      ElMessage.error(t('forensic.banAppliedNone', { cidr }))
    } else if (bannedCount < total) {
      ElMessage.warning(t('forensic.banAppliedPartial', { cidr, count: bannedCount, total }))
    } else {
      ElMessage.success(t('forensic.banApplied', { cidr, count: bannedCount }))
    }
    banToken.value = ''
    banDialogVisible.value = false
    // 封禁结果会改变聚类视图的判定依据，刷新一次让界面与库一致（能走到这里必有 security:config）
    if (canSeeClusters.value) loadClusters()
  } catch (e) {
    if (isCanceledError(e)) return
    // 拒绝原因必须落到页面上（toast 一闪而过，运维要能对着看）
    banRefusalText.value = refusalTextOf(e)
    // 票据被判失效/未知时本地也作废：否则界面上再点一次仍是同一张死票，
    // 用户会以为"重试没用"，而正确动作是重新走第一步拿新票。
    const reason = e?.response?.data?.errors?.reason
    if (reason === 'unknown_token' || reason === 'token_expired') {
      banToken.value = ''
      banStage.value = 'request'
    }
    ElMessage.error(banRefusalText.value)
  } finally {
    banSubmitting.value = false
    banSubmittingLock = false
    banStage.value = 'request'
  }
}

// ===== 签名导出 =====
const exporting = ref(false)
let exportLock = false

const handleExport = async () => {
  if (exportLock) return
  // 与查询同一套判据：没有判据就不该导出一份「全量包」
  if (!hasCriteria()) {
    ElMessage.warning(t('forensic.noCriteria'))
    return
  }
  exportLock = true
  exporting.value = true
  try {
    const res = await api.security.exportForensic(buildParams())
    const payload = res?.data?.data || {}
    const pkg = payload.pkg
    if (!pkg) {
      // 没有 pkg = 契约漂移；绝不能提示导出成功
      ElMessage.error(t('forensic.exportFailed'))
      return
    }
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    // 文件名日期走本地时区（toISOString 在东八区 0-8 点会早一天）
    link.download = `forensic_package_${defaultDateRange()[1]}.json`
    link.click()
    window.URL.revokeObjectURL(url)
    ElMessage.success(t('forensic.exportSuccess', { count: pkg.count ?? 0 }))
  } catch (e) {
    if (isCanceledError(e)) return
    // FORENSIC_EXPORT_NO_SECRET 已在拦截器按码翻译成「未配置密钥，请联系管理员」；
    // 这里不再叠加一条笼统文案，避免把具体原因盖掉。
  } finally {
    exporting.value = false
    exportLock = false
  }
}
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.glass-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
  gap: 12px;
}
.card-meta {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  font-weight: 400;
  color: var(--xf-gray-500);
}
.card-hint {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  margin: 6px 0 12px;
  letter-spacing: var(--xf-tracking-wide);
}
.capability-note {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  margin-top: var(--xf-spacing-md);
  border-left: 2px solid var(--xf-warning-strong);
  padding-left: 8px;
}
.criteria-form {
  margin-bottom: 0;
}
.section-title {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-base);
  font-weight: 600;
  margin: var(--xf-spacing-lg) 0 var(--xf-spacing-sm);
  color: var(--xf-gray-800);
  letter-spacing: var(--xf-tracking-wide);
}
.mono {
  font-family: var(--xf-font-mono);
}
.muted {
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-xs);
}
.empty-tip {
  font-family: var(--xf-font-body);
  text-align: center;
  padding: 24px 0;
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-sm);
}
.load-error,
.truncated-alert {
  margin-bottom: var(--xf-spacing-md);
}
.dist-row {
  display: flex;
  gap: var(--xf-spacing-lg);
  flex-wrap: wrap;
}
.dist-col {
  flex: 1 1 300px;
  min-width: 0;
}
.cluster-controls {
  display: flex;
  gap: var(--xf-spacing-lg);
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: var(--xf-spacing-md);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
}
.control-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.ban-summary {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.ban-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.ban-label {
  min-width: 120px;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}
.ban-value {
  font-weight: 600;
  color: var(--xf-gray-800);
}
.ban-impact {
  margin: 4px 0;
}
.ban-refusal {
  margin-top: 4px;
}
.ban-reason {
  width: 100%;
}
/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .criteria-form .el-input,
  .criteria-form .el-date-editor,
  .criteria-form .el-input-number {
    width: 100% !important;
  }
  .dist-row {
    flex-direction: column;
  }
  .ban-label {
    min-width: 90px;
  }
}
/* 无障碍降级：本页动效纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .glass-card {
    animation: none !important;
  }
}
</style>
