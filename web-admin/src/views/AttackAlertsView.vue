<template>
  <div class="page">
    <!-- 标题卡：工作台内嵌时（showTitle=false）由工作台标题承接 -->
    <div v-if="showTitle" class="glass glass-card alerts-title">
      <div class="card-header">
        <span>{{ $t('attackAlerts.pageTitle') }}</span>
      </div>
      <p class="card-hint">{{ $t('attackAlerts.pageSubtitle') }}</p>
    </div>

    <!-- 分类分段：tab 即 attackType 筛选（LANSEC 专家分析同构），带分类计数角标 -->
    <div class="glass glass-card alerts-bar">
      <GlassSegmented
        v-model="filters.attackType"
        :options="typeOptions"
        :aria-label="$t('attackAlerts.typeCol')"
        data-test="alerts-type-segmented"
        @change="handleSearch"
      />
      <el-alert
        v-if="summaryFailed"
        :title="$t('common.listLoadFailed')"
        type="warning"
        :closable="false"
        show-icon
        class="summary-error"
        data-test="alerts-summary-error"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            @click="loadSummary"
          >
            {{ $t('common.retry') }}
          </button>
        </template>
      </el-alert>
    </div>

    <!-- 筛选卡：字段语义与审计页同族；el-select 只绑 @change 不绑 @clear，防双请求 -->
    <div class="glass filter-card">
      <el-form :model="filters" label-position="top" class="filter-form">
        <el-form-item :label="$t('report.dateRange')" class="filter-item--wide">
          <el-date-picker
            v-model="filters.dateRange"
            type="daterange"
            range-separator="-"
            :start-placeholder="$t('report.startDate')"
            :end-placeholder="$t('report.endDate')"
            value-format="YYYY-MM-DD"
            style="width: 100%"
            @change="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.sourceIp')">
          <el-input
            v-model="filters.ip"
            :placeholder="$t('attackAlerts.sourceIpHint')"
            clearable
            maxlength="64"
            data-test="alerts-filter-ip"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.account')">
          <el-input
            v-model="filters.username"
            :placeholder="$t('attackAlerts.accountHint')"
            clearable
            maxlength="30"
            data-test="alerts-filter-username"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.severityMin')">
          <el-select v-model="filters.severityMin" clearable @change="handleSearch">
            <el-option :label="$t('attackAlerts.severity.critical')" value="critical" />
            <el-option :label="$t('attackAlerts.severity.high')" value="high" />
            <el-option :label="$t('attackAlerts.severity.medium')" value="medium" />
            <el-option :label="$t('attackAlerts.severity.low')" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.severityMax')">
          <el-select v-model="filters.severityMax" clearable @change="handleSearch">
            <el-option :label="$t('attackAlerts.severity.critical')" value="critical" />
            <el-option :label="$t('attackAlerts.severity.high')" value="high" />
            <el-option :label="$t('attackAlerts.severity.medium')" value="medium" />
            <el-option :label="$t('attackAlerts.severity.low')" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.ruleName')">
          <el-select
            v-model="filters.action"
            clearable
            filterable
            :data-test="'alerts-filter-action'"
            @change="handleSearch"
          >
            <el-option
              v-for="actionCode in ALL_ATTACK_EVENT_ACTIONS"
              :key="actionCode"
              :label="actionTitle(actionCode)"
              :value="actionCode"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('attackAlerts.pathFilter')">
          <el-input
            v-model="filters.path"
            :placeholder="$t('attackAlerts.pathHint')"
            clearable
            maxlength="200"
            data-test="alerts-filter-path"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <!-- type="button" 防止 el-form 内原生按钮触发 submit 刷新页面（审计页同惯例） -->
        <div class="filter-actions glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            data-test="alerts-search"
            @click="handleSearch"
          >
            {{ $t('common.search') }}
          </button>
          <button
            type="button"
            class="glass-btn glass-btn--default"
            data-test="alerts-reset"
            @click="resetFilters"
          >
            {{ $t('common.reset') }}
          </button>
        </div>
      </el-form>
    </div>

    <!-- 数据范围自述：蜜罐行不带 userId，self/department 档空结果不等于「没有攻击」 -->
    <el-alert
      v-if="scopeLimited"
      :title="$t('attackAlerts.scopeLimited')"
      type="info"
      :closable="false"
      show-icon
      data-test="alerts-scope-limited"
    />

    <!-- 失败语义与审计/报警同契约：stale 保留旧数据并标注，failed 让位错误块 -->
    <el-alert
      v-if="listState.failed.value"
      :title="listState.stale.value ? $t('common.staleData') : $t('common.listLoadFailed')"
      type="warning"
      :closable="false"
      show-icon
      class="load-error"
      data-test="alerts-load-error"
    >
      <template #default>
        <button
          type="button"
          class="glass-btn glass-btn--default glass-btn--sm"
          :disabled="loading"
          :aria-label="$t('attackAlerts.retryAria')"
          @click="loadData"
        >
          {{ $t('common.retry') }}
        </button>
      </template>
    </el-alert>

    <GlassSkeleton
      v-if="loading && rows.length === 0"
      variant="table"
      :rows="6"
      :cols="['15%', '16%', '20%', '10%', '24%', '8%', '7%']"
    />
    <div v-else-if="listState.showTable.value" class="glass table-card">
      <el-table
        v-loading="loading"
        :data="rows"
        border
        stripe
        style="width: 100%"
        data-test="alerts-table"
      >
        <el-table-column type="index" label="#" width="55" />
        <el-table-column :label="$t('attackAlerts.detailTime')" width="165">
          <template #default="{ row }">
            <span :title="row.timestamp">{{ formatTime(row.timestamp) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.sourceCol')" min-width="150">
          <template #default="{ row }">
            <div class="cell-main">{{ row.ip || '—' }}</div>
            <div v-if="row.username" class="cell-sub">{{ row.username }}</div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.requestCol')" min-width="180">
          <template #default="{ row }">
            <div class="cell-main request-cell">
              <el-tag v-if="row.method" size="small" effect="plain" class="method-tag">
                {{ row.method }}
              </el-tag>
              <span class="path-text" :title="row.path">{{ row.path || '—' }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.typeCol')" width="105" align="center">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ attackTypeText(row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.evidenceCol')" min-width="250">
          <template #default="{ row }">
            <div class="cell-main">{{ actionTitle(row.action) }}</div>
            <div class="cell-sub evidence-sub" :title="evidenceOf(row)">
              {{ evidenceOf(row) }}
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.severityCol')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="riskTagType(row.riskLevel)" size="small">
              {{ severityText(row.riskLevel) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('attackAlerts.disposalCol')" width="95" align="center">
          <template #default="{ row }">
            <el-tag :type="disposalTagType(row.disposal)" size="small" effect="plain">
              {{ disposalText(row.disposal) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="150" fixed="right" align="center">
          <template #default="{ row }">
            <button
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              data-test="alerts-detail-btn"
              @click="openDetail(row)"
            >
              {{ $t('common.detail') }}
            </button>
            <button
              v-if="row.ip"
              type="button"
              class="glass-btn glass-btn--default glass-btn--link"
              data-test="alerts-forensic-btn"
              @click="goForensic(row)"
            >
              {{ $t('attackAlerts.goForensic') }}
            </button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页：total 未知（游标语义/字段缺失）时显式标注，不拿页长顶替 -->
      <div v-if="listState.showTable.value" class="pagination">
        <span v-if="!listState.totalKnown.value" class="total-unknown">
          {{ $t('common.totalUnknown') }}
        </span>
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="limit"
          :total="listState.total.value ?? 0"
          :page-sizes="[20, 50, 100]"
          :layout="
            listState.totalKnown.value
              ? 'total, sizes, prev, pager, next, jumper'
              : 'sizes, prev, pager, next, jumper'
          "
          data-test="alerts-pagination"
          @size-change="handleSizeChange"
          @current-change="loadData"
        />
      </div>
    </div>

    <!-- 审计读取二次验证：与审计页同族，无票据 → 弹框验过后重放被拦动作 -->
    <ReauthDialog
      v-model="reauthVisible"
      :submitting="reauthSubmitting"
      @submit="handleReauthSubmit"
    />

    <!-- 详情对话框：列表投影刻意不含 body/头袋，完整记录由单条详情接口补齐 -->
    <el-dialog
      v-model="detail.visible"
      :title="$t('attackAlerts.detailTitle')"
      width="min(760px, 94vw)"
      append-to-body
    >
      <div v-loading="detail.loading" class="detail-scroll" data-test="alerts-detail-dialog">
        <el-alert
          v-if="detail.error"
          :title="$t('attackAlerts.detailLoadFailed')"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-descriptions v-if="detail.row" :column="2" border size="small">
          <el-descriptions-item :label="$t('attackAlerts.detailTime')">
            {{ formatTime(detail.row.timestamp) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailSource')">
            {{ detail.row.ip || '—' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailRequest')" :span="2">
            {{ detail.row.method || '' }} {{ detail.row.path || '' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailAction')">
            {{ actionTitle(detail.row.action) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.typeCol')">
            {{ attackTypeText(detail.row) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailSeverity')">
            {{ severityText(detail.row.riskLevel) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailDisposal')">
            {{ disposalText(detail.row.disposal) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('attackAlerts.detailDescription')" :span="2">
            {{ detail.row.description || $t('attackAlerts.noDescription') }}
          </el-descriptions-item>
          <el-descriptions-item
            v-if="detail.row.errorMessage"
            :label="$t('attackAlerts.detailError')"
            :span="2"
          >
            {{ detail.row.errorMessage }}
          </el-descriptions-item>
        </el-descriptions>
        <div v-if="(detail.row?.riskFactors || []).length" class="risk-factors">
          <span class="risk-factors__title">{{ $t('attackAlerts.riskFactorsTitle') }}</span>
          <el-tag
            v-for="factor in detail.row.riskFactors"
            :key="factor"
            size="small"
            effect="plain"
            class="risk-factors__tag"
          >
            <el-tooltip
              :content="riskFactorDesc(factor, locale)"
              :disabled="!riskFactorDesc(factor, locale)"
              placement="top"
            >
              <span>{{ riskFactorLabel(factor, locale) }}</span>
            </el-tooltip>
          </el-tag>
        </div>
      </div>
      <template #footer>
        <button
          v-if="detail.row && detail.row.ip"
          type="button"
          class="glass-btn glass-btn--default"
          @click="goForensic(detail.row)"
        >
          {{ $t('attackAlerts.goForensic') }}
        </button>
        <button type="button" class="glass-btn glass-btn--primary" @click="detail.visible = false">
          {{ $t('common.close') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { api, isCanceledError } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useListLoadState } from '@/composables/useListLoadState'
import GlassSegmented from '@/components/GlassSegmented.vue'
import GlassSkeleton from '@/components/GlassSkeleton.vue'
import ReauthDialog from '@/components/ReauthDialog.vue'
import { formatTime } from '@/utils/datetime'
// 风险码的展示期翻译与审计详情共用一份（i18n/auditRiskFactors.js），避免两处文案漂移
import { riskFactorLabel, riskFactorDesc } from '@/i18n/auditRiskFactors'
import {
  ATTACK_EVENT_TYPE_CODES,
  ALL_ATTACK_EVENT_ACTIONS,
  attackTypeOfAction,
} from '@/constants/attackAlerts'
import i18n from '@/i18n'
import attackAlertsZhCN from '@/i18n/locales/attackAlerts.zh-CN'
import attackAlertsEnUS from '@/i18n/locales/attackAlerts.en-US'

// 懒加载词典随本 chunk 注入（attackProfile 同款：入口词表不背这组文案）
i18n.global.mergeLocaleMessage('zh-CN', { attackAlerts: attackAlertsZhCN })
i18n.global.mergeLocaleMessage('en-US', { attackAlerts: attackAlertsEnUS })

defineProps({ showTitle: { type: Boolean, default: true } })

const { t, te, locale } = useI18n()
const router = useRouter()

// 词典 miss 时 te() 为 false：退回原始码（新码表漏登记时页面显示裸码而不是空白，
// attackProfile 词典闸同一条哲学——错要错得可见）
const dictText = (prefix, code, fallback) => {
  if (!code) return fallback
  return te(`${prefix}.${code}`) ? t(`${prefix}.${code}`) : code
}

// ===== 筛选状态：字段名与后端 buildAttackEventFilters 一一对应 =====
const filters = reactive({
  attackType: '', // '' = 全部攻击（分段控件的「全部」项）
  dateRange: null,
  ip: '',
  username: '',
  severityMin: '',
  severityMax: '',
  action: '',
  path: '',
})

const page = ref(1)
const limit = ref(50) // LANSEC 参考页默认 50 条
const rows = ref([])
const loading = ref(false)

// ===== 分类计数（tab 角标）=====
const summary = reactive({ all: null, byType: {} })
const summaryFailed = ref(false)
const summaryGuard = useLatestRequest()

const typeOptions = computed(() => [
  { label: t('attackAlerts.tabsAll'), value: '', count: summary.all },
  ...ATTACK_EVENT_TYPE_CODES.map((code) => ({
    label: t(`attackAlerts.types.${code}`),
    value: code,
    count: summary.byType[code],
  })),
])

// ===== 数据范围自述（meta.dataScopeType ≠ all 时提示）=====
const scopeLimited = ref(false)

// ===== 竞态守卫 + 三态契约（与审计/报警列表同源）=====
const listGuard = useLatestRequest()
const listState = useListLoadState()

// ===== 二次验证票据（与 AuditLogView 同契约：按 tag 去重、验后重放）=====
const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']
const reauthVisible = ref(false)
const reauthSubmitting = ref(false)
const pendingReauthTags = new Set()

const requireReauth = (tag) => {
  pendingReauthTags.add(tag)
  reauthVisible.value = true
}

const readReauthErrorCode = async (e) => {
  const data = e?.response?.data
  if (data?.errors?.errorCode) return data.errors.errorCode
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    try {
      return JSON.parse(await data.text())?.errors?.errorCode || ''
    } catch (_) {
      return ''
    }
  }
  return ''
}

const handleReauthSubmit = async (credential) => {
  reauthSubmitting.value = true
  try {
    const res = await api.security.createReauthTicket(credential)
    if (!res?.data?.data) return
    // 前端不保存 ticket（窗口在服务端），只重放被拦动作
    const tags = [...pendingReauthTags]
    pendingReauthTags.clear()
    reauthVisible.value = false
    for (const tag of tags) {
      if (tag === 'events') loadData()
      else if (tag === 'summary') loadSummary()
      else if (tag === 'detail' && detail.id) loadDetail(detail.id)
    }
  } catch (_) {
    // 凭据错误提示由 api 拦截器统一输出；弹层保持打开便于重试
  } finally {
    reauthSubmitting.value = false
  }
}

// 构建查询参数：只塞非空值（空串会改变后端谓词语义）
const buildFilterParams = () => {
  const params = {}
  if (filters.attackType) params.attackType = filters.attackType
  if (String(filters.ip || '').trim()) params.ip = String(filters.ip).trim()
  if (String(filters.username || '').trim()) params.username = String(filters.username).trim()
  if (filters.severityMin) params.severityMin = filters.severityMin
  if (filters.severityMax) params.severityMax = filters.severityMax
  if (filters.action) params.action = filters.action
  if (String(filters.path || '').trim()) params.path = String(filters.path).trim()
  if (filters.dateRange && filters.dateRange.length === 2) {
    params.startDate = filters.dateRange[0]
    params.endDate = filters.dateRange[1]
  }
  return params
}

// 分类计数：角标语义是「给定其它筛选，各类各有多少」，attackType 由后端剔除
const loadSummary = async () => {
  const isCurrent = summaryGuard()
  summaryFailed.value = false
  try {
    const res = await api.security.getAttackEventSummary(buildFilterParams())
    if (!isCurrent()) return
    summary.byType = res.data?.data || {}
    summary.all = res.data?.meta?.all ?? null
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('summary')
      return
    }
    // 计数失败不拖垮列表：分段降级为无角标，留一条可重试的痕迹
    summaryFailed.value = true
  }
}

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  listState.begin()
  try {
    const res = await api.security.getAttackEvents({
      page: page.value,
      limit: limit.value,
      ...buildFilterParams(),
    })
    if (!isCurrent()) return
    rows.value = res.data?.data || []
    listState.commit({ total: res.data?.meta?.total, count: rows.value.length })
    scopeLimited.value = (res.data?.meta?.dataScopeType || 'all') !== 'all'
    const clamped = listState.clampPage(page.value, limit.value)
    if (clamped !== page.value) {
      page.value = clamped
      return loadData()
    }
  } catch (e) {
    // 路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) {
      listState.abort()
      return
    }
    if (!isCurrent()) return
    // 票据过期：重新验证后重放本次查询，不当作业务失败提示
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('events')
      return
    }
    // 失败提示由 api 拦截器统一输出；有旧数据 ⇒ stale（保留+标注），无 ⇒ failed
    listState.fail()
  } finally {
    if (isCurrent()) loading.value = false
  }
}

const handleSearch = () => {
  page.value = 1
  loadData()
  loadSummary()
}

const handleSizeChange = () => {
  page.value = 1
  loadData()
}

const resetFilters = () => {
  filters.attackType = ''
  filters.dateRange = null
  filters.ip = ''
  filters.username = ''
  filters.severityMin = ''
  filters.severityMax = ''
  filters.action = ''
  filters.path = ''
  handleSearch()
}

// ===== 行渲染派生 =====
const actionTitle = (action) => dictText('attackAlerts.actions', action, '—')

const attackTypeText = (row) => {
  const code = attackTypeOfAction(row.action)
  // 未注册 action（滚动部署窗口内前后端注册表短暂分叉）：显示 action 裸码，
  // 不冒充任何分类——「全部攻击」是 tab 文案，当行级标签用会误导
  return code
    ? dictText('attackAlerts.types', code, code)
    : dictText('attackAlerts.actions', row.action, '—')
}

const severityText = (level) => dictText('attackAlerts.severity', level, '—')

const riskTagType = (level) =>
  ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'success' })[level] || 'info'

const disposalText = (disposal) => dictText('attackAlerts.disposal', disposal, '—')

const disposalTagType = (disposal) =>
  ({ banned: 'danger', forensic: 'warning', observing: 'info', unknown: 'warning' })[disposal] ||
  'info'

// 证据副行：描述/原因/错误信息取第一个非空；全部为空给占位文案
const evidenceOf = (row) =>
  row.description || row.reason || row.errorMessage || t('attackAlerts.noDescription')

// ===== 详情抽屉：列表投影不含正文/头袋，单条详情接口补齐 =====
const detail = reactive({ visible: false, loading: false, error: false, row: null, id: null })
const detailGuard = useLatestRequest()

const openDetail = (row) => {
  // 先用行数据占位（列表行缺正文，详情到达后覆盖），失败保留占位并就地提示
  detail.visible = true
  detail.row = { ...row }
  detail.id = row._id
  loadDetail(row._id)
}

const loadDetail = async (id) => {
  const isCurrent = detailGuard()
  detail.loading = true
  detail.error = false
  try {
    const res = await api.security.getAuditLogDetail(id)
    if (!isCurrent()) return
    detail.row = res.data?.data || detail.row
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('detail')
      return
    }
    detail.error = true
  } finally {
    if (isCurrent()) detail.loading = false
  }
}

// ===== 查取证深链：取证视图监听 ?ip=&since=&until=（date-only）自动带入判据 =====
const wallDateOf = (value) => {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return ''
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return `${d.getFullYear()}-${mm}-${dd}`
}

const goForensic = (row) => {
  const until = wallDateOf(Date.now())
  const since = wallDateOf(row.timestamp) || until
  router.push({
    path: '/security-analysis',
    query: { tab: 'forensic', ip: row.ip, since, until },
  })
}

onMounted(() => {
  loadData()
  loadSummary()
})
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
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.card-hint {
  margin: 6px 0 0;
  font-size: 13px;
  opacity: 0.72;
}
.alerts-bar {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.summary-error {
  margin: 0;
}
.cell-main {
  font-weight: 500;
}
.cell-sub {
  margin-top: 2px;
  font-size: 12px;
  opacity: 0.72;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.evidence-sub {
  max-width: 320px;
}
.request-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.method-tag {
  flex-shrink: 0;
}
.path-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pagination {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 12px;
}
.total-unknown {
  font-size: 12px;
  opacity: 0.72;
}
.load-error {
  margin: 0;
}
.detail-scroll {
  max-height: 60vh;
  overflow: auto;
}
.risk-factors {
  margin-top: 12px;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.risk-factors__title {
  font-size: 12px;
  opacity: 0.72;
}
.risk-factors__tag {
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
}
@media (prefers-reduced-motion: reduce) {
  .glass-card {
    animation: none !important;
  }
}
</style>
