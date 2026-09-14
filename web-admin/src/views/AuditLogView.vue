<template>
  <div class="page">
    <!-- 筛选条件 -->
    <div class="glass filter-card">
      <el-form :inline="true" :model="filters">
        <el-form-item :label="$t('report.dateRange')">
          <el-date-picker
            v-model="filters.dateRange"
            type="daterange"
            range-separator="-"
            :start-placeholder="$t('report.startDate')"
            :end-placeholder="$t('report.endDate')"
            value-format="YYYY-MM-DD"
            style="width: 280px"
            @change="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('user.title')">
          <el-input
            v-model="filters.username"
            :placeholder="$t('user.username')"
            clearable
            maxlength="30"
            style="width: 150px"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('security.title')">
          <el-select
            v-model="filters.category"
            :placeholder="$t('common.pleaseSelect')"
            clearable
            style="width: 150px"
            @change="handleSearch"
            @clear="handleSearch"
          >
            <el-option :label="$t('auditLog.catAuthLogin')" value="auth" />
            <el-option :label="$t('auditLog.catUserManagement')" value="user" />
            <el-option :label="$t('auditLog.catRoleManagement')" value="role" />
            <el-option :label="$t('auditLog.catPermissionManagement')" value="permission" />
            <el-option :label="$t('auditLog.catDeviceManagement')" value="device" />
            <el-option :label="$t('auditLog.catAlarmHandling')" value="alarm" />
            <el-option :label="$t('auditLog.catInspectionManagement')" value="inspection" />
            <el-option :label="$t('auditLog.catSecurity')" value="security" />
            <el-option :label="$t('auditLog.catReport')" value="report" />
            <el-option :label="$t('auditLog.catSystemOps')" value="system" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('auditLog.logLevel')">
          <el-select
            v-model="filters.level"
            :placeholder="$t('common.pleaseSelect')"
            clearable
            style="width: 120px"
            @change="handleSearch"
            @clear="handleSearch"
          >
            <el-option :label="$t('auditLog.levelInfo')" value="info" />
            <el-option :label="$t('auditLog.levelWarning')" value="warning" />
            <el-option :label="$t('auditLog.levelError')" value="error" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('auditLog.riskLevel')">
          <el-select
            v-model="filters.riskLevel"
            :placeholder="$t('common.pleaseSelect')"
            clearable
            style="width: 120px"
            @change="handleSearch"
            @clear="handleSearch"
          >
            <el-option :label="$t('auditLog.riskCritical')" value="critical" />
            <el-option :label="$t('common.levelHigh')" value="high" />
            <el-option :label="$t('common.levelMedium')" value="medium" />
            <el-option :label="$t('common.levelLow')" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('auditLog.resultLabel')">
          <el-select
            v-model="filters.success"
            :placeholder="$t('common.pleaseSelect')"
            clearable
            style="width: 120px"
            @change="handleSearch"
            @clear="handleSearch"
          >
            <el-option :label="$t('auditLog.resultSuccess')" :value="true" />
            <el-option :label="$t('auditLog.resultFailure')" :value="false" />
          </el-select>
        </el-form-item>
        <el-form-item class="glass-btn-group">
          <!-- type="button" 防止 el-form 内原生按钮触发 submit 刷新页面 -->
          <button type="button" class="glass-btn glass-btn--primary" @click="handleSearch">
            {{ $t('common.search') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="resetFilters">
            {{ $t('common.reset') }}
          </button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 统计卡片 -->
    <el-row v-if="statsLoaded" :gutter="16">
      <el-col :xs="12" :sm="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-value critical">
              {{ stats.criticalAlerts || 0 }}
            </div>
            <div class="stat-label">
              {{ $t('auditLog.severeAlert') }}
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-value high">
              {{ stats.highAlerts || 0 }}
            </div>
            <div class="stat-label">
              {{ $t('auditLog.highRiskOps') }}
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-value warning">
              {{ stats.failedLogins || 0 }}
            </div>
            <div class="stat-label">
              {{ $t('auditLog.loginFailed') }}
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-value info">
              {{ total }}
            </div>
            <div class="stat-label">
              {{ $t('auditLog.totalRecords') }}
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 日志列表 -->
    <div class="glass glass-card" style="margin-top: 16px">
      <div class="card-header" style="margin-bottom: 16px">
        <span>{{ $t('security.auditLogs') }}</span>
        <button
          v-if="canExportAudit"
          type="button"
          class="glass-btn glass-btn--primary glass-btn--sm"
          :disabled="exporting"
          @click="exportLogs"
        >
          {{ $t('common.export') }}
        </button>
      </div>

      <!-- 首屏骨架：日志未到达时占位 -->
      <GlassSkeleton
        v-if="loading && logs.length === 0"
        variant="table"
        :rows="8"
        :cols="['12%', '12%', '16%', '14%', '12%', '9%', '9%', '8%', '8%']"
      />
      <el-table
        v-else
        v-loading="loading"
        :data="logs"
        stripe
        size="small"
        style="width: 100%"
        :row-class-name="riskRowClass"
      >
        <el-table-column prop="timestamp" :label="$t('common.createTime')" width="165" fixed>
          <template #default="{ row }">
            {{ formatTime(row.timestamp) }}
          </template>
        </el-table-column>
        <!-- 操作用户 + IP 合并：主行用户名，副行 IP（等宽字体） -->
        <el-table-column :label="$t('user.title')" width="150">
          <template #default="{ row }">
            <div class="cell-main">
              {{ row.username || '-' }}
            </div>
            <div class="cell-sub cell-mono">
              {{ row.ip || '-' }}
            </div>
          </template>
        </el-table-column>
        <!-- 操作类型 + 分类合并：主行动作名，副行分类标签 -->
        <el-table-column :label="$t('common.operation')" min-width="140">
          <template #default="{ row }">
            <div class="cell-main">
              {{ actionLabel(row.action) }}
            </div>
            <div class="cell-sub">
              <el-tag size="small" effect="plain">
                {{ categoryLabel(row.category) }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <!-- 请求方式 + 路径合并：事件型日志（登录/告警等）无请求信息时显示占位符 -->
        <el-table-column label="Request" min-width="200">
          <template #default="{ row }">
            <template v-if="row.method || row.path">
              <el-tag
                v-if="row.method"
                :type="getMethodType(row.method)"
                size="small"
                class="method-tag"
              >
                {{ row.method }}
              </el-tag>
              <span class="path-text" :title="row.path">{{ row.path || '-' }}</span>
            </template>
            <span v-else class="cell-sub">—</span>
          </template>
        </el-table-column>
        <!-- 风险等级 + 日志等级合并：主行风险等级（数据字段），副行日志等级（success+riskLevel 派生，口径同筛选） -->
        <el-table-column label="Risk/Level" width="95" align="center">
          <template #default="{ row }">
            <el-tag :type="riskType(row.riskLevel)" size="small">
              {{ riskText(row.riskLevel) }}
            </el-tag>
            <div class="cell-sub">
              <el-tag :type="logLevelType(row)" size="small" effect="plain">
                {{ logLevelText(row) }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="success" :label="$t('common.status')" width="75" align="center">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'" size="small">
              {{ row.success ? $t('common.yes') : $t('common.no') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="80" fixed="right" align="center">
          <template #default="{ row }">
            <button
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="viewDetail(row)"
            >
              {{ $t('common.operation') }}
            </button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="limit"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="loadData"
        />
      </div>
    </div>

    <!-- 详情对话框 -->
    <!-- append-to-body：传送至 body，避免任何祖先 transform/filter 改变 fixed 遮罩的定位基准 -->
    <el-dialog
      v-model="detailDialog.visible"
      :title="$t('security.auditLogs')"
      width="700px"
      append-to-body
    >
      <el-descriptions v-if="detailDialog.data" :column="1" border>
        <el-descriptions-item :label="$t('auditLog.opTime')">
          {{ formatTime(detailDialog.data.timestamp) }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.opUser')">
          {{ detailDialog.data.username }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.userIdLabel')">
          {{ detailDialog.data.userId || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.opType')">
          {{ actionLabel(detailDialog.data.action) }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.categoryLabel')">
          {{ categoryLabel(detailDialog.data.category) }}
        </el-descriptions-item>
        <el-descriptions-item
          v-if="detailDialog.data.targetUsername"
          :label="$t('auditLog.targetUser')"
        >
          {{ detailDialog.data.targetUsername }}
        </el-descriptions-item>
        <el-descriptions-item v-if="detailDialog.data.reason" :label="$t('auditLog.opReason')">
          {{ detailDialog.data.reason }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.reqMethod')">
          {{ detailDialog.data.method || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.reqPath')">
          {{ detailDialog.data.path || '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="IP 地址">
          {{ detailDialog.data.ip || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.riskLevel')">
          <el-tag :type="riskType(detailDialog.data.riskLevel)">
            {{ riskText(detailDialog.data.riskLevel) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="detailDialog.data.riskFactors && detailDialog.data.riskFactors.length"
          :label="$t('auditLog.riskFactors')"
        >
          <el-tag
            v-for="factor in detailDialog.data.riskFactors"
            :key="factor"
            size="small"
            type="warning"
            effect="plain"
            class="risk-factor-tag"
          >
            {{ factor }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.resultLabel')">
          <el-tag :type="detailDialog.data.success ? 'success' : 'danger'">
            {{
              detailDialog.data.success
                ? $t('auditLog.resultSuccess')
                : $t('auditLog.resultFailure')
            }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="detailDialog.data.errorMessage"
          :label="$t('auditLog.errorInfo')"
        >
          {{ detailDialog.data.errorMessage }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.reqBody')">
          <pre class="json-preview">{{
            formatJson(detailDialog.data.body ?? detailDialog.data.params)
          }}</pre>
        </el-descriptions-item>
        <el-descriptions-item label="User-Agent">
          <span class="ua-text">{{ detailDialog.data.userAgent || '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="detailDialog.data.duration != null"
          :label="$t('auditLog.duration')"
        >
          {{ detailDialog.data.duration }}ms
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="detailDialog.visible = false"
        >
          {{ $t('common.close') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { apiClient } from '@/utils/api'
import { localDateStr } from '@/utils/datetime'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { usePermission } from '@/composables/usePermission'

const { t, locale } = useI18n()
const { hasAllPerms } = usePermission()

/**
 * 导出按钮的门控（P3-40）
 *
 * 后端 /api/reports/export 对 audit 类型要求**两个**权限：
 *   1. 路由级 checkPermission('report:export')
 *   2. 控制器内额外校验 security:audit（reportController.js:476-485）
 * 第二道校验是刻意加的越权出口封堵：审计日志含全系统所有用户的 IP/路径/
 * 操作记录，若只需 report:export（通常下发运营岗）就能导出，等于绕过
 * 整个 security:audit 权限模型。
 *
 * 前端原先完全不做门控，audit-only 管理员（有 security:audit 无
 * report:export）点击必吃 403。因此必须两个权限**同时**具备才显示按钮，
 * 少任何一个都点不动。
 */
const canExportAudit = computed(() => hasAllPerms(['report:export', 'security:audit']))

const loading = ref(false)
const page = ref(1)
const limit = ref(20)
const total = ref(0)
const logs = ref([])
const stats = ref({ criticalAlerts: 0, highAlerts: 0, failedLogins: 0 })
const statsLoaded = ref(false)

const filters = reactive({
  dateRange: null,
  username: '',
  category: '',
  level: '',
  riskLevel: '',
  success: null,
})

const detailDialog = reactive({
  visible: false,
  data: null,
})

// 构建当前筛选条件对应的查询参数（列表与导出共用，保证"导出即所见"）
const buildFilterParams = () => {
  const params = {}
  if (filters.username) params.username = filters.username
  if (filters.category) params.category = filters.category
  if (filters.level) params.level = filters.level
  if (filters.riskLevel) params.riskLevel = filters.riskLevel
  // 注意：el-select clearable 清空后值为空字符串，需一并排除，
  // 否则空串会被后端解析为 false，导致"清空筛选=只看失败"的错误结果
  if (filters.success === true || filters.success === false) params.success = filters.success
  if (filters.dateRange && filters.dateRange.length === 2) {
    params.startDate = filters.dateRange[0]
    params.endDate = filters.dateRange[1]
  }
  return params
}

// 加载数据
// 竞态守卫：快速筛选/翻页时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const params = {
      page: page.value,
      limit: limit.value,
      ...buildFilterParams(),
    }

    const res = await apiClient.get('/security/audit-logs', { params })
    if (!isCurrent()) return
    // 后端返回结构：{ success: true, data: { data: [logs], meta: {...} }, message: '...' }
    const result = res.data?.data
    logs.value = result?.data || []
    total.value = result?.meta?.total || 0
  } catch (e) {
    if (!isCurrent()) return
    ElMessage.error(t('messages.loadFailed'))
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 筛选条件变更 / 点击查询：重置到第一页再加载，避免停留在超出结果集的页码上看到空列表
const handleSearch = () => {
  page.value = 1
  loadData()
}

// 分页大小变化：同样回到第一页
const handleSizeChange = () => {
  page.value = 1
  loadData()
}

// 加载统计数据（统计卡片统一由安全概览接口提供，与列表查询解耦，避免相互覆盖）
const loadStats = async () => {
  try {
    const res = await apiClient.get('/security/overview')
    const data = res.data?.data
    if (data) {
      stats.value = {
        criticalAlerts: data.criticalAlerts || 0,
        highAlerts: data.highAlerts || 0,
        failedLogins: data.failedLogins || 0,
      }
      statsLoaded.value = true
    }
  } catch (e) {
    // 统计加载失败，静默处理
  }
}

// 重置筛选条件
const resetFilters = () => {
  filters.dateRange = null
  filters.username = ''
  filters.category = ''
  filters.level = ''
  filters.riskLevel = ''
  filters.success = null
  handleSearch()
}

// 查看详情
const viewDetail = (row) => {
  // 直接使用当前行的数据作为详情（因为列表已经包含完整信息）
  detailDialog.data = row
  detailDialog.visible = true
}

// 导出日志
const exporting = ref(false)

const exportLogs = async () => {
  exporting.value = true
  try {
    const params = {
      type: 'audit', // 审计日志类型
      ...buildFilterParams(),
    }

    const response = await apiClient.get('/reports/export', {
      params,
      responseType: 'blob',
    })

    // 截断提示：/reports/export 的 xlsx 分支当前不返回截断标记字段（EXPORT_LIMIT 静默截断）；
    // 若后端后续补充截断提示（响应头 X-Export-Truncated 或 JSON 体 notice 字段），这里自动向用户展示
    const notice = response?.headers?.['x-export-truncated'] || ''
    if (notice) ElMessage.warning(String(notice))

    const blob = new Blob([response.data], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    // 评价报告 #20：文件名日期走本地时区（toISOString 在东八区 0-8 点会早一天）
    link.download = `audit_logs_${localDateStr()}.xlsx`
    link.click()
    window.URL.revokeObjectURL(url)

    ElMessage.success(t('messages.exportSuccess'))
  } catch (e) {
    ElMessage.error(t('messages.exportFailed'))
  } finally {
    exporting.value = false
  }
}

// 格式化时间
const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString(locale.value, { hour12: false })
}

// 格式化 JSON（列表接口出于安全不返回 body/params 时显示占位符）
const formatJson = (value) => {
  if (value === null || value === undefined) return '-'
  if (typeof value !== 'object' || Object.keys(value).length === 0) return '-'
  return JSON.stringify(value, null, 2)
}

// 操作类型标签：audit.action 文案组与后端 securityController AUDIT_LOG_ACTIONS
// 枚举全集一一对应（含路由派生型/事件型/历史兼容三部分）
const actionLabel = (action) => {
  if (!action) return '-'
  const key = `audit.action.${action}`
  const label = t(key)
  // 无对应文案时回退展示原始动作名，便于识别新增的枚举值
  return label === key ? action : label
}

// 分类标签
const categoryLabel = (category) => {
  const labels = {
    auth: t('auditLog.shortAuth'),
    user: t('auditLog.shortUser'),
    role: t('auditLog.shortRole'),
    permission: t('auditLog.shortPermission'),
    device: t('auditLog.shortDevice'),
    alarm: t('auditLog.shortAlarm'),
    inspection: t('auditLog.shortInspection'),
    security: t('auditLog.catSecurity'),
    report: t('auditLog.catReport'),
    system: t('auditLog.shortSystem'),
  }
  return labels[category] || category || '-'
}

// 风险等级样式
const riskType = (level) => {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'success' }[level] || 'info'
}

const riskText = (level) => {
  return (
    {
      critical: t('common.critical'),
      high: t('common.high'),
      medium: t('common.medium'),
      low: t('common.low'),
    }[level] ||
    level ||
    '-'
  )
}

// 请求方式样式
const getMethodType = (method) => {
  return (
    { GET: 'info', POST: 'success', PUT: 'warning', DELETE: 'danger', PATCH: 'primary' }[method] ||
    ''
  )
}

// ===== 日志等级（派生自 success + riskLevel，与后端筛选口径完全一致） =====
// 错误 = 操作失败 或 高危/严重风险；警告 = 成功且中风险；信息 = 成功且非中高以上风险
const logLevel = (row) => {
  if (!row.success || ['high', 'critical'].includes(row.riskLevel)) return 'error'
  if (row.riskLevel === 'medium') return 'warning'
  return 'info'
}

const logLevelText = (row) =>
  ({ error: t('common.error'), warning: t('common.warning'), info: t('common.info') })[
    logLevel(row)
  ]

const logLevelType = (row) => ({ error: 'danger', warning: 'warning', info: 'info' })[logLevel(row)]

// 高风险行着色：严重行淡红、高风险行淡橙，便于在长列表中快速定位安全事件
const riskRowClass = ({ row }) => {
  if (row.riskLevel === 'critical') return 'row-risk-critical'
  if (row.riskLevel === 'high') return 'row-risk-high'
  return ''
}

onMounted(() => {
  loadData()
  loadStats()
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.table-toolbar {
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}
.stat-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.stat-card :deep(.el-card__body) {
  padding: 16px;
}
.stat-content {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.stat-value {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-base);
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  letter-spacing: var(--xf-tracking-tight);
  line-height: 1.2;
  color: var(--xf-gray-900);
}
.stat-value.critical {
  color: var(--xf-danger-strong);
}
.stat-value.high {
  color: var(--xf-warning);
}
.stat-value.warning {
  color: var(--xf-warning);
}
.stat-value.info {
  color: var(--xf-gray-900);
}
.stat-label {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
  text-transform: uppercase;
}
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  font-family: var(--xf-font-mono);
}
.json-preview {
  font-family: var(--xf-font-mono);
  background: var(--xf-gray-100);
  padding: 8px;
  border-radius: var(--xf-radius-sm);
  max-height: 200px;
  overflow-y: auto;
  font-size: var(--xf-font-size-xs);
}

/* ===== 列表双层单元格 ===== */
.cell-main {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-900);
  line-height: 1.5;
}
.cell-sub {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  line-height: 1.4;
  margin-top: 2px;
}
.cell-mono {
  font-family: var(--xf-font-mono);
  letter-spacing: var(--xf-tracking-tight);
}
.method-tag {
  margin-right: 6px;
}
.path-text {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
  display: inline-block;
  max-width: calc(100% - 52px);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}

/* ===== 高风险行着色（与斑马纹叠加，色调克制） ===== */
:deep(.el-table .row-risk-critical td.el-table__cell) {
  background: rgba(193, 18, 31, 0.06);
}
:deep(.el-table .row-risk-high td.el-table__cell) {
  background: rgba(217, 119, 6, 0.05);
}

/* ===== 详情对话框 ===== */
.risk-factor-tag {
  margin: 2px 6px 2px 0;
}
.ua-text {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  word-break: break-all;
  color: var(--xf-gray-600);
}
:deep(.el-col:nth-child(1) .stat-card) {
  animation-delay: 0.05s;
}
:deep(.el-col:nth-child(2) .stat-card) {
  animation-delay: 0.1s;
}
:deep(.el-col:nth-child(3) .stat-card) {
  animation-delay: 0.15s;
}
:deep(.el-col:nth-child(4) .stat-card) {
  animation-delay: 0.2s;
}

/* ===== Apple 风格增量（交互手感层：只叠反馈与过渡，不改布局；数据密集页保持克制） ===== */

/* 统计卡 hover：轻浮起（可中断阴影过渡，无弹跳） */
.stat-card {
  transition:
    box-shadow 280ms cubic-bezier(0.32, 0.72, 0, 1),
    transform 280ms cubic-bezier(0.32, 0.72, 0, 1);
}
.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
}

/* 玻璃卡（筛选区 / 表格区）：顺滑阴影过渡 + 材质化入场（blur+scale，非纯淡入） */
.filter-card,
.glass-card {
  transition: box-shadow 280ms cubic-bezier(0.32, 0.72, 0, 1);
  animation: glass-material-enter 0.45s cubic-bezier(0.32, 0.72, 0, 1) both;
}
.filter-card:hover,
.glass-card:hover {
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
}
@keyframes glass-material-enter {
  from {
    opacity: 0;
    transform: translateY(10px) scale(0.99);
    filter: blur(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
    filter: blur(0);
  }
}

/* 表格行背景（含风险行着色）平滑渐变，避免斑马纹/风险色跳变 */
:deep(.el-table .el-table__row td.el-table__cell) {
  transition: background-color 150ms ease;
}

/* JSON 预览滚动区：细滚动条 + 预留滚动槽，避免滚动条出现时布局抖动 */
.json-preview {
  scrollbar-width: thin;
  scrollbar-gutter: stable;
}

/* 无障碍降级：本页新增的动效全部纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .stat-card,
  .filter-card,
  .glass-card {
    animation: none !important;
    transition: opacity 150ms ease !important;
    transform: none !important;
  }
  .stat-card:hover {
    transform: none !important;
  }
}
</style>
