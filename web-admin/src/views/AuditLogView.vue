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
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('auditLog.shortUser')">
          <el-input
            v-model="filters.username"
            :placeholder="$t('auditLog.usernamePrefixHint')"
            clearable
            maxlength="30"
            style="width: 150px"
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('auditLog.categoryLabel')">
          <!-- 下面四个 el-select 只绑 @change 不绑 @clear：点清除图标时
               deleteSelected 会先 emit update:modelValue 再 emit change
               （useSelect.mjs:321-325），双绑定会让同一次清除发两遍完全相同
               的请求。用户名输入框只有 @clear（无 @change），那条保留。 -->
          <el-select
            v-model="filters.category"
            :placeholder="$t('common.pleaseSelect')"
            clearable
            style="width: 150px"
            @change="handleSearch"
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
              <!-- P1④：total 未知时显示「—」而不是 0——0 是「一条都没有」这个
                   事实断言，契约漂移时我们并不知道总数 -->
              {{ listState.totalKnown.value ? listState.total.value : '—' }}
            </div>
            <div class="stat-label">
              {{ $t('auditLog.totalRecords') }}
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 合规与防篡改面板：overview.compliance 随统计接口同包下发，此前前端取完 3 个计数就丢弃 -->
    <div v-if="compliance && !compliance.error" class="glass compliance-card">
      <div class="compliance-card__header">
        <span class="compliance-card__title">{{ $t('auditLog.complianceTitle') }}</span>
        <button
          type="button"
          class="glass-btn glass-btn--default glass-btn--sm"
          :disabled="verifying"
          @click="verifyChain"
        >
          {{ verifying ? $t('auditLog.verifying') : $t('auditLog.verifyChain') }}
        </button>
      </div>
      <div class="compliance-card__chips">
        <span class="compliance-chip">
          {{ $t('auditLog.retentionDaysLabel') }} {{ compliance.retentionDays
          }}{{ $t('auditLog.dayUnit') }}
        </span>
        <span class="compliance-chip" :class="compliance.appendOnlyEnforced ? 'is-ok' : 'is-bad'">
          {{ $t('auditLog.appendOnlyLabel') }}·{{
            compliance.appendOnlyEnforced ? $t('common.enabled') : $t('common.disabled')
          }}
        </span>
        <span class="compliance-chip" :class="compliance.monitorRunning ? 'is-ok' : 'is-bad'">
          {{ $t('auditLog.monitorLabel') }}·{{
            compliance.monitorRunning ? $t('common.enabled') : $t('common.disabled')
          }}
        </span>
        <span class="compliance-chip" :class="compliance.walEnabled ? 'is-ok' : 'is-bad'">
          {{ $t('auditLog.walLabel') }}·{{
            compliance.walEnabled ? $t('common.enabled') : $t('common.disabled')
          }}
        </span>
        <span class="compliance-chip" :class="compliance.shippingEnabled ? 'is-ok' : ''">
          {{ $t('auditLog.shippingLabel') }}·{{
            compliance.shippingEnabled ? $t('common.enabled') : $t('common.disabled')
          }}
        </span>
        <span
          class="compliance-chip"
          :class="auditLossTotal > 0 ? 'is-bad' : 'is-ok'"
          :title="auditLossDetail"
        >
          {{ $t('auditLog.auditLossLabel') }} {{ auditLossTotal }}
        </span>
        <span
          v-if="compliance.chainTailHash"
          class="compliance-chip compliance-chip--mono"
          :title="compliance.chainTailHash"
        >
          {{ $t('auditLog.chainTailLabel') }} {{ compliance.chainTailHash.slice(0, 12) }}…
        </span>
      </div>
      <!-- 监控读数：三个定时任务 getHealth() 的只读快照（compliance.monitorHealth /
           chainMonitorHealth / honeypotChainHealth）。monitorRunning 只说「定时器挂着没有」，
           而最常见的静默失效形态是「面板说活着、每轮都失败」——判据落在这一块：
           连续失败 > 0、最近成功为 null 都必须是可见的告警，而不是留白。
           某个读数整体缺失（后端降级为 null）时只把**那一行**降级，卡片其余字段照常。 -->
      <div class="compliance-monitors">
        <span class="compliance-monitors__title">{{ $t('auditLog.monitorReadingsTitle') }}</span>
        <div
          v-for="row in monitorHealthRows"
          :key="row.source"
          class="monitor-row"
          :data-monitor="row.source"
        >
          <span class="monitor-row__name">{{ $t(row.labelKey) }}</span>
          <span v-if="row.degraded" class="compliance-chip is-bad monitor-row__degraded">
            {{ $t('auditLog.monitorDegraded') }}
          </span>
          <template v-else>
            <span
              class="compliance-chip monitor-row__running"
              :class="row.running ? 'is-ok' : 'is-bad'"
            >
              {{ $t('auditLog.monitorRunningLabel') }}·{{
                row.running ? $t('common.enabled') : $t('common.disabled')
              }}
            </span>
            <!-- lastSuccessAt === null 是「定时器在、却一次都没跑成」的凭据，
                 必须显式成文（不能留白、也不能渲染 null 字面量） -->
            <span
              class="compliance-chip monitor-row__success"
              :class="row.lastSuccessAt ? 'is-ok' : 'is-bad'"
            >
              {{ $t('auditLog.monitorLastSuccessLabel') }}·{{
                row.lastSuccessAt
                  ? formatTime(row.lastSuccessAt)
                  : $t('auditLog.monitorNeverSucceeded')
              }}
            </span>
            <span
              class="compliance-chip monitor-row__failures"
              :class="row.consecutiveFailures > 0 ? 'is-bad' : 'is-ok'"
              :title="row.failureDetail"
            >
              {{ $t('auditLog.monitorConsecutiveFailuresLabel') }} {{ row.consecutiveFailures }}
            </span>
            <span class="compliance-chip monitor-row__lastrun">
              {{ $t('auditLog.monitorLastRunLabel') }}·{{
                row.lastRunAt ? formatTime(row.lastRunAt) : $t('auditLog.monitorNeverRun')
              }}
            </span>
          </template>
        </div>
      </div>
    </div>

    <!-- 最近安全告警（GET /security/alerts，security:audit）：
         后端为单层信封 { data: [alerts], meta: {...} }，数组在 res.data.data，
         元数据在 res.data.meta。失败静默且面板不出现（与统计卡同契约）：
         「没有告警」和「查不到」必须可区分，一次瞬断不能把面板装成一片祥和的空态。 -->
    <div v-if="alertsLoaded" class="glass alerts-card">
      <div class="alerts-card__header">
        <span class="alerts-card__title">{{ $t('security.recentAlerts') }}</span>
        <div class="alerts-card__actions">
          <span v-if="alertsMeta?.lastUpdated" class="alerts-card__meta">
            {{ $t('security.alertsUpdatedAt', { time: formatTime(alertsMeta.lastUpdated) }) }}
          </span>
          <span v-if="alertsMeta?.hasMore" class="alerts-card__meta">
            {{ $t('security.alertsHasMore', { limit: alertsMeta.limit || alerts.length }) }}
          </span>
          <button
            v-if="alerts.length > ALERTS_PREVIEW_COUNT"
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :aria-expanded="alertsExpanded"
            @click="alertsExpanded = !alertsExpanded"
          >
            {{ alertsExpanded ? $t('security.collapseAlerts') : $t('security.viewAllAlerts') }}
          </button>
        </div>
      </div>
      <div v-if="alerts.length === 0" class="alerts-card__empty">
        {{ $t('security.alertsEmpty') }}
      </div>
      <ul v-else class="alerts-list">
        <li v-for="alert in visibleAlerts" :key="alert._id" class="alert-row">
          <el-tag :type="riskType(alert.riskLevel)" size="small" class="alert-row__risk">
            {{ riskText(alert.riskLevel) }}
          </el-tag>
          <span class="alert-row__action">{{ actionLabel(alert.action) }}</span>
          <span class="alert-row__user cell-mono">
            {{ alert.username || '-' }} · {{ alert.ip || '—' }}
          </span>
          <span class="alert-row__time cell-mono">{{ formatTime(alert.timestamp) }}</span>
          <button
            type="button"
            class="glass-btn glass-btn--primary glass-btn--link alert-row__detail"
            @click="viewDetail(alert)"
          >
            {{ $t('common.detail') }}
          </button>
        </li>
      </ul>
    </div>

    <!-- 日志列表 -->
    <div class="glass glass-card" style="margin-top: 16px">
      <div class="card-header" style="margin-bottom: 16px">
        <span>{{ $t('security.auditLogs') }}</span>
        <div class="card-header__actions">
          <button
            v-if="canExportAudit"
            type="button"
            class="glass-btn glass-btn--primary glass-btn--sm"
            :disabled="exporting"
            @click="exportLogs"
          >
            {{ $t('common.export') }}
          </button>
          <!-- 取证级导出：CSV + 签名 manifest（含截断/记录数响应头），只需 security:audit -->
          <button
            v-if="canAudit"
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="forensicExporting"
            @click="exportForensic"
          >
            {{ $t('auditLog.forensicExport') }}
          </button>
        </div>
      </div>

      <!-- P1③（裁决②：保持旧数据）：审计日志是定责依据。失败时**不得抹掉**
           最后已知的一屏——有旧数据就继续显示并标注已过期（stale），
           没有旧数据才让位给错误块。两种情形都不显示「暂无数据」。 -->
      <el-alert
        v-if="listState.failed.value"
        :title="listState.stale.value ? $t('common.staleData') : $t('common.listLoadFailed')"
        type="warning"
        :closable="false"
        show-icon
        class="load-error"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="loading"
            @click="loadData"
          >
            {{ $t('common.retry') }}
          </button>
        </template>
      </el-alert>
      <!-- 首屏骨架：日志未到达时占位 -->
      <GlassSkeleton
        v-if="loading && logs.length === 0"
        variant="table"
        :rows="8"
        :cols="['12%', '12%', '16%', '14%', '12%', '9%', '9%', '8%', '8%']"
      />
      <el-table
        v-else-if="listState.showTable.value"
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
        <!-- 操作用户 + IP 合并：主行用户名，副行 IP（等宽字体）+ 归属地（后端可选增强，缺字段省略） -->
        <el-table-column :label="$t('auditLog.shortUser')" width="150">
          <template #default="{ row }">
            <div class="cell-main">
              {{ row.username || '-' }}
            </div>
            <div class="cell-sub cell-mono">
              {{ row.ip || '—'
              }}<span v-if="row.location" class="ip-loc">
                · {{ ipLocationText(row.location) }}</span
              >
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
              {{ $t('common.detail') }}
            </button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页：失败且无旧数据时整块不渲染（无表可分页） -->
      <div v-if="listState.showTable.value" class="pagination">
        <!-- P1④：meta.total 未知时不得用当前页长度顶替（会显示「共 N 条 / 1 页」） -->
        <span v-if="!listState.totalKnown.value" class="total-unknown">
          {{ $t('common.totalUnknown') }}
        </span>
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="limit"
          :total="listState.total.value ?? 0"
          :page-sizes="[10, 20, 50, 100]"
          :layout="
            listState.totalKnown.value
              ? 'total, sizes, prev, pager, next, jumper'
              : 'sizes, prev, pager, next, jumper'
          "
          @size-change="handleSizeChange"
          @current-change="loadData"
        />
      </div>
    </div>

    <!-- 审计读取二次验证（P3-2）：票据缺失/过期时弹出，验过后重放被拦下的动作 -->
    <ReauthDialog
      v-model="reauthVisible"
      :submitting="reauthSubmitting"
      @submit="handleReauthSubmit"
    />

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
          {{ auditReasonText(detailDialog.data.reason) }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.reqMethod')">
          {{ detailDialog.data.method || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.reqPath')">
          {{ detailDialog.data.path || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLog.ipAddress')">
          {{ detailDialog.data.ip || '—'
          }}<span v-if="detailDialog.data.location" class="ip-loc">
            · {{ ipLocationText(detailDialog.data.location) }}</span
          >
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
        <!-- 4xx 拒绝原因码：errorMessage 只有 HTTP 措辞，同一 errorCode 下的细分原因只在这里 -->
        <el-descriptions-item
          v-if="detailDialog.data.refusalReason"
          :label="$t('auditLog.refusalReason')"
        >
          <el-tag size="small" type="danger" effect="plain">
            {{ detailDialog.data.refusalReason }}
          </el-tag>
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
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api, apiClient, isCanceledError, resolveErrorMessage } from '@/utils/api'
import { useListLoadState } from '@/composables/useListLoadState'
import { markReauthVerified } from '@/utils/reauthTicket'
import ReauthDialog from '@/components/ReauthDialog.vue'
import { formatTime, localDateStr } from '@/utils/datetime'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { usePermission } from '@/composables/usePermission'
// 动作/分类文案映射与「我的操作日志」自助面共用同一份（utils/auditLabels.js），
// 避免后端新增 action 枚举时两处文案漂移
import { actionLabel as toActionLabel, categoryLabel as toCategoryLabel } from '@/utils/auditLabels'
// IP 归属地：后端只出稳定码，中文「内网」/ 英文 "Internal network" 的本地化在这一个模块
import { ipLocationLabel as toIpLocationLabel } from '@/utils/ipLocationLabels'
// 审计 reason 的展示期翻译（落库原文不动，模板映射见 i18n/auditReasons.js）
import { translateAuditReason } from '@/i18n/auditReasons'

const { t, locale } = useI18n()
const { hasPerm, hasAllPerms } = usePermission()

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
// 只需 security:audit 的「审计操作」门控（核验、取证导出）
const canAudit = computed(() => hasPerm('security:audit'))

const loading = ref(false)
const page = ref(1)
const limit = ref(20)
// 原 total ref 已并入 listState.total（契约统一保管 total 三态），
// 避免「分页器读一个 total、卡片读另一个」的双份事实。
const logs = ref([])
const stats = ref({ criticalAlerts: 0, highAlerts: 0, failedLogins: 0 })
const statsLoaded = ref(false)

// 合规面板（overview.compliance 数据已随统计接口下发，之前只取了 3 个计数就丢了）
const compliance = ref(null)
const verifying = ref(false)

const auditLossTotal = computed(() => {
  const s = compliance.value?.auditLoss
  if (!s) return 0
  // walDurableDropped 计入总数：它不是"取证缺失"而是"承诺缺失"
  // （已向调用方回成功却永久不入库），严重度不低于其它项，不能从总数里漏掉。
  // walDurableTrimRefusals 不计入：它表示"拒绝裁剪、WAL 在增长"，
  // 此刻还没有丢记录，混进"已丢失"会误导处置方向（要扩容而不是取证）。
  return (
    (s.droppedCount || 0) +
    (s.walDroppedLines || 0) +
    (s.walDiscardedLines || 0) +
    (s.walDurableDropped || 0)
  )
})

const auditLossDetail = computed(() => {
  const s = compliance.value?.auditLoss
  if (!s) return ''
  const parts = []
  if (s.droppedCount) parts.push(`dropped ${s.droppedCount}`)
  if (s.walDroppedLines) parts.push(`walDropped ${s.walDroppedLines}`)
  if (s.walDiscardedLines) parts.push(`walDiscarded ${s.walDiscardedLines}`)
  if (s.walDurableDropped) parts.push(`durableLost ${s.walDurableDropped}`)
  if (s.walDurableTrimRefusals) parts.push(`durableTrimRefused ${s.walDurableTrimRefusals}`)
  return parts.join(' / ')
})

/**
 * 三个监控模块的健康读数出口（compliance.monitorHealth / chainMonitorHealth /
 * honeypotChainHealth）。字段名以服务端 getHealth() 的返回为准：
 *   - auditMonitor / auditChainMonitor：runs/failures/consecutiveFailures/skippedOverlaps/
 *     lastRunAt/lastSuccessAt/lastFailureAt/lastFailureMessage/intervalMs/running
 *     （auditChainMonitor 另有 lastVerdictCode）
 *   - honeypotChainWatch：同一组基础计数之外还有 escalated/escalationFailures/
 *     unparsableSources/droppedCandidates 等，本区块只取三家共有的那几项。
 * 三者都可能为 null（后端 getHealth 缺失或整块降级），此时**只降级那一行**。
 */
const MONITOR_HEALTH_SOURCES = [
  { source: 'auditMonitor', field: 'monitorHealth', labelKey: 'auditLog.monitorAuditDetectLabel' },
  {
    source: 'auditChainMonitor',
    field: 'chainMonitorHealth',
    labelKey: 'auditLog.monitorChainVerifyLabel',
  },
  {
    source: 'honeypotChainWatch',
    field: 'honeypotChainHealth',
    labelKey: 'auditLog.monitorHoneypotChainLabel',
  },
]

/** 计数只认有限数字：结构漂移时按 0 计（不要 NaN 进到 chip 里） */
const healthCount = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0)

/**
 * 连续失败的 tooltip：把「连着失败几轮 / 累计失败 / 跳过几轮 / 最后一次失败」
 * 收在一处——区块本身只留四个判据字段，长文本进 title 不挤占行高。
 */
const healthFailureDetail = (h) => {
  const parts = []
  if (h.consecutiveFailures) parts.push(`consecutiveFailures ${h.consecutiveFailures}`)
  if (h.failures) parts.push(`failures ${h.failures}`)
  if (h.skippedOverlaps) parts.push(`skippedOverlaps ${h.skippedOverlaps}`)
  if (h.lastFailureAt) parts.push(`lastFailureAt ${formatTime(h.lastFailureAt)}`)
  if (h.lastFailureMessage) parts.push(String(h.lastFailureMessage).slice(0, 200))
  // 链核验的裁决码：'broken' 之类与「跑成功了但链断了」是两件事，混进计数会误读
  if (h.lastVerdictCode) parts.push(`lastVerdictCode ${h.lastVerdictCode}`)
  return parts.join(' / ')
}

const monitorHealthRows = computed(() =>
  MONITOR_HEALTH_SOURCES.map(({ source, field, labelKey }) => {
    const h = compliance.value?.[field]
    // 读数整体不可用：只降级本行（卡片其余字段与另外两行不受影响）
    if (!h || typeof h !== 'object') {
      return {
        source,
        labelKey,
        degraded: true,
        running: false,
        lastSuccessAt: null,
        consecutiveFailures: 0,
        lastRunAt: null,
        failureDetail: '',
      }
    }
    return {
      source,
      labelKey,
      degraded: false,
      // running 与 compliance.monitorRunning 是两处口径：这里是各模块自己的定时器状态
      running: h.running === true,
      lastSuccessAt: h.lastSuccessAt || null,
      consecutiveFailures: healthCount(h.consecutiveFailures),
      lastRunAt: h.lastRunAt || null,
      failureDetail: healthFailureDetail(h),
    }
  })
)

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

// P1③/P1④ 三态契约。本视图口径由 lead 裁决②定为「保持旧数据」：
// 审计日志是定责依据，「失败时把最后已知的一屏抹掉」比
// 「显示可能过期的一屏 + 明示已过期」更危险。契约的 stale 态正是为此存在。
const listState = useListLoadState()

// ===== 审计读取二次验证票据（P3-2）=====
// 后端对 audit-logs / alerts / audit-logs/export 要求短期票据（5 分钟）。
// 页面统一在此收口：无票据 → 先弹框，验过后重放被拦下的动作。
const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']
const reauthVisible = ref(false)
const reauthSubmitting = ref(false)
// 按 tag 去重：首屏 logs+alerts 同时被拦只弹一次框；连续筛选也不会堆叠重放
const pendingReauthTags = new Set()

const requireReauth = (tag) => {
  pendingReauthTags.add(tag)
  reauthVisible.value = true
}

const readReauthErrorCode = async (e) => {
  const data = e?.response?.data
  if (data?.errors?.errorCode) return data.errors.errorCode
  // 导出请求 responseType 为 blob，错误 JSON 也被包成 Blob
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
    // 服务端只回 { ticket, expiresIn }：窗口已按会话落库，ticket 是给无会话客户端用的。
    // 前端**不保存** ticket（审计一-3：客户端不再持有可重放凭据），只记一个
    // "刚验证过"的本地时间戳，避免重放首屏时又被弹一次框。
    if (!res?.data?.data) return
    markReauthVerified()
    const tags = [...pendingReauthTags]
    pendingReauthTags.clear()
    reauthVisible.value = false
    for (const tag of tags) {
      if (tag === 'logs') loadData()
      else if (tag === 'alerts') loadAlerts()
      else if (tag === 'forensic') exportForensic()
    }
  } catch (_) {
    // 凭据错误等提示由 api 响应拦截器统一输出；弹层保持打开便于重试
  } finally {
    reauthSubmitting.value = false
  }
}

watch(reauthVisible, (visible) => {
  // 用户取消：放弃本轮被拦下的动作，避免下次验证后重放早已过期的操作
  if (!visible) pendingReauthTags.clear()
})

const loadData = async () => {
  // 授权判据在服务端（会话窗口），客户端手里没有任何凭据可查——所以这里**不做**
  // 前置判断，直接发请求，由 401 REAUTH_TICKET_* 驱动弹框（见下方 catch）。
  // 前置判断只会变成第二份（且更弱的）判据：原来"本地票据还在"就放行，
  // 服务端不认时照样白跑一趟，而本地票据过期时又会拦下本可直接通过的请求。
  const isCurrent = listGuard()
  loading.value = true
  listState.begin()
  try {
    const params = {
      page: page.value,
      limit: limit.value,
      ...buildFilterParams(),
    }

    const res = await api.security.queryAuditLogs(params)
    if (!isCurrent()) return
    // 后端返回结构：{ success: true, message, data: [logs], meta: {...} }
    const rows = res.data?.data || []
    logs.value = rows
    // P1④：meta.total 缺失传 undefined（= 未知），不再用 0 冒充已知
    listState.commit({ total: res.data?.meta?.total, count: rows.length })
    const clamped = listState.clampPage(page.value, limit.value)
    if (clamped !== page.value) {
      page.value = clamped
      return loadData()
    }
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // 票据过期：重新验证后重放本次查询，不当作业务失败提示
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('logs')
      return
    }
    // P2-3：加载失败只清态，**提示由 api.js 响应拦截器统一负责**（与 alarmView 同契约）。
    // 此前组件这里再弹一条 messages.loadFailed，同一次失败会弹两条：
    // 拦截器的具体文案（400/403/404/429/5xx/网络错误）+ 组件的泛化文案。
    //
    // P1③（裁决②）：失败不得抹掉最后已知的一屏。有旧数据 ⇒ stale（保留 + 标注过期）；
    // 无旧数据 ⇒ failed（错误块顶替空表）。两者都不显示「暂无数据」。
    listState.fail()
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
      // compliance 与计数同包下发：留存/护栏/监控/WAL/链尾哈希/丢失计数
      compliance.value = data.compliance || null
      statsLoaded.value = true
    }
  } catch (e) {
    // A-2：概览查询失败（503 degraded）时隐藏统计卡片，不渲染一排 0——
    // 「零风险」与「数据不可用」是相反结论。提示由 api 响应拦截器统一负责。
    statsLoaded.value = false
    compliance.value = null
  }
}

// ===== 最近安全告警（GET /security/alerts）=====
// 单层信封：{ success, message, data: [alerts], meta } → 数组在 res.data.data，
// 元数据在 res.data.meta。后端固定最多回 50 条（多取 1 条探测 hasMore 后截断），
// lastUpdated 是服务端时间。
const ALERTS_PREVIEW_COUNT = 5
const alerts = ref([])
const alertsMeta = ref(null)
const alertsLoaded = ref(false)
const alertsExpanded = ref(false)
const visibleAlerts = computed(() =>
  alertsExpanded.value ? alerts.value : alerts.value.slice(0, ALERTS_PREVIEW_COUNT)
)

const loadAlerts = async () => {
  try {
    const res = await api.security.getAlerts()
    // 结构性兜底：非预期包络一律视为失败（面板不出现），不做部分渲染
    if (!Array.isArray(res?.data?.data)) return
    alerts.value = res.data.data
    alertsMeta.value = res.data.meta || null
    alertsLoaded.value = true
  } catch (e) {
    // 票据过期：重新验证后重放；其余失败静默（与统计卡同契约，提示归拦截器）
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('alerts')
    }
  }
}

// 链完整性核验：结论分 success / warning / error 三档，
// 判绿依据后端的 canAttestIntact（扫全+无断+各层真跑过），不能只看 intact。
const verifyChain = async () => {
  verifying.value = true
  try {
    const res = await api.security.verifyAuditChain()
    const d = res.data?.data
    if (!d) return
    const title = d.canAttestIntact
      ? t('auditLog.verifyOkTitle')
      : d.breaks > 0
        ? t('auditLog.verifyBrokenTitle')
        : t('auditLog.verifyPartialTitle')
    const type = d.canAttestIntact ? 'success' : d.breaks > 0 ? 'error' : 'warning'
    const lines = []
    if (d.breaks > 0) lines.push(t('auditLog.verifyBreaksLine', { n: d.breaks }))
    lines.push(t('auditLog.verifyDetail', { scanned: d.total, total: d.collectionTotal }))
    ElMessageBox.alert(lines.join('\n'), title, {
      type,
      confirmButtonText: t('common.confirm'),
      // 两行信息（断链条数 + 扫描范围）要分开显示：默认样式会把换行折掉
      customClass: 'mb-multiline',
    })
  } catch (e) {
    // 错误提示由 api 响应拦截器统一输出（含 strictLimiter 的 429）
    if (isCanceledError(e)) return
  } finally {
    verifying.value = false
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

/**
 * 从 blob 响应中解析后端错误信息（P2-56）
 *
 * /reports/export 的响应类型是 xlsx，但失败路径（403/400/500 等）返回的是
 * JSON 包络。responseType:'blob' 下 axios 把 JSON 体也包成 Blob，若不识别
 * 就会把这段错误 JSON 当成 xlsx 下载下来（文件损坏且界面报「导出成功」）。
 * 与 ReportView.vue 的 extractErrorMessage 同口径：读文本 → 取 message 字段，
 * 并优先走码化翻译（api.js 的 resolveErrorMessage）。
 */
const extractBlobErrorMessage = async (data, fallback) => {
  if (data instanceof Blob) {
    try {
      const parsed = JSON.parse(await data.text())
      return resolveErrorMessage(parsed) || parsed?.message || fallback
    } catch (_) {
      /* 非 JSON 内容（正常 xlsx 等）或解析失败 → 走兜底文案 */
    }
  }
  return data?.message || fallback
}

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

    // P2-56：后端以 JSON 返回错误时不得继续下载（否则得到损坏的 xlsx + 假成功）
    const payload = response?.data
    const contentType = String(response?.headers?.['content-type'] || '')
    if (
      payload instanceof Blob &&
      (payload.type?.includes('json') || contentType.includes('application/json'))
    ) {
      ElMessage.error(await extractBlobErrorMessage(payload, t('messages.exportFailed')))
      return
    }
    if (!(payload instanceof Blob)) {
      ElMessage.error(await extractBlobErrorMessage(payload, t('messages.exportFailed')))
      return
    }

    // 截断标记：xlsx 侧的 X-Export-Truncated 值是字面 'true' —— 头只表态"不保证完整"，
    // 说人话属于展示层。原实现 `ElMessage.warning(String(notice))` 因此给用户弹一个
    // "true"；而它的用例喂的是"已达上限，结果被截断"这种后端从不发的值，所以一直判绿。
    // （CSV 侧另有一道 X-Audit-Truncated，本视图没有 CSV 下载入口，不在这里猜。）
    if (response?.headers?.['x-export-truncated']) {
      ElMessage.warning(t('messages.exportTruncated'))
    }

    const blob = new Blob([payload], {
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
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    // P2-56：blob 形态的错误体在 e.response.data 中，统一提取（含码化翻译）
    ElMessage.error(await extractBlobErrorMessage(e?.response?.data, t('messages.exportFailed')))
  } finally {
    exporting.value = false
  }
}

// 取证级导出：/security/audit-logs/export 的 CSV + 签名 manifest。
// 与上方 xlsx 报表导出定位不同：xlsx 给人看，CSV 给取证（文件自带 csvSha256 摘要，
// 尾部 manifest 注释行 + X-Audit-Manifest-* 响应头双通道）。
const forensicExporting = ref(false)

const exportForensic = async () => {
  forensicExporting.value = true
  try {
    const response = await api.security.exportAuditLogs(buildFilterParams())

    // 同 P2-56：失败路径后端回 JSON 包络，blob 下须先识别再决定要不要下载
    const payload = response?.data
    const contentType = String(response?.headers?.['content-type'] || '')
    if (
      payload instanceof Blob &&
      (payload.type?.includes('json') || contentType.includes('application/json'))
    ) {
      ElMessage.error(await extractBlobErrorMessage(payload, t('messages.exportFailed')))
      return
    }
    if (!(payload instanceof Blob)) {
      ElMessage.error(await extractBlobErrorMessage(payload, t('messages.exportFailed')))
      return
    }

    // CSV 侧截断头是 X-Audit-Truncated: 'true'（在首个流块发出前设置）
    if (response?.headers?.['x-audit-truncated']) {
      ElMessage.warning(t('messages.exportTruncated'))
    }

    const blob = new Blob([payload], { type: 'text/csv;charset=utf-8' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `audit_logs_forensic_${localDateStr()}.csv`
    link.click()
    window.URL.revokeObjectURL(url)

    ElMessage.success(t('messages.exportSuccess'))
  } catch (e) {
    if (isCanceledError(e)) return
    // 票据过期：不当作导出失败，重新验证后重放
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth('forensic')
      return
    }
    ElMessage.error(await extractBlobErrorMessage(e?.response?.data, t('messages.exportFailed')))
  } finally {
    forensicExporting.value = false
  }
}

// 时间格式化统一走 utils/datetime.formatTime（O-3 单一事实来源，本地时区 +
// 固定 YYYY-MM-DD HH:mm:ss 口径）。此前这里用 toLocaleString(locale)：
// ① 切换界面语言会让同一列的时间格式突变（月/日顺序与分隔符都变）；
// ② 非法时间戳渲染成 "Invalid Date"。两者都已由 formatTime 兜住。

// 格式化 JSON（列表接口出于安全不返回 body/params 时显示占位符）
const formatJson = (value) => {
  if (value === null || value === undefined) return '-'
  if (typeof value !== 'object' || Object.keys(value).length === 0) return '-'
  return JSON.stringify(value, null, 2)
}

// 操作类型 / 分类标签：映射本体已抽至 utils/auditLabels.js（与 MyLogsCard 共用）。
// audit.action.* 文案组与后端 AUDIT_LOG_ACTIONS 枚举一一对应，枚举全集见
// src/constants/audit.js（含路由派生型/事件型/历史兼容三部分）。
// 此处仅把模块级 t 绑定进去，模板与 viewDetail 的调用点不变。
const actionLabel = (action) => toActionLabel(t, action)
const categoryLabel = (category) => toCategoryLabel(t, category)
// 归属地是后端可选增强字段：稳定码走本地化，数据文本（公网归属）原样透传
const ipLocationText = (location) => toIpLocationLabel(t, location)
// 英文界面把已知的系统生成 reason 模板译出；未命中/中文界面一律原样返回
const auditReasonText = (reason) =>
  String(locale.value || '').startsWith('en') ? translateAuditReason(reason) : reason

// 风险等级样式
const riskType = (level) => {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'success' }[level] || 'info'
}

const riskText = (level) => {
  return (
    {
      critical: t('common.critical'),
      high: t('common.levelHigh'),
      medium: t('common.levelMedium'),
      low: t('common.levelLow'),
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
  loadAlerts()
})
</script>

<style scoped>
.load-error {
  margin-bottom: var(--xf-spacing-md);
}
.total-unknown {
  margin-right: var(--xf-spacing-sm);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

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
.card-header__actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
/* 合规与防篡改面板：状态键值 chips，好/坏两档配色 */
.compliance-card {
  padding: 14px 16px;
}
.compliance-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.compliance-card__title {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.compliance-card__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.compliance-chip {
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  white-space: nowrap;
}
.compliance-chip--mono {
  font-family: var(--xf-font-mono);
}
.compliance-chip.is-ok {
  color: var(--xf-success-strong);
  border-color: var(--xf-success-alpha-45);
  background: var(--xf-success-alpha-8);
}
.compliance-chip.is-bad {
  color: var(--xf-danger-strong);
  border-color: var(--xf-danger-alpha-45);
  background: var(--xf-danger-alpha-8);
}
/* 监控读数：三个定时任务各一行，沿用 chips 的排版习惯（细分割线 + 紧凑行高） */
.compliance-monitors {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--xf-border-color);
}
.compliance-monitors__title {
  display: block;
  margin-bottom: 6px;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-gray-500);
}
.monitor-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 3px 0;
}
.monitor-row__name {
  flex: none;
  min-width: 96px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-700);
  white-space: nowrap;
}
.monitor-row .compliance-chip {
  font-variant-numeric: tabular-nums;
}
/* 最近安全告警：紧凑单行列表（风险标签 / 动作 / 用户+IP / 时间 / 详情） */
.alerts-card {
  padding: 14px 16px;
}
.alerts-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.alerts-card__title {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.alerts-card__actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.alerts-card__meta {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  white-space: nowrap;
}
.alerts-card__empty {
  padding: 6px 0;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-500);
}
.alerts-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.alert-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  border-top: 1px solid var(--xf-border-color);
}
.alert-row:first-child {
  border-top: none;
}
.alert-row__risk {
  flex: none;
}
.alert-row__action {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-900);
  white-space: nowrap;
}
.alert-row__user {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.alert-row__time {
  margin-left: auto;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  white-space: nowrap;
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
/* 归属地：与等宽 IP 同行但弱一级（辅助信息，不与主键值抢视觉权重），
   非 mono 与 ipListView 口径一致 */
/* 归属地：与等宽 IP 同格但弱一级（辅助信息，不与主键值抢视觉权重）。
   与 ipListView 的 .ip-location 同口径：非 mono + 小一号。此前只改了颜色，
   等宽字体仍从父级 .cell-mono 继承 ⇒ 弱化层级实际没生效（P2-6）。 */
.ip-loc {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
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
