<template>
  <div class="page">
    <!-- 查询区：只需要一个 IP。默认窗口 7 天，其余参数都不让用户操心 -->
    <div class="glass glass-card">
      <div v-if="showTitle" class="card-header">
        <span>{{ $t('attackProfile.pageTitle') }}</span>
      </div>
      <p class="card-hint">{{ $t('attackProfile.pageSubtitle') }}</p>
      <el-form :inline="true" class="query-form" @submit.prevent>
        <el-form-item :label="$t('attackProfile.ipLabel')">
          <el-input
            v-model="ip"
            :placeholder="$t('attackProfile.ipPlaceholder')"
            style="width: 220px"
            clearable
            maxlength="64"
            @keyup.enter="handleAnalyze"
          />
        </el-form-item>
        <el-form-item :label="$t('attackProfile.windowLabel')">
          <el-select v-model="hours" style="width: 130px">
            <el-option :label="$t('attackProfile.window24h')" :value="24" />
            <el-option :label="$t('attackProfile.window7d')" :value="168" />
            <el-option :label="$t('attackProfile.window30d')" :value="720" />
          </el-select>
        </el-form-item>
        <el-form-item class="glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            :disabled="loading"
            @click="handleAnalyze"
          >
            {{ loading ? $t('attackProfile.analyzing') : $t('attackProfile.analyze') }}
          </button>
          <button
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="loading"
            @click="resetQuery"
          >
            {{ $t('attackProfile.reset') }}
          </button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 结果区：先给一句人话结论，再给数据、分类、证据与建议 -->
    <div v-if="hasQueried" class="glass glass-card">
      <div class="card-header">
        <span>{{ $t('attackProfile.resultCard') }}</span>
        <span v-if="profile" class="card-meta">{{ resultSummary }}</span>
      </div>

      <el-alert
        v-if="loadError"
        :title="hasResult ? $t('attackProfile.staleData') : $t('attackProfile.loadError')"
        type="warning"
        :closable="false"
        show-icon
        class="load-alert"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="loading"
            @click="handleAnalyze"
          >
            {{ $t('attackProfile.retry') }}
          </button>
        </template>
      </el-alert>

      <AttackProfileResult
        v-if="profile"
        :profile="profile"
        @inspect="openEvidence"
        @view-audit="openAuditLogs"
        @open-report="openReport"
      />
    </div>

    <ReauthDialog
      v-model="reauthVisible"
      :submitting="reauthSubmitting"
      @submit="handleReauthSubmit"
    />

    <el-dialog
      v-model="reportVisible"
      :title="$t('attackProfile.reportTitle')"
      width="760px"
      append-to-body
      class="report-dialog"
    >
      <p class="card-hint">{{ $t('attackProfile.reportHint') }}</p>
      <pre class="report-preview" data-test="report-preview">{{ reportText }}</pre>
      <template #footer>
        <button type="button" class="glass-btn glass-btn--default" @click="copyReport">
          {{ $t('attackProfile.reportCopy') }}
        </button>
        <button type="button" class="glass-btn glass-btn--primary" @click="downloadReport">
          {{ $t('attackProfile.reportDownload') }}
        </button>
        <button type="button" class="glass-btn glass-btn--default" @click="reportVisible = false">
          {{ $t('attackProfile.reportClose') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import i18n from '@/i18n'
import attackProfileZhCN from '@/i18n/locales/attackProfile.zh-CN'
import attackProfileEnUS from '@/i18n/locales/attackProfile.en-US'
import { api, isCanceledError } from '@/utils/api'
import { formatTime, localDateStr } from '@/utils/datetime'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { attackReportFileName, buildAttackReport } from '@/utils/attackProfileReport'
import { markReauthVerified } from '@/utils/reauthTicket'
import ReauthDialog from '@/components/ReauthDialog.vue'
import AttackProfileResult from '@/components/AttackProfileResult.vue'

// 词表随本页 chunk 懒加载：画像文案只服务这一页，留在入口词表会让首屏白白背着
i18n.global.mergeLocaleMessage('zh-CN', { attackProfile: attackProfileZhCN })
i18n.global.mergeLocaleMessage('en-US', { attackProfile: attackProfileEnUS })

defineProps({ showTitle: { type: Boolean, default: true } })

const { t, te } = useI18n()
const route = useRoute()
const router = useRouter()

const ip = ref('')
const hours = ref(168)
const loading = ref(false)
const hasQueried = ref(false)
const profile = ref(null)
const loadError = ref(false)

// 同步重入锁：loading 要等重渲染才对按钮生效，同一 tick 连点会发多个请求
let submitting = false
const analyzeGuard = useLatestRequest()

const hasResult = computed(() => Boolean(profile.value))

const resultSummary = computed(() => {
  const p = profile.value
  if (!p) return ''
  const parts = [t('attackProfile.recordCount', { count: p.total ?? 0 })]
  if (p.window?.since && p.window?.until) {
    parts.push(
      t('attackProfile.windowRange', {
        since: formatTime(p.window.since),
        until: formatTime(p.window.until),
      })
    )
  }
  return parts.join(' · ')
})

// ===== 二次验证（与审计读取同一套服务端会话窗口）=====
const REAUTH_TICKET_ERROR_CODES = ['REAUTH_TICKET_REQUIRED', 'REAUTH_TICKET_INVALID']
const reauthVisible = ref(false)
const reauthSubmitting = ref(false)
let pendingReauth = false

const requireReauth = () => {
  pendingReauth = true
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

const loadProfile = async (targetIp, windowHours) => {
  if (submitting) return
  submitting = true
  loading.value = true
  hasQueried.value = true
  const isCurrent = analyzeGuard()
  try {
    const res = await api.security.getAttackProfile({
      ip: targetIp,
      hours: windowHours,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    if (!payload) {
      loadError.value = true
      return
    }
    profile.value = payload
    loadError.value = false
  } catch (e) {
    if (isCanceledError(e) || !isCurrent()) return
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth()
      return
    }
    // 保留上一次结果并标注为旧数据，绝不把失败画成「这个 IP 很干净」
    loadError.value = true
  } finally {
    if (isCurrent()) loading.value = false
    submitting = false
  }
}

const handleAnalyze = () => {
  const target = ip.value.trim()
  if (!target) {
    ElMessage.warning(t('attackProfile.noIp'))
    return
  }
  loadProfile(target, hours.value)
}

const resetQuery = () => {
  ip.value = ''
  hours.value = 168
  profile.value = null
  loadError.value = false
  hasQueried.value = false
}

const handleReauthSubmit = async (credential) => {
  reauthSubmitting.value = true
  try {
    const res = await api.security.createReauthTicket(credential)
    if (!res?.data?.data) return
    markReauthVerified()
    reauthVisible.value = false
    if (pendingReauth) {
      pendingReauth = false
      handleAnalyze()
    }
  } catch (_) {
    // 凭据错误的提示由 API 拦截器统一输出；弹层保持打开便于重试
  } finally {
    reauthSubmitting.value = false
  }
}

watch(reauthVisible, (visible) => {
  if (!visible) pendingReauth = false
})

// ===== 取证钻取 =====
// 画像只读审计元数据聚合；单条完整取证（请求/响应头与正文、客户端、哈希链）
// 仍由审计详情接口按权限与数据范围读取，不在画像接口里复制第二条敏感数据通道。
const openEvidence = (row) => {
  if (!row?.logId) return
  router.push({ name: 'audit-logs', query: { logId: row.logId } })
}

// 把当前画像的 IP 与统计日期带到审计页，直接列出可逐条打开的原始记录。
const openAuditLogs = () => {
  if (!profile.value) return
  const query = { ip: profile.value.ip }
  const since = localDateStr(profile.value.window?.since)
  const until = localDateStr(profile.value.window?.until)
  if (since) query.startDate = since
  if (until) query.endDate = until
  router.push({ name: 'audit-logs', query })
}

// ===== 一键报告 =====
const reportVisible = ref(false)
const reportText = computed(() =>
  profile.value ? buildAttackReport(profile.value, { t, te, formatTime }) : ''
)

const openReport = () => {
  if (!profile.value) return
  reportVisible.value = true
}

const copyReport = async () => {
  try {
    await navigator.clipboard.writeText(reportText.value)
    ElMessage.success(t('attackProfile.reportCopied'))
  } catch (_) {
    ElMessage.error(t('attackProfile.reportCopyFailed'))
  }
}

const downloadReport = () => {
  if (!profile.value) return
  const blob = new Blob([reportText.value], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = attackReportFileName(profile.value)
  link.click()
  URL.revokeObjectURL(url)
}

// 审计页携带 ?ip= 跳转进来时自动分析。用 watch 而不是 onMounted：
// 路由解析完成与组件挂载的先后不保证（memory history 下尤甚），监听 query 变化
// 既能接住首跳，也能接住「已在本页时从审计页再点一个 IP」。
watch(
  () => route.query.ip,
  (value) => {
    const queryIp = Array.isArray(value) ? value[0] : value
    const initial = String(queryIp || '').trim()
    if (!initial) return
    ip.value = initial
    handleAnalyze()
  },
  { immediate: true }
)
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
.query-form {
  margin-bottom: 0;
}
.load-alert {
  margin-bottom: var(--xf-spacing-md);
}
.report-preview {
  max-height: 52vh;
  overflow: auto;
  margin: 0;
  padding: 14px;
  border: 1px solid var(--xf-gray-200);
  border-radius: 10px;
  background: var(--el-fill-color-lighter);
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}
/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .query-form .el-input,
  .query-form .el-select {
    width: 100% !important;
  }
}
/* 无障碍降级：本页动效纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .glass-card {
    animation: none !important;
  }
}
</style>
