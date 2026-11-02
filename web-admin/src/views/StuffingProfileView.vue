<template>
  <div class="page">
    <!-- 查询区：业务日单选，其余参数由服务端按保留期与样本门槛收口 -->
    <div class="glass glass-card">
      <div v-if="showTitle" class="card-header">
        <span>{{ $t('stuffingProfile.pageTitle') }}</span>
      </div>
      <p class="card-hint">{{ $t('stuffingProfile.pageSubtitle') }}</p>
      <el-form :inline="true" class="query-form" @submit.prevent>
        <el-form-item :label="$t('stuffingProfile.dayLabel')">
          <el-date-picker
            v-model="businessDay"
            type="date"
            value-format="YYYY-MM-DD"
            :clearable="false"
            style="width: 170px"
          />
        </el-form-item>
        <el-form-item class="glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            :disabled="loading"
            @click="loadProfile"
          >
            {{ loading ? $t('stuffingProfile.querying') : $t('stuffingProfile.query') }}
          </button>
          <button
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="loading"
            @click="resetQuery"
          >
            {{ $t('stuffingProfile.reset') }}
          </button>
        </el-form-item>
      </el-form>
    </div>

    <div v-if="hasQueried" class="glass glass-card">
      <div class="card-header">
        <span>{{ $t('stuffingProfile.resultCard') }}</span>
        <span v-if="meta" class="card-meta">{{ resultSummary }}</span>
      </div>

      <el-alert
        v-if="loadError"
        :title="hasResult ? $t('stuffingProfile.staleData') : $t('stuffingProfile.loadError')"
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
            @click="loadProfile"
          >
            {{ $t('stuffingProfile.retry') }}
          </button>
        </template>
      </el-alert>

      <template v-if="meta">
        <!-- 空表必须自述原因：保留期外、数据范围受限、样本不足是三件不同的事 -->
        <el-alert
          v-if="meta.expired"
          :title="$t('stuffingProfile.emptyExpired')"
          type="warning"
          :closable="false"
          show-icon
          class="meta-alert"
        />
        <el-alert
          v-else-if="meta.dataScopeType !== 'all'"
          :title="$t('stuffingProfile.emptyScope', { scope: scopeLabel(meta.dataScopeType) })"
          type="warning"
          :closable="false"
          show-icon
          class="meta-alert"
        />
        <el-alert
          v-if="droppedNote"
          :title="droppedNote"
          type="info"
          :closable="false"
          show-icon
          class="meta-alert"
        />

        <el-table
          v-if="entries.length > 0"
          data-test="stuffing-table"
          :data="entries"
          border
          stripe
          style="width: 100%"
        >
          <el-table-column
            prop="sourceKey"
            :label="$t('stuffingProfile.sourceKey')"
            min-width="150"
          />
          <el-table-column prop="attempts" :label="$t('stuffingProfile.attempts')" width="110" />
          <el-table-column prop="successes" :label="$t('stuffingProfile.successes')" width="110" />
          <el-table-column
            prop="accountCardinality"
            :label="$t('stuffingProfile.accounts')"
            width="120"
          />
          <el-table-column :label="$t('stuffingProfile.stemHits')" width="120">
            <template #default="{ row }">
              <el-tag v-if="row.credentialStemHits > 0" type="danger" size="small">
                {{ row.credentialStemHits }}
              </el-tag>
              <span v-else>{{ row.credentialStemHits || 0 }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('stuffingProfile.lengthBucket')" width="130">
            <template #default="{ row }">
              {{ lengthBucketText(row.lengthBucket) }}
            </template>
          </el-table-column>
          <el-table-column :label="$t('stuffingProfile.charsetClass')" min-width="140">
            <template #default="{ row }">
              {{ charsetText(row.charsetClass) }}
            </template>
          </el-table-column>
        </el-table>
        <el-alert
          v-else-if="!meta.expired && meta.dataScopeType === 'all'"
          :title="$t('stuffingProfile.emptyTitle')"
          :description="$t('stuffingProfile.emptyGeneric')"
          type="info"
          :closable="false"
          show-icon
          class="meta-alert"
        />

        <p class="card-hint footer-hint">
          {{ $t('stuffingProfile.sourceHint') }}
          {{ $t('stuffingProfile.thresholdHint', { min: meta.minSamples }) }}
        </p>
      </template>
    </div>

    <ReauthDialog
      v-model="reauthVisible"
      :submitting="reauthSubmitting"
      @submit="handleReauthSubmit"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import i18n from '@/i18n'
import stuffingProfileZhCN from '@/i18n/locales/stuffingProfile.zh-CN'
import stuffingProfileEnUS from '@/i18n/locales/stuffingProfile.en-US'
import { api, isCanceledError } from '@/utils/api'
import { formatTime, localDateStr } from '@/utils/datetime'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { markReauthVerified } from '@/utils/reauthTicket'
import ReauthDialog from '@/components/ReauthDialog.vue'

// 词表随本页 chunk 懒加载：画像文案只服务这一页，留在入口词表会让首屏白白背着
i18n.global.mergeLocaleMessage('zh-CN', { stuffingProfile: stuffingProfileZhCN })
i18n.global.mergeLocaleMessage('en-US', { stuffingProfile: stuffingProfileEnUS })

defineProps({ showTitle: { type: Boolean, default: true } })

const { t } = useI18n()

const businessDay = ref(localDateStr())
const loading = ref(false)
const hasQueried = ref(false)
const entries = ref([])
const meta = ref(null)
const loadError = ref(false)

// 同步重入锁：loading 要等重渲染才对按钮生效，同一 tick 连点会发多个请求
let submitting = false
const profileGuard = useLatestRequest()

const hasResult = computed(() => Boolean(meta.value))

const resultSummary = computed(() => {
  if (!meta.value) return ''
  const parts = [
    t('stuffingProfile.recordCount', { count: meta.value.count ?? entries.value.length }),
  ]
  if (meta.value.windowStart && meta.value.windowEnd) {
    parts.push(
      t('stuffingProfile.windowRange', {
        since: formatTime(meta.value.windowStart),
        until: formatTime(meta.value.windowEnd),
      })
    )
  }
  return parts.join(' · ')
})

const SCOPE_KEY = { all: 'scopeAll', self: 'scopeSelf', department: 'scopeDepartment' }
const scopeLabel = (type) =>
  SCOPE_KEY[type] ? t('stuffingProfile.' + SCOPE_KEY[type]) : type || '-'

const droppedNote = computed(() => {
  const m = meta.value
  if (!m) return ''
  const lines = []
  if (m.droppedBelowMin > 0) {
    lines.push(t('stuffingProfile.droppedBelowMin', { n: m.droppedBelowMin, min: m.minSamples }))
  }
  if (m.droppedUnparsable > 0) {
    lines.push(t('stuffingProfile.droppedUnparsable', { n: m.droppedUnparsable }))
  }
  return lines.join(' ')
})

// 枚举值缺失/漂移时回落后端原值：宁可显示裸码，也不编造一个档位
const lengthBucketText = (value) => {
  if (!value) return '-'
  const key = 'stuffingProfile.lengthBucketValue.' + value
  const label = t(key)
  return label === key ? value : label
}

const charsetText = (code) => {
  if (!code) return '-'
  return String(code)
    .split('')
    .map((flag) => {
      const key = 'stuffingProfile.charsetFlag.' + flag
      const label = t(key)
      return label === key ? flag : label
    })
    .join('+')
}

// ===== 二次验证（与审计/攻击画像同一套服务端会话窗口）=====
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

const loadProfile = async () => {
  if (submitting) return
  submitting = true
  loading.value = true
  hasQueried.value = true
  const isCurrent = profileGuard()
  try {
    const res = await api.security.getStuffingProfile({ businessDay: businessDay.value })
    if (!isCurrent()) return
    const payload = res?.data?.data
    const metaPayload = res?.data?.meta
    if (!Array.isArray(payload) || !metaPayload) {
      loadError.value = true
      return
    }
    entries.value = payload
    meta.value = metaPayload
    loadError.value = false
  } catch (e) {
    if (isCanceledError(e) || !isCurrent()) return
    if (REAUTH_TICKET_ERROR_CODES.includes(await readReauthErrorCode(e))) {
      requireReauth()
      return
    }
    // 保留上一次结果并标注为旧数据，绝不把失败画成「这个业务日很干净」
    loadError.value = true
  } finally {
    if (isCurrent()) loading.value = false
    submitting = false
  }
}

const resetQuery = () => {
  businessDay.value = localDateStr()
  entries.value = []
  meta.value = null
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
      loadProfile()
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
.footer-hint {
  margin: var(--xf-spacing-md) 0 0;
}
.query-form {
  margin-bottom: 0;
}
.load-alert,
.meta-alert {
  margin-bottom: var(--xf-spacing-md);
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
