<template>
  <!--
    我的安全信息（B 组自助面接线）：GET /api/security/my-info
    后端一次返回 { user, securityScore, suggestions[], recentLogins[] }，
    此处只做展示，不提供任何写操作。
  -->
  <el-card shadow="never">
    <template #header>
      <span class="card-header">{{ $t('securitySelf.infoTitle') }}</span>
    </template>

    <GlassSkeleton v-if="loading" variant="detail" :rows="4" />

    <div v-else-if="error" class="self-error">
      <span>{{ $t('securitySelf.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--default glass-btn--sm" @click="load">
        {{ $t('common.refresh') }}
      </button>
    </div>

    <template v-else>
      <!-- 安全评分：0~100，后端已钳到 [0,100]。分数只做展示，不做「好/坏」的强断言 -->
      <div class="score-row">
        <div class="score-value" :class="scoreClass">{{ score }}</div>
        <div class="score-meta">
          <div class="score-label">{{ $t('securitySelf.score') }}</div>
          <div class="score-hint">{{ $t('securitySelf.scoreHint') }}</div>
        </div>
      </div>

      <div class="self-block">
        <div class="self-block__label">{{ $t('securitySelf.suggestions') }}</div>
        <ul v-if="suggestions.length" class="suggest-list">
          <li v-for="(item, idx) in suggestions" :key="idx">{{ suggestionLabel(item) }}</li>
        </ul>
        <p v-else class="empty-hint">{{ $t('securitySelf.noSuggestions') }}</p>
      </div>

      <div class="self-block">
        <div class="self-block__label">{{ $t('securitySelf.recentLogins') }}</div>
        <el-table
          v-if="recentLogins.length"
          :data="recentLogins"
          size="small"
          stripe
          style="width: 100%"
        >
          <el-table-column :label="$t('securitySelf.loginTime')" min-width="150">
            <template #default="{ row }">{{ formatTime(row.time) }}</template>
          </el-table-column>
          <el-table-column :label="$t('securitySelf.loginAction')" min-width="110">
            <template #default="{ row }">{{ actionLabel(row.action) }}</template>
          </el-table-column>
          <el-table-column :label="$t('securitySelf.loginIp')" min-width="120">
            <template #default="{ row }">{{ row.ip || '—' }}</template>
          </el-table-column>
          <el-table-column :label="$t('securitySelf.loginResult')" width="90" align="center">
            <template #default="{ row }">
              <el-tag :type="row.success ? 'success' : 'danger'" size="small">
                {{ row.success ? $t('securitySelf.loginSuccess') : $t('securitySelf.loginFailed') }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
        <p v-else class="empty-hint">{{ $t('securitySelf.noRecentLogins') }}</p>
      </div>
    </template>
  </el-card>
</template>

<script setup>
/**
 * 我的安全信息卡片
 *
 * 解决的是「后端已能返回本人的安全画像（评分/建议/最近登录），但界面无入口」——
 * 端点在 securityRoutes.js:154，此前前端只有 i18n 标签没有调用点。
 *
 * 错误处理：失败时**不展示上一次的过期数据**（与 SessionManager.load 同口径），
 * 而是落到可重试的错误态——安全画像过期比空着更误导（用户会以为当前就是这个分数）。
 */
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import { formatTime } from '@/utils/datetime'
import { actionLabel as toActionLabel } from '@/utils/auditLabels'
import { securitySuggestionLabel } from '@/utils/securityLabels'
import GlassSkeleton from '@/components/GlassSkeleton.vue'

const { t } = useI18n()

const info = ref({})
const loading = ref(true)
const error = ref(false)

const score = computed(() =>
  typeof info.value.securityScore === 'number' ? info.value.securityScore : '—'
)
const suggestions = computed(() =>
  Array.isArray(info.value.suggestions) ? info.value.suggestions : []
)
const recentLogins = computed(() =>
  Array.isArray(info.value.recentLogins) ? info.value.recentLogins : []
)

// 仅用于配色分级，不改变数字本身；阈值与「高分绿/中分黄/低分红」的直觉一致
const scoreClass = computed(() => {
  const s = info.value.securityScore
  if (typeof s !== 'number') return ''
  if (s >= 80) return 'is-good'
  if (s >= 60) return 'is-warn'
  return 'is-bad'
})

const actionLabel = (action) => toActionLabel(t, action)

// 后端只出稳定码（constants/securitySuggestions.js），文案在前端词表；
// 未知码原样回退，便于发现后端新增建议
const suggestionLabel = (code) => securitySuggestionLabel(t, code)

const load = async () => {
  loading.value = true
  error.value = false
  try {
    const { data: resp } = await api.security.getMySecurityInfo()
    info.value = resp.data || {}
  } catch (_) {
    // 错误提示已由拦截器统一处理；此处清空并置错误态，避免展示过期数据
    info.value = {}
    error.value = true
  } finally {
    loading.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<style scoped>
.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.self-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.score-row {
  display: flex;
  align-items: center;
  gap: 16px;
}

.score-value {
  font-family: var(--xf-font-display);
  font-size: 40px;
  font-weight: 700;
  line-height: 1;
  color: var(--xf-gray-900);
}

/* 分数分级色：与 el-tag 的 success/warning/danger 语义同频 */
.score-value.is-good {
  color: var(--xf-success, #67c23a);
}
.score-value.is-warn {
  color: var(--xf-warning, #e6a23c);
}
.score-value.is-bad {
  color: var(--xf-danger, #f56c6c);
}

.score-label {
  font-size: var(--xf-font-size-base);
  color: var(--xf-gray-700);
}

.score-hint {
  margin-top: 2px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

.self-block {
  margin-top: 16px;
}

.self-block__label {
  margin-bottom: 8px;
  font-size: var(--xf-font-size-sm);
  font-weight: 600;
  color: var(--xf-text-secondary);
}

.suggest-list {
  margin: 0;
  padding-left: 18px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-700);
}

.suggest-list li + li {
  margin-top: 4px;
}

.empty-hint {
  margin: 0;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}
</style>
