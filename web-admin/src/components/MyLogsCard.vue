<template>
  <!--
    我的操作日志（B 组自助面接线）：GET /api/security/my-logs?days=&limit=
    与审计日志页（AuditLogView）的区别：这里只返回**本人**的记录，无需
    security:audit 权限，任何登录用户都可用；因此不做跨用户筛选、不做导出。
  -->
  <el-card shadow="never">
    <template #header>
      <div class="logs-header">
        <span class="card-header">{{ $t('securitySelf.logsTitle') }}</span>
        <el-select
          v-model="days"
          size="small"
          class="logs-range"
          :disabled="loading"
          @change="load"
        >
          <el-option :value="7" :label="$t('securitySelf.range7')" />
          <el-option :value="30" :label="$t('securitySelf.range30')" />
          <el-option :value="90" :label="$t('securitySelf.range90')" />
        </el-select>
      </div>
    </template>

    <GlassSkeleton v-if="loading" variant="table" :rows="4" />

    <div v-else-if="error" class="self-error">
      <span>{{ $t('securitySelf.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--default glass-btn--sm" @click="load">
        {{ $t('common.refresh') }}
      </button>
    </div>

    <template v-else>
      <el-table v-if="logs.length" :data="logs" size="small" stripe style="width: 100%">
        <el-table-column :label="$t('securitySelf.colTime')" min-width="150">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column :label="$t('securitySelf.colAction')" min-width="130">
          <template #default="{ row }">
            <div class="cell-main">{{ actionLabel(row.action) }}</div>
            <div class="cell-sub">
              <el-tag size="small" effect="plain">{{ categoryLabel(row.category) }}</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('securitySelf.colIp')" min-width="120">
          <template #default="{ row }">{{ row.ip || '—' }}</template>
        </el-table-column>
        <el-table-column :label="$t('securitySelf.colResult')" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'" size="small">
              {{ row.success ? $t('securitySelf.loginSuccess') : $t('securitySelf.loginFailed') }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>

      <p v-else class="empty-hint">{{ $t('securitySelf.logsEmpty') }}</p>

      <div v-if="logs.length" class="logs-count">
        {{ $t('securitySelf.logsCount', { count: logs.length }) }}
      </div>
    </template>
  </el-card>
</template>

<script setup>
/**
 * 我的操作日志卡片
 *
 * 端点在 securityRoutes.js:263（authenticate 即可，无权限码）。后端按
 * days∈[1,365]、limit∈[1,500] 钳制，此处固定 limit=50、days 由下拉选择。
 *
 * 为什么不做客户端分页：后端 getUserActivity 是「取最近 N 条」的语义，
 * 没有 total 计数，做不出真实分页；把它包装成分页器只会让用户以为
 * 「还有下一页」。故以时间范围（7/30/90 天）作为唯一的收窄手段，
 * 并在底部如实标注本次返回的条数。
 */
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import { formatTime } from '@/utils/datetime'
import { actionLabel as toActionLabel, categoryLabel as toCategoryLabel } from '@/utils/auditLabels'
import GlassSkeleton from '@/components/GlassSkeleton.vue'

const { t } = useI18n()

// 后端单次最多 500 条；这里取 50 条，兼顾「最近一段时间的完整视图」与首屏体积
const LOG_LIMIT = 50

const days = ref(7)
const logs = ref([])
const loading = ref(true)
const error = ref(false)

const actionLabel = (action) => toActionLabel(t, action)
const categoryLabel = (category) => toCategoryLabel(t, category)

const load = async () => {
  loading.value = true
  error.value = false
  try {
    const { data: resp } = await api.security.getMyLogs({ days: days.value, limit: LOG_LIMIT })
    logs.value = Array.isArray(resp.data) ? resp.data : []
  } catch (_) {
    // 错误提示已由拦截器统一处理；清空避免展示过期数据
    logs.value = []
    error.value = true
  } finally {
    loading.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<style scoped>
.logs-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.logs-range {
  width: 120px;
}

.self-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.cell-main {
  color: var(--xf-gray-700);
}

.cell-sub {
  margin-top: 2px;
}

.logs-count {
  margin-top: 8px;
  text-align: right;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

.empty-hint {
  margin: 0;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}
</style>
