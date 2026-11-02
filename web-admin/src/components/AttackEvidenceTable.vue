<template>
  <el-table :data="evidence" size="small" border class="evidence-table" style="width: 100%">
    <template #empty>
      <div class="empty-tip">{{ $t('attackProfile.evidenceEmpty') }}</div>
    </template>
    <el-table-column :label="$t('attackProfile.evidenceTime')" width="165">
      <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
    </el-table-column>
    <el-table-column :label="$t('attackProfile.evidenceAction')" min-width="130">
      <template #default="{ row }">{{ actionLabel(row.action) }}</template>
    </el-table-column>
    <el-table-column :label="$t('attackProfile.evidenceMethod')" width="80">
      <template #default="{ row }">
        <span class="mono">{{ row.method || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column
      :label="$t('attackProfile.evidencePath')"
      min-width="180"
      show-overflow-tooltip
    >
      <template #default="{ row }">
        <span class="mono">{{ row.path || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column :label="$t('attackProfile.evidenceStatus')" width="80">
      <template #default="{ row }">{{ row.statusCode ?? '-' }}</template>
    </el-table-column>
    <el-table-column :label="$t('attackProfile.evidenceAccount')" width="110">
      <template #default="{ row }">{{ row.username || '-' }}</template>
    </el-table-column>
    <el-table-column
      :label="$t('attackProfile.evidenceReason')"
      min-width="140"
      show-overflow-tooltip
    >
      <template #default="{ row }">
        {{ row.refusalReason || row.reason || '-' }}
      </template>
    </el-table-column>
    <el-table-column :label="$t('attackProfile.evidenceTrace')" width="126" fixed="right">
      <template #default="{ row }">
        <button
          type="button"
          class="glass-btn glass-btn--primary glass-btn--link"
          :disabled="!row.logId"
          @click="$emit('inspect', row)"
        >
          {{ $t('attackProfile.viewForensics') }}
        </button>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import { formatTime } from '@/utils/datetime'
import { actionLabel as toActionLabel } from '@/utils/auditLabels'

defineProps({
  evidence: { type: Array, default: () => [] },
})
defineEmits(['inspect'])

const { t } = useI18n()
const actionLabel = (code) => toActionLabel(t, code)
</script>

<style scoped>
.mono {
  font-family: var(--xf-font-mono);
}
.empty-tip {
  font-family: var(--xf-font-body);
  text-align: center;
  padding: 18px 0;
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-sm);
}
</style>
