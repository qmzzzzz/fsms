<template>
  <!--
    设备到期提醒清单（只读展示组件，数据/请求归 DeviceView 持有）：
    四个档位列表 + 扫描时间 + 降级信号（partial/skipped）+ 单档截断提示。
    形状来自后端 services/deviceReminder.js：
      { scannedAt, summary{expired,expiringSoon,needMaintenance,needSchedule,total},
        expired[], expiringSoon[], needMaintenance[], needSchedule[],
        limits{resultLimit, truncated{四档}}, partial, skipped }
  -->
  <el-dialog
    :model-value="visible"
    :title="$t('device.remindersTitle')"
    width="620px"
    @update:model-value="$emit('update:visible', $event)"
  >
    <div v-loading="loading">
      <!-- 降级信号：partial 为真时列表可能不完整（扫描进行中/受限），必须显式告知 -->
      <el-alert
        v-if="data && (data.partial || data.skipped)"
        type="warning"
        :closable="false"
        show-icon
        class="reminder-alert"
        :title="$t('device.reminderPartial')"
      />
      <div v-if="failed && !data" class="reminder-failed">
        <span>{{ $t('device.reminderLoadFailed') }}</span>
        <button type="button" class="glass-btn glass-btn--sm" @click="$emit('refresh')">
          {{ $t('common.refresh') }}
        </button>
      </div>
      <template v-else-if="data">
        <div class="reminder-scanned">
          {{ $t('device.scannedAt') }}: {{ formatTime(data.scannedAt) }}
        </div>
        <div v-if="data.summary?.total === 0" class="reminder-empty">
          {{ $t('device.reminderEmpty') }}
        </div>
        <template v-else>
          <section v-for="bucket in activeBuckets" :key="bucket.key" class="reminder-bucket">
            <h4 class="reminder-bucket-title" :class="bucket.cls">
              {{ bucket.label }}（{{ bucket.list(data).length }}）
            </h4>
            <ul class="reminder-list">
              <li v-for="(item, i) in bucket.list(data)" :key="item._id || i" class="reminder-item">
                <span class="reminder-code">{{ item.deviceCode }}</span>
                <span class="reminder-name">{{ item.deviceName }}</span>
                <span class="reminder-location">{{ locationText(item.location) }}</span>
                <span class="reminder-date">{{ dateOnly(item[bucket.dateKey]) }}</span>
              </li>
            </ul>
            <!-- 单档被 resultLimit 截断：档内计数是页内值而非库里总数，必须说明 -->
            <div v-if="data.limits?.truncated?.[bucket.key]" class="reminder-truncated">
              {{ $t('device.reminderTruncated', { limit: data.limits.resultLimit }) }}
            </div>
          </section>
        </template>
      </template>
    </div>
    <template #footer>
      <button
        type="button"
        class="glass-btn glass-btn--default"
        :disabled="loading"
        @click="$emit('refresh')"
      >
        {{ $t('common.refresh') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        @click="$emit('update:visible', false)"
      >
        {{ $t('common.close') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { localDateStr, formatTime } from '@/utils/datetime'

const props = defineProps({
  visible: { type: Boolean, default: false },
  /** 后端 reminders 响应体（data 层）；null = 尚未拿到 */
  data: { type: Object, default: null },
  loading: { type: Boolean, default: false },
  /** 请求失败且无历史数据时展示失败块 + 重试 */
  failed: { type: Boolean, default: false },
})
defineEmits(['update:visible', 'refresh'])

const { t } = useI18n()

// 日期列：设备日期字段是本地日历概念，按本地时区取 YYYY-MM-DD（UTC 口径会跨日）
const dateOnly = (v) => {
  if (!v) return '-'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '-' : localDateStr(d)
}
const locationText = (loc) =>
  loc ? [loc.building, loc.floor, loc.room].filter(Boolean).join(' ') || loc.detail || '-' : '-'

// computed：档位标题随语言切换即时更新（模块级常量会把挂载时的语言钉死）
const buckets = computed(() => [
  {
    key: 'expired',
    dateKey: 'expiryDate',
    cls: 'is-danger',
    label: t('device.expired'),
    list: (d) => d.expired || [],
  },
  {
    key: 'expiringSoon',
    dateKey: 'expiryDate',
    cls: 'is-warning',
    label: t('device.expiringSoon'),
    list: (d) => d.expiringSoon || [],
  },
  {
    key: 'needMaintenance',
    dateKey: 'nextCheckDate',
    cls: 'is-primary',
    label: t('device.needMaintenance'),
    list: (d) => d.needMaintenance || [],
  },
  {
    key: 'needSchedule',
    dateKey: 'installDate',
    cls: 'is-info',
    label: t('device.needSchedule'),
    list: (d) => d.needSchedule || [],
  },
])

// 空档位整节不渲染（v-show 留下的空标题会被读成「加载中」；v-for+v-if 同节点
// 在 Vue 3 里 v-if 先求值拿不到循环变量，故在 computed 里过滤）
const activeBuckets = computed(() =>
  props.data ? buckets.value.filter((b) => b.list(props.data).length > 0) : []
)
</script>

<style scoped>
.reminder-alert {
  margin-bottom: 12px;
}
.reminder-scanned {
  margin-bottom: 12px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}
.reminder-empty {
  padding: 24px 0;
  text-align: center;
  color: var(--xf-text-secondary);
}
.reminder-failed {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  color: var(--xf-text-secondary);
}
.reminder-bucket {
  margin-bottom: 16px;
}
.reminder-bucket-title {
  margin: 0 0 8px;
  font-size: var(--xf-font-size-sm);
  font-weight: 600;
}
.reminder-bucket-title.is-danger {
  color: var(--xf-danger);
}
.reminder-bucket-title.is-warning {
  color: var(--xf-warning);
}
.reminder-bucket-title.is-primary {
  color: var(--xf-primary);
}
.reminder-bucket-title.is-info {
  color: var(--xf-info);
}
.reminder-list {
  margin: 0;
  padding: 0;
  list-style: none;
  max-height: 180px;
  overflow-y: auto;
}
.reminder-item {
  display: flex;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-sm);
}
.reminder-code {
  flex: 0 0 90px;
  color: var(--xf-text-secondary);
}
.reminder-name {
  flex: 1 1 auto;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.reminder-location {
  flex: 1 1 auto;
  color: var(--xf-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.reminder-date {
  flex: 0 0 90px;
  text-align: right;
  color: var(--xf-text-secondary);
}
.reminder-truncated {
  padding-top: 6px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-warning);
}
</style>
