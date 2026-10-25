<template>
  <!-- 最近报警（D-2 自 DashboardView 拆出）：
       纯渲染组件——数据加载/权限门控留在视图层，因为首屏骨架屏要
       等报警数据到达后才直换（子组件在骨架期尚未挂载，无法参与 await） -->
  <el-card shadow="never" class="alarm-card">
    <template #header>
      <div class="card-header">
        <span>{{ $t('dashboard.recentAlarms') }}</span>
        <button
          type="button"
          class="glass-btn glass-btn--primary glass-btn--link"
          @click="$router.push('/alarms')"
        >
          {{ $t('dashboard.viewAll') }} <el-icon><ArrowRight /></el-icon>
        </button>
      </div>
    </template>
    <!-- 加载失败必须显式可见：空表无法与「确实没有报警」区分。
         有旧数据时标注为上次数据并保留，首次加载失败则只显示错误提示。 -->
    <el-alert
      v-if="error"
      :title="rows.length > 0 ? $t('dashboard.alarmsStale') : $t('dashboard.alarmsLoadFailed')"
      type="warning"
      :closable="false"
      show-icon
      class="alarm-alert"
    >
      <template #default>
        <button
          type="button"
          class="glass-btn glass-btn--default glass-btn--sm"
          @click="$emit('retry')"
        >
          {{ $t('common.retry') }}
        </button>
      </template>
    </el-alert>
    <el-table v-if="!(error && rows.length === 0)" :data="rows" style="width: 100%">
      <el-table-column prop="time" :label="$t('common.createTime')" width="180" />
      <el-table-column prop="location" :label="$t('alarm.location')" />
      <el-table-column prop="type" :label="$t('alarm.alarmType')" width="120">
        <template #default="{ row }">
          <el-tag :type="row.tagType" size="small">
            {{ row.type }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="status" :label="$t('common.status')" width="120">
        <template #default="{ row }">
          <el-tag :type="row.statusType" effect="plain" size="small">
            {{ row.status }}
          </el-tag>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup>
import { ArrowRight } from '@element-plus/icons-vue'

defineProps({
  /** 已映射为展示结构的报警行：{ time, location, type, tagType, status, statusType } */
  rows: { type: Array, default: () => [] },
  /** 最近一次加载/刷新是否失败（为 true 时显示错误或陈旧数据提示） */
  error: { type: Boolean, default: false },
})

defineEmits(['retry'])
</script>

<style scoped>
/* 父视图的 scoped 样式不穿透子组件内部元素，此处自带同值定义 */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-base);
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-gray-800);
}

/* ===== 报警记录卡片 =====
   不加入场动画：与图表区同理，骨架直换零位移（D-2） */
.alarm-alert {
  margin-bottom: 12px;
}
</style>
