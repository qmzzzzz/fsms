<template>
  <div class="page">
    <!-- 快速入口 -->
    <el-row :gutter="16">
      <el-col v-for="card in reportCards" :key="card.title" :xs="12" :md="6">
        <el-card
          shadow="hover"
          class="report-card"
          @click="card.path ? $router.push(card.path) : showExportDialog()"
        >
          <div class="report-card-body">
            <el-icon :size="36" :color="card.color">
              <component :is="card.icon" />
            </el-icon>
            <div>
              <div class="card-title">
                {{ card.title }}
              </div>
              <div class="card-desc">
                {{ card.desc }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 概览数据 -->
    <el-card v-if="loading" shadow="never" class="overview-card">
      <GlassSkeleton variant="table" :rows="3" :cols="['30%', '30%', '30%']" />
    </el-card>
    <el-card v-else shadow="never" class="overview-card">
      <template #header>
        <div class="card-header">
          <span>{{ $t('report.dashboard') }}</span>
          <button
            v-if="hasPerm('report:export')"
            type="button"
            class="glass-btn glass-btn--primary glass-btn--sm"
            @click="showExportDialog"
          >
            {{ $t('common.export') }}
          </button>
        </div>
      </template>
      <el-descriptions :column="3" border>
        <el-descriptions-item :label="$t('device.totalDevices')">
          {{ overview.devices }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('report.deviceOnlineRate')">
          {{ overview.deviceOnlineRate }}%
        </el-descriptions-item>
        <el-descriptions-item :label="$t('device.maintenance')">
          {{ overview.needMaintenance }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('alarm.stats')">
          {{ overview.alarmTotal }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('dashboard.pendingAlarms')">
          {{ overview.alarmPending }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('report.avgResponseTime')">
          {{ overview.avgResponse }}min
        </el-descriptions-item>
        <el-descriptions-item :label="$t('inspection.title')">
          {{ overview.inspectionTotal }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('inspection.completed')">
          {{ overview.completionRate }}%
        </el-descriptions-item>
        <el-descriptions-item :label="$t('common.warning')">
          {{ overview.overdue }}
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- 简单图表区域 -->
    <el-row v-if="loading" :gutter="16">
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>
            <span class="card-header"><span class="sk-block sk-text" style="width: 100px" /></span>
          </template>
          <GlassSkeleton variant="chart" />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>
            <span class="card-header"><span class="sk-block sk-text" style="width: 120px" /></span>
          </template>
          <GlassSkeleton variant="chart" />
        </el-card>
      </el-col>
    </el-row>
    <el-row v-else :gutter="16">
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>
            <span class="card-header">{{ $t('alarm.stats') }}</span>
          </template>
          <div ref="alarmTypeChart" class="chart-box" />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>
            <span class="card-header">{{ $t('device.status') }}</span>
          </template>
          <div ref="deviceStatusChart" class="chart-box" />
        </el-card>
      </el-col>
    </el-row>

    <!-- 导出对话框 -->
    <el-dialog v-model="exportDialog.visible" :title="$t('common.export')" width="450px">
      <el-form label-width="100px">
        <el-form-item :label="$t('common.type')">
          <el-radio-group v-model="exportDialog.type">
            <el-radio value="alarms">
              {{ $t('report.alarmReport') }}
            </el-radio>
            <el-radio value="devices">
              {{ $t('report.deviceReport') }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('report.dateRange')">
          <el-date-picker
            v-model="exportDialog.dateRange"
            type="daterange"
            range-separator="-"
            :start-placeholder="$t('report.startDate')"
            :end-placeholder="$t('report.endDate')"
            style="width: 100%"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="exportDialog.visible = false"
        >
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="exporting"
          @click="handleExport"
        >
          {{ $t('report.exportExcel') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, reactive, computed, nextTick, watch, markRaw } from 'vue'
import { useI18n } from 'vue-i18n'
import { Cpu, Bell, Tickets, DataAnalysis } from '@element-plus/icons-vue'
import * as echarts from 'echarts/core'
import { PieChart, BarChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { usePermission } from '@/composables/usePermission'
import { useAppStore } from '@/store'

const { hasPerm } = usePermission()
const { t } = useI18n()
const appStore = useAppStore()

const loading = ref(true)

// 注册 echarts 组件（按需导入，减少包体积；import 已统一收敛至文件顶部，O-4）
echarts.use([PieChart, BarChart, TooltipComponent, LegendComponent, GridComponent, CanvasRenderer])
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'

const reportCards = computed(() => [
  {
    title: t('report.deviceReport'),
    desc: t('device.status'),
    icon: markRaw(Cpu),
    color: '#475569',
    path: '/devices',
  },
  {
    title: t('report.alarmReport'),
    desc: t('alarm.stats'),
    icon: markRaw(Bell),
    color: '#e63946',
    path: '/alarms',
  },
  {
    title: t('report.inspectionReport'),
    desc: t('inspection.completed'),
    icon: markRaw(Tickets),
    color: '#d97706',
    path: '/inspections',
  },
  {
    title: t('report.dashboard'),
    desc: t('common.export'),
    icon: markRaw(DataAnalysis),
    color: '#c1121f',
    path: '',
  },
])

const overview = ref({
  devices: 0,
  deviceOnlineRate: 0,
  needMaintenance: 0,
  alarmTotal: 0,
  alarmPending: 0,
  avgResponse: 0,
  inspectionTotal: 0,
  completionRate: 0,
  overdue: 0,
})

const alarmTypeChart = ref(null)
const deviceStatusChart = ref(null)
let aChart = null
let dChart = null

// 报警类型颜色映射（与 FireAlarm 模型 alarmType 枚举一致）
const alarmTypeColors = {
  smoke: '#e63946',
  temp_abnormal: '#d97706',
  manual_button: '#c1121f',
  phone_report: '#d97706',
  patrol_find: '#16a34a',
  other: '#64748b',
}

// alarmTypeNames 已抽取至 utils/labelMaps.js 单一来源（O-1）
import { makeAlarmTypeLabels } from '@/utils/labelMaps'
const alarmTypeNames = computed(() => makeAlarmTypeLabels(t))

const initCharts = () => {
  // 报警类型分布
  if (alarmTypeChart.value) {
    aChart = echarts.init(alarmTypeChart.value)
  }

  // 设备状态分布
  if (deviceStatusChart.value) {
    dChart = echarts.init(deviceStatusChart.value)
  }
}

// 图表暗色适配（最小方案）：饼图描边/网格线/空数据占位三处颜色随主题切换
const chartTheme = () => {
  const dark = appStore.isDarkMode
  return {
    borderColor: dark ? '#0f172a' : '#ffffff',
    splitLineColor: dark ? 'rgba(148, 163, 184, 0.25)' : '#e2e8f0',
    noDataColor: dark ? '#475569' : '#cbd5e1',
  }
}

// 加载图表数据（实例仅在 onMounted 初始化一次，后续复用实例仅 setOption）
const loadChartData = async () => {
  try {
    // 按当前主题取色，主题切换时由 watch 触发重绘
    const theme = chartTheme()

    // 获取报警类型分布
    // O-2：报警与设备两个图表请求并行，避免串行叠加时延
    const [alarmRes, deviceRes] = await Promise.all([
      api.reports.getAlarms(),
      api.reports.getDevices(),
    ])
    const alarmData = alarmRes?.data?.data || {}
    const byType = alarmData.byType || []

    // 转换报警类型数据为图表格式
    const alarmTypeSeries = byType.map((item) => ({
      value: item.count || 0,
      name: alarmTypeNames.value[item._id] || item._id || t('common.noData'),
      itemStyle: { color: alarmTypeColors[item._id] || '#64748b' },
    }))

    if (aChart) {
      aChart.setOption({
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { bottom: 0, orient: 'horizontal' },
        series: [
          {
            type: 'pie',
            radius: ['40%', '65%'],
            center: ['50%', '45%'],
            itemStyle: { borderRadius: 6, borderColor: theme.borderColor, borderWidth: 2 },
            label: { show: true, formatter: '{b}: {c}' },
            data:
              alarmTypeSeries.length > 0
                ? alarmTypeSeries
                : [{ value: 1, name: t('common.noData'), itemStyle: { color: theme.noDataColor } }],
          },
        ],
      })
    }

    const deviceData = deviceRes?.data?.data || {}
    const byStatus = deviceData.byStatus || []

    // 创建状态到数量的映射
    const statusMap = {}
    byStatus.forEach((item) => {
      statusMap[item._id] = item.count || 0
    })

    // 设备状态数据（normal=在线，offline=离线，fault=故障，maintenance=维护中）
    const deviceStatusData = [
      {
        value: statusMap['normal'] || 0,
        name: t('deviceStatus.normal'),
        itemStyle: { color: '#16a34a' },
      },
      {
        value: statusMap['offline'] || 0,
        name: t('deviceStatus.offline'),
        itemStyle: { color: '#64748b' },
      },
      {
        value: statusMap['fault'] || 0,
        name: t('deviceStatus.fault'),
        itemStyle: { color: '#e63946' },
      },
      {
        value: statusMap['maintenance'] || 0,
        name: t('deviceStatus.maintenance'),
        itemStyle: { color: '#d97706' },
      },
    ]

    if (dChart) {
      dChart.setOption({
        tooltip: { trigger: 'axis', formatter: '{b}: {c}台' },
        xAxis: {
          type: 'category',
          data: [
            t('deviceStatus.normal'),
            t('deviceStatus.offline'),
            t('deviceStatus.fault'),
            t('deviceStatus.maintenance'),
          ],
          axisLabel: { color: '#64748b' },
        },
        yAxis: {
          type: 'value',
          axisLabel: { color: '#64748b' },
          splitLine: { lineStyle: { color: theme.splitLineColor } },
        },
        grid: { left: '3%', right: '4%', bottom: '10%', containLabel: true },
        series: [
          {
            type: 'bar',
            barWidth: '50%',
            itemStyle: { borderRadius: [6, 6, 0, 0] },
            data: deviceStatusData,
          },
        ],
      })
    }
  } catch (e) {
    // B-2：失败给一次非阻断式提示，区分「无数据」与「加载失败」
    ElMessage.error(t('messages.loadFailed'))
  }
}

// 主题切换后按新配色重绘图表（复用已有实例）
watch(
  () => appStore.isDarkMode,
  () => {
    if (aChart || dChart) {
      loadChartData()
    }
  }
)

// 节流函数
let resizeTimer = null
const throttledResize = () => {
  if (resizeTimer) return
  resizeTimer = setTimeout(() => {
    aChart?.resize && aChart.resize()
    dChart?.resize && dChart.resize()
    resizeTimer = null
  }, 100)
}

const exportDialog = reactive({
  visible: false,
  type: 'alarms',
  dateRange: null,
})

const exporting = ref(false)

const showExportDialog = () => {
  exportDialog.visible = true
  exportDialog.type = 'alarms'
  exportDialog.dateRange = null
}

// 报表类型 → 中文文件名前缀(与服务端 sheetName 保持一致)
const exportTypeNames = computed(() => ({
  alarms: t('report.alarmReport'),
  devices: t('report.deviceReport'),
  inspections: t('report.inspectionReport'),
  audit: t('security.auditLogs'),
}))

// 本地时区日期串（YYYY-MM-DD）：date-picker 未设 value-format 时返回 Date 对象，
// 本地日期串已抽取至 utils/datetime.js 统一口径（O-3），此处按需引入
import { localDateStr } from '@/utils/datetime'

// 从 blob 响应中解析后端错误信息：responseType:'blob' 时 JSON 错误也被包成 Blob，
// 通过 MIME 类型识别后读取文本内容
const extractErrorMessage = async (data, fallback) => {
  if (data instanceof Blob && data.type?.includes('json')) {
    try {
      const parsed = JSON.parse(await data.text())
      if (parsed?.message) return parsed.message
    } catch (_) {
      /* 解析失败走兜底文案 */
    }
  }
  return data?.message || fallback
}

const handleExport = async () => {
  exporting.value = true
  try {
    const params = {
      type: exportDialog.type,
    }

    if (exportDialog.dateRange && exportDialog.dateRange.length === 2) {
      params.startDate = localDateStr(exportDialog.dateRange[0])
      params.endDate = localDateStr(exportDialog.dateRange[1])
    }

    // responseType: 'blob' 时,Blob 在 response.data,response 本身是完整 axios 响应对象
    const response = await api.reports.export(params)
    const blob = response.data

    // 后端返回 JSON 错误而非 Excel 时,提前给出明确提示
    if (blob instanceof Blob && blob.type?.includes('json')) {
      ElMessage.error(await extractErrorMessage(blob, t('messages.exportFailed')))
      return
    }
    if (!(blob instanceof Blob)) {
      ElMessage.error(await extractErrorMessage(response.data, t('messages.exportFailed')))
      return
    }

    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url

    // 直接由前端生成中文名文件名,避免依赖 Content-Disposition 解析
    const prefix = exportTypeNames.value[exportDialog.type] || t('common.export')
    const filename = `${prefix}_${localDateStr()}.xlsx` // O-7: 本地日期，避免东八区 0-8 点 UTC 日期早一天
    link.download = filename
    link.click()
    window.URL.revokeObjectURL(url)

    ElMessage.success(t('messages.exportSuccess'))
    exportDialog.visible = false
  } catch (e) {
    // blob 响应的错误信息在 e.response.data（Blob）中，统一提取后提示
    const msg = await extractErrorMessage(
      e?.response?.data,
      e?.message || t('messages.exportFailed')
    )
    ElMessage.error(msg)
  } finally {
    exporting.value = false
  }
}

const loadOverview = async () => {
  try {
    const res = await api.reports.getDashboard()

    if (res.data.success) {
      const d = res.data.data
      const devices = d.devices || {}
      const alarms = d.alarms || {}
      const inspections = d.inspections || {}

      overview.value = {
        devices: devices.total || 0,
        deviceOnlineRate:
          devices.total > 0 ? Math.round((devices.online / devices.total) * 100) : 0,
        needMaintenance: devices.needMaintenance || 0,
        alarmTotal: alarms.total || 0,
        alarmPending: alarms.pending || 0,
        avgResponse: alarms.avgResponse || 0,
        inspectionTotal: inspections.total || 0,
        completionRate: inspections.completionRate || 0,
        overdue: inspections.overdue || 0,
      }
    }
  } catch (e) {
    // 静默处理
  }
}

onMounted(async () => {
  loading.value = true
  // 先注册 resize 监听再进入 await 流程，确保任何提前返回的路径下监听器都已就位
  window.addEventListener('resize', throttledResize, { passive: true })
  // 先加载概览数据，骨架替换为真实内容后再初始化图表并渲染图表数据
  // （图表 setOption 依赖 echarts 实例，实例必须在 DOM 就绪后创建）
  await loadOverview()
  loading.value = false
  await nextTick()
  initCharts()
  await loadChartData()
})

onUnmounted(() => {
  window.removeEventListener('resize', throttledResize)
  if (resizeTimer) clearTimeout(resizeTimer)
  aChart?.dispose && aChart.dispose()
  dChart?.dispose && dChart.dispose()
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: var(--xf-spacing-md);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.report-card {
  cursor: pointer;
  transition:
    transform var(--xf-duration-base) var(--xf-ease-glass),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.report-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--xf-shadow-lg);
}

.el-col:nth-child(1) .report-card {
  animation-delay: 0.05s;
}
.el-col:nth-child(2) .report-card {
  animation-delay: 0.1s;
}
.el-col:nth-child(3) .report-card {
  animation-delay: 0.15s;
}
.el-col:nth-child(4) .report-card {
  animation-delay: 0.2s;
}

.report-card :deep(.el-card__body) {
  padding: var(--xf-spacing-lg);
}

.report-card-body {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-lg);
}

.card-title {
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-md);
  color: var(--xf-gray-900);
}

.card-desc {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-500);
  margin-top: var(--xf-spacing-xs);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.overview-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.25s;
}

.overview-card :deep(.el-descriptions__content) {
  font-family: var(--xf-font-display);
  font-variant-numeric: tabular-nums;
}

.chart-box {
  height: 280px;
  width: 100%;
}

/* ===== Apple 风格增量（交互手感层：只叠反馈与过渡，不改布局） ===== */

/* 可交互元素按压即时反馈（pointer-down，非松开） */
.el-button:active {
  transform: scale(0.97);
  transition: transform 100ms ease-out;
}

/* 卡片 hover 轻浮起（可中断阴影过渡，无弹跳，克制） */
.el-card {
  transition: box-shadow 280ms cubic-bezier(0.32, 0.72, 0, 1);
}
.el-card:hover {
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
}

/* 表格行背景平滑渐变，避免斑马纹/状态色跳变 */
:deep(.el-table .el-table__row td.el-table__cell) {
  transition: background-color 150ms ease;
}

/* 标签（el-tag）hover 轻微加深，仅提示可读性 */
:deep(.el-tag) {
  transition: opacity 150ms ease;
}

/* 无障碍降级：本页新增动效全部纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .el-button:active {
    transform: none !important;
  }
  .el-card {
    transition: opacity 150ms ease !important;
  }
  .el-card:hover {
    box-shadow: none !important;
  }
  :deep(.el-table .el-table__row td.el-table__cell) {
    transition: none !important;
  }
}
</style>
