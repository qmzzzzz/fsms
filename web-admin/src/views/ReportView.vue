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
      <el-descriptions v-if="!overviewFailed" :column="3" border>
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
      <div v-else class="overview-failed">
        <span>{{ $t('messages.loadFailed') }}</span>
        <button type="button" class="glass-btn glass-btn--sm" @click="loadOverview">
          {{ $t('common.refresh') }}
        </button>
      </div>
    </el-card>

    <!-- 简单图表区域 -->
    <!--
      时间范围选择器：默认「全部」保持既有口径不变。「今日」按浏览器所在时区的
      本地自然日计算——把浏览器的 IANA 时区原样传给后端（tz 参数），后端用
      DST 安全的日界算法换算成 UTC 瞬间，跨夏令时切换日（23/25 小时日）不重叠不空洞。
    -->
    <div v-if="!loading" class="range-bar">
      <el-radio-group v-model="statsRange" @change="loadChartData">
        <el-radio-button value="all">{{ $t('report.range.all') }}</el-radio-button>
        <el-radio-button value="today">{{ $t('report.range.today') }}</el-radio-button>
        <el-radio-button value="7d">{{ $t('report.range.last7') }}</el-radio-button>
        <el-radio-button value="30d">{{ $t('report.range.last30') }}</el-radio-button>
      </el-radio-group>
    </div>
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
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useAppStore } from '@/store'

const { hasPerm } = usePermission()
const { t, locale } = useI18n()
const appStore = useAppStore()

const loading = ref(true)

// 注册 echarts 组件（按需导入，减少包体积；import 已统一收敛至文件顶部，O-4）
echarts.use([PieChart, BarChart, TooltipComponent, LegendComponent, GridComponent, CanvasRenderer])
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api, isCanceledError } from '@/utils/api'

const reportCards = computed(() =>
  [
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
      // 没有 path 的卡片=导出入口（模板里 `card.path ? push : showExportDialog()`）。
      // 权限必须与概览卡片头部那个「导出」按钮同源：原先只给按钮加了
      // `v-if="hasPerm('report:export')"`，这张卡片却没有，于是无 report:export 的
      // 用户点它照样弹出导出对话框并发起导出请求（后端会 403，但"入口消失"这条
      // 本文件自己声明的口径就破了）。写成 perm 字段而不是在模板里加判断，
      // 是为了让"哪张卡需要哪个权限"留在数据里、不散到模板。
      perm: 'report:export',
    },
  ].filter((card) => !card.perm || hasPerm(card.perm))
)

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

// 概览请求失败（或后端 success:false）：九个数值位不能继续以 0 面孔出现。
// 初值 false ⇒ 首帧（loading 骨架期）不会闪出失败块。
const overviewFailed = ref(false)

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
    // 轴标签色（P2-8）：此前柱图 x/y 轴都硬编码 #64748b，两主题同色，
    // 暗色下对比度偏低。并入 chartTheme 后随主题切换。
    axisLabelColor: dark ? '#94a3b8' : '#64748b',
  }
}

// 统计时间范围：默认「全部」保持既有口径。「今日/近7天/近30天」的日期串由
// 浏览器本地时钟产生（setDate 日历日加减，跨夏令时切换不会像毫秒减法那样
// 漂到错误的日历日），并把浏览器 IANA 时区一并交给后端换算成日界瞬间。
const statsRange = ref('all')

/**
 * 浏览器所在时区（IANA 名，如 Asia/Shanghai）。resolvedOptions 在极端环境
 * （无 ICU 数据）可能给空串，此时后端回落业务时区，行为与旧版一致。
 */
const browserTimezone = () => Intl.DateTimeFormat().resolvedOptions().timeZone || ''

/** 当前范围的查询参数：all ⇒ 不带任何日期参数（口径与历史版本完全一致）。
 *  时间基准快照一次（now）：两个 dayStr 各自 new Date() 会在跨午夜瞬间分叉，
 *  「近7天」漂成 8 天、「今日」漂成两天——概率极低但零成本可消。 */
const rangeParams = () => {
  if (statsRange.value === 'all') return {}
  const now = new Date()
  const offset = statsRange.value === 'today' ? 0 : statsRange.value === '7d' ? -6 : -29
  const dayStr = (off) => {
    const d = new Date(now)
    d.setDate(d.getDate() + off)
    return localDateStr(d)
  }
  return { startDate: dayStr(offset), endDate: dayStr(0), tz: browserTimezone() }
}

// 竞态守卫（与 AuditLogView/ipListView 同款）：连续切范围/切主题时丢弃过期
// 响应——「今日」的慢响应后到会把已渲染的「近7天」分布静默覆盖成错误时间窗
const chartGuard = useLatestRequest()

// 加载图表数据（实例仅在 onMounted 初始化一次，后续复用实例仅 setOption）
const loadChartData = async () => {
  const isCurrent = chartGuard()
  try {
    // 按当前主题取色，主题切换时由 watch 触发重绘
    const theme = chartTheme()

    const params = rangeParams()

    // 获取报警类型分布
    // O-2：报警与设备两个图表请求并行，避免串行叠加时延
    const [alarmRes, deviceRes] = await Promise.all([
      api.reports.getAlarms(params),
      api.reports.getDevices(),
    ])
    if (!isCurrent()) return
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

    // 设备状态数据：必须覆盖 FireDevice.status 全部 6 个枚举值
    // （normal/warning/fault/offline/maintenance/scrapped）。此前只画 4 项，
    // warning 与 scrapped 设备在「设备状态分布」里静默消失，分布图与总数对不上。
    const deviceStatusData = [
      {
        value: statusMap['normal'] || 0,
        name: t('deviceStatus.normal'),
        itemStyle: { color: '#16a34a' },
      },
      {
        value: statusMap['warning'] || 0,
        name: t('deviceStatus.warning'),
        itemStyle: { color: '#eab308' },
      },
      {
        value: statusMap['fault'] || 0,
        name: t('deviceStatus.fault'),
        itemStyle: { color: '#e63946' },
      },
      {
        value: statusMap['offline'] || 0,
        name: t('deviceStatus.offline'),
        itemStyle: { color: '#64748b' },
      },
      {
        value: statusMap['maintenance'] || 0,
        name: t('deviceStatus.maintenance'),
        itemStyle: { color: '#d97706' },
      },
      {
        value: statusMap['scrapped'] || 0,
        name: t('deviceStatus.scrapped'),
        itemStyle: { color: '#94a3b8' },
      },
    ]

    if (dChart) {
      dChart.setOption({
        tooltip: { trigger: 'axis', formatter: '{b}: {c}台' },
        xAxis: {
          type: 'category',
          // 由 deviceStatusData 单一来源派生，轴标签与 series 永远同序同长，
          // 再也不会出现「改了状态列表漏改 xAxis」的错位（也避免硬编码漏枚举）。
          data: deviceStatusData.map((d) => d.name),
          axisLabel: { color: theme.axisLabelColor },
        },
        yAxis: {
          type: 'value',
          // 计数数据不出小数刻度
          minInterval: 1,
          axisLabel: { color: theme.axisLabelColor },
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
  } catch {
    // P2-3：本次加载失败一律静默——提示由 api.js 响应拦截器统一负责（取消错误
    // ERR_CANCELED 拦截器本就不提示）。此前组件这里再弹一条泛化的 messages.loadFailed，
    // 同一次失败会弹两条：拦截器的具体原因 + 组件的泛化文案。
    // 已知边界（非本次引入）：图表卡没有常驻失败态，失败时画布保持空白，与「真的
    // 没有数据」在视觉上不可区分；拦截器 toast 是唯一线索，且会自行消失。
    // 本 catch 仅用于吞掉 rejection（避免未处理拒绝），不产生副作用。
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

// 切语言后图表文案（图例/空态）物化在 canvas 里不会自愈，与 DashboardCharts
// 同款 watch 重建；并发竞态由 chartGuard 统一兜底
watch(locale, () => {
  if (aChart || dChart) {
    loadChartData()
  }
})

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

    // 截断声明与 AuditLogView 同一条判据：后端只在"这份不保证完整"时发
    // X-Export-Truncated（值为字面 'true'），此前本视图完全不读它 —— 于是同一份被封顶的
    // 报表，从审计页下载会提示、从报表页下载只报"导出成功"，用户按后者的口径信了文件。
    if (response?.headers?.['x-export-truncated']) {
      ElMessage.warning(t('messages.exportTruncated'))
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
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
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
      overviewFailed.value = false
    } else {
      overviewFailed.value = true
    }
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不算失败（用户已离开本页）
    if (isCanceledError(e)) return
    // 旧口径是「静默处理」：失败时九个格子仍以 0 面孔出现，读作「设备 0 台、告警 0 起」
    overviewFailed.value = true
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

.overview-failed {
  display: flex;
  gap: var(--xf-spacing-md);
  align-items: center;
}

/* 时间范围选择器：与卡片间距一致，右对齐弱化（辅助控件不抢图表注意力） */
.range-bar {
  margin-bottom: 16px;
  display: flex;
  justify-content: flex-end;
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
