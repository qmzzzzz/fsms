<template>
  <!-- 图表区（D-2 自 DashboardView 拆出）：
       数据全部来自 report 接口，无 report:read 时整块不渲染（P3-39）。
       echarts 注册/初始化/窗口 resize 与数据加载全部内聚在本组件，
       父级经 load() 触发刷新（定时/可见性恢复/语言切换） -->
  <el-row :gutter="20">
    <el-col :xs="24" :md="16">
      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">
            <span>{{ $t('dashboard.alarmTrend') }}</span>
            <el-tag type="danger" size="small">
              {{ $t('dashboard.realtime') }}
            </el-tag>
          </div>
        </template>
        <div ref="trendChartRef" class="chart-container" />
      </el-card>
    </el-col>
    <el-col :xs="24" :md="8">
      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">
            <span>{{ $t('dashboard.deviceTypeDist') }}</span>
          </div>
        </template>
        <div ref="pieChartRef" class="chart-container" />
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'

// L7：ECharts tooltip 按 HTML 渲染，类目名（设备名等）属用户可控输入，
// 拼入 formatter 前必须转义，防注入
const escapeHtml = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')

import * as echarts from 'echarts/core'
import { LineChart, PieChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  GraphicComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
// echarts 6 中 grid.containLabel 需显式注册旧版兼容组件，否则控制台告警
import { LegacyGridContainLabel } from 'echarts/features'

echarts.use([
  LineChart,
  PieChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  GraphicComponent,
  CanvasRenderer,
  LegacyGridContainLabel,
])

import { usePermission } from '@/composables/usePermission'
import { api } from '@/utils/api'
// 类型/状态 → i18n 标签映射（O-1 抽取的单一事实来源，与 ReportView 共用）
import { makeDeviceTypeLabels } from '@/utils/labelMaps'
// 本地日期串（YYYY-MM-DD）：与后端 byDay 的业务时区聚合口径对齐，
// 避免 toISOString 的 UTC 日期在东八区每天 0-8 点与图表标签错位一天
// 本地日期串已抽取至 utils/datetime.js 统一口径（O-3）
import { localDateStr as toLocalDateStr } from '@/utils/datetime'

const { t, locale } = useI18n()
const { hasPerm } = usePermission()
// 图表数据全部来自 report 接口，无该权限时整个图表区不渲染（而非渲染空图表）
const canShowCharts = () => hasPerm('report:read')

const trendChartRef = ref(null)
const pieChartRef = ref(null)
let trendChart = null
let pieChart = null

const initCharts = (alarmTrendData, deviceTypeData, failed = {}) => {
  // 「这张图没数据」和「这张图的数据没取到」必须写成两种空态。曾经两者都渲染成
  // common.noData（"暂无数据"），于是 reports 接口抖动一次后，7 天趋势图上盖的是
  // "这几天没有报警"——值班界面把一次失败读成一次安全。失败侧改说"加载失败"，
  // 图仍照常初始化（不留白屏，那是本组件既有的契约）。
  const emptyText = (isFailed) => (isFailed ? t('messages.loadFailed') : t('common.noData'))
  if (!trendChartRef.value || !pieChartRef.value) return

  // 销毁旧图表
  trendChart?.dispose && trendChart.dispose()
  pieChart?.dispose && pieChart.dispose()

  // 趋势图
  trendChart = echarts.init(trendChartRef.value)
  const dates = alarmTrendData.map((d) => d._id || d.date)
  const counts = alarmTrendData.map((d) => d.count || 0)

  // 添加一些示例数据，如果没有数据
  const hasData = counts.some((c) => c > 0)

  trendChart.setOption({
    tooltip: {
      trigger: 'axis',
      formatter: (params) => {
        const data = params[0]
        return `${escapeHtml(data.name)}<br/>${t('dashboard.alarmCount')}: ${escapeHtml(data.value)}`
      },
    },
    grid: { left: '3%', right: '4%', top: '10%', bottom: '15%', containLabel: true },
    xAxis: {
      type: 'category',
      data: dates,
      boundaryGap: false,
      axisLabel: {
        rotate: 0,
      },
    },
    yAxis: {
      type: 'value',
      // 计数数据不出小数刻度（0.2/0.6 个报警没有意义）
      minInterval: 1,
      splitLine: { show: true, lineStyle: { type: 'dashed' } },
    },
    series: [
      {
        name: t('dashboard.alarmCount'),
        type: 'line',
        smooth: true,
        data: counts,
        areaStyle: {
          opacity: 0.3,
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(193, 18, 31, 0.5)' },
            { offset: 1, color: 'rgba(193, 18, 31, 0.1)' },
          ]),
        },
        itemStyle: { color: '#c1121f' },
        lineStyle: { width: 2 },
        symbolSize: 6,
        label: {
          show: hasData,
          position: 'top',
          formatter: '{c}',
        },
      },
    ],
    graphic: !hasData
      ? [
          {
            type: 'text',
            left: 'center',
            top: 'center',
            style: {
              text: emptyText(failed.trend),
              fontSize: 14,
              // Canvas 渲染器无法解析 CSS 变量，使用主题灰的十六进制值
              fill: '#64748b',
            },
          },
        ]
      : [],
  })

  // 饼图
  pieChart = echarts.init(pieChartRef.value)

  // 评价报告 #19：空数据不再渲染「示例数据」（易被误认成真实占比），
  // 空态文案与折线图同款（失败 / 真的没有 两种）
  const displayDeviceData = deviceTypeData

  pieChart.setOption({
    title: {
      show: displayDeviceData.length === 0,
      text: emptyText(failed.pie),
      left: 'center',
      top: 'center',
      textStyle: { fontSize: 14, color: '#64748b' },
    },
    tooltip: {
      trigger: 'item',
      // L7：类目名与数值都走 escapeHtml——正常时 value/percent 是数字（String() 原样），
      // 但后端聚合口径若漂移（count 变成含 HTML 的字符串），函数型 formatter 的返回值会
      // 直进 ECharts tooltip 的 innerHTML，故对全部插值字段一律转义，不只 name。
      formatter: (p) =>
        `${escapeHtml(p.seriesName)}<br/>${escapeHtml(p.name)}: ${escapeHtml(p.value)} (${escapeHtml(p.percent)}%)`,
    },
    legend: {
      show: displayDeviceData.length > 0,
      bottom: 0,
      left: 'center',
      data: displayDeviceData.map((d) => d.name),
    },
    series: [
      {
        name: t('dashboard.deviceCount'),
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['50%', '45%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 6,
          borderColor: '#fff',
          borderWidth: 2,
        },
        label: {
          show: false,
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold',
          },
        },
        data: displayDeviceData.map((item) => ({
          value: item.count || item.value,
          name: item.name,
          itemStyle: { color: getColor(item.name) },
        })),
      },
    ],
  })

  // 触发重绘
  trendChart.resize()
  pieChart.resize()
}

const colors = [
  '#c1121f',
  '#16a34a',
  '#b91c1c',
  '#d97706',
  '#e63946',
  '#15803d',
  '#b45309',
  '#7f1d1d',
]
const getColor = (name) => {
  const idx = Math.abs(name.length + name.charCodeAt(0)) % colors.length
  return colors[idx]
}

const deviceTypeLabel = (type) => makeDeviceTypeLabels(t)[type] || type

const doLoad = async () => {
  // P3-39：图表数据全部来自 report 接口
  if (!canShowCharts()) return
  try {
    // 两个报表请求无依赖关系，并行发出；各自 .catch(() => null) 保持与串行时一致的容错语义
    const [alarmRes, deviceRes] = await Promise.all([
      // 近7天的报警数据
      api.reports
        .getAlarms({
          startDate: toLocalDateStr(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)),
        })
        .catch(() => null),
      // 设备类型分布数据
      api.reports.getDevices({}).catch(() => null),
    ])

    // 处理报警数据 - 按天统计
    const alarmByDay = alarmRes?.data?.data?.byDay || []
    // 生成最近7天的日期
    const dates = []
    const counts = []
    for (let i = 6; i >= 0; i--) {
      const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000)
      const dateStr = toLocalDateStr(date)
      const dayData = alarmByDay.find((d) => d._id === dateStr)
      // X 轴标签刻意用 locale 短格式（MM-DD）：轴宽有限，定长串会挤爆刻度。
      // 数据表格的时间列才需要 utils/datetime 的定长口径，两者诉求不同。
      dates.push(date.toLocaleDateString(locale.value, { month: '2-digit', day: '2-digit' }))
      counts.push(dayData?.count || 0)
    }

    // 处理设备类型数据
    const deviceByType = deviceRes?.data?.data?.byType || []

    const deviceTypeData = deviceByType.map((item) => ({
      name: deviceTypeLabel(item._id) || item._id || t('common.all'),
      count: item.count || 0,
    }))

    // 使用处理后的数据初始化图表
    const processedAlarmData = dates.map((date, index) => ({ _id: date, count: counts[index] }))
    initCharts(processedAlarmData, deviceTypeData, {
      // null 只有一个成因：那条请求 rejected（成功但空集合会是 `{data:{data:{}}}`）。
      // 这里把它当成"这一格没取到"而不是"这一格是零"。
      trend: alarmRes === null,
      pie: deviceRes === null,
    })
  } catch (e) {
    // 使用空数据初始化图表
    initCharts([], [], { trend: true, pie: true })
  }
}

const handleResize = () => {
  trendChart?.resize && trendChart.resize()
  pieChart?.resize && pieChart.resize()
}

let resizeTimer = null
const throttledResize = () => {
  if (resizeTimer) return
  resizeTimer = setTimeout(() => {
    handleResize()
    resizeTimer = null
  }, 100)
}

// 本组件由父视图异步加载（defineAsyncComponent）。挂载完成前父级的 load() 调用
// 会落空，挂载后自身又会补调一次，两个触发点可能重叠 —— 这里用 in-flight 复用
// 保证同一时刻只发出一份请求，重叠的调用直接复用进行中的 Promise。
let loadInFlight = null
const load = () => {
  if (loadInFlight) return loadInFlight
  loadInFlight = doLoad().finally(() => {
    loadInFlight = null
  })
  return loadInFlight
}

// 语言切换时重建图表标签；骨架屏阶段容器未挂载则跳过（首屏完成后另行初始化）
watch(locale, () => {
  if (trendChartRef.value) load()
})

onMounted(() => {
  window.addEventListener('resize', throttledResize, { passive: true })
  // 本组件是异步加载的：父视图在数据返回后按 nextTick 触发 load() 时，这里往往
  // 尚未挂载完成，那次调用会落空。挂载后自行补一次，避免图表永久停在空白状态。
  load()
})

onUnmounted(() => {
  window.removeEventListener('resize', throttledResize)
  if (resizeTimer) clearTimeout(resizeTimer)
  trendChart?.dispose && trendChart.dispose()
  pieChart?.dispose && pieChart.dispose()
})

defineExpose({ load })
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

/* ===== 图表卡片 =====
   不加入场动画：原实现中父级 is-loading/is-loaded 双态均将其置为 none，
   骨架屏 → 真实内容为原地直换，页面不跳（D-2 拆出后保持同行为） */
.chart-card {
  height: 380px;
}

.chart-card :deep(.el-card__body) {
  height: calc(100% - 56px);
  padding: 16px 20px;
}

.chart-container {
  width: 100%;
  height: 100%;
  min-height: 280px;
}

/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .chart-card {
    height: 300px;
  }
  .chart-container {
    min-height: 220px;
  }
}
</style>
