<template>
  <div class="page">
    <el-row :gutter="16" class="stat-row">
      <el-col v-for="s in statCards" :key="s.title" :xs="12" :sm="6">
        <el-card shadow="hover" class="mini-stat">
          <div class="mini-stat-body">
            <el-icon :size="32" :color="s.color">
              <component :is="s.icon" />
            </el-icon>
            <div>
              <div class="num">
                {{ s.value }}
              </div>
              <div class="label">
                {{ s.title }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <div class="glass glass-card">
      <div class="table-toolbar">
        <div class="glass-btn-group">
          <button
            v-if="hasPerm('alarm:create')"
            type="button"
            class="glass-btn glass-btn--danger"
            @click="showReportDialog"
          >
            {{ $t('alarm.reportAlarm') }}
          </button>
          <!-- 苹果液态玻璃分段控件：透镜滑块平滑滑动 + 实时计数徽标 -->
          <GlassSegmented
            v-model="filters.status"
            :options="statusOptions"
            :aria-label="$t('alarm.statusFilterLabel')"
            @change="handleFilterChange"
          />
        </div>
        <button type="button" class="glass-btn glass-btn--default" @click="refreshAll">
          {{ $t('common.refresh') }}
        </button>
      </div>
      <!-- 首屏骨架占位；数据到达后直接替换（带数据刷新时走表格内 loading） -->
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['6%', '18%', '16%', '12%', '11%', '11%', '16%']"
      />
      <el-table v-else v-loading="loading" :data="tableData" border stripe style="width: 100%">
        <el-table-column type="index" label="#" width="60" />
        <el-table-column prop="_time" :label="$t('alarm.occurredAt')" width="170" />
        <el-table-column :label="$t('alarm.location')" min-width="160">
          <template #default="{ row }">
            {{ row._location || formatLocation(row.location) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('alarm.alarmType')" width="120">
          <template #default="{ row }">
            <el-tag :type="row._tagType || row.tagType" size="small">
              {{ row._type || row.type }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('alarm.handler')" width="110">
          <template #default="{ row }">
            {{ row._handler || formatHandler(row.handler) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.status')" width="110">
          <template #default="{ row }">
            <el-tag :type="row._statusType || statusType(row.status)" effect="light">
              {{ row._status || statusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="240" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasAnyPerm(['alarm:dispatch', 'alarm:handle'])"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              :disabled="rowBusy === row._id"
              @click="handle(row)"
            >
              {{ $t('alarm.dispatch') }}
            </button>
            <button
              v-if="hasPerm('alarm:handle')"
              type="button"
              class="glass-btn glass-btn--success glass-btn--link"
              :disabled="rowBusy === row._id"
              @click="resolve(row)"
            >
              {{ $t('alarm.resolve') }}
            </button>
            <button
              type="button"
              class="glass-btn glass-btn--default glass-btn--link"
              @click="detail(row)"
            >
              {{ $t('common.operation') }}
            </button>
          </template>
        </el-table-column>
      </el-table>
      <!--
        P3-45：补分页。原实现不传 page/limit，后端 normalizePagination 默认
        limit=10 —— 也就是说页面**永远只显示最新 10 条报警**，且没有任何翻页
        入口。用户看到列表底部就以为「只有这些报警」，历史报警实际无从访问。
        （报告称「不分页全量拉取」，实测恰好相反：是被静默截断到 10 条。）
      -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="page.total"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="handlePageSizeChange"
        />
      </div>
    </div>

    <!-- 新建报警对话框 -->
    <el-dialog
      v-model="reportDialog.visible"
      :title="$t('alarm.reportAlarm')"
      width="500px"
      @close="resetReportForm"
    >
      <el-form ref="reportFormRef" :model="reportForm" :rules="reportRules" label-width="100px">
        <el-form-item :label="$t('alarm.alarmType')" prop="alarmType">
          <el-select
            v-model="reportForm.alarmType"
            :placeholder="$t('messages.selectRequired')"
            style="width: 100%"
          >
            <el-option :label="$t('dashboard.smokeAlarm')" value="smoke" />
            <el-option :label="$t('dashboard.tempAbnormal')" value="temp_abnormal" />
            <el-option :label="$t('dashboard.manualAlarm')" value="manual_button" />
            <el-option :label="$t('dashboard.phoneReport')" value="phone_report" />
            <el-option :label="$t('dashboard.patrolFind')" value="patrol_find" />
            <el-option :label="$t('common.all')" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('alarm.location')" prop="location">
          <el-input
            v-model="reportForm.location"
            :placeholder="$t('alarm.location')"
            maxlength="100"
          />
        </el-form-item>
        <el-form-item :label="$t('alarm.description')" prop="description">
          <el-input
            v-model="reportForm.description"
            type="textarea"
            :rows="4"
            :placeholder="$t('alarm.description')"
            maxlength="500"
            show-word-limit
          />
        </el-form-item>
        <el-form-item label="Device ID" prop="deviceId">
          <el-input v-model="reportForm.deviceId" placeholder="Optional device ID" maxlength="24" />
        </el-form-item>
      </el-form>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="reportDialog.visible = false"
        >
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--danger"
          :disabled="reportDialog.submitting"
          @click="submitReport"
        >
          {{ $t('alarm.reportAlarm') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed, h } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, WarningFilled, CircleCheckFilled, Tools } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'

import { ElRadioGroup, ElRadio } from 'element-plus/es/components/radio/index.mjs'
import { api } from '@/utils/api'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import GlassSegmented from '@/components/GlassSegmented.vue'

const { hasPerm, hasAnyPerm } = usePermission()
const { t, locale } = useI18n()

const CAUSE_OPTIONS = computed(() => [
  { value: 'fire', label: t('alarm.causeFire') },
  { value: 'false_alarm', label: t('alarm.falseAlarmTag') },
  { value: 'equipment_fault', label: t('alarm.causeEquipmentFault') },
  { value: 'test', label: t('alarm.causeTest') },
  { value: 'unknown', label: t('alarm.causeUnknown') },
])

const loading = ref(false)
// 行级操作锁：派单/完成请求进行中时禁用该行按钮，防止重复提交
const rowBusy = ref(null)
const filters = reactive({ status: '' })
// P3-45：分页状态（此前缺失，导致列表被后端默认 limit=10 静默截断）
const page = reactive({ current: 1, size: 10, total: 0 })
const reportFormRef = ref(null)

// 报警状态分段控件选项（count 绑定实时统计，随 loadStats 联动刷新；
// 误报/取消暂无统计维度，不展示计数徽标）
const statusOptions = computed(() => [
  { label: t('common.all'), value: '', count: undefined },
  { label: t('alarm.pending'), value: 'pending', count: stats.pending },
  { label: t('alarm.processing'), value: 'processing', count: stats.processing },
  { label: t('alarm.resolved'), value: 'resolved', count: stats.resolvedToday },
  { label: t('alarm.statusFalseAlarm'), value: 'false_alarm', count: undefined },
  { label: t('alarm.statusCancelled'), value: 'cancelled', count: undefined },
])

// 统计数据
const stats = reactive({
  pending: 0,
  processing: 0,
  resolvedToday: 0,
  totalMonth: 0,
})

const statCards = computed(() => [
  { title: t('alarm.pending'), value: stats.pending, color: '#e63946', icon: Bell },
  { title: t('alarm.processing'), value: stats.processing, color: '#d97706', icon: Tools },
  {
    title: t('alarm.resolved'),
    value: stats.resolvedToday,
    color: '#16a34a',
    icon: CircleCheckFilled,
  },
  { title: t('alarm.stats'), value: stats.totalMonth, color: '#c1121f', icon: WarningFilled },
])

// 新建报警对话框状态
const reportDialog = reactive({
  visible: false,
  submitting: false,
})

// 新建报警表单
const reportForm = reactive({
  alarmType: '',
  location: '',
  description: '',
  deviceId: '',
})

// 表单验证规则
const reportRules = {
  alarmType: [{ required: true, message: t('messages.selectRequired'), trigger: 'change' }],
  location: [
    { required: true, message: t('alarm.location'), trigger: 'blur' },
    { min: 1, max: 100, message: '1-100 chars', trigger: 'blur' },
  ],
  description: [
    { required: true, message: t('alarm.description'), trigger: 'blur' },
    { min: 1, max: 500, message: '1-500 chars', trigger: 'blur' },
  ],
}

const statusType = (s) =>
  ({
    pending: 'danger',
    processing: 'warning',
    resolved: 'success',
    // 误报用中性灰、取消用警示黄，与主流程三态区分
    false_alarm: 'info',
    cancelled: 'warning',
  })[s] || 'info'
const statusText = (s) =>
  ({
    pending: t('alarm.pending'),
    processing: t('alarm.processing'),
    resolved: t('alarm.resolved'),
    false_alarm: t('alarm.statusFalseAlarm'),
    cancelled: t('alarm.statusCancelled'),
  })[s] || s

// 格式化位置显示
const formatLocation = (location) => {
  if (typeof location === 'object' && location.building) {
    return `${location.building}${location.floor || ''}${location.room ? ' ' + location.room : ''}`
  }
  return location || t('common.noData')
}

const formatHandler = (handler) => {
  if (!handler) return t('common.noData')
  if (typeof handler === 'string') return handler
  if (typeof handler === 'object') {
    return handler.realName || handler.name || handler.username || t('common.noData')
  }
  return t('common.noData')
}

const alarmTypeMap = computed(() => ({
  smoke: t('dashboard.smokeAlarm'),
  temp_abnormal: t('dashboard.tempAbnormal'),
  manual_button: t('dashboard.manualAlarm'),
  phone_report: t('dashboard.phoneReport'),
  patrol_find: t('dashboard.patrolFind'),
  other: t('common.all'),
}))

// 标签颜色映射
const tagTypeMap = {
  smoke: 'danger',
  temp_abnormal: 'warning',
  manual_button: 'danger',
  phone_report: 'warning',
  patrol_find: 'warning',
  other: 'info',
}

const tableData = ref([])

// 加载统计数据
const loadStats = async () => {
  try {
    const res = await api.alarms.getStats()
    const data = res?.data?.data
    if (data) {
      // 从 byStatus 数组中提取数据
      const byStatus = data.byStatus || []
      stats.pending = byStatus.find((s) => s._id === 'pending')?.count || 0
      stats.processing = byStatus.find((s) => s._id === 'processing')?.count || 0
      const resolvedCount = byStatus.find((s) => s._id === 'resolved')?.count || 0

      // 卡片标签与统计口径保持一致（后端未提供"今日/本月"维度时展示累计值）
      stats.resolvedToday = resolvedCount
      // 报警总数（累计口径）
      stats.totalMonth = data.total || 0
    }
  } catch (e) {
    // 统计加载失败，静默处理
  }
}

// 竞态守卫：快速筛选时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

/** 切换每页条数时回到第一页（停在旧页码上可能超出结果集，显示空列表） */
const handlePageSizeChange = () => {
  page.current = 1
  loadData()
}

/** 状态筛选变更后必须回到第一页：留在第 5 页去看只有 2 页的筛选结果只会看到空表 */
const handleFilterChange = () => {
  page.current = 1
  loadData()
}

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const res = await api.alarms.getList({
      page: page.current,
      limit: page.size,
      status: filters.status,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    const list = Array.isArray(payload) ? payload : payload?.list || payload?.items || []

    // 转换数据格式，确保 handler 字段正确显示
    tableData.value = list.map((item) => ({
      ...item,
      _handler: formatHandler(item.handler),
      _location: formatLocation(item.location),
      _type: alarmTypeMap.value[item.alarmType] || item.type || '-',
      _status: statusText(item.status),
      _statusType: statusType(item.status),
      _tagType: tagTypeMap[item.alarmType] || 'info',
      _time: item.occurredAt
        ? new Date(item.occurredAt).toLocaleString(locale.value, { hour12: false })
        : '-',
    }))
    // 后端 ApiResponse.paginated 把总数放在 pagination.total
    page.total = res?.data?.pagination?.total ?? tableData.value.length
  } catch (e) {
    if (!isCurrent()) return
    tableData.value = []
    page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 刷新数据和统计
const refreshAll = async () => {
  await Promise.all([loadData(), loadStats()])
}

// 显示新建报警对话框
const showReportDialog = () => {
  reportDialog.visible = true
}

// 重置表单
const resetReportForm = () => {
  reportForm.alarmType = ''
  reportForm.location = ''
  reportForm.description = ''
  reportForm.deviceId = ''
  if (reportFormRef.value) {
    reportFormRef.value.clearValidate()
  }
}

// 提交报警
const submitReport = async () => {
  if (!reportFormRef.value) return

  await reportFormRef.value.validate(async (valid) => {
    if (!valid) return

    reportDialog.submitting = true
    try {
      // 解析位置信息（支持格式："A栋3楼配电室" / "A 栋 3 楼 配电室"，自动忽略空白）
      const parseLocation = (str) => {
        const s = String(str || '')
          .trim()
          .replace(/\s+/g, '')
        if (!s) return null
        const firstDigit = s.search(/\d/)
        // 无数字：整串视为建筑/区域名
        if (firstDigit === -1) return { building: s, floor: '', room: '' }
        const building = s.slice(0, firstDigit)
        const rest = s.slice(firstDigit)
        // 楼层 = 楼栋后的连续数字（可带 层/楼/F 后缀），其余为房间/位置描述
        const floorMatch = rest.match(/^(\d+)(?:\s*(?:层|楼|F))?(.*)$/)
        if (!building || !floorMatch) {
          return { building: s, floor: '', room: '' }
        }
        return {
          building,
          floor: floorMatch[1] ? `${floorMatch[1]}层` : '',
          room: floorMatch[2] || '',
        }
      }
      const location = parseLocation(reportForm.location)

      const payload = {
        alarmType: reportForm.alarmType,
        level: 'warning', // 默认级别为警告
        description: reportForm.description,
        occurredAt: new Date(), // 报警发生时间
      }

      // 解析后的位置信息（解析失败时整串作为建筑名，避免数据污染）
      payload.location = location || {
        building: reportForm.location,
        floor: '',
        room: '',
      }

      if (reportForm.deviceId) {
        payload.deviceId = reportForm.deviceId
      }

      await api.alarms.report(payload)
      ElMessage.success(t('messages.createSuccess'))
      reportDialog.visible = false
      await refreshAll()
    } catch (e) {
      ElMessage.error(t('messages.createFailed'))
    } finally {
      reportDialog.submitting = false
    }
  })
}

// 处理报警（pending→派单给当前操作人；processing→登记到达现场）
const handle = async (row) => {
  if (row.status !== 'pending' && row.status !== 'processing') return

  rowBusy.value = row._id
  try {
    if (row.status === 'pending') {
      // 派单语义即"指派给自己"，确认后执行
      await ElMessageBox.confirm(t('alarm.dispatchSelfConfirm'), t('messages.confirmTitle'), {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'info',
      })
      await api.alarms.dispatch(row._id, {})
      ElMessage.success(t('alarm.dispatch'))
    } else {
      await api.alarms.arrive(row._id)
      ElMessage.success(t('alarm.arrive'))
    }
    await refreshAll()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') {
      // 错误已在拦截器处理
    }
  } finally {
    rowBusy.value = null
  }
}

// 完成报警
const resolve = async (row) => {
  if (row.status !== 'processing') {
    // P3-45：此前这里提示 t('alarm.dispatch')，即「指派处理」——
    // 一个动作名而非说明，用户看到的是「指派处理」四个字，
    // 完全不知道自己为什么点不动、下一步该做什么。
    // 改为说明真实前置条件（须先派单 + 登记到达现场）。
    ElMessage.warning(t('alarm.resolveRequiresProcessing'))
    return
  }

  rowBusy.value = row._id
  try {
    try {
      await ElMessageBox.confirm(t('alarm.resolveConfirm'), t('messages.confirmTitle'), {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      })

      const { value } = await ElMessageBox.prompt(t('alarm.handleResult'), t('alarm.resolve'), {
        inputType: 'textarea',
        inputPattern: /.+/,
        inputErrorMessage: t('alarm.handleResult'),
        inputValidator: (value) =>
          (value && value.trim().length > 0 && value.length <= 1000) ||
          t('alarm.handleResultRequired'),
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
      })

      // 选择报警原因，避免所有完成场景都被硬编码记录为火灾
      const cause = await new Promise((resolveCause, rejectCause) => {
        const selected = ref('unknown')
        ElMessageBox.confirm(
          () =>
            h('div', { style: 'padding: 8px 4px' }, [
              h(
                'p',
                { style: 'margin: 0 0 12px; font-size: 14px; color: var(--xf-gray-700)' },
                t('alarm.cause')
              ),
              h(
                ElRadioGroup,
                {
                  modelValue: selected.value,
                  'onUpdate:modelValue': (v) => {
                    selected.value = v
                  },
                  style:
                    'display: flex; flex-direction: column; gap: 10px; align-items: flex-start;',
                },
                () =>
                  CAUSE_OPTIONS.value.map((opt) =>
                    h(ElRadio, { key: opt.value, value: opt.value }, () => opt.label)
                  )
              ),
            ]),
          t('alarm.causeTitle'),
          {
            confirmButtonText: t('common.confirm'),
            cancelButtonText: t('common.cancel'),
            showCancelButton: true,
            distinguishCancelAndClose: true,
          }
        )
          .then(() => resolveCause(selected.value))
          .catch(rejectCause)
      })

      await api.alarms.resolve(row._id, {
        handleResult: value,
        cause,
      })

      ElMessage.success(t('alarm.resolved'))
      await refreshAll()
    } catch (e) {
      if (e !== 'cancel') {
        // 错误已在拦截器处理
      }
    }
  } finally {
    rowBusy.value = null
  }
}

const detail = (row) => {
  const details = [
    `${t('alarm.alarmType')}: ${alarmTypeMap.value[row.alarmType] || row.type || '-'}`,
    `${t('alarm.location')}: ${formatLocation(row.location)}`,
    `${t('alarm.handler')}: ${formatHandler(row.handler)}`,
    `${t('common.status')}: ${statusText(row.status)}`,
    `${t('alarm.occurredAt')}: ${row._time || '-'}`,
  ]

  ElMessageBox.alert(details.join('\n'), t('alarm.title'), {
    confirmButtonText: t('common.confirm'),
    customClass: 'alarm-detail-dialog',
  })
}

onMounted(() => {
  loadData()
  loadStats()
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.stat-row {
  margin-bottom: 4px;
}

.mini-stat {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.stat-row :deep(.el-col:nth-child(1)) .mini-stat {
  animation-delay: 0.05s;
}
.stat-row :deep(.el-col:nth-child(2)) .mini-stat {
  animation-delay: 0.1s;
}
.stat-row :deep(.el-col:nth-child(3)) .mini-stat {
  animation-delay: 0.15s;
}
.stat-row :deep(.el-col:nth-child(4)) .mini-stat {
  animation-delay: 0.2s;
}

.mini-stat :deep(.el-card__body) {
  padding: 16px;
}
.mini-stat-body {
  display: flex;
  align-items: center;
  gap: 16px;
}
.mini-stat-body .num {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-xl);
  font-weight: 700;
  letter-spacing: var(--xf-tracking-tight);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
  color: var(--xf-gray-900);
}
.mini-stat-body .label {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
  text-transform: uppercase;
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}
.glass-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.25s;
}

/* 与 DeviceView / InspectionView 的分页容器保持同一布局口径 */
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
}

/* 报警详情对话框样式 */
:deep(.alarm-detail-dialog .el-message-box__content) {
  white-space: pre-line;
  line-height: 1.8;
  font-size: var(--xf-font-size-base);
}

:deep(.alarm-detail-dialog .el-message-box__content p) {
  margin: 8px 0;
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
