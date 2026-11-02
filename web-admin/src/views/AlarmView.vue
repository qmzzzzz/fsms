<template>
  <div class="page">
    <div v-if="statsFailed && !statsLoadedOnce" class="stats-failed">
      <span>{{ $t('messages.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--sm" @click="loadStats">
        {{ $t('common.refresh') }}
      </button>
    </div>
    <el-row v-else :gutter="16" class="stat-row">
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
      <!-- P1③：报警列表加载失败必须有持久痕迹。此前失败只清表，界面与「真的没有报警」
           完全一致——值班员会判断为「一切正常」，这比其它页面同型缺陷更危险。 -->
      <el-alert
        v-if="listState.failed.value"
        :title="listState.stale.value ? $t('common.staleData') : $t('common.listLoadFailed')"
        type="warning"
        :closable="false"
        show-icon
        class="load-error"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="loading"
            @click="loadData"
          >
            {{ $t('common.retry') }}
          </button>
        </template>
      </el-alert>
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['6%', '18%', '16%', '12%', '11%', '11%', '16%']"
      />
      <el-table
        v-else-if="listState.showTable.value"
        v-loading="loading"
        :data="tableData"
        border
        stripe
        style="width: 100%"
      >
        <el-table-column type="index" label="#" width="60" />
        <el-table-column prop="_time" :label="$t('alarm.occurredAt')" width="170" />
        <el-table-column :label="$t('alarm.location')" min-width="160">
          <template #default="{ row }">
            {{ formatLocation(row.location) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('alarm.alarmType')" width="120">
          <template #default="{ row }">
            <el-tag :type="row._tagType || row.tagType" size="small">
              {{ alarmTypeText(row) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('alarm.handler')" width="110">
          <template #default="{ row }">
            {{ formatHandler(row.handler) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.status')" width="110">
          <template #default="{ row }">
            <el-tag :type="row._statusType || statusType(row.status)" effect="light">
              {{ statusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <!--
          列宽预算：新增「取消报警」后同一行最多四个操作按钮 + 详情
          （pending 行：指派处理+处理完成+标记误报+取消报警+详情 = 68×4+44 = 316px），
          加单元格左右 padding 24px 需 340px——340px 为当前下限。
          位置列是 min-width 弹性列，会吸收视口富余，整表总宽不受影响。
        -->
        <el-table-column :label="$t('common.operation')" width="340" fixed="right">
          <template #default="{ row }">
            <!--
              handle(row) 按状态走两条不同后端接口：pending→dispatch（需 alarm:dispatch）、
              processing→arrive（需 alarm:handle）。旧门控 hasAnyPerm(['alarm:dispatch','alarm:handle'])
              对两者取或：只有 alarm:handle 的消防员在 pending 行看到「指派处理」→点击发 dispatch→403；
              反之只有 alarm:dispatch 的角色在 processing 行→发 arrive→403。按状态与所需权限一一对应。
            -->
            <button
              v-if="
                (row.status === 'pending' && hasPerm('alarm:dispatch')) ||
                (row.status === 'processing' && hasPerm('alarm:handle'))
              "
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
            <!--
              标记误报：门控与 arrive/resolve 同码（alarm:handle）——误报判定
              属「处理」语义而非「派单」。状态上仅 pending/processing 开放：终态行
              渲染出来只会吃后端 ALARM_STATUS_NOT_ALLOWED；已指派给他人时服务层
              还会按 handler 拒绝（对象级授权），该情况保留入口让用户看到真实反馈。
            -->
            <button
              v-if="
                hasPerm('alarm:handle') && (row.status === 'pending' || row.status === 'processing')
              "
              type="button"
              class="glass-btn glass-btn--warning glass-btn--link"
              :disabled="rowBusy === row._id"
              @click="markAsFalseAlarm(row)"
            >
              {{ $t('alarm.falseAlarm') }}
            </button>
            <button
              v-if="
                hasPerm('alarm:handle') && (row.status === 'pending' || row.status === 'processing')
              "
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              :disabled="rowBusy === row._id"
              @click="cancelAlarm(row)"
            >
              {{ $t('alarm.cancel') }}
            </button>
            <button
              type="button"
              class="glass-btn glass-btn--default glass-btn--link"
              @click="detail(row)"
            >
              {{ $t('common.detail') }}
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
      <div v-if="listState.showTable.value" class="pagination">
        <!-- P1④：total 未知时不得用当前页长度顶替（会显示「共 N 条 / 1 页」，第 2 页永不出现） -->
        <span v-if="!listState.totalKnown.value" class="total-unknown">
          {{ $t('common.totalUnknown') }}
        </span>
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="listState.total.value ?? 0"
          :page-sizes="[10, 20, 50]"
          :layout="
            listState.totalKnown.value
              ? 'total, sizes, prev, pager, next, jumper'
              : 'sizes, prev, pager, next, jumper'
          "
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
            <el-option
              v-for="(label, value) in alarmTypeMap"
              :key="value"
              :label="label"
              :value="value"
            />
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
        <el-form-item :label="$t('alarm.deviceId')" prop="deviceId">
          <el-input
            v-model="reportForm.deviceId"
            :placeholder="$t('alarm.deviceIdPlaceholder')"
            maxlength="24"
          />
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
import { formatTime } from '@/utils/datetime'
import { Bell, WarningFilled, CircleCheckFilled, Tools } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'

import { ElRadioGroup, ElRadio } from 'element-plus/es/components/radio/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { useListLoadState } from '@/composables/useListLoadState'
import { createSubmissionKey } from '@/utils/idempotency'
import { makeAlarmTypeLabels } from '@/utils/labelMaps'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useRealtimeRefresh } from '@/composables/useRealtimeRefresh'
import GlassSegmented from '@/components/GlassSegmented.vue'

const { hasPerm } = usePermission()
const { t } = useI18n()

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

// 首屏统计请求失败时，四张卡不得以 0 面孔出现（0 读作「今日没有待处理报警」）。
// 已有读数后的刷新失败仍保留上一次数字：见 alarmView.test「第二次刷新失败」。
const statsFailed = ref(false)
const statsLoadedOnce = ref(false)

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
  // 本次上报的幂等键（审计一-1）：报火警是现场最容易被连点的动作，
  // 重复上报会在台账里变成两条互不相干的警情。
  submission: createSubmissionKey(),
})

// 新建报警表单
const reportForm = reactive({
  alarmType: '',
  location: '',
  description: '',
  deviceId: '',
})

// 表单验证规则
const reportRules = computed(() => ({
  alarmType: [{ required: true, message: t('messages.selectRequired'), trigger: 'change' }],
  location: [
    { required: true, message: t('alarm.location'), trigger: 'blur' },
    { min: 1, max: 100, message: t('validation.locationLen'), trigger: 'blur' },
  ],
  description: [
    { required: true, message: t('alarm.description'), trigger: 'blur' },
    { min: 1, max: 500, message: t('validation.descriptionLen'), trigger: 'blur' },
  ],
}))

const statusType = (s) =>
  ({
    pending: 'danger',
    processing: 'warning',
    resolved: 'success',
    // 误报用中性灰、取消用警示黄，与主流程三态区分
    false_alarm: 'info',
    cancelled: 'warning',
  })[s] || 'info'
// 报警类型文案：词表未覆盖的新类型回落后端 type 字段，再回落 '-'。
// 列表与详情弹窗共用，避免两处口径漂移。
const alarmTypeText = (row) => alarmTypeMap.value[row.alarmType] || row.type || '-'

const statusText = (s) =>
  ({
    pending: t('alarm.pending'),
    processing: t('alarm.processing'),
    resolved: t('alarm.resolved'),
    false_alarm: t('alarm.statusFalseAlarm'),
    cancelled: t('alarm.statusCancelled'),
  })[s] || s

// 格式化位置显示
// 注意 typeof null === "object"：null 必须先挡掉，否则读 location.building 抛
// TypeError，异常沿 loadData 的 catch 冒泡后整张表被清空（实测 0 行且无提示）。
// 另：没有 building 的对象（{} / {building:null}）不可直出，会渲染成 "{}"
// 或 "{ \"building\": null }"，对值班员是噪音，统一回落到「暂无数据」。
const formatLocation = (location) => {
  if (location && typeof location === 'object') {
    if (location.building) {
      return `${location.building}${location.floor || ''}${location.room ? ' ' + location.room : ''}`
    }
    // 后端 FireAlarm.location.detail（maxlength 200）是「只填详细位置、不填楼栋」的
    // 合法形态（路由对 building 声明 optional）。DeviceView / DeviceReminderDialog 都有
    // 这条回落，报警页此前没有：这类报警一律显示「暂无数据」，值班员丢掉唯一定位信息。
    if (location.detail) return String(location.detail)
    // 对象但没有可读的 building（{} / {building:null}）：直出会渲染成 "{}" 或
    // "{ \"building\": null }"，对值班员是噪音，统一回落到「暂无数据」
    return t('common.noData')
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

// 类型标签取自 utils/labelMaps 的单一词表（DashboardView / ReportView 同源）：
// 本处曾自抄一份并把 other 写成「全部」，于是列表列与上报下拉框显示出一个并不存在的
// 类型，用户按字面选「全部」= 上报一条 alarmType='other' 的工单。
const alarmTypeMap = computed(() => makeAlarmTypeLabels(t))

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
      statsLoadedOnce.value = true
      statsFailed.value = false
    } else {
      statsFailed.value = true
    }
  } catch (e) {
    // 旧口径是「静默处理」：首屏失败后四张卡恒为 0/0/0/0，读作「今日无报警」
    statsFailed.value = true
  }
}

// 竞态守卫：快速筛选时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()
// P1③/P1④ 共用三态契约（与 UserView/DeviceView 同一判据）
const listState = useListLoadState()

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
  listState.begin()
  try {
    const res = await api.alarms.getList({
      page: page.current,
      limit: page.size,
      status: filters.status,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    const list = Array.isArray(payload) ? payload : payload?.list || payload?.items || []

    // 只物化「与语言无关」的派生列（标签色 / 时间串）。类型、状态、位置、处理人
    // 一律留给模板渲染期取词：此处若存 t(...) 的字符串，页内切语言后表头变英文、
    // 行内仍是中文（同一张表两种语言，实测复现）。
    tableData.value = list.map((item) => ({
      ...item,
      _statusType: statusType(item.status),
      _tagType: tagTypeMap[item.alarmType] || 'info',
      // 时间列统一走 utils/datetime.formatTime（O-3 单一事实来源）：本地时区 +
      // 固定 YYYY-MM-DD HH:mm:ss。此前用 toLocaleString(locale)，切界面语言会让
      // 同一列格式突变（月/日顺序与分隔符都变）；非法值也不再有 Invalid Date。
      _time: formatTime(item.occurredAt),
    }))
    // 后端 ApiResponse.paginated 把总数放在 pagination.total
    // P1④：缺失时传 undefined（= 未知），不再用 tableData.length 顶替
    listState.commit({ total: res?.data?.pagination?.total, count: tableData.value.length })
    const clamped = listState.clampPage(page.current, page.size)
    if (clamped !== page.current) {
      page.current = clamped
      return loadData()
    }
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不算失败（原实现缺这条守卫：
    // 离开页面时被打断的请求会被记成「加载失败」，回退到本页就带一条假错误）。
    if (isCanceledError(e)) return listState.abort()
    if (!isCurrent()) return
    // P1③：失败不得画成「没有报警」——值班员会以为一切正常。
    // 交给三态契约：无旧数据进 failed（表格让位给错误块），有旧数据进 stale（保留 + 标注）。
    listState.fail()
    if (!listState.showTable.value) tableData.value = []
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 刷新数据和统计
const refreshAll = async () => {
  await Promise.all([loadData(), loadStats()])
}

// 后端在报警创建/派单/到场/结单等状态迁移后向 'alarm' 房间推送 notification。
// 收到就刷新列表与统计：此前本页没有任何订阅，值班员只能手动刷新，
// 新报警要等下一次操作才出现在台账里。
useRealtimeRefresh({
  rooms: ['alarm'],
  subscriptions: [{ event: 'notification', handler: refreshAll }],
  label: 'AlarmView',
})

// 显示新建报警对话框
const showReportDialog = () => {
  // 每打开一次上报框算一次新的提交意图（上一次的键可能已用它生成过警情）
  reportDialog.submission.renew()
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
  if (reportDialog.submitting) return

  reportDialog.submitting = true
  try {
    let valid = false
    try {
      valid = await reportFormRef.value.validate()
    } catch (_) {
      return
    }
    if (!valid) return

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
        floor: floorMatch[1] ? `${floorMatch[1]}${t('alarm.floorSuffix')}` : '',
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

    await api.alarms.report(payload, { headers: reportDialog.submission.header() })
    ElMessage.success(t('messages.createSuccess'))
    reportDialog.visible = false
    await refreshAll()
  } catch (_) {
    // 错误已在拦截器统一提示（2026-09-26 审计：此处再补泛化 toast 会双提示，
    // 且泛化文案会覆盖拦截器给出的具体错误语义）
  } finally {
    reportDialog.submitting = false
  }
}

// 处理报警（pending→派单给当前操作人；processing→登记到达现场）
const handle = async (row) => {
  if (row.status !== 'pending' && row.status !== 'processing') return
  // 重入守卫必须在首行同步判定：rowBusy 只是渲染态，同一 tick 的第二次点击
  // 到达时按钮尚未 disabled（实测双击弹出 2 个确认框），会重复发请求。
  if (rowBusy.value === row._id) return

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

  // 同 handle：首行同步判定，避免双击弹出两次确认框并重复提交完成请求
  if (rowBusy.value === row._id) return

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
        // 不设 inputPattern：与 inputValidator 并存时先报 pattern 那条，而它只能填
        // 一句静态文案（此前填的是字段名「处理结果/Result」，用户看到提示框里只有
        // 两个字，不知道错在哪）。校验全交给 validator，按「必填/超长」分别说明。
        // validator 返回字符串时 Element Plus 直接显示该串；返回 false 才用这条兜底，
        // 所以兜底也必须是「说明」而不是字段名（字段名当错误提示＝用户看不懂错在哪）。
        inputErrorMessage: t('alarm.handleResultRequired'),
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

// 取消报警（pending/processing → cancelled；可选原因写入处理日志）
const cancelAlarm = async (row) => {
  if (row.status !== 'pending' && row.status !== 'processing') return
  // 同 handle/resolve/markAsFalse：首行同步判定，避免同一 tick 双击弹出两次原因框
  if (rowBusy.value === row._id) return

  rowBusy.value = row._id
  try {
    const { value } = await ElMessageBox.prompt(t('alarm.cancelConfirm'), t('alarm.cancel'), {
      inputType: 'textarea',
      inputPlaceholder: t('alarm.cancelReasonPlaceholder'),
      // 选填：上限与路由 handleReasonValidation 的 1000 同口径
      inputValidator: (v) => !v || v.trim().length <= 1000 || t('alarm.cancelReasonTooLong'),
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
    const reason = (value || '').trim()
    await api.alarms.cancel(row._id, reason ? { reason } : {})
    ElMessage.success(t('alarm.cancelSuccess'))
    await refreshAll()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') {
      // 错误已在拦截器处理
    }
  } finally {
    rowBusy.value = null
  }
}

// 标记误报（pending/processing → false_alarm；可选原因写入 handleResult 与处理日志）
const markAsFalseAlarm = async (row) => {
  if (row.status !== 'pending' && row.status !== 'processing') return
  // 同 handle/resolve：首行同步判定，同一 tick 的第二次点击到达时按钮尚未 disabled
  if (rowBusy.value === row._id) return

  rowBusy.value = row._id
  try {
    // 单弹窗即确认：确认按钮本身就是「执行标记」的意图表达，再叠一层 confirm
    // 只是双份摩擦（原因还是选填的）。文案里写清后果（会记入处理日志）。
    const { value } = await ElMessageBox.prompt(
      t('alarm.falseAlarmConfirm'),
      t('alarm.falseAlarm'),
      {
        inputType: 'textarea',
        inputPlaceholder: t('alarm.falseAlarmReasonPlaceholder'),
        // 选填：空值放行；上限与路由 handleReasonValidation 的 1000 同口径
        inputValidator: (v) => !v || v.trim().length <= 1000 || t('alarm.falseAlarmReasonTooLong'),
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )

    const reason = (value || '').trim()
    // 空原因不塞空串（后端 trim 后只判上限，但空键与缺键语义上不同：缺键走默认说明）
    await api.alarms.markAsFalse(row._id, reason ? { reason } : {})
    ElMessage.success(t('alarm.falseAlarmSuccess'))
    await refreshAll()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') {
      // 错误已在拦截器处理
    }
  } finally {
    rowBusy.value = null
  }
}

const detail = (row) => {
  // 冒号随语言：中文全角「：」、英文「: 」；与 ProfileView / SessionManager 同一词条，
  // 不再手写半角冒号（否则中文弹窗会出现「报警类型: 」的中英混排标点）。
  const colon = t('common.labelColon')
  const details = [
    `${t('alarm.alarmType')}${colon}${alarmTypeText(row)}`,
    `${t('alarm.location')}${colon}${formatLocation(row.location)}`,
    `${t('alarm.handler')}${colon}${formatHandler(row.handler)}`,
    `${t('common.status')}${colon}${statusText(row.status)}`,
    `${t('alarm.occurredAt')}${colon}${row._time || '-'}`,
  ]

  ElMessageBox.alert(details.join('\n'), t('alarm.detailTitle'), {
    confirmButtonText: t('common.confirm'),
    customClass: 'mb-multiline',
  })
}

onMounted(() => {
  loadData()
  loadStats()
})
</script>

<style scoped>
.load-error {
  margin-bottom: var(--xf-spacing-md);
}
/* P1④：total 未知时的显式标注（不拿当前页长度冒充总数） */
.total-unknown {
  margin-right: var(--xf-spacing-sm);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.stat-row {
  margin-bottom: 4px;
}

.stats-failed {
  display: flex;
  gap: var(--xf-spacing-md);
  align-items: center;
  margin-bottom: var(--xf-spacing-md);
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

/* 与 DeviceView / InspectionView 的分页容器保持同一布局口径 */
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
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
