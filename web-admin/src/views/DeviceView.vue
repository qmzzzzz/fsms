<template>
  <div class="page">
    <!--
      概览条（GET /devices/stats，与列表同数据范围口径）。
      首屏拿不到统计时整条不渲染——5 张 0 卡读作「设备全好」，与「没拿到数据」不可区分；
      已有读数后刷新失败保留上一次已知数字（赋值只在成功分支）。
      「即将到期」卡可点击：进入到期窗口清单（7/30/90 天）。
    -->
    <div v-if="stats" class="device-overview">
      <el-card
        v-for="s in overviewCards"
        :key="s.key"
        shadow="hover"
        class="mini-stat"
        :class="{ 'is-clickable': s.clickable }"
        @click="s.clickable && openExpiring()"
      >
        <div class="mini-stat-body">
          <el-icon :size="28" :color="s.color">
            <component :is="s.icon" />
          </el-icon>
          <div>
            <div class="num">
              {{ s.value }}
            </div>
            <div class="label">
              {{ s.label }}
            </div>
          </div>
        </div>
      </el-card>
    </div>

    <div class="glass filter-card">
      <el-form :inline="true" :model="filters">
        <el-form-item :label="$t('device.deviceName')">
          <el-input
            v-model="filters.name"
            :placeholder="$t('device.deviceName')"
            maxlength="100"
            clearable
            @keyup.enter="handleSearch"
            @clear="handleSearch"
          />
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-select
            v-model="filters.status"
            :placeholder="$t('common.all')"
            clearable
            style="width: 120px"
            @change="handleSearch"
            @clear="handleSearch"
          >
            <el-option :label="$t('deviceStatus.normal')" value="normal" />
            <el-option :label="$t('deviceStatus.warning')" value="warning" />
            <el-option :label="$t('deviceStatus.fault')" value="fault" />
            <el-option :label="$t('deviceStatus.offline')" value="offline" />
            <el-option :label="$t('deviceStatus.maintenance')" value="maintenance" />
            <el-option :label="$t('deviceStatus.scrapped')" value="scrapped" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <button type="button" class="glass-btn glass-btn--primary" @click="handleSearch">
            {{ $t('common.search') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="resetFilters">
            {{ $t('common.reset') }}
          </button>
        </el-form-item>
      </el-form>
    </div>

    <div class="glass glass-card">
      <div class="table-toolbar">
        <div class="toolbar-left glass-btn-group">
          <button
            v-if="hasPerm('device:create')"
            type="button"
            class="glass-btn glass-btn--primary"
            @click="handleAdd"
          >
            <span>+</span> {{ $t('device.addDevice') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="refreshAll">
            {{ $t('common.refresh') }}
          </button>
          <!--
            到期提醒入口：徽标取 summary.total（与弹窗同一次请求的数据源）。
            达到提醒条件时数字必须可见——0 隐藏徽标是有意的（无待办不打扰）。
          -->
          <el-badge
            :value="reminderSummary ? reminderSummary.total : 0"
            :hidden="!reminderSummary || reminderSummary.total === 0"
            class="reminder-badge-wrap"
          >
            <button type="button" class="glass-btn glass-btn--default" @click="openReminders">
              {{ $t('device.openReminders') }}
            </button>
          </el-badge>
        </div>
      </div>
      <!-- 首屏骨架占位；数据到达后直接替换（带数据刷新时走表格内 loading） -->
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['6%', '20%', '14%', '20%', '14%', '10%', '16%']"
      />
      <el-table v-else v-loading="loading" :data="tableData" border stripe style="width: 100%">
        <el-table-column type="index" label="#" width="60" />
        <el-table-column prop="deviceName" :label="$t('device.deviceName')" min-width="140" />
        <el-table-column prop="deviceCode" :label="$t('device.deviceCode')" width="130" />
        <el-table-column :label="$t('device.location')" min-width="160">
          <template #default="{ row }">
            {{ formatLocation(row.location) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('device.deviceType')" width="120">
          <template #default="{ row }">
            {{ deviceTypeLabel(row.deviceType) }}
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="$t('common.status')" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" effect="light">
              {{ statusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <!--
          列宽预算：新增「变更状态/维护」后同一行最多四个按钮
          （编辑44 + 变更状态68 + 维护44 + 删除44 = 200px），
          加单元格左右 padding 24px = 224px，原 220px 会把「删除」挤到第二行 → 240px。
        -->
        <el-table-column :label="$t('common.operation')" width="240" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('device:update')"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="handleEdit(row)"
            >
              {{ $t('common.edit') }}
            </button>
            <!--
              变更状态：可写集与后端 constants/deviceStatus 的 WRITABLE 同口径
              （全集 − scrapped，报废走专门接口）；报废行后端必 400，不渲染。
            -->
            <button
              v-if="hasPerm('device:update') && row.status !== 'scrapped'"
              type="button"
              class="glass-btn glass-btn--warning glass-btn--link"
              :disabled="rowBusy === row._id"
              @click="handleChangeStatus(row)"
            >
              {{ $t('device.changeStatus') }}
            </button>
            <!-- 维护：模型层对已报废设备拒绝一切维护记录，同样不渲染注定失败的入口 -->
            <button
              v-if="hasPerm('device:maintain') && row.status !== 'scrapped'"
              type="button"
              class="glass-btn glass-btn--info glass-btn--link"
              @click="handleMaintain(row)"
            >
              {{ $t('device.maintain') }}
            </button>
            <button
              v-if="hasPerm('device:delete')"
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              @click="handleDelete(row)"
            >
              {{ $t('common.delete') }}
            </button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pagination">
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="page.total"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="handleSearch"
        />
      </div>
    </div>

    <!-- 新增/编辑对话框 -->
    <el-dialog
      v-model="dialog.visible"
      :title="dialog.isEdit ? $t('device.editDevice') : $t('device.addDevice')"
      width="550px"
      @close="resetForm"
    >
      <el-form ref="formRef" :model="dialog.form" :rules="dialogRules" label-width="100px">
        <el-form-item :label="$t('device.deviceCode')" prop="deviceCode">
          <el-input
            v-model="dialog.form.deviceCode"
            :placeholder="$t('messages.autoGenerate')"
            maxlength="50"
            :disabled="dialog.isEdit"
          />
        </el-form-item>
        <el-form-item :label="$t('device.deviceName')" prop="deviceName">
          <el-input
            v-model="dialog.form.deviceName"
            :placeholder="$t('device.deviceName')"
            maxlength="100"
          />
        </el-form-item>
        <el-form-item :label="$t('device.deviceType')" prop="deviceType">
          <el-select
            v-model="dialog.form.deviceType"
            :placeholder="$t('messages.selectRequired')"
            style="width: 100%"
          >
            <el-option :label="$t('dashboard.fireAlarm')" value="fire_alarm" />
            <el-option :label="$t('dashboard.sprinkler')" value="sprinkler" />
            <el-option :label="$t('dashboard.hydrant')" value="hydrant" />
            <el-option :label="$t('dashboard.extinguisher')" value="extinguisher" />
            <el-option :label="$t('dashboard.smokeDetector')" value="smoke_detector" />
            <el-option :label="$t('dashboard.heatDetector')" value="heat_detector" />
            <el-option :label="$t('dashboard.emergencyLight')" value="emergency_light" />
            <el-option :label="$t('dashboard.evacuationSign')" value="evacuation_sign" />
            <el-option :label="$t('device.typeFireDoor')" value="fire_door" />
            <el-option :label="$t('device.typeOther')" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('device.location')" prop="location">
          <el-input
            v-model="dialog.form.building"
            :placeholder="$t('device.building')"
            maxlength="100"
            style="margin-bottom: 8px"
          />
          <el-input
            v-model="dialog.form.floor"
            :placeholder="$t('device.floor')"
            maxlength="100"
            style="margin-bottom: 8px"
          />
          <el-input v-model="dialog.form.room" :placeholder="$t('device.room')" maxlength="100" />
        </el-form-item>
        <el-form-item :label="$t('device.installDate')" prop="installDate">
          <el-date-picker
            v-model="dialog.form.installDate"
            type="date"
            :placeholder="$t('device.installDate')"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="$t('device.checkCycle')" prop="checkCycle">
          <el-input-number v-model="dialog.form.checkCycle" :min="1" :max="365" />
        </el-form-item>
        <el-form-item :label="$t('messages.remark')" prop="remark">
          <el-input
            v-model="dialog.form.remark"
            type="textarea"
            :rows="2"
            maxlength="500"
            show-word-limit
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <button type="button" class="glass-btn glass-btn--default" @click="dialog.visible = false">
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="dialog.submitting"
          @click="submitForm"
        >
          {{ dialog.isEdit ? $t('common.save') : $t('common.add') }}
        </button>
      </template>
    </el-dialog>

    <!-- 即将到期清单（GET /devices/expiring；days ∈ 7/30/90） -->
    <el-dialog v-model="expiring.visible" :title="$t('device.expiringTitle')" width="640px">
      <div class="expiring-toolbar">
        <el-radio-group v-model="expiring.days" @change="loadExpiring">
          <el-radio-button :value="7">
            {{ $t('device.expiringWithin', { days: 7 }) }}
          </el-radio-button>
          <el-radio-button :value="30">
            {{ $t('device.expiringWithin', { days: 30 }) }}
          </el-radio-button>
          <el-radio-button :value="90">
            {{ $t('device.expiringWithin', { days: 90 }) }}
          </el-radio-button>
        </el-radio-group>
      </div>
      <div v-loading="expiring.loading" class="expiring-body">
        <div v-if="expiring.failed && expiring.list.length === 0" class="expiring-failed">
          <span>{{ $t('messages.loadFailed') }}</span>
          <button type="button" class="glass-btn glass-btn--sm" @click="loadExpiring">
            {{ $t('common.refresh') }}
          </button>
        </div>
        <div v-else-if="!expiring.loading && expiring.list.length === 0" class="expiring-empty">
          {{ $t('device.expiringEmpty') }}
        </div>
        <template v-else>
          <ul class="expiring-list">
            <li v-for="(item, i) in expiring.list" :key="item._id || i" class="expiring-item">
              <span class="expiring-code">{{ item.deviceCode }}</span>
              <span class="expiring-name">{{ item.deviceName }}</span>
              <span class="expiring-location">{{ formatLocation(item.location) }}</span>
              <el-tag :type="statusType(item.status)" size="small" effect="light">
                {{ statusText(item.status) }}
              </el-tag>
              <span class="expiring-date">{{ dateOnly(item.expiryDate) }}</span>
            </li>
          </ul>
          <!-- F-174 截断事实：清单只回最先到期的 limit 台，total 是真实命中数 -->
          <div v-if="expiring.hasMore" class="expiring-more">
            {{ $t('device.expiringMoreHint', { total: expiring.total, limit: expiring.limit }) }}
          </div>
        </template>
      </div>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="expiring.visible = false"
        >
          {{ $t('common.close') }}
        </button>
      </template>
    </el-dialog>

    <!-- 到期提醒四档清单（数据归本视图持有，见 script 注释） -->
    <DeviceReminderDialog
      v-model:visible="reminder.visible"
      :data="reminder.data"
      :loading="reminder.loading"
      :failed="reminder.failed"
      @refresh="loadReminders"
    />

    <!-- 维护登记 -->
    <DeviceMaintenanceDialog
      v-model:visible="maintenance.visible"
      :device="maintenance.device"
      @saved="onMaintenanceSaved"
    />
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed, watch, h } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { Box, Calendar, Timer, Tools, WarningFilled } from '@element-plus/icons-vue'
import { ElRadioGroup, ElRadio } from 'element-plus/es/components/radio/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { localDateStr as sharedLocalDateStr } from '@/utils/datetime'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import DeviceReminderDialog from '@/components/DeviceReminderDialog.vue'
import DeviceMaintenanceDialog from '@/components/DeviceMaintenanceDialog.vue'

const { hasPerm } = usePermission()
const { t, locale } = useI18n()

const loading = ref(false)
const filters = reactive({ name: '', status: '' })
const page = reactive({ current: 1, size: 10, total: 0 })
const formRef = ref(null)

const tableData = ref([])

const deviceTypeLabel = (type) =>
  ({
    fire_alarm: t('dashboard.fireAlarm'),
    sprinkler: t('dashboard.sprinkler'),
    hydrant: t('dashboard.hydrant'),
    extinguisher: t('dashboard.extinguisher'),
    smoke_detector: t('dashboard.smokeDetector'),
    heat_detector: t('dashboard.heatDetector'),
    emergency_light: t('dashboard.emergencyLight'),
    evacuation_sign: t('dashboard.evacuationSign'),
    fire_door: t('device.typeFireDoor'),
    other: t('device.typeOther'),
  })[type] || type
const statusType = (s) =>
  ({
    normal: 'success',
    warning: 'warning',
    fault: 'danger',
    offline: 'info',
    maintenance: 'warning',
    scrapped: 'danger',
  })[s] || 'info'
const statusText = (s) =>
  ({
    normal: t('deviceStatus.normal'),
    warning: t('deviceStatus.warning'),
    fault: t('deviceStatus.fault'),
    offline: t('deviceStatus.offline'),
    maintenance: t('deviceStatus.maintenance'),
    scrapped: t('deviceStatus.scrapped'),
  })[s] || s

// 本地时区日期串（YYYY-MM-DD）：toISOString 按 UTC 取日期会导致跨日偏移。
// 评价报告 #20：删除本文件的重复实现，统一走 utils/datetime 单一事实来源
const localDateStr = sharedLocalDateStr
// 编辑回填：已是 YYYY-MM-DD 字符串则原样使用，Date/时间戳按本地时区取日期部分
const toDateOnly = (value) => {
  if (!value) return ''
  if (value instanceof Date) return localDateStr(value)
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : localDateStr(new Date(value))
}
const formatLocation = (loc) => {
  if (!loc) return ''
  return [loc.building, loc.floor, loc.room].filter(Boolean).join(' ') || loc.detail || ''
}
// 日期列（到期日等）：'-' 明确表达「缺值」，留空会被读成「没有这个字段」
const dateOnly = (v) => {
  if (!v) return '-'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '-' : localDateStr(d)
}

const dialog = reactive({
  visible: false,
  isEdit: false,
  submitting: false,
  form: {
    _id: null,
    deviceCode: '',
    deviceName: '',
    deviceType: '',
    building: '',
    floor: '',
    room: '',
    detail: '',
    installDate: '',
    checkCycle: 30,
    remark: '',
  },
})

// 表单校验规则：随语言切换动态重建（消息文案跟随 i18n）
const dialogRules = computed(() => ({
  deviceName: [{ required: true, message: t('device.deviceName'), trigger: 'blur' }],
  deviceType: [{ required: true, message: t('messages.selectRequired'), trigger: 'change' }],
  installDate: [{ required: true, message: t('device.installDate'), trigger: 'change' }],
}))

// 查询条件变更时回到第一页，避免停留在超出结果集的页码上看到空列表
const handleSearch = () => {
  page.current = 1
  loadData()
}

// 竞态守卫：快速搜索/翻页时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const res = await api.devices.getList({
      page: page.current,
      limit: page.size,
      search: filters.name,
      status: filters.status,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    tableData.value = Array.isArray(payload) ? payload : []
    page.total = res?.data?.pagination?.total || tableData.value.length
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // P2-3：加载失败只清态，**提示由 api.js 响应拦截器统一负责**（与 alarmView 同契约）。
    // 此前组件这里再弹一条 messages.loadFailed，同一次失败会弹两条：
    // 拦截器的具体文案（400/403/404/429/5xx/网络错误）+ 组件的泛化文案。
    tableData.value = []
    page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

const resetFilters = () => {
  filters.name = ''
  filters.status = ''
  page.current = 1
  loadData()
}

const handleAdd = () => {
  dialog.isEdit = false
  dialog.form._id = null
  dialog.form.deviceCode = ''
  dialog.form.deviceName = ''
  dialog.form.deviceType = ''
  dialog.form.building = ''
  dialog.form.floor = ''
  dialog.form.room = ''
  dialog.form.detail = ''
  dialog.form.installDate = localDateStr()
  dialog.form.checkCycle = 30
  dialog.form.remark = ''
  dialog.visible = true
}

const handleEdit = (row) => {
  dialog.isEdit = true
  dialog.form._id = row._id
  dialog.form.deviceCode = row.deviceCode
  dialog.form.deviceName = row.deviceName
  dialog.form.deviceType = row.deviceType
  dialog.form.building = row.location?.building || ''
  dialog.form.floor = row.location?.floor || ''
  dialog.form.room = row.location?.room || ''
  // detail 是后端真实字段（FireDevice.location.detail，maxlength 200），随表单原样回填，
  // 不再折叠进 room——否则编辑保存会把详细位置误存到 room 并丢掉 detail（消防设备定位被破坏）。
  dialog.form.detail = row.location?.detail || ''
  // 不再暂存原始 location 作回传底：DeviceService.updateDevice 对 location 按子字段合并，
  // 「没发的键保持原值」，表单不维护的子字段（API/导入写入的 location.coordinates）
  // 无需客户端参与就能存活——该存活语义由 src/tests/services/deviceLocationMerge.test.js 钉住。
  dialog.form.installDate = toDateOnly(row.installDate)
  dialog.form.checkCycle = row.checkCycle || 30
  dialog.form.remark = row.remark || ''
  dialog.visible = true
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('messages.deleteConfirm')}「${row.deviceName}」?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await api.devices.delete(row._id)
    ElMessage.success(t('messages.deleteSuccess'))
    loadData()
  } catch (e) {
    if (e !== 'cancel') {
      // 错误已在拦截器统一提示（2026-09-26 审计：泛化 toast 会双提示并覆盖具体语义）
    }
  }
}

const submitForm = async () => {
  if (!formRef.value) return
  try {
    const valid = await formRef.value.validate()
    if (!valid) return
  } catch (e) {
    return
  }
  dialog.submitting = true
  try {
    const payload = {
      deviceCode: dialog.form.deviceCode || undefined,
      deviceName: dialog.form.deviceName,
      deviceType: dialog.form.deviceType,
      // 只发表单维护的 4 个键：服务端按子字段合并，未提及的键（coordinates 等）保持原值。
      // 清空发空串而不是 undefined —— JSON.stringify 会丢掉值为 undefined 的键，
      // 服务端收到「没提这个键」＝保持原值，"把详细位置删空"就永远保存不下去。
      location: {
        building: dialog.form.building,
        floor: dialog.form.floor,
        room: dialog.form.room,
        detail: dialog.form.detail,
      },
      installDate: dialog.form.installDate,
      // el-input-number 清空时 v-model 变 null；后端 update 的 checkCycle 校验是
      // .optional().isInt({min:1,max:365})，而 .optional() 只对 undefined 放行，
      // null 仍会进 isInt → 400「检查周期应为 1-365 天」。归一成 undefined：
      // 未填即「不改动该字段 / 用默认值」。与上面的 detail 相反是有意为之：
      // 后端没有"空周期"这个合法值（min:1），检查周期因此没有清空这条出路。
      checkCycle: dialog.form.checkCycle ?? undefined,
      remark: dialog.form.remark,
    }
    if (dialog.isEdit) {
      await api.devices.update(dialog.form._id, payload)
      ElMessage.success(t('messages.updateSuccess'))
    } else {
      await api.devices.create(payload)
      ElMessage.success(t('messages.createSuccess'))
    }
    dialog.visible = false
    loadData()
  } catch (e) {
    // 错误已在拦截器统一提示（2026-09-26 审计：泛化 toast 会双提示并覆盖具体语义）
  } finally {
    dialog.submitting = false
  }
}

const resetForm = () => {
  dialog.form = {
    _id: null,
    deviceCode: '',
    deviceName: '',
    deviceType: '',
    building: '',
    floor: '',
    room: '',
    detail: '',
    installDate: '',
    checkCycle: 30,
    remark: '',
  }
  if (formRef.value) {
    formRef.value.clearValidate()
  }
}

// ===== 概览统计 / 到期提醒 / 到期清单 / 状态变更 / 维护登记 =====

const rowBusy = ref(null)

// 概览统计（GET /devices/stats）：只在成功分支赋值——首屏失败整条隐藏（0 卡会被读作
// 「设备全好」），已有读数后的刷新失败保留上一次已知数字（陈旧但真实）
const stats = ref(null)
const loadStats = async () => {
  try {
    const res = await api.devices.getStats()
    const payload = res?.data?.data
    if (payload && typeof payload === 'object') stats.value = payload
  } catch (e) {
    if (isCanceledError(e)) return
    // 失败静默：概览条不是操作入口，失败由「隐藏/保留旧值」表达；
    // 拦截器已对真实请求错误统一提示，这里再弹会双提示
  }
}

const overviewCards = computed(() => {
  if (!stats.value) return []
  const s = stats.value
  return [
    {
      key: 'total',
      label: t('device.totalDevices'),
      value: s.total || 0,
      color: '#475569',
      icon: Box,
    },
    {
      key: 'expired',
      label: t('device.expired'),
      value: s.expired || 0,
      color: '#b91c1c',
      icon: WarningFilled,
    },
    {
      key: 'expiringSoon',
      label: t('device.expiringSoon'),
      value: s.expiringSoon || 0,
      color: '#d97706',
      icon: Timer,
      clickable: true,
    },
    {
      key: 'needMaintenance',
      label: t('device.needMaintenance'),
      value: s.needMaintenance || 0,
      color: '#c1121f',
      icon: Tools,
    },
    {
      key: 'needSchedule',
      label: t('device.needSchedule'),
      value: s.needSchedule || 0,
      color: '#64748b',
      icon: Calendar,
    },
  ]
})

// 到期提醒（GET /devices/reminders）：数据归本视图持有——徽标与弹窗消费同一份响应，
// 避免「徽标一个数、弹窗另一个数」；打开时刷新，弹窗内重试走同一函数
const reminder = reactive({ visible: false, loading: false, failed: false, data: null })
const reminderSummary = computed(() => reminder.data?.summary || null)
const loadReminders = async () => {
  reminder.loading = true
  try {
    const res = await api.devices.getReminders()
    reminder.data = res?.data?.data || null
    reminder.failed = false
  } catch (e) {
    if (isCanceledError(e)) return
    // 有历史数据保留旧值（徽标不闪零）；无数据才进失败态（弹窗内展示重试入口）
    reminder.failed = true
  } finally {
    reminder.loading = false
  }
}
const openReminders = () => {
  reminder.visible = true
  loadReminders()
}

// 即将到期清单（GET /devices/expiring?days=7|30|90）
const expiring = reactive({
  visible: false,
  days: 30,
  loading: false,
  failed: false,
  list: [],
  total: 0,
  hasMore: false,
  limit: null,
})
// 快速切换 7/30/90 时丢弃过期响应，防止旧窗口的数据覆盖新窗口
const expiringGuard = useLatestRequest()
const loadExpiring = async () => {
  const isCurrent = expiringGuard()
  expiring.loading = true
  expiring.failed = false
  try {
    const res = await api.devices.getExpiring({ days: expiring.days })
    if (!isCurrent()) return
    const payload = res?.data?.data
    expiring.list = Array.isArray(payload) ? payload : []
    const paging = res?.data?.pagination || {}
    expiring.total = paging.total ?? expiring.list.length
    expiring.hasMore = !!paging.hasMore
    expiring.limit = paging.limit ?? null
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    expiring.failed = true
    expiring.list = []
    expiring.total = 0
    expiring.hasMore = false
  } finally {
    if (isCurrent()) expiring.loading = false
  }
}
const openExpiring = () => {
  expiring.visible = true
  expiring.days = 30
  loadExpiring()
}

// 与后端 constants/deviceStatus 的 WRITABLE 集同口径（全集 − scrapped，报废走专门接口）
const WRITABLE_STATUSES = ['normal', 'warning', 'fault', 'offline', 'maintenance']

const handleChangeStatus = async (row) => {
  // 重入守卫放在 await 之前（同一 tick 的双击时按钮 disabled 尚未生效）
  if (rowBusy.value === row._id) return
  rowBusy.value = row._id
  try {
    const selected = ref(row.status)
    await ElMessageBox.confirm(
      () =>
        h('div', [
          h(
            'p',
            { style: 'margin: 0 0 12px; font-size: 14px; color: #334155;' },
            t('device.changeStatusConfirm', { name: row.deviceName })
          ),
          // 状态是 5 选 1 枚举：自由输入会产生非法值、到提交后才 400；
          // 单选框让「可选值集合」本身成为约束（同报警页原因选择先例）
          h(
            ElRadioGroup,
            {
              modelValue: selected.value,
              'onUpdate:modelValue': (v) => {
                selected.value = v
              },
              style: 'display:flex; flex-direction:column; gap:10px; align-items:flex-start;',
            },
            () =>
              WRITABLE_STATUSES.map((s) => h(ElRadio, { key: s, value: s }, () => statusText(s)))
          ),
        ]),
      t('device.changeStatus'),
      {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
    await api.devices.updateStatus(row._id, { status: selected.value })
    ElMessage.success(t('device.statusSuccess'))
    refreshAll()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') {
      // 错误已在拦截器统一提示
    }
  } finally {
    rowBusy.value = null
  }
}

// 维护登记：弹窗自己提交，成功后回刷新本页三块（列表/概览/提醒）
const maintenance = reactive({ visible: false, device: null })
const handleMaintain = (row) => {
  maintenance.device = row
  maintenance.visible = true
}
const onMaintenanceSaved = () => {
  refreshAll()
}

// 列表 + 概览 + 提醒徽标一起刷新：三块同页展示，分开刷新会出现段间数字不一致
const refreshAll = () => {
  loadData()
  loadStats()
  loadReminders()
}

// 语言切换时重新加载列表，状态/类型等文案随语言同步刷新
watch(locale, () => {
  refreshAll()
})

onMounted(refreshAll)
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.filter-card :deep(.el-form-item) {
  margin-bottom: 0;
}
.filter-card {
  transition:
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard);
}
.glass-card {
  transition:
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard);
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
}

/* ===== 概览条：5 卡用 grid（el-col 的 24 格不能整除 5），卡内样式对齐报警页 mini-stat ===== */
.device-overview {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: var(--xf-spacing-lg);
}
.mini-stat.is-clickable {
  cursor: pointer;
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
@media (max-width: 1200px) {
  .device-overview {
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  }
}

/* ===== 即将到期弹窗 ===== */
.expiring-toolbar {
  margin-bottom: 12px;
}
.expiring-body {
  min-height: 80px;
}
.expiring-failed {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  color: var(--xf-text-secondary);
}
.expiring-empty {
  padding: 24px 0;
  text-align: center;
  color: var(--xf-text-secondary);
}
.expiring-list {
  margin: 0;
  padding: 0;
  list-style: none;
  max-height: 320px;
  overflow-y: auto;
}
.expiring-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-sm);
}
.expiring-code {
  flex: 0 0 90px;
  color: var(--xf-text-secondary);
}
.expiring-name {
  flex: 1 1 auto;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.expiring-location {
  flex: 1 1 auto;
  color: var(--xf-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.expiring-date {
  flex: 0 0 90px;
  text-align: right;
  color: var(--xf-text-secondary);
}
.expiring-more {
  padding-top: 8px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-warning);
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
