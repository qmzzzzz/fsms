<template>
  <div class="page">
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
          <button type="button" class="glass-btn glass-btn--default" @click="loadData">
            {{ $t('common.refresh') }}
          </button>
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
        <el-table-column :label="$t('common.operation')" width="220" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('device:update')"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="handleEdit(row)"
            >
              {{ $t('common.edit') }}
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
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api } from '@/utils/api'
import { localDateStr as sharedLocalDateStr } from '@/utils/datetime'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'

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
    if (!isCurrent()) return
    ElMessage.error(t('messages.loadFailed'))
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
  dialog.form.room = row.location?.room || row.location?.detail || ''
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
      ElMessage.error(t('messages.deleteFailed'))
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
      location: {
        building: dialog.form.building,
        floor: dialog.form.floor,
        room: dialog.form.room,
      },
      installDate: dialog.form.installDate,
      checkCycle: dialog.form.checkCycle,
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
    ElMessage.error(dialog.isEdit ? t('messages.updateFailed') : t('messages.createFailed'))
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
    installDate: '',
    checkCycle: 30,
    remark: '',
  }
  if (formRef.value) {
    formRef.value.clearValidate()
  }
}

// 语言切换时重新加载列表，状态/类型等文案随语言同步刷新
watch(locale, () => {
  loadData()
})

onMounted(loadData)
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
