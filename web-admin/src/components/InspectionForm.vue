<template>
  <el-dialog
    v-model="visible"
    :title="title"
    width="800px"
    :before-close="handleClose"
    destroy-on-close
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="120px" label-position="right">
      <!-- 基本信息 -->
      <el-card :header="$t('inspection.basicInfo')" class="mb-4">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item :label="$t('inspection.inspectionTitle')" prop="title">
              <el-input
                v-model="form.title"
                :placeholder="$t('inspection.titlePlaceholder')"
                maxlength="200"
                show-word-limit
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('inspection.inspectionType')" prop="inspectionType">
              <el-select v-model="form.inspectionType" style="width: 100%">
                <el-option :label="$t('inspection.typeDaily')" value="daily" />
                <el-option :label="$t('inspection.typeWeekly')" value="weekly" />
                <el-option :label="$t('inspection.typeMonthly')" value="monthly" />
                <el-option :label="$t('inspection.typeQuarterly')" value="quarterly" />
                <el-option :label="$t('inspection.typeAnnual')" value="annual" />
                <el-option :label="$t('inspection.typeSpecial')" value="special" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
      </el-card>

      <!-- 巡检范围 -->
      <el-card :header="$t('inspection.scopeLabel')" class="mb-4">
        <el-form-item :label="$t('inspection.selectDevices')" prop="devices">
          <el-select
            v-model="form.devices"
            multiple
            filterable
            remote
            reserve-keyword
            :placeholder="$t('inspection.deviceSearchPlaceholder')"
            style="width: 100%"
            :remote-method="searchDevices"
            :loading="deviceLoading"
          >
            <el-option
              v-for="item in deviceOptions"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="$t('inspection.locationScope')">
          <el-row :gutter="16">
            <el-col :span="8">
              <el-input
                v-model="form.building"
                :placeholder="$t('inspection.buildingLabel')"
                maxlength="100"
              />
            </el-col>
            <el-col :span="8">
              <el-input
                v-model="form.floor"
                :placeholder="$t('inspection.floorLabel')"
                maxlength="100"
              />
            </el-col>
            <el-col :span="8">
              <el-input
                v-model="form.area"
                :placeholder="$t('inspection.areaLabel')"
                maxlength="100"
              />
            </el-col>
          </el-row>
        </el-form-item>
      </el-card>

      <!-- 检查项目 -->
      <el-card :header="$t('inspection.checkItems')" class="mb-4">
        <div class="check-items-container">
          <div v-for="(item, index) in form.checkItems" :key="item.__uid" class="check-item">
            <el-row :gutter="16" align="middle">
              <el-col :span="8">
                <el-input
                  v-model="item.name"
                  :placeholder="$t('inspection.checkItemNameLabel')"
                  maxlength="100"
                />
              </el-col>
              <el-col :span="10">
                <el-input
                  v-model="item.standard"
                  :placeholder="$t('inspection.standardLabel')"
                  maxlength="200"
                />
              </el-col>
              <el-col :span="4">
                <el-switch
                  v-model="item.required"
                  :active-text="$t('inspection.checkRequired')"
                  :inactive-text="$t('inspection.checkOptional')"
                  size="small"
                />
              </el-col>
              <el-col :span="2">
                <button
                  type="button"
                  class="glass-btn glass-btn--danger glass-btn--icon"
                  :title="$t('common.delete')"
                  @click="removeCheckItem(index)"
                >
                  ×
                </button>
              </el-col>
            </el-row>
          </div>
        </div>
        <div class="mt-2">
          <button
            type="button"
            class="glass-btn glass-btn--primary glass-btn--sm"
            @click="addCheckItem"
          >
            <span>+</span>{{ $t('inspection.addCheckItem') }}
          </button>
        </div>
      </el-card>

      <!-- 人员安排 -->
      <el-card :header="$t('inspection.staffing')" class="mb-4">
        <el-form-item :label="$t('inspection.ownerLabel')">
          <el-select
            v-model="form.assignedTo"
            multiple
            filterable
            remote
            reserve-keyword
            :placeholder="$t('inspection.ownerSearchPlaceholder')"
            style="width: 100%"
            :remote-method="searchUsers"
            :loading="userLoading"
          >
            <el-option
              v-for="item in userOptions"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>
      </el-card>

      <!-- 时间计划 -->
      <el-card :header="$t('inspection.scheduleLabel')" class="mb-4">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item :label="$t('inspection.planStartTime')" prop="planStartTime">
              <el-date-picker
                v-model="form.planStartTime"
                type="datetime"
                :placeholder="$t('inspection.startTimePlaceholder')"
                style="width: 100%"
                format="YYYY-MM-DD HH:mm:ss"
                value-format="YYYY-MM-DD HH:mm:ss"
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('inspection.planEndTime')" prop="planEndTime">
              <el-date-picker
                v-model="form.planEndTime"
                type="datetime"
                :placeholder="$t('inspection.endTimePlaceholder')"
                style="width: 100%"
                format="YYYY-MM-DD HH:mm:ss"
                value-format="YYYY-MM-DD HH:mm:ss"
              />
            </el-form-item>
          </el-col>
        </el-row>
        <div class="el-form-item__help">
          {{ $t('inspection.scheduleHint') }}
        </div>
      </el-card>

      <!-- 备注 -->
      <el-form-item :label="$t('inspection.remarkLabel')">
        <el-input
          v-model="form.remark"
          type="textarea"
          :rows="3"
          :placeholder="$t('inspection.remarkPlaceholder')"
          maxlength="500"
          show-word-limit
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="handleClose">
        {{ $t('common.cancel') }}
      </button>
      <button
        v-if="!disabled"
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': loading || submitting }"
        :disabled="loading || submitting"
        @click="handleSubmit"
      >
        {{ isEdit ? $t('common.save') : $t('common.add') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'
import { toLocalWallClock } from '@/utils/datetime'
import { useLatestRequest } from '@/composables/useLatestRequest'

const { t } = useI18n()

const props = defineProps({
  modelValue: {
    type: Boolean,
    default: false,
  },
  editData: {
    type: Object,
    default: null,
  },
  // 只读模式（查看详情）：隐藏底部保存按钮，禁止提交
  disabled: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['update:modelValue', 'success'])

const visible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const title = computed(() =>
  props.editData ? t('inspection.editPlanTitle') : t('inspection.createPlanTitle')
)
const isEdit = computed(() => !!props.editData)

const loading = ref(false)
// 提交重入锁：与 loading 分开，同步置位（loading 要等异步校验通过才置位，
// 连点时来不及拦住后面的点击——实测同一 tick 三次点击发出 3 个 PUT）
const submitting = ref(false)
const deviceLoading = ref(false)
const userLoading = ref(false)
const deviceOptions = ref([])
const userOptions = ref([])

const formRef = ref()

// 行级自增标识：v-for key 用稳定 uid，避免 splice 删除时 index key 引发的状态错位
let uidSeq = 0
const defaultCheckItems = () => [
  {
    __uid: ++uidSeq,
    name: t('inspection.sampleEquipmentCheck'),
    standard: t('inspection.sampleEquipmentPass'),
    required: true,
  },
  {
    __uid: ++uidSeq,
    name: t('inspection.samplePassageCheck'),
    standard: t('inspection.samplePassagePass'),
    required: true,
  },
]

const form = reactive({
  title: '',
  inspectionType: 'daily',
  devices: [],
  building: '',
  floor: '',
  area: '',
  checkItems: defaultCheckItems(),
  assignedTo: [],
  planStartTime: '',
  planEndTime: '',
  remark: '',
})

const rules = computed(() => ({
  title: [
    { required: true, message: t('inspection.titlePlaceholder'), trigger: 'blur' },
    { min: 2, max: 200, message: t('inspection.titleLengthMsg'), trigger: 'blur' },
  ],
  inspectionType: [{ required: true, message: t('inspection.typeRequiredMsg'), trigger: 'change' }],
  devices: [{ required: true, message: t('inspection.devicesRequiredMsg'), trigger: 'change' }],
  planStartTime: [
    { required: true, message: t('inspection.startTimeRequiredMsg'), trigger: 'change' },
  ],
  planEndTime: [
    { required: true, message: t('inspection.endTimeRequiredMsg'), trigger: 'change' },
    { validator: validateEndTime, trigger: 'change' },
  ],
  checkItems: [{ required: true, message: t('inspection.checkItemsRequiredMsg'), trigger: 'blur' }],
}))

// 手工解析 'YYYY-MM-DD HH:mm:ss' 为本地时间：Safari 对该格式 new Date 会返回 Invalid Date
function parseLocalDateTime(value) {
  const m = String(value || '').match(
    /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?/
  )
  if (!m) return new Date(value)
  return new Date(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0))
}

// 验证结束时间晚于开始时间
function validateEndTime(rule, value, callback) {
  if (
    value &&
    form.planStartTime &&
    parseLocalDateTime(value) <= parseLocalDateTime(form.planStartTime)
  ) {
    callback(new Error(t('inspection.endAfterStartMsg')))
  } else {
    callback()
  }
}

// 远程搜索竞态门票：远程搜索是"每个字符发一次请求"的形态，慢响应后到会把
// 上一次的搜索结果盖回来（换关键词/切记录时用户看到的是错的那批选项）
const deviceGuard = useLatestRequest()
const userGuard = useLatestRequest()

// 搜索设备
const searchDevices = async (query) => {
  if (!query) {
    deviceOptions.value = []
    return
  }

  const isCurrent = deviceGuard()
  deviceLoading.value = true
  try {
    const res = await api.devices.getList({ search: query, limit: 20 })
    if (!isCurrent()) return
    deviceOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.deviceCode} - ${item.deviceName} (${item.deviceType})`,
    }))
  } catch (error) {
    if (!isCurrent()) return
    // 失败同样清空：留着上一次的选项，用户会误选到与本次关键词无关的设备
    deviceOptions.value = []
  } finally {
    if (isCurrent()) deviceLoading.value = false
  }
}

// 搜索用户
const searchUsers = async (query) => {
  if (!query) {
    userOptions.value = []
    return
  }

  const isCurrent = userGuard()
  userLoading.value = true
  try {
    const res = await api.users.getList({ search: query, limit: 20 })
    if (!isCurrent()) return
    userOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.realName || item.username} (${item.username})`,
    }))
  } catch (error) {
    if (!isCurrent()) return
    userOptions.value = []
  } finally {
    if (isCurrent()) userLoading.value = false
  }
}

// 添加检查项目
const addCheckItem = () => {
  form.checkItems.push({ __uid: ++uidSeq, name: '', standard: '', required: true })
}

// 删除检查项目
const removeCheckItem = (index) => {
  if (form.checkItems.length > 1) {
    form.checkItems.splice(index, 1)
  }
}

// 初始化表单
const initForm = () => {
  if (props.editData) {
    Object.assign(form, {
      title: props.editData.title,
      inspectionType: props.editData.inspectionType,
      devices: props.editData.devices?.map((d) => d._id || d) || [],
      assignedTo: props.editData.assignedTo?.map((u) => u._id || u) || [],
      // 后端下发 ISO（UTC）；picker 的 value-format 是本地格式串，直接塞会按字面小时
      // 显示（东八区差 8 小时），保存时再转回 ISO 就把计划时间整体平移（实测复现）
      planStartTime: toLocalWallClock(props.editData.planStartTime),
      planEndTime: toLocalWallClock(props.editData.planEndTime),
      remark: props.editData.remark || '',
    })

    // 远程搜索候选项不随记录复用：deviceOptions/userOptions 是上一次搜索的
    // 产物，不清空的话切记录后下拉里还是上一条记录的搜索结果（id 对不上当前
    // 表单，选中即提交错误的对象）
    deviceOptions.value = []
    userOptions.value = []

    // 位置回填：无位置数据时清空，避免残留上一次编辑的脏数据
    const location = props.editData.locations?.[0]
    form.building = location?.building || ''
    form.floor = location?.floor || ''
    form.area = location?.area || ''

    // 检查项深拷贝：避免 v-model 直接修改父组件表格行对象（并补齐行级 uid）
    form.checkItems = props.editData.checkItems
      ? props.editData.checkItems.map((item) => ({ ...item, __uid: ++uidSeq }))
      : [{ __uid: ++uidSeq, name: '', standard: '', required: true }]
  } else {
    // 重置表单
    Object.assign(form, {
      title: '',
      inspectionType: 'daily',
      devices: [],
      building: '',
      floor: '',
      area: '',
      assignedTo: [],
      planStartTime: '',
      planEndTime: '',
      remark: '',
      checkItems: defaultCheckItems(),
    })
    deviceOptions.value = []
    userOptions.value = []
  }
}

// 提交表单
const handleSubmit = async () => {
  if (!formRef.value) return

  // 检查项逐行手动校验：定位到第几项缺名称/缺标准，阻止提交
  // （同步循环，且在拿重入锁之前——早退不能把锁留下）
  for (let i = 0; i < form.checkItems.length; i++) {
    const item = form.checkItems[i]
    if (!item.name || !String(item.name).trim()) {
      ElMessage.warning(t('inspection.checkItemNameRequired', { index: i + 1 }))
      return
    }
    if (!item.standard || !String(item.standard).trim()) {
      ElMessage.warning(t('inspection.checkItemStandardRequired', { index: i + 1 }))
      return
    }
  }

  // 重入防护：必须同步置位。submit 按钮的 :disabled="loading" 要等异步校验
  // 通过后才生效，连点时来不及拦住后面的点击（实测同一 tick 三次点击发出 3 个 PUT）
  if (submitting.value) return
  submitting.value = true

  try {
    await formRef.value.validate(async (valid) => {
      if (!valid) return
      loading.value = true
      try {
        // 构建提交数据（时间串转 ISO：value-format 的本地时间串不含时区，
        // 直接提交会被后端按 UTC 解析产生时区偏移）
        const submitData = {
          title: form.title,
          inspectionType: form.inspectionType,
          devices: form.devices,
          locations: [],
          checkItems: form.checkItems,
          assignedTo: form.assignedTo,
          planStartTime: form.planStartTime
            ? parseLocalDateTime(form.planStartTime).toISOString()
            : '',
          planEndTime: form.planEndTime ? parseLocalDateTime(form.planEndTime).toISOString() : '',
          remark: form.remark,
        }

        // 添加位置信息
        if (form.building || form.floor || form.area) {
          submitData.locations = [
            {
              building: form.building,
              floor: form.floor,
              area: form.area,
            },
          ]
        }

        if (isEdit.value) {
          await api.inspections.update(props.editData._id, submitData)
          ElMessage.success(t('inspection.planUpdateSuccessMsg'))
        } else {
          await api.inspections.create(submitData)
          ElMessage.success(t('inspection.planCreateSuccessMsg'))
        }

        visible.value = false
        emit('success')
      } catch (error) {
        ElMessage.error(t('common.submitFailedRetry'))
      } finally {
        loading.value = false
      }
    })
  } finally {
    // 校验不通过 / 请求失败 / 成功，都要解锁：否则按钮永久卡死或被后续点击绕过
    submitting.value = false
  }
}

// 关闭对话框
const handleClose = () => {
  visible.value = false
  formRef.value?.resetFields()
  initForm()
}

// 监听编辑数据变化
const editData = computed(() => props.editData)
watch(
  editData,
  () => {
    initForm()
  },
  { immediate: true }
)

// 监听对话框显示状态
watch(visible, (val) => {
  if (val) {
    initForm()
  }
})
</script>

<style scoped>
.mb-4 {
  margin-bottom: 16px;
}

.mt-2 {
  margin-top: 8px;
}

.check-items-container {
  max-height: 400px;
  overflow-y: auto;
}

.check-item {
  margin-bottom: 16px;
  padding: 16px;
  border: 1px solid var(--xf-border-color);
  border-radius: var(--xf-radius-sm);
  background-color: var(--xf-gray-50);
}

.check-item:last-child {
  margin-bottom: 0;
}

.el-form-item__help {
  color: var(--xf-gray-400);
  font-size: 12px;
  line-height: 1.2;
}
</style>
