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
      <el-card :header="$t('基本信息')" class="mb-4">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item :label="$t('巡检标题')" prop="title">
              <el-input
                v-model="form.title"
                :placeholder="$t('请输入巡检标题')"
                maxlength="200"
                show-word-limit
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('巡检类型')" prop="inspectionType">
              <el-select v-model="form.inspectionType" style="width: 100%">
                <el-option :label="$t('日常巡检')" value="daily" />
                <el-option :label="$t('每周巡检')" value="weekly" />
                <el-option :label="$t('每月巡检')" value="monthly" />
                <el-option :label="$t('季度巡检')" value="quarterly" />
                <el-option :label="$t('年度巡检')" value="annual" />
                <el-option :label="$t('专项巡检')" value="special" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
      </el-card>

      <!-- 巡检范围 -->
      <el-card :header="$t('巡检范围')" class="mb-4">
        <el-form-item :label="$t('选择设备')" prop="devices">
          <el-select
            v-model="form.devices"
            multiple
            filterable
            remote
            reserve-keyword
            :placeholder="$t('请搜索并选择设备')"
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

        <el-form-item :label="$t('位置范围')">
          <el-row :gutter="16">
            <el-col :span="8">
              <el-input v-model="form.building" :placeholder="$t('栋号')" maxlength="100" />
            </el-col>
            <el-col :span="8">
              <el-input v-model="form.floor" :placeholder="$t('楼层')" maxlength="100" />
            </el-col>
            <el-col :span="8">
              <el-input v-model="form.area" :placeholder="$t('区域')" maxlength="100" />
            </el-col>
          </el-row>
        </el-form-item>
      </el-card>

      <!-- 检查项目 -->
      <el-card :header="$t('检查项目')" class="mb-4">
        <div class="check-items-container">
          <div v-for="(item, index) in form.checkItems" :key="item.__uid" class="check-item">
            <el-row :gutter="16" align="middle">
              <el-col :span="8">
                <el-input v-model="item.name" :placeholder="$t('检查项目名称')" maxlength="100" />
              </el-col>
              <el-col :span="10">
                <el-input v-model="item.standard" :placeholder="$t('检查标准')" maxlength="200" />
              </el-col>
              <el-col :span="4">
                <el-switch
                  v-model="item.required"
                  :active-text="$t('必检')"
                  :inactive-text="$t('选检')"
                  size="small"
                />
              </el-col>
              <el-col :span="2">
                <button
                  type="button"
                  class="glass-btn glass-btn--danger glass-btn--icon"
                  :title="$t('删除')"
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
            <span>+</span>{{ $t('添加检查项目') }}
          </button>
        </div>
      </el-card>

      <!-- 人员安排 -->
      <el-card :header="$t('人员安排')" class="mb-4">
        <el-form-item :label="$t('负责人')">
          <el-select
            v-model="form.assignedTo"
            multiple
            filterable
            remote
            reserve-keyword
            :placeholder="$t('请搜索并选择负责人')"
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
      <el-card :header="$t('时间计划')" class="mb-4">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item :label="$t('计划开始时间')" prop="planStartTime">
              <el-date-picker
                v-model="form.planStartTime"
                type="datetime"
                :placeholder="$t('选择开始时间')"
                style="width: 100%"
                format="YYYY-MM-DD HH:mm:ss"
                value-format="YYYY-MM-DD HH:mm:ss"
              />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('计划结束时间')" prop="planEndTime">
              <el-date-picker
                v-model="form.planEndTime"
                type="datetime"
                :placeholder="$t('选择结束时间')"
                style="width: 100%"
                format="YYYY-MM-DD HH:mm:ss"
                value-format="YYYY-MM-DD HH:mm:ss"
              />
            </el-form-item>
          </el-col>
        </el-row>
        <div class="el-form-item__help">
          {{ $t('请合理设置巡检时间避免任务过载') }}
        </div>
      </el-card>

      <!-- 备注 -->
      <el-form-item :label="$t('备注')">
        <el-input
          v-model="form.remark"
          type="textarea"
          :rows="3"
          :placeholder="$t('巡检计划相关说明（可选）')"
          maxlength="500"
          show-word-limit
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="handleClose">
        {{ $t('取消') }}
      </button>
      <button
        v-if="!disabled"
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': loading }"
        :disabled="loading"
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

const title = computed(() => (props.editData ? t('编辑巡检计划') : t('新建巡检计划')))
const isEdit = computed(() => !!props.editData)

const loading = ref(false)
const deviceLoading = ref(false)
const userLoading = ref(false)
const deviceOptions = ref([])
const userOptions = ref([])

const formRef = ref()

// 行级自增标识：v-for key 用稳定 uid，避免 splice 删除时 index key 引发的状态错位
let uidSeq = 0
const defaultCheckItems = () => [
  { __uid: ++uidSeq, name: t('消防器材检查'), standard: t('完好率100%'), required: true },
  { __uid: ++uidSeq, name: t('消防通道检查'), standard: t('畅通无阻'), required: true },
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

const rules = {
  title: [
    { required: true, message: t('请输入巡检标题'), trigger: 'blur' },
    { min: 2, max: 200, message: t('标题长度在 2 到 200 个字符'), trigger: 'blur' },
  ],
  inspectionType: [{ required: true, message: t('请选择巡检类型'), trigger: 'change' }],
  devices: [{ required: true, message: t('请至少选择一个设备'), trigger: 'change' }],
  planStartTime: [{ required: true, message: t('请选择计划开始时间'), trigger: 'change' }],
  planEndTime: [
    { required: true, message: t('请选择计划结束时间'), trigger: 'change' },
    { validator: validateEndTime, trigger: 'change' },
  ],
  checkItems: [{ required: true, message: t('至少添加一个检查项目'), trigger: 'blur' }],
}

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
    callback(new Error(t('结束时间必须晚于开始时间')))
  } else {
    callback()
  }
}

// 搜索设备
const searchDevices = async (query) => {
  if (!query) {
    deviceOptions.value = []
    return
  }

  deviceLoading.value = true
  try {
    const res = await api.devices.getList({ search: query, limit: 20 })
    deviceOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.deviceCode} - ${item.deviceName} (${item.deviceType})`,
    }))
  } catch (error) {
  } finally {
    deviceLoading.value = false
  }
}

// 搜索用户
const searchUsers = async (query) => {
  if (!query) {
    userOptions.value = []
    return
  }

  userLoading.value = true
  try {
    const res = await api.users.getList({ search: query, limit: 20 })
    userOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.realName || item.username} (${item.username})`,
    }))
  } catch (error) {
  } finally {
    userLoading.value = false
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
      planStartTime: props.editData.planStartTime,
      planEndTime: props.editData.planEndTime,
      remark: props.editData.remark || '',
    })

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
  }
}

// 提交表单
const handleSubmit = async () => {
  if (!formRef.value) return

  // 检查项逐行手动校验：定位到第几项缺名称/缺标准，阻止提交
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

  await formRef.value.validate(async (valid) => {
    if (valid) {
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
          ElMessage.success(t('巡检计划更新成功'))
        } else {
          await api.inspections.create(submitData)
          ElMessage.success(t('巡检计划创建成功'))
        }

        visible.value = false
        emit('success')
      } catch (error) {
        ElMessage.error(t('提交失败，请重试'))
      } finally {
        loading.value = false
      }
    }
  })
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
