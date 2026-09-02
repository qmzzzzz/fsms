<template>
  <el-dialog
    v-model="visible"
    :title="$t('审核巡检结果')"
    width="500px"
    :before-close="handleClose"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
      <el-alert v-if="inspectionData" type="info" :closable="false" class="mb-4">
        <template #title>
          {{ $t('巡检信息') }}
        </template>
        <div>标题：{{ inspectionData.title }}</div>
        <div>负责人：{{ inspectionAssignedNames }}</div>
        <div>
          巡检时间：{{ inspectionData.actualStartTime }} 至 {{ inspectionData.actualEndTime }}
        </div>
        <div>巡检结果：{{ resultLabel }}</div>
      </el-alert>

      <el-alert v-if="hasFindings" type="warning" :closable="false" class="mb-4">
        <template #title> 发现问题（{{ findingsCount }}个） </template>
        <div v-for="(finding, index) in inspectionData.findings" :key="index" class="mb-2">
          <div class="finding-item">
            <span class="finding-device">{{ finding.deviceCode }} - {{ finding.deviceName }}</span>
            <el-tag :type="severityType(finding.severity)" size="small" class="ml-2">
              {{ severityLabel(finding.severity) }}
            </el-tag>
          </div>
          <div class="finding-issue">
            {{ finding.issue }}
          </div>
        </div>
      </el-alert>

      <el-form-item :label="$t('审核意见')" prop="reviewComment">
        <el-input
          v-model="form.reviewComment"
          type="textarea"
          :rows="4"
          :placeholder="$t('请输入审核意见')"
          maxlength="500"
          show-word-limit
        />
      </el-form-item>

      <el-form-item :label="$t('审核结果')">
        <el-radio-group v-model="form.result">
          <el-radio label="approved">
            {{ $t('通过') }}
          </el-radio>
          <el-radio label="rejected">
            {{ $t('不通过') }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
    </el-form>

    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="handleClose">
        {{ $t('取消') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': loading }"
        :disabled="loading"
        @click="handleSubmit"
      >
        {{ $t('提交审核') }}
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
  inspectionId: {
    type: String,
    required: true,
  },
})

const emit = defineEmits(['update:modelValue', 'success'])

const visible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const loading = ref(false)
const inspectionData = ref(null)

const formRef = ref()
const form = reactive({
  reviewComment: '',
  result: 'approved',
})

const rules = {
  reviewComment: [
    { required: true, message: t('请输入审核意见'), trigger: 'blur' },
    { min: 10, message: t('审核意见至少需要10个字符'), trigger: 'blur' },
  ],
}

// 计算属性
const inspectionAssignedNames = computed(() => {
  if (!inspectionData.value?.assignedTo?.length) return t('未分配')
  return inspectionData.value.assignedTo.map((u) => u.realName || u.username).join(', ')
})

const resultLabel = computed(() => {
  if (!inspectionData.value.result) return t('未提交')
  const map = { normal: t('正常'), abnormal: t('异常'), partial: t('部分异常') }
  return map[inspectionData.value.result] || t('未知')
})

const hasFindings = computed(() => {
  return inspectionData.value?.findings && inspectionData.value.findings.length > 0
})

const findingsCount = computed(() => {
  return inspectionData.value?.findings?.length || 0
})

// 严重程度类型
const severityType = (severity) => {
  const map = { low: 'info', medium: 'warning', high: 'danger', critical: 'danger' }
  return map[severity] || 'info'
}

// 严重程度标签
const severityLabel = (severity) => {
  const map = { low: t('低'), medium: t('中'), high: t('高'), critical: t('紧急') }
  return map[severity] || t('未知')
}

// 加载巡检详情
const loadInspectionDetail = async () => {
  try {
    const res = await api.inspections.getById(props.inspectionId)
    inspectionData.value = res.data.data
    form.reviewComment = ''
  } catch (error) {
    ElMessage.error(t('加载巡检详情失败'))
  }
}

// 提交审核
const handleSubmit = async () => {
  if (!formRef.value) return

  await formRef.value.validate(async (valid) => {
    if (valid) {
      loading.value = true
      try {
        await api.inspections.review(props.inspectionId, {
          reviewComment: form.reviewComment,
          // 审核结论必须随载荷提交，否则后端无法得知通过/不通过
          reviewResult: form.result,
        })
        ElMessage.success(t('审核提交成功'))
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
  inspectionData.value = null
}

// 监听对话框显示
watch(visible, (val) => {
  if (val) {
    loadInspectionDetail()
  }
})
</script>

<style scoped>
.mb-4 {
  margin-bottom: 16px;
}

.mb-2 {
  margin-bottom: 8px;
}

.ml-2 {
  margin-left: 8px;
}

.finding-item {
  display: flex;
  align-items: center;
  margin-bottom: 8px;
}

.finding-device {
  font-weight: 500;
  color: var(--xf-gray-800);
}

.finding-issue {
  color: var(--xf-gray-600);
  font-size: 14px;
  line-height: 1.5;
}
</style>
