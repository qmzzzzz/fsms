<template>
  <el-dialog
    v-model="visible"
    :title="$t('inspectionReview.title')"
    width="500px"
    :before-close="handleClose"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
      <el-alert v-if="inspectionData" type="info" :closable="false" class="mb-4">
        <template #title>
          {{ $t('inspectionReview.infoLabel') }}
        </template>
        <div>{{ $t('inspection.inspectionTitle') }}：{{ inspectionData.title }}</div>
        <div>{{ $t('inspection.ownerLabel') }}：{{ inspectionAssignedNames }}</div>
        <div>
          {{ $t('inspection.actualStartTime') }}：{{ inspectionData.actualStartTime }} 至
          {{ inspectionData.actualEndTime }}
        </div>
        <div>{{ $t('inspection.result') }}：{{ resultLabel }}</div>
      </el-alert>

      <el-alert v-if="hasFindings" type="warning" :closable="false" class="mb-4">
        <template #title> {{ $t('inspection.findingsCount', { count: findingsCount }) }} </template>
        <div v-for="(finding, index) in inspectionData.findings" :key="index" class="mb-2">
          <div class="finding-item">
            <!-- 后端 InspectionService 用 populate('findings.deviceId', select:'deviceCode deviceName')
                 返回嵌套对象；直接读 finding.deviceCode 恒为 undefined（实测渲染成「 - 」） -->
            <span class="finding-device">
              {{ finding.deviceId?.deviceCode || finding.deviceCode }} -
              {{ finding.deviceId?.deviceName || finding.deviceName }}
            </span>
            <el-tag :type="severityType(finding.severity)" size="small" class="ml-2">
              {{ severityLabel(finding.severity) }}
            </el-tag>
          </div>
          <div class="finding-issue">
            {{ finding.issue }}
          </div>
        </div>
      </el-alert>

      <el-form-item :label="$t('inspection.reviewComment')" prop="reviewComment">
        <el-input
          v-model="form.reviewComment"
          type="textarea"
          :rows="4"
          :placeholder="$t('inspection.reviewCommentPlaceholder')"
          maxlength="500"
          show-word-limit
        />
      </el-form-item>

      <el-form-item :label="$t('inspection.reviewResult')" prop="result">
        <el-radio-group v-model="form.result">
          <el-radio value="approved">
            {{ $t('inspection.approved') }}
          </el-radio>
          <el-radio value="rejected">
            {{ $t('inspection.rejected') }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
    </el-form>

    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="handleClose">
        {{ $t('common.cancel') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': loading }"
        :disabled="loading"
        @click="handleSubmit"
      >
        {{ $t('inspection.submitReviewBtn') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'

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
const detailRequest = useLatestRequest()

const formRef = ref()
/** 出厂态的唯一来源：初值与复位共用（与 InspectionCompleteForm 同一写法，避免新增字段时漏一处） */
const factoryState = () => ({
  reviewComment: '',
  result: 'approved',
})
const form = reactive(factoryState())

const rules = computed(() => ({
  reviewComment: [
    { required: true, message: t('inspection.reviewCommentPlaceholder'), trigger: 'blur' },
    { min: 10, message: t('inspection.reviewCommentMinMsg'), trigger: 'blur' },
  ],
}))

// 计算属性
const inspectionAssignedNames = computed(() => {
  if (!inspectionData.value?.assignedTo?.length) return t('inspectionReview.unassigned')
  return inspectionData.value.assignedTo.map((u) => u.realName || u.username).join(', ')
})

const resultLabel = computed(() => {
  if (!inspectionData.value.result) return t('inspectionReview.notSubmitted')
  const map = {
    normal: t('inspection.normal'),
    abnormal: t('inspection.abnormal'),
    partial: t('inspection.partial'),
  }
  return map[inspectionData.value.result] || t('inspectionReview.unknown')
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
  const map = {
    low: t('common.levelLow'),
    medium: t('common.levelMedium'),
    high: t('common.levelHigh'),
    critical: t('common.urgent'),
  }
  return map[severity] || t('inspectionReview.unknown')
}

// 加载巡检详情
const loadInspectionDetail = async () => {
  // 门票式竞态守卫：InspectionView 复用同一个组件实例、只换 inspectionId，而上一条的
  // GET 可能比这一条的更晚返回（慢网/重试）。无守卫时后到的旧响应会把新记录的标题与
  // 隐患整块覆盖成上一条的内容——复核人正对着 A 的隐患给 B 下结论。
  const isCurrent = detailRequest()
  try {
    const res = await api.inspections.getById(props.inspectionId)
    if (!isCurrent()) return
    inspectionData.value = res.data.data
    form.reviewComment = ''
  } catch (error) {
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(error)) return
    ElMessage.error(t('inspectionReview.loadFailedMsg'))
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
        ElMessage.success(t('inspectionReview.submitSuccessMsg'))
        visible.value = false
        emit('success')
      } catch (error) {
        ElMessage.error(t('common.submitFailedRetry'))
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
  resetForm()
}

/**
 * 复位 = 回到 factoryState 的出厂态，并清掉上一条的详情。
 *
 * 为什么打开时也要复位（不只是关闭时）：提交成功路径只写 `visible.value = false`，
 * 而 `:before-close` 只对**用户发起**的关闭（X / ESC / 点遮罩）生效——程序化关闭
 * 根本不走 handleClose。`InspectionView` 复用同一个组件实例、只换 `:inspection-id`，
 * 于是上一条的审核结论会带着出现在下一条弹窗里（默认值 'approved' 形同虚设，
 * 复核人什么都不点就把「不通过」提交到新记录），详情区块也会在 GET 回来之前
 * 一直显示上一条的隐患——GET 失败时更是永久停在那里。
 */
function resetForm() {
  Object.assign(form, factoryState())
  inspectionData.value = null
}

// 监听对话框显示
watch(visible, (val) => {
  if (val) {
    // 先清场再拉数据：loadInspectionDetail 只覆盖 reviewComment，
    // 失败分支更是直接 return，不先清空就会拿上一条的内容给这一条下结论。
    resetForm()
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
