<template>
  <el-dialog
    v-model="visible"
    :title="$t('inspectionResult.submitTitle')"
    width="600px"
    :before-close="handleClose"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
      <el-form-item :label="$t('inspection.result')" prop="result">
        <el-radio-group v-model="form.result">
          <el-radio value="normal">
            {{ $t('inspection.normal') }}
          </el-radio>
          <el-radio value="abnormal">
            {{ $t('inspection.abnormal') }}
          </el-radio>
          <el-radio value="partial">
            {{ $t('inspection.partial') }}
          </el-radio>
        </el-radio-group>
      </el-form-item>

      <el-form-item
        v-if="form.result !== 'normal'"
        :label="$t('inspection.issuesFound')"
        prop="findings"
      >
        <div v-for="(finding, index) in form.findings" :key="finding.__uid" class="finding-item">
          <el-card shadow="never" class="mb-2">
            <div class="finding-header">
              <span class="title">{{ $t('inspectionResult.issueNo', { n: index + 1 }) }}</span>
              <button
                type="button"
                class="glass-btn glass-btn--danger glass-btn--icon"
                :title="$t('common.delete')"
                @click="removeFinding(index)"
              >
                ×
              </button>
            </div>
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item
                  :label="$t('inspection.selectDevices')"
                  :prop="'findings.' + index + '.deviceId'"
                  :rules="{
                    required: true,
                    message: $t('inspectionResult.deviceRequiredMsg'),
                    trigger: 'change',
                  }"
                >
                  <el-select
                    v-model="finding.deviceId"
                    :placeholder="$t('inspectionResult.issueDeviceLabel')"
                    style="width: 100%"
                    @change="(val) => selectDevice(val, index)"
                  >
                    <el-option
                      v-for="item in deviceOptions"
                      :key="item.value"
                      :label="item.label"
                      :value="item.value"
                    />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item
                  :label="$t('inspectionResult.issueDescLabel')"
                  :prop="'findings.' + index + '.issue'"
                  :rules="{
                    required: true,
                    message: $t('inspectionResult.issueDescPlaceholder'),
                    trigger: 'blur',
                  }"
                >
                  <el-input
                    v-model="finding.issue"
                    type="textarea"
                    :rows="2"
                    :placeholder="$t('inspectionResult.issueDescPlaceholder')"
                    maxlength="500"
                    show-word-limit
                  />
                </el-form-item>
              </el-col>
            </el-row>
            <el-row :gutter="16" class="mt-2">
              <el-col :span="8">
                <el-form-item
                  :label="$t('inspectionResult.severityLabel')"
                  :prop="'findings.' + index + '.severity'"
                  :rules="{
                    required: true,
                    message: $t('inspectionResult.severityRequiredMsg'),
                    trigger: 'change',
                  }"
                >
                  <el-select v-model="finding.severity" style="width: 100%">
                    <el-option :label="$t('common.levelLow')" value="low" />
                    <el-option :label="$t('common.levelMedium')" value="medium" />
                    <el-option :label="$t('common.levelHigh')" value="high" />
                    <el-option :label="$t('common.urgent')" value="critical" />
                  </el-select>
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item
                  :label="$t('inspectionResult.suggestionLabel')"
                  :prop="'findings.' + index + '.suggestion'"
                  :rules="{
                    required: true,
                    message: $t('inspectionResult.suggestionPlaceholder'),
                    trigger: 'blur',
                  }"
                >
                  <el-input
                    v-model="finding.suggestion"
                    :placeholder="$t('inspectionResult.suggestionPlaceholder')"
                    maxlength="500"
                  />
                </el-form-item>
              </el-col>
              <el-col :span="8">
                <el-form-item
                  :label="$t('inspectionResult.photosLabel')"
                  :prop="'findings.' + index + '.photo'"
                  :rules="photoRule"
                >
                  <!--
                    P3-45：此处原为 el-upload + auto-upload=false 的组合，是彻底空转的：
                    没有任何上传请求发出，on-change 只生成 blob: 本地预览，
                    而提交时又用 `!photo.startsWith('blob:')` 把它过滤掉 ——
                    用户选完图、看到缩略图、点提交，照片静默消失且无任何提示。
                    这比「没有照片功能」更糟：用户以为已留证，实际记录里没有。

                    全仓核查确认后端**不存在**文件上传能力（无 multer、无静态资源
                    目录、无 /upload 路由），而 Inspection.findings.photo 是
                    maxlength 500 的字符串字段，设计意图本就是存「地址」。
                    因此改为地址录入：功能真实可用（配合企业内已有图床/对象存储），
                    且不再欺骗用户。待后端接入上传服务后可换回上传控件。
                  -->
                  <el-input
                    v-model="finding.photo"
                    :placeholder="$t('inspection.photoUrlPlaceholder')"
                    maxlength="500"
                    clearable
                  />
                  <div class="photo-hint">
                    {{ $t('inspection.photoUrlHint') }}
                  </div>
                </el-form-item>
              </el-col>
            </el-row>
          </el-card>
        </div>
        <div class="mt-2">
          <button
            type="button"
            class="glass-btn glass-btn--primary glass-btn--sm"
            @click="addFinding"
          >
            <span>+</span>{{ $t('inspectionResult.addIssue') }}
          </button>
        </div>
      </el-form-item>

      <el-form-item :label="$t('inspectionResult.locationLabel')">
        <el-input
          v-model="form.location"
          :placeholder="$t('inspectionResult.locationPlaceholder')"
          maxlength="100"
        />
      </el-form-item>

      <el-form-item :label="$t('inspection.remarkLabel')">
        <el-input
          v-model="form.remark"
          type="textarea"
          :rows="3"
          :placeholder="$t('inspectionResult.remarkPlaceholder')"
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
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': loading }"
        :disabled="loading"
        @click="handleSubmit"
      >
        {{ $t('inspectionResult.submitBtn') }}
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
  inspectionTitle: {
    type: String,
    default: '',
  },
})

const emit = defineEmits(['update:modelValue', 'success'])

const visible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const loading = ref(false)
const deviceOptions = ref([])

// 行级自增标识：v-for key 用稳定 uid，避免 splice 删除时 index key 引发的状态错位
let uidSeq = 0
const newFinding = () => ({
  __uid: ++uidSeq,
  deviceId: '',
  issue: '',
  severity: 'medium',
  suggestion: '',
  photo: '',
})

/**
 * 照片地址校验规则（P3-45）
 *
 * 与后端 inspectionRoutes 的 `findings.*.photo` 校验对齐（可选、≤500 字符），
 * 并额外要求形如 URL 或站内绝对路径 —— 后端只校验长度，若前端放任任意文本，
 * 库里会积累「手机拍了」这类无法解析的内容，事后追溯等于没有留证。
 * 空值放行：照片本身是可选项。
 */
const photoRule = {
  validator: (rule, value, callback) => {
    const v = String(value ?? '').trim()
    if (!v) return callback()
    if (v.length > 500) return callback(new Error(t('inspection.photoUrlTooLong')))
    // http(s) 绝对地址，或站内绝对路径（拒绝协议相对地址 //host/x，
    // 它会被浏览器按当前协议解析到第三方域）
    const ok = /^https?:\/\/\S+$/i.test(v) || /^\/(?!\/)\S*$/.test(v)
    return ok ? callback() : callback(new Error(t('inspection.photoUrlInvalid')))
  },
  trigger: 'blur',
}

const formRef = ref()
const form = reactive({
  result: 'normal',
  findings: [],
  location: '',
  remark: '',
})

const rules = {
  result: [{ required: true, message: t('inspectionResult.resultRequiredMsg'), trigger: 'change' }],
  findings: [
    {
      validator: (rule, value, callback) => {
        if (form.result === 'normal') {
          callback()
        } else {
          validateFindings(rule, value, callback)
        }
      },
      trigger: 'blur',
    },
  ],
}

// 验证至少有一个问题
function validateFindings(rule, value, callback) {
  if (form.result === 'normal' && value.length === 0) {
    callback()
  } else if (form.result !== 'normal' && value.length === 0) {
    callback(new Error(t('inspectionResult.issueRequiredMsg')))
  } else {
    // 检查每个问题是否完整
    const isValid = value.every((item) => item.deviceId && item.issue)
    if (isValid) {
      callback()
    } else {
      callback(new Error(t('inspectionResult.issueIncompleteMsg')))
    }
  }
}

// 选择设备
const selectDevice = async (deviceId, _index) => {
  if (!deviceId) return

  try {
    const res = await api.devices.getById(deviceId)
    // 设备信息仅用于显示，不在提交数据中使用
    void res
  } catch (error) {
    // 静默处理
  }
}

// 添加问题
const addFinding = () => {
  form.findings.push(newFinding())
}

// 删除问题
const removeFinding = (index) => {
  if (form.findings.length > 1) {
    form.findings.splice(index, 1)
  }
}

// 加载设备列表
const loadDevices = async () => {
  try {
    const res = await api.devices.getList({ limit: 100 })
    deviceOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.deviceCode} - ${item.deviceName} (${item.deviceType})`,
    }))
  } catch (error) {
    // 静默处理
  }
}

// 提交表单
const handleSubmit = async () => {
  if (!formRef.value) return

  // 如果结果不是正常，确保每个问题都有必填字段
  if (form.result !== 'normal') {
    const hasEmptyField = form.findings.some(
      (finding) => !finding.deviceId || !finding.issue || !finding.severity || !finding.suggestion
    )

    if (hasEmptyField) {
      ElMessage.warning(t('inspectionResult.allIssuesIncompleteMsg'))
      return
    }
  }

  await formRef.value.validate(async (valid) => {
    if (valid) {
      loading.value = true
      try {
        // 如果结果正常，清空问题列表
        const submitData = {
          result: form.result,
          location: form.location,
          remark: form.remark,
        }

        if (form.result !== 'normal') {
          // 转换findings数据结构以匹配后端期望的格式
          submitData.findings = form.findings.map((finding) => ({
            deviceId: finding.deviceId, // 前端传递的是ObjectId字符串，后端可以直接处理
            issue: finding.issue,
            severity: finding.severity,
            // P3-45：photo 现为用户录入的地址，原样提交。
            // 此前这里有 `!startsWith('blob:')` 过滤——那是为了兜住上传空转
            // 产生的假地址，改为地址录入后不再需要，且过滤会让合法地址被误删。
            photo: String(finding.photo || '').trim(),
            suggestion: finding.suggestion,
          }))
        }

        await api.inspections.complete(props.inspectionId, submitData)
        ElMessage.success(t('inspectionResult.submitSuccessMsg'))
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
  Object.assign(form, {
    result: 'normal',
    findings: [newFinding()],
    location: '',
    remark: '',
  })
}

// 监听对话框显示
watch(visible, (val) => {
  if (val) {
    loadDevices()
    form.findings = [newFinding()]
  }
})

// 说明：结果切换回 normal 时不再清空 findings（破坏性操作），
// 提交时按 result 过滤——result 为 normal 时 submitData 不携带 findings
</script>

<style scoped>
.mb-2 {
  margin-bottom: 8px;
}

.mt-2 {
  margin-top: 8px;
}

.finding-item {
  margin-bottom: 16px;
}

.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.finding-header .title {
  font-weight: 600;
  color: var(--xf-gray-800);
}

/* P3-45：照片地址输入下方的说明文字 */
.photo-hint {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--xf-gray-500, #64748b);
}

/* 当隐藏问题时，添加最小高度避免表单看起来很空 */
:deep(.el-form) {
  min-height: 200px;
}

/* 当没有问题时显示提示 */
.empty-findings-tip {
  text-align: center;
  color: var(--xf-gray-400);
  padding: 20px;
  font-size: 14px;
}
</style>
