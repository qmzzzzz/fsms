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
                  <div v-if="deviceHint" class="device-hint" :data-kind="deviceState.kind">
                    {{ deviceHint }}
                  </div>
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

// 设备下拉的缺数据状态：partial = 后端还有没下发的设备，failed = 请求本身失败。
// 两种都必须看得见（见 loadDevices 里的说明）。
const deviceState = reactive({ kind: 'ok', loaded: 0, total: 0 })
const deviceHint = computed(() => {
  if (deviceState.kind === 'partial') {
    return t('inspectionResult.deviceListPartial', {
      loaded: deviceState.loaded,
      total: deviceState.total,
    })
  }
  if (deviceState.kind === 'failed') return t('inspectionResult.deviceListFailed')
  return ''
})

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
/**
 * 表单出厂态的唯一来源（初值与复位共用同一个对象）。
 *
 * 之前这里写的是两个字面量：初值 `findings: []`、复位 `findings: [newFinding()]`。
 * 它们对「一条新记录该长什么样」给了两个答案，而答案不一致时没人会发现——
 * 新增字段只补一处，另一处就静默漂移。收成一个工厂后不可能再分叉。
 */
const factoryState = () => ({
  result: 'normal',
  findings: [newFinding()],
  location: '',
  remark: '',
})
const form = reactive(factoryState())

const rules = computed(() => ({
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
}))

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
  deviceState.kind = 'ok'
  deviceState.loaded = 0
  deviceState.total = 0
  try {
    const res = await api.devices.getList({ limit: 100 })
    deviceOptions.value = res.data.data.map((item) => ({
      value: item._id,
      label: `${item.deviceCode} - ${item.deviceName} (${item.deviceType})`,
    }))
    deviceState.loaded = deviceOptions.value.length
    const total = res.data.pagination?.total
    // 后端 normalizePagination 把 limit 封顶在 100，台账超过 100 台时，
    // 第 101 台起在这个下拉里根本不存在 —— 不说出来，现场只会以为「这台设备没录进系统」。
    // 反过来，total 缺位（老响应/别的调用方）时按「未知」处理、不报未列全：
    // undefined / null / NaN 与数字比较恒为 false，所以这里不需要额外的类型守卫。
    if (total > deviceState.loaded) {
      deviceState.kind = 'partial'
      deviceState.total = total
    }
  } catch (error) {
    // 这张表是巡检闭环的最后一步：漏记的隐患不会留下任何痕迹，
    // 所以失败既不能静默，也不能留着上一次的半截选项让人以为已经加载完。
    deviceOptions.value = []
    deviceState.kind = 'failed'
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
  resetForm()
}

/**
 * 复位 = 回到 factoryState 的出厂态。
 *
 * 为什么打开时也要复位（不只是关闭时）：提交成功路径只写 `visible.value = false`，
 * 而 `:before-close` 只对**用户发起**的关闭（X 按钮 / ESC / 点遮罩）生效——程序化关闭
 * 根本不走 handleClose。`InspectionView` 复用同一个组件实例、只换 `:inspection-id`，
 * 于是上一条记录的 result/location/remark 会带着出现在下一条记录的弹窗里，
 * 用户看不见地提交到错误的巡检上。关闭侧的复位继续保留（它同时清 el-form 记着的
 * initialValue），打开侧的复位负责覆盖所有关闭方式。
 */
function resetForm() {
  Object.assign(form, factoryState())
}

// 监听对话框显示
watch(visible, (val) => {
  if (val) {
    loadDevices()
    // 复位排在 loadDevices 之后无所谓：两者写的是不同的响应式键（设备下拉 vs 表单），
    // 且 deviceState 的计数由 loadDevices 自己按实到条数刷新，不会读到上一轮的残值。
    resetForm()
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

/* 设备没列全 / 压根没加载出来：属于「看不见的数据」，
   比 placeholder 更显眼才不算白说一遍 */
.device-hint {
  font-size: var(--xf-font-size-sm);
  line-height: 1.5;
  color: var(--xf-warning);
}

.device-hint[data-kind='failed'] {
  color: var(--xf-danger);
}
</style>
