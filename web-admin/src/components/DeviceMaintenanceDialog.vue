<template>
  <!-- 设备维护登记（POST /api/devices/:id/maintenance；需 device:maintain） -->
  <el-dialog
    :model-value="visible"
    :title="$t('device.addMaintenance')"
    width="520px"
    @update:model-value="$emit('update:visible', $event)"
    @close="resetForm"
  >
    <div v-if="device" class="maint-target">{{ device.deviceCode }} · {{ device.deviceName }}</div>
    <el-form ref="formRef" :model="form" :rules="rules" label-width="100px">
      <el-form-item :label="$t('device.maintenanceType')" prop="type">
        <el-select v-model="form.type" style="width: 100%">
          <el-option
            v-for="(label, value) in typeOptions"
            :key="value"
            :label="label"
            :value="value"
          />
        </el-select>
      </el-form-item>
      <el-form-item :label="$t('device.maintenanceContent')" prop="content">
        <el-input
          v-model="form.content"
          type="textarea"
          :rows="4"
          maxlength="500"
          show-word-limit
          :placeholder="$t('device.maintenanceContentPlaceholder')"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <button
        type="button"
        class="glass-btn glass-btn--default"
        @click="$emit('update:visible', false)"
      >
        {{ $t('common.cancel') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :disabled="submitting"
        @click="submit"
      >
        {{ $t('common.confirm') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'

const props = defineProps({
  visible: { type: Boolean, default: false },
  /** 目标设备行（含 _id 与展示字段）；null = 未选择 */
  device: { type: Object, default: null },
})
const emit = defineEmits(['update:visible', 'saved'])

const { t } = useI18n()

const formRef = ref(null)
const submitting = ref(false)
// 默认 routine：日常维护是绝大多数场景，与模型层「routine/inspection 顺延检查周期」
// 的默认语义一致（repair/replacement 属维修行为，不顺延）
const form = reactive({ type: 'routine', content: '' })

const typeOptions = computed(() => ({
  routine: t('device.typeRoutine'),
  repair: t('device.typeRepair'),
  replacement: t('device.typeReplacement'),
  inspection: t('device.typeInspection'),
}))

const rules = computed(() => ({
  content: [
    { required: true, message: t('device.maintenanceContentRequired'), trigger: 'blur' },
    {
      validator: (rule, value, callback) => {
        // trim 后判长，与路由 maintenanceValidation 的 `.trim().isLength({min:1,max:500})` 同口径：
        // 纯空格在 async-validator 的 required 下能过，必须在提交前拦住
        const v = (value || '').trim()
        if (!v || v.length > 500) callback(new Error(t('device.maintenanceContentRequired')))
        else callback()
      },
      trigger: 'blur',
    },
  ],
}))

// 打开时重置为默认值；关闭由 @close 兜底（取消按钮路径）
watch(
  () => props.visible,
  (v) => {
    if (v) {
      form.type = 'routine'
      form.content = ''
      formRef.value?.clearValidate()
    }
  }
)

const resetForm = () => {
  form.type = 'routine'
  form.content = ''
  formRef.value?.clearValidate()
}

const submit = async () => {
  if (!formRef.value || submitting.value) return
  try {
    const valid = await formRef.value.validate()
    if (!valid) return
  } catch (e) {
    return
  }
  submitting.value = true
  try {
    await api.devices.addMaintenance(props.device._id, {
      content: form.content.trim(),
      type: form.type,
    })
    ElMessage.success(t('device.maintenanceSuccess'))
    emit('update:visible', false)
    emit('saved')
  } catch (e) {
    // 错误已在拦截器统一提示（2026-09-26 审计：泛化 toast 会双提示并覆盖具体语义）；
    // 对话框保持打开，用户不必重填
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.maint-target {
  margin-bottom: 12px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}
</style>
