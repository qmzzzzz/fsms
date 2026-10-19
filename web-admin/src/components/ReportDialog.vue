<template>
  <el-dialog
    :model-value="visible"
    :title="$t('security.report')"
    width="480px"
    @update:model-value="$emit('update:visible', $event)"
    @close="resetForm"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
      <el-form-item :label="$t('security.reportTargetType')" prop="targetType">
        <el-select v-model="form.targetType" style="width: 100%">
          <el-option :label="$t('security.reportTargetSystem')" value="system" />
          <el-option :label="$t('security.reportTargetUser')" value="user" />
          <el-option :label="$t('security.reportTargetDevice')" value="device" />
          <el-option :label="$t('security.reportTargetAlarm')" value="alarm" />
        </el-select>
      </el-form-item>
      <!-- 记录型才需要 ObjectId：system 型若携带 targetId，后端路由直接 400
           （否则改一下类型就能绕过「目标必须是数据范围内的真实记录」的核验） -->
      <el-form-item
        v-if="form.targetType !== 'system'"
        :label="$t('security.reportTargetId')"
        prop="targetId"
      >
        <el-input
          v-model="form.targetId"
          name="targetId"
          maxlength="24"
          :placeholder="$t('security.reportTargetIdPlaceholder')"
        />
      </el-form-item>
      <el-form-item :label="$t('security.reportReason')" prop="reason">
        <el-input
          v-model="form.reason"
          name="reason"
          maxlength="200"
          :placeholder="$t('security.reportReasonPlaceholder')"
        />
      </el-form-item>
      <el-form-item :label="$t('security.reportDescription')" prop="description">
        <el-input
          v-model="form.description"
          name="description"
          type="textarea"
          :rows="3"
          maxlength="500"
          show-word-limit
          :placeholder="$t('security.reportDescriptionPlaceholder')"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <button
        type="button"
        class="glass-btn glass-btn--default"
        @click="emit('update:visible', false)"
      >
        {{ $t('common.cancel') }}
      </button>
      <!-- 举报刻意不挂权限码：一线人员必须报得了警（securityRoutes.js 的
           PERMISSION-EXEMPT 注释同源），安全由「目标记录存在性+数据范围核验」
           与账号级限流承担，而不是把按钮藏起来 -->
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': submitting }"
        :disabled="submitting"
        @click="submit"
      >
        {{ $t('common.submit') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 举报异常对话框（挂在顶栏，人人可用）
 *
 * 契约对齐 POST /api/security/report（securityRoutes.js: 101-146, 244-250）：
 *  · targetType ∈ user/device/alarm/system；记录型 targetId 必填且为 24 位 ObjectId，
 *    system 型不得携带 targetId（携带即 400）；
 *  · reason 必填 1-200；description 可选 ≤500；
 *  · 目标记录的存在性与数据范围由服务端核验（这里只做格式前置，避免注定 400 的请求出网）。
 * 成功后关闭并清空；失败提示归 api.js 拦截器，组件不重复弹。
 */
import { computed, ref, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'

defineProps({
  visible: { type: Boolean, default: false },
})

const emit = defineEmits(['update:visible'])

const { t } = useI18n()
const formRef = ref(null)
const submitting = ref(false)

const form = reactive({
  targetType: 'system',
  targetId: '',
  reason: '',
  description: '',
})

/** 与 Mongo ObjectId 的十六进制形态一致（后端 isMongoId 同口径） */
const OBJECT_ID_PATTERN = /^[a-fA-F0-9]{24}$/

const rules = computed(() => ({
  targetId: [
    { required: true, message: t('validation.reportTargetIdRequired'), trigger: 'blur' },
    { pattern: OBJECT_ID_PATTERN, message: t('security.reportTargetIdInvalid'), trigger: 'blur' },
  ],
  reason: [
    {
      // required 规则不感知首尾空白（' ' 能过），而后端是先 .trim() 再判 1-200，
      // 纯空格提交只在服务端失败——这里用 trim 后的长度做同一判据
      validator: (_, value, callback) => {
        const text = String(value || '').trim()
        if (!text) return callback(new Error(t('validation.reportReasonRequired')))
        if (text.length > 200) return callback(new Error(t('validation.reportReasonLen')))
        callback()
      },
      trigger: 'blur',
    },
  ],
}))

const resetForm = () => {
  form.targetType = 'system'
  form.targetId = ''
  form.reason = ''
  form.description = ''
  formRef.value?.clearValidate()
}

const submit = async () => {
  if (!formRef.value) return
  // 重入防护必须同步置位（同 RoleFormDialog）：el-form 的 validate(callback)
  // 是异步的，按钮 :disabled 等下一帧才生效，同一 tick 的二次点击会穿透
  if (submitting.value) return
  submitting.value = true
  try {
    await formRef.value.validate(async (valid) => {
      if (!valid) return
      try {
        const payload = {
          targetType: form.targetType,
          reason: form.reason.trim(),
        }
        if (form.targetType !== 'system') payload.targetId = form.targetId.trim()
        const description = form.description.trim()
        if (description) payload.description = description
        await api.security.report(payload)
        ElMessage.success(t('security.reportSuccess'))
        emit('update:visible', false)
        resetForm()
      } catch (_) {
        // 错误已在拦截器处理（含目标不存在/越权等码化文案）
      }
    })
  } finally {
    // 覆盖校验未通过与校验链抛错两条路径，确保解锁
    submitting.value = false
  }
}
</script>
