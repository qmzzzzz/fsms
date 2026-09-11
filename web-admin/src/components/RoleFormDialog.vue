<template>
  <el-dialog
    :model-value="visible"
    :title="$t('role.addRole')"
    width="450px"
    @update:model-value="$emit('update:visible', $event)"
    @close="resetForm"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="80px">
      <el-form-item :label="$t('role.roleName')" prop="name">
        <el-input
          id="roleName"
          v-model="form.name"
          name="name"
          :placeholder="$t('role.roleName')"
          maxlength="50"
        />
      </el-form-item>
      <el-form-item :label="$t('role.roleCode')" prop="code">
        <el-input
          id="roleCode"
          v-model="form.code"
          name="code"
          :placeholder="$t('role.codePlaceholder')"
          maxlength="50"
          @input="onCodeInput"
        />
      </el-form-item>
      <el-form-item :label="$t('role.description')" prop="description">
        <el-input
          id="roleDescription"
          v-model="form.description"
          name="description"
          type="textarea"
          :rows="3"
          maxlength="200"
          show-word-limit
          :placeholder="$t('role.description')"
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
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': submitting }"
        :disabled="submitting"
        @click="submit"
      >
        {{ $t('common.add') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 新增角色对话框（自 RoleView 拆出）
 * 提交成功后 emit('created', newRole)，列表刷新与选中新角色由父组件处理。
 */
import { ref, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'

defineProps({
  visible: { type: Boolean, default: false },
})

const emit = defineEmits(['update:visible', 'created'])

const { t } = useI18n()
const formRef = ref(null)
const submitting = ref(false)

const form = reactive({
  name: '',
  code: '',
  description: '',
})

/**
 * 角色编码校验正则（P3-44）
 *
 * 与后端 roleRoutes.js 的 `matches(/^[A-Z_]+$/)` 严格一致 —— 前端不能更严，
 * 否则合法输入被前端拦下、用户无从得知规则；也不能更松，否则填完才吃 400。
 *
 * 注意后端 Role 模型对 code 设了 `uppercase: true`（写入时自动大写），
 * 但路由校验发生在模型之前，所以小写输入仍会被 400 拒绝。因此这里配套
 * onCodeInput 做即时大写转换：用户输入 `admin_role` 直接变成 `ADMIN_ROLE`，
 * 既符合校验又免去「为什么不能输小写」的困惑。
 */
const ROLE_CODE_PATTERN = /^[A-Z_]+$/

/**
 * 角色编码输入即时归一：转大写并剔除非法字符
 * 与后端 Role 模型的 uppercase:true 同向，避免用户因大小写被 400 拒绝
 * @param {string} val 输入值
 * @returns {void}
 */
const onCodeInput = (val) => {
  form.code = String(val || '')
    .toUpperCase()
    .replace(/[^A-Z_]/g, '')
}

const rules = {
  name: [
    // P3-44：原先误用 validation.username* 文案——角色名称被提示成
    // 「请输入用户名」「用户名长度应为 3-30 个字符」，而这里的实际约束是 1-50。
    // 文案与约束都不对，用户按提示改也过不了校验。
    { required: true, message: t('validation.roleNameRequired'), trigger: 'blur' },
    { min: 1, max: 50, message: t('validation.roleNameLen'), trigger: 'blur' },
  ],
  code: [
    { required: true, message: t('validation.roleCodeRequired'), trigger: 'blur' },
    { min: 1, max: 50, message: t('validation.roleCodeLen'), trigger: 'blur' },
    { pattern: ROLE_CODE_PATTERN, message: t('validation.roleCodePattern'), trigger: 'blur' },
  ],
}

const resetForm = () => {
  form.name = ''
  form.code = ''
  form.description = ''
  formRef.value?.clearValidate()
}

const submit = async () => {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (!valid) return
    submitting.value = true
    try {
      const res = await api.roles.create({
        name: form.name,
        code: form.code,
        description: form.description,
      })
      ElMessage.success(t('messages.createSuccess'))
      emit('update:visible', false)
      resetForm()
      const newRole = res?.data?.data
      if (newRole) emit('created', newRole)
    } catch (_) {
      // 错误已在拦截器处理
    } finally {
      submitting.value = false
    }
  })
}
</script>
