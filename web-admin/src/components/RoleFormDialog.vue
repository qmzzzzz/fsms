<template>
  <el-dialog
    :model-value="visible"
    :title="isEdit ? $t('role.editRole') : $t('role.addRole')"
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
          :disabled="builtinLock"
        />
        <!-- 名称被锁的原因必须可见：一个灰掉的输入框不加说明等于「界面坏了」。
             锁的口径与后端 guardBuiltInNameOrLevel（BUILTIN_ROLE_NAME_LEVEL_LOCKED）一致 -->
        <div v-if="builtinLock" class="form-hint">{{ $t('role.builtinNameLocked') }}</div>
      </el-form-item>
      <el-form-item :label="$t('role.roleCode')" prop="code">
        <el-input
          id="roleCode"
          v-model="form.code"
          name="code"
          :placeholder="$t('role.codePlaceholder')"
          maxlength="50"
          :disabled="isEdit"
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
        v-if="isEdit ? hasPerm('role:update') : hasPerm('role:create')"
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': submitting }"
        :disabled="submitting"
        @click="submit"
      >
        {{ isEdit ? $t('common.save') : $t('common.add') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 角色表单对话框（自 RoleView 拆出），新增与编辑共用：
 *  - 新增：提交 POST /roles，成功后 emit('created', newRole)
 *  - 编辑（传入 role）：预填并 PUT /roles/:id，成功后 emit('updated', updatedRole)
 * 列表刷新、选中态维护归父组件。
 */
import { computed, ref, reactive, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'
import { usePermission } from '@/composables/usePermission'

const props = defineProps({
  visible: { type: Boolean, default: false },
  /** 传入即为编辑模式：预填表单并提交 PUT /roles/:id；null = 新增模式 */
  role: { type: Object, default: null },
})

const emit = defineEmits(['update:visible', 'created', 'updated'])

const { t } = useI18n()
const { hasPerm } = usePermission()
const formRef = ref(null)
const submitting = ref(false)

const isEdit = computed(() => !!props.role)
// 内置角色的名称锁定与后端 guardBuiltInNameOrLevel 同口径；
// 内置角色按 code 寻址（播种/迁移/授权链），改名等于换了一个它
const builtinLock = computed(() => isEdit.value && !!props.role?.isBuiltIn)

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

const rules = computed(() => ({
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
}))

const resetForm = () => {
  form.name = ''
  form.code = ''
  form.description = ''
  formRef.value?.clearValidate()
}

// 打开时按模式初始化：编辑模式用 role 回填，新增模式清空。
// immediate 覆盖「挂载即 visible=true」的宿主（测试基座与深链路直达）；
// 关闭路径由 @close 的 resetForm 兜底，两条路径都落在确定状态上。
watch(
  () => props.visible,
  (v) => {
    if (!v) return
    if (props.role) {
      form.name = props.role.name || ''
      form.code = props.role.code || ''
      form.description = props.role.description || ''
      formRef.value?.clearValidate()
    } else {
      resetForm()
    }
  },
  { immediate: true }
)

const submit = async () => {
  if (!formRef.value) return
  // 重入防护必须同步置位：el-form 的 validate(callback) 是异步的，按钮的
  // :disabled 要等下一帧才生效——同一 tick 的第二次点击、或长按回车的自动
  // 重复会穿透，重复调用 POST /roles（探针实测：修复前两次点击发出 2 个请求，
  // 用户会先看到一次「创建成功」再连吃错误提示）。编辑路径同理适用于 PUT。
  if (submitting.value) return
  submitting.value = true
  try {
    await formRef.value.validate(async (valid) => {
      if (!valid) return
      try {
        if (isEdit.value) {
          const target = props.role
          // 内置角色禁发 name：后端对「内置角色 + name!==undefined」直接 400
          // （BUILTIN_ROLE_NAME_LEVEL_LOCKED），只把 description 送出去；
          // level/status 不在本表单职责内，一律不发。
          const payload = target.isBuiltIn
            ? { description: form.description }
            : { name: form.name, description: form.description }
          const res = await api.roles.update(target._id, payload)
          ElMessage.success(t('messages.updateSuccess'))
          emit('update:visible', false)
          resetForm()
          const updatedRole = res?.data?.data
          if (updatedRole) emit('updated', updatedRole)
        } else {
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
        }
      } catch (_) {
        // 错误已在拦截器处理
      }
    })
  } finally {
    // 覆盖校验未通过（callback 未被调用）与校验链抛错两条路径，确保解锁
    submitting.value = false
  }
}
</script>

<style scoped>
/* 锁定原因说明文字（内置角色名称不可改） */
.form-hint {
  width: 100%;
  margin-top: 4px;
  font-size: var(--xf-font-size-xs);
  line-height: 1.5;
  color: var(--xf-text-secondary);
}
</style>
