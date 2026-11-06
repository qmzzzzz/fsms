<template>
  <el-dialog
    v-model="visible"
    :title="title || t('reauth.title')"
    width="420px"
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="!submitting"
    @closed="resetForm"
  >
    <p class="reauth-hint">{{ hint || t('reauth.hint') }}</p>
    <el-form @submit.prevent>
      <el-form-item v-if="mode === 'password'">
        <el-input
          v-model="password"
          type="password"
          show-password
          autocomplete="current-password"
          :placeholder="t('auth.currentPassword')"
          @keydown.enter.prevent="submit"
        />
      </el-form-item>
      <!-- 已开启 MFA 的账号不能仅凭密码通过 step-up（服务端 REAUTH_MFA_REQUIRED），
           必须提供第二因子入口。两种凭据走显式切换而非同屏二选一：
           两个框都填时静默取一个会让用户误以为另一个也在参与校验。 -->
      <el-form-item v-else>
        <el-input
          v-model="mfaCode"
          maxlength="6"
          inputmode="numeric"
          autocomplete="one-time-code"
          :placeholder="t('user.revealMfaPlaceholder')"
          @keydown.enter.prevent="submit"
        />
      </el-form-item>
      <button
        type="button"
        class="glass-btn glass-btn--link reauth-mode-toggle"
        :disabled="submitting"
        @click="toggleMode"
      >
        {{ mode === 'mfa' ? t('user.revealUsePassword') : t('user.revealUseMfa') }}
      </button>
    </el-form>
    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="visible = false">
        {{ t('common.cancel') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :disabled="submitting || !canSubmit"
        @click="submit"
      >
        {{ t('common.confirm') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { encryptPassword } from '@/utils/loginCipher'

/**
 * 通用二次验证弹层：收集口令 / MFA 码并加密后交给父组件。
 *
 * 父组件负责真正发请求（写操作或换取审计票据），并通过 submitting 控制忙态；
 * 失败时弹层保持打开、输入保留（MFA 码提交后清空，避免原样重送错误码）。
 */
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  submitting: { type: Boolean, default: false },
  title: { type: String, default: '' },
  hint: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue', 'submit'])

const { t } = useI18n()
const mode = ref('password')
const password = ref('')
const mfaCode = ref('')

const visible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const canSubmit = computed(() =>
  mode.value === 'mfa' ? /^\d{6}$/.test(mfaCode.value.trim()) : !!password.value
)

const toggleMode = () => {
  mode.value = mode.value === 'mfa' ? 'password' : 'mfa'
  password.value = ''
  mfaCode.value = ''
}

const resetForm = () => {
  mode.value = 'password'
  password.value = ''
  mfaCode.value = ''
}

const submit = async () => {
  if (props.submitting || !canSubmit.value) return
  if (mode.value === 'mfa') {
    const code = mfaCode.value.trim()
    mfaCode.value = ''
    emit('submit', { mfaCode: code })
    return
  }
  let encrypted
  try {
    // 与服务端 requireReAuthentication 的解密用途绑定（PASSWORD_CURRENT）。
    // 加密失败必须阻断，不得静默降级为明文上行。
    encrypted = await encryptPassword(password.value, 'PASSWORD_CURRENT')
  } catch (e) {
    ElMessage.error(
      e?.code === 'PUBLIC_KEY_PIN_MISMATCH'
        ? t('login.publicKeyPinMismatch')
        : e?.code === 'INSECURE_CONTEXT'
          ? t('login.insecureContext')
          : t('login.encryptionFailed')
    )
    return
  }
  // G2 统一口径：dev 非安全上下文返回 null 时阻断提交（明文回退轨已删）
  if (!encrypted) {
    ElMessage.error(t('login.insecureContext'))
    return
  }
  emit('submit', { encCurrentPassword: encrypted })
}
</script>

<style scoped>
.reauth-hint {
  margin: 0 0 16px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.reauth-mode-toggle {
  margin-top: 4px;
}
</style>
