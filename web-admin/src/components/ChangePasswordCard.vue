<template>
  <!-- 修改口令（D-2 自 ProfileView 拆出）：
       密文双轨上行与改密后延时登出逻辑内聚在本组件 -->
  <el-card shadow="never">
    <template #header>
      <span class="card-header">{{ $t('profile.changePassword') }}</span>
    </template>
    <el-form :model="pwdForm" label-width="100px" class="profile-form" @submit.prevent>
      <el-form-item :label="$t('auth.currentPassword')">
        <el-input
          id="currentPassword"
          v-model="pwdForm.currentPassword"
          name="currentPassword"
          type="password"
          show-password
          :placeholder="$t('auth.currentPassword')"
          maxlength="128"
          autocomplete="current-password"
          @keydown.enter.prevent="enterSubmit($event, changePwd)"
        />
      </el-form-item>
      <el-form-item :label="$t('auth.newPassword')">
        <el-input
          id="newPassword"
          v-model="pwdForm.newPassword"
          name="newPassword"
          type="password"
          show-password
          :placeholder="$t('validation.passwordMin')"
          maxlength="128"
          autocomplete="new-password"
          @keydown.enter.prevent="enterSubmit($event, changePwd)"
        />
      </el-form-item>
      <el-form-item :label="$t('auth.confirmPassword')">
        <el-input
          id="confirmPassword"
          v-model="pwdForm.confirmPassword"
          name="confirmPassword"
          type="password"
          show-password
          :placeholder="$t('register.confirmPwdPlaceholder')"
          maxlength="128"
          autocomplete="new-password"
          @keydown.enter.prevent="enterSubmit($event, changePwd)"
        />
      </el-form-item>
      <el-form-item>
        <button type="button" class="glass-btn glass-btn--primary" @click="changePwd">
          {{ $t('profile.changePassword') }}
        </button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { reactive, ref, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'
import { api } from '@/utils/api'
import { encryptPassword } from '@/utils/loginCipher'
import { isStrongPassword } from '@/utils/password'
import { enterSubmit } from '@/utils/enterSubmit'

const { t } = useI18n()
const router = useRouter()
const authStore = useAuthStore()

const pwdForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: '',
})

const logoutTimer = ref(null)

const changePwd = async () => {
  if (!pwdForm.currentPassword || !pwdForm.newPassword) {
    ElMessage.warning(t('profile.pwdIncomplete'))
    return
  }
  if (pwdForm.newPassword !== pwdForm.confirmPassword) {
    ElMessage.error(t('profile.pwdMismatch'))
    return
  }
  if (!isStrongPassword(pwdForm.newPassword)) {
    ElMessage.warning(t('profile.pwdTooShort'))
    return
  }
  try {
    // 口令密文轨：两个字段各自独立信封（每次随机 ECDH 临时密钥+nonce）；
    // WebCrypto 不可用（纯 HTTP 内网）或加密失败时降级明文轨（后端双轨兼容）
    const payload = {}
    const encCurrent = await encryptPassword(pwdForm.currentPassword).catch(() => null)
    const encNew = await encryptPassword(pwdForm.newPassword).catch(() => null)
    if (encCurrent) payload.encCurrentPassword = encCurrent
    else payload.currentPassword = pwdForm.currentPassword
    if (encNew) payload.encNewPassword = encNew
    else payload.newPassword = pwdForm.newPassword

    await api.auth.changePassword(payload)
    ElMessage.success(t('profile.pwdChanged'))
    pwdForm.currentPassword = ''
    pwdForm.newPassword = ''
    pwdForm.confirmPassword = ''
    // 保存定时器 ID 以便组件卸载时清理
    logoutTimer.value = setTimeout(() => {
      authStore.clearAuth()
      router.push('/login')
    }, 1500)
  } catch (e) {
    // 错误已在拦截器处理
  }
}

onUnmounted(() => {
  // 清理登出定时器，防止组件卸载后仍执行
  if (logoutTimer.value) {
    clearTimeout(logoutTimer.value)
    logoutTimer.value = null
  }
})
</script>

<style scoped>
/* 父视图的 scoped 样式不穿透子组件内部元素，此处自带同值定义 */
.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.profile-form {
  width: 100%;
  max-width: 520px;
}
</style>
