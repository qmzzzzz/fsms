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
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="submitting"
          @click="changePwd"
        >
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
// 提交锁：changePwd 走的是带 passwordChangeLimiter(5/15min) 的 PUT /auth/password，
// 三个输入框都绑了 enterSubmit→changePwd，无守卫时连点/长按回车会并发多次改密
// → 撞限流返回 429，或在成功提示之上叠加"当前密码不正确"，还白白烧掉改密配额。
const submitting = ref(false)

const changePwd = async () => {
  if (submitting.value) return
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
  submitting.value = true
  try {
    // 口令密文轨（FE-H1）：两个字段各自独立信封（每次随机 ECDH 临时密钥+nonce）。
    // null 仅限 WebCrypto 不可用（设计内降级）；「可用但失败」抛错时阻断提交
    // 并提示重试，不静默明文上行（console.warn 留痕监控密文率）
    const payload = {}
    let encCurrent
    let encNew
    try {
      encCurrent = await encryptPassword(pwdForm.currentPassword, 'PASSWORD_CURRENT')
      encNew = await encryptPassword(pwdForm.newPassword, 'PASSWORD_NEW')
    } catch (e) {
      console.warn('[loginCipher] 口令加密失败，已阻断提交：', e?.message)
      // 公钥指纹不符（PUBLIC_KEY_PIN_MISMATCH）：主动 MITM 或服务端轮换密钥后
      // 前端包未随之重建——与「网络抖动、重试即可」不是一回事，文案须可执行
      ElMessage.error(
        e?.code === 'PUBLIC_KEY_PIN_MISMATCH'
          ? t('login.publicKeyPinMismatch')
          : t('login.encryptionFailed')
      )
      return
    }
    if (encCurrent) payload.encCurrentPassword = encCurrent
    else payload.currentPassword = pwdForm.currentPassword
    if (encNew) payload.encNewPassword = encNew
    else payload.newPassword = pwdForm.newPassword

    await api.auth.changePassword(payload)
    ElMessage.success(t('profile.pwdChanged'))
    pwdForm.currentPassword = ''
    pwdForm.newPassword = ''
    pwdForm.confirmPassword = ''
    // 后端改密成功后已 invalidateUserTokens（该用户所有会话令牌即时失效），必须登出；
    // 给一次延时是为了让用户看到「已修改」提示。定时器 id 留存，供卸载兜底。
    logoutTimer.value = setTimeout(() => {
      logoutTimer.value = null
      authStore.clearAuth()
      router.push('/login')
    }, 1500)
  } catch (e) {
    // 错误已在拦截器处理
  } finally {
    // 成功路径也要解锁：若稍后未及登出（用户在 1.5s 窗口内），至少按钮不永久禁用
    submitting.value = false
  }
}

onUnmounted(() => {
  // 改密成功→后端已 invalidateUserTokens（该用户所有会话令牌即时失效）。若组件在
  // 1.5s 延时登出窗口内被卸载（切页），原实现 clearTimeout 会把这次登出整个吞掉，
  // 把 SPA 留在"看似已登录、token 却全死"的错乱态。这里就地清认证态。
  // 刻意不做 router.push：卸载后主动跳转是既定的防内存泄漏/防导航竞态约束（见测试
  // 「定时器未到期就卸载」），登出后的路由重定向交给导航守卫在用户下一次跳转时完成。
  if (logoutTimer.value) {
    clearTimeout(logoutTimer.value)
    logoutTimer.value = null
    authStore.clearAuth()
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
