<template>
  <div ref="loginRootRef" class="login">
    <div class="login__grid" />
    <div class="login__panel">
      <section class="login-brand">
        <div class="login-brand__tag">
          {{ $t('login.brandTag') }}
        </div>
        <h1 class="login-brand__title">
          <ScrambleText :text="$t('login.brandTitle')" />
        </h1>
        <p class="login-brand__subtitle">
          {{ $t('login.brandSubtitle') }}
        </p>
        <div class="login-brand__meta">
          <span>{{ $t('login.meta1') }}</span>
          <span>{{ $t('login.meta2') }}</span>
          <span>{{ $t('login.meta3') }}</span>
        </div>
      </section>

      <div class="login-card">
        <div class="login-card__header">
          <div>
            <h2 class="login-card__title">
              {{ $t('login.cardTitle') }}
            </h2>
            <p class="login-card__subtitle">
              {{ $t('login.cardSubtitle') }}
            </p>
          </div>
          <!-- 主题 + 语言偏好控件：与注册页共用 AuthPrefs 组件。
               此前登录页只有语言、注册页却有主题+语言，功能不对称且两处实现
               各自漂移（类名都不同）。抽离后两个认证页由构造保证一致 -->
          <AuthPrefs class="login-card__lang" />
        </div>

        <el-form
          ref="loginFormRef"
          :model="loginForm"
          :rules="rules"
          label-position="top"
          size="large"
          :validate-on-rule-change="false"
          @keyup.enter="onLogin"
        >
          <el-form-item prop="username">
            <el-input
              id="username"
              v-model="loginForm.username"
              name="username"
              :placeholder="t('auth.username')"
              :prefix-icon="User"
              maxlength="128"
              clearable
              autocomplete="username"
              @keyup.enter.stop="focusPassword"
            />
          </el-form-item>
          <el-form-item prop="password">
            <el-input
              id="password"
              ref="passwordRef"
              v-model="loginForm.password"
              name="password"
              type="password"
              :placeholder="t('auth.password')"
              :prefix-icon="Lock"
              maxlength="128"
              show-password
              autocomplete="current-password"
              @keyup.enter.stop="onPasswordEnter"
            />
          </el-form-item>
          <el-form-item v-if="captchaEnabled" prop="captchaText">
            <div class="login-card__captcha">
              <el-input
                id="captcha"
                ref="captchaRef"
                v-model="loginForm.captchaText"
                name="captcha"
                :placeholder="t('auth.captcha')"
                :prefix-icon="Key"
                maxlength="4"
                clearable
                autocomplete="off"
                @keyup.enter.stop="onCaptchaEnter"
              />
              <!-- 键盘可达：验证码图是"点击刷新"的控件，纯鼠标绑定会把键盘用户挡在门外。
                   tabindex + role=button + Enter/Space，与同文件 captcha 输入框的
                   @keyup.enter.stop 保持同一套键盘路径（作者本就意识得到，见上方输入框） -->
              <img
                v-if="captchaImg"
                :src="captchaImg"
                class="login-card__captcha-img"
                :alt="t('auth.captcha')"
                :title="$t('login.captchaRefresh')"
                :aria-label="$t('login.captchaRefresh')"
                role="button"
                tabindex="0"
                @click="loadCaptcha"
                @keydown.enter.prevent="loadCaptcha"
                @keydown.space.prevent="loadCaptcha"
              />
              <div
                v-else
                class="login-card__captcha-img login-card__captcha-placeholder"
                role="button"
                tabindex="0"
                :aria-label="$t('login.captchaRefresh')"
                @click="loadCaptcha"
                @keydown.enter.prevent="loadCaptcha"
                @keydown.space.prevent="loadCaptcha"
              >
                {{ $t('login.captchaLoading') }}
              </div>
            </div>
          </el-form-item>

          <!-- MFA 两期验证（I-06）：密码通过后后端返回 mfaRequired，切换到动态口令输入。
               同一输入框兼容备用恢复码（XXXX-XXXX）：手机丢失时的登录恢复途径 -->
          <el-form-item v-if="mfaRequired" prop="mfaCode">
            <el-input
              id="mfaCode"
              ref="mfaRef"
              v-model="loginForm.mfaCode"
              name="mfaCode"
              :placeholder="t('auth.mfaCodeOrRecovery')"
              :prefix-icon="Key"
              maxlength="9"
              clearable
              autocomplete="one-time-code"
              @keyup.enter.stop="onLogin"
            />
          </el-form-item>

          <div class="login-card__tip">
            {{ $t('login.tip') }}
          </div>

          <el-form-item class="login-card__actions">
            <LiquidGlassButtons
              v-if="!loading"
              :buttons="[{ id: 'login', label: $t('login.loginBtn'), type: 'primary' }]"
              :height="50"
              @press="onLogin"
            />
            <button
              v-else
              type="button"
              class="glass-btn glass-btn--primary is-loading"
              style="width: 100%"
              disabled
            >
              {{ $t('login.loggingIn') }}
            </button>
          </el-form-item>
        </el-form>

        <div class="login-card__footer">
          <span>{{ $t('login.noAccount') }}</span>
          <router-link to="/register">
            {{ $t('login.registerLink') }}
          </router-link>
          <p class="login-card__copyright">
            {{ $t('login.copyright') }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { User, Lock, Key } from '@element-plus/icons-vue'
import { api } from '@/utils/api'
import { haptic } from '@/utils/haptic'
import { encryptPassword } from '@/utils/loginCipher'
import { useAuthStore } from '@/store'
import LiquidGlassButtons from '@/components/LiquidGlassButtons.vue'
import AuthPrefs from '@/components/AuthPrefs.vue'
import ScrambleText from '@/components/ScrambleText.vue'
import { usePointerGradient } from '@/composables/usePointerGradient'

// 偏好控件（主题/语言）已抽为 AuthPrefs 组件，本页不再持有语言状态；
// locale 仍需保留——下方 watch 用它同步标签页标题
const { t, locale } = useI18n()
const router = useRouter()
const authStore = useAuthStore()

const loading = ref(false)
// 鼠标追踪渐变：指针位置写入 .login 的 --posX/--posY，驱动 ::before 光斑跟随
const loginRootRef = ref(null)
usePointerGradient(loginRootRef)
// 提交重入锁：与 loading 分离并**同步**置位。loading 只在校验通过后才置位，
// 连点时后面的点击已进入 await 之前的分支（实测同一 tick 三次点击发出 3 次登录请求）。
const submitting = ref(false)
const loginFormRef = ref(null)
const passwordRef = ref(null)
const captchaRef = ref(null)
const mfaRef = ref(null)
// 用户名框回车：聚焦到密码框，而非触发整表单的 onLogin 提交
const focusPassword = () => passwordRef.value?.focus()

// 密码框回车：开启验证码时聚焦验证码框（延续 username→password 的流式跳转，
// 此前回车直接触发表单提交，验证码为空校验失败、焦点滞留密码框）；
// 未开启验证码时回车直接提交
const onPasswordEnter = () => {
  if (captchaEnabled.value) {
    captchaRef.value?.focus()
  } else {
    onLogin()
  }
}

// 验证码框回车：已进入 MFA 二次验证时聚焦动态口令框，否则提交
const onCaptchaEnter = () => {
  if (mfaRequired.value) {
    mfaRef.value?.focus()
  } else {
    onLogin()
  }
}

const loginForm = reactive({
  username: '',
  password: '',
  captchaText: '',
  mfaCode: '',
})

// MFA 二期（I-06）：密码验证通过且账户已开启两步验证时置真，显示动态口令输入
const mfaRequired = ref(false)

// 图形验证码：captchaId 随登录请求提交，图片以 data URI 内联渲染
// 开关由系统配置控制（默认关闭），仅开启时渲染并校验
const captchaEnabled = ref(false)
const captchaId = ref('')
const captchaImg = ref('')

const loadCaptcha = async () => {
  // 先清空再拉取：getCaptcha 走 apiClient，失败时拦截器已统一提示。后端 captchaService
  // 每次校验都会删除旧记录（一次性消费），若刷新失败却留着**上一个已消费的** captchaId 和
  // 旧图，用户会照旧图反复输入并一直收到"验证码错误"，且 v-if="captchaImg" 会藏掉可点击重试的占位区
  // → 登录卡死无出口。清空后刷新失败 = 回到"点击重试"占位，是有出口的降级态。
  captchaId.value = ''
  captchaImg.value = ''
  try {
    const { data: resp } = await api.auth.getCaptcha()
    if (resp.success && resp.data?.captchaId) {
      captchaId.value = resp.data.captchaId
      captchaImg.value = `data:image/svg+xml;utf8,${encodeURIComponent(resp.data.svg)}`
    }
  } catch (_) {
    // 错误已在 axios 拦截器中统一提示；验证码加载失败时用户可点击占位区重试
  }
}

const loadCaptchaStatus = async () => {
  try {
    const { data: resp } = await api.auth.getCaptchaStatus()
    captchaEnabled.value = !!resp.data?.loginCaptchaEnabled
    if (captchaEnabled.value) {
      loadCaptcha()
    }
  } catch (_) {
    // 状态查询失败按默认关闭处理，登录不受影响
    captchaEnabled.value = false
  }
}

onMounted(() => {
  loadCaptchaStatus()
  // 消费跨标签页会话同步提示：其他标签页登录了新账号/同账号登出时，
  // 原 tab 由 store 写入 authSyncNotice 后整页跳转至此，展示原因后即清除
  try {
    const noticeKey = sessionStorage.getItem('authSyncNotice')
    if (noticeKey) {
      sessionStorage.removeItem('authSyncNotice')
      ElMessage.warning(t(noticeKey))
    }
  } catch (_) {
    /* sessionStorage 不可用时静默 */
  }
})

// 标签页标题响应式跟随语言：locale 变化（含挂载后手动切换、其他入口切换）
// 时重新解析 docTitle。此前只在 onMounted 设一次，下拉切语言后标题滞留旧语言
watch(
  locale,
  () => {
    document.title = t('login.docTitle')
  },
  { immediate: true }
)

// rules 依赖 t() 随语言重建：EP 默认 validate-on-rule-change=true 会把「规则对象变了」
// 当成需要重新校验的信号，导致切换语言时空表单立刻冒出 required 红错（模板已显式关闭）
const rules = computed(() => {
  const base = {
    username: [{ required: true, message: t('validation.usernameRequired'), trigger: 'blur' }],
    password: [
      { required: true, message: t('validation.passwordRequired'), trigger: 'blur' },
      { min: 6, message: t('validation.passwordMin'), trigger: 'blur' },
    ],
  }
  if (captchaEnabled.value) {
    base.captchaText = [
      { required: true, message: t('validation.captchaRequired'), trigger: 'blur' },
      { len: 4, message: t('validation.captchaLen'), trigger: 'blur' },
    ]
  }
  return base
})

const onLogin = async () => {
  // 重入防护必须同步生效：loading 要到校验通过后才置位，连点时拦不住后面的点击
  if (submitting.value) return
  submitting.value = true
  haptic(10)

  try {
    await loginFormRef.value.validate()
  } catch (_) {
    submitting.value = false
    return
  }

  loading.value = true
  try {
    const payload = { username: loginForm.username.trim() }
    // 口令密文轨（FE-H1）：encryptPassword 返回 null 仅限 WebCrypto 不可用
    // （纯 HTTP 内网设计内降级）；「可用但失败」会抛错——阻断提交并提示重试
    // 而非静默明文上行（用户重试成本为零），console.warn 留痕监控密文率
    let enc
    try {
      enc = await encryptPassword(loginForm.password, 'LOGIN')
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
    if (enc) payload.encPassword = enc
    else payload.password = loginForm.password
    // 仅开启验证码时携带校验字段
    if (captchaEnabled.value) {
      payload.captchaId = captchaId.value
      payload.captchaText = loginForm.captchaText.trim()
    }
    // MFA 二期：首次响应要求动态口令时，后续提交携带验证码重试
    // （每次提交重新加密，ts/nonce 全新，天然兼容二次验证流程）
    if (mfaRequired.value) {
      payload.mfaCode = loginForm.mfaCode.trim()
    }

    const { data: resp } = await api.auth.login(payload)

    // MFA 一期响应（I-06）：密码正确但需两步验证，切换输入框后等待用户提交
    if (resp.success && resp.data?.mfaRequired) {
      mfaRequired.value = true
      ElMessage.info(t('auth.mfaRequired'))
      // 验证码一次性消费：进入 MFA 二次提交前清空并换新验证码
      if (captchaEnabled.value) {
        loginForm.captchaText = ''
        loadCaptcha()
      }
      return
    }

    // I-01：令牌由响应 Set-Cookie 写入 httpOnly cookie，此处只校验业务成功与用户信息
    if (resp.success && resp.data?.user) {
      const { token, refreshToken, user } = resp.data
      authStore.setAuth(token, refreshToken, user, user?.permissions || [])
      ElMessage.success(t('login.success'))
      // 跳转前清理敏感字段，避免密码/动态口令残留在内存中
      loginForm.password = ''
      loginForm.mfaCode = ''
      router.push('/dashboard')
    } else {
      ElMessage.error(resp.message || t('login.failed'))
      // 验证码一次性消费：任何失败尝试后都必须换新的
      if (captchaEnabled.value) {
        loginForm.captchaText = ''
        loadCaptcha()
      }
    }
  } catch (error) {
    // 错误已在 axios 拦截器中统一提示
    // 密文被拒的公钥缓存失效已统一收敛到 api.js 拦截器（FE-M1），此处不再重复
    // MFA 码错误时保留二期状态供用户直接重输；验证码一次性消费，失败后换新
    if (captchaEnabled.value) {
      loginForm.captchaText = ''
      loadCaptcha()
    }
    if (mfaRequired.value) {
      loginForm.mfaCode = ''
    }
  } finally {
    loading.value = false
    // 成功/失败/异常都必须解锁，否则登录按钮永久失效
    submitting.value = false
  }
}
</script>

<style scoped>
.login {
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  min-height: 100dvh;
  padding: 40px 24px;
  overflow: hidden;
  /* 鼠标位置变量：composable 写入纯数值 --posX/--posY，此处换算为长度。
     结构照搬参考效果：多层**实色**渐变 + overlay/lighten/darken 混合才有戏剧性，
     颜色由绿色系逐一映射为品牌红 #c1121f 系（primary/strong/light/deep）。
     （此前用 transparent 端点 + 低 alpha 的版本在视觉上等于没有效果，已废弃） */
  --posX: 0;
  --posY: 0;
  --x: calc(var(--posX) * 1px);
  --y: calc(var(--posY) * 1px);
  /* 鼠标追踪混合渐变（亮色主题）：结构照搬参考效果，
     多层实色渐变 + overlay/lighten/darken 混合，颜色为浅玫瑰色系 */
  background-image:
    linear-gradient(115deg, rgb(230 57 70), rgb(255 255 255)),
    radial-gradient(
      90% 100% at calc(50% + var(--x)) calc(0% + var(--y)),
      rgb(255 255 255),
      rgb(253 228 230)
    ),
    radial-gradient(
      100% 100% at calc(80% - var(--x)) calc(0% - var(--y)),
      rgb(230 57 70),
      rgb(250 210 214)
    ),
    radial-gradient(
      150% 210% at calc(100% + var(--x)) calc(0% + var(--y)),
      rgb(245 245 245),
      rgb(230 57 70)
    ),
    radial-gradient(
      100% 100% at calc(100% - var(--x)) calc(30% - var(--y)),
      rgb(193 18 31),
      rgb(255 245 246)
    ),
    linear-gradient(60deg, rgb(240 128 134), rgb(230 57 70));
  background-blend-mode: overlay, overlay, lighten, darken, normal;
}

/* 暗色主题：同结构换成深红墨黑系（对应参考效果的纯黑底戏剧性） */
html.dark .login {
  background-image:
    linear-gradient(115deg, rgb(193 18 31), rgb(0 0 0)),
    radial-gradient(
      90% 100% at calc(50% + var(--x)) calc(0% + var(--y)),
      rgb(200 200 200),
      rgb(45 6 10)
    ),
    radial-gradient(
      100% 100% at calc(80% - var(--x)) calc(0% - var(--y)),
      rgb(193 18 31),
      rgb(36 4 7)
    ),
    radial-gradient(
      150% 210% at calc(100% + var(--x)) calc(0% + var(--y)),
      rgb(125 125 125),
      rgb(193 18 31)
    ),
    radial-gradient(
      100% 100% at calc(100% - var(--x)) calc(30% - var(--y)),
      rgb(164 22 26),
      rgb(0 0 0)
    ),
    linear-gradient(60deg, rgb(230 57 70), rgb(193 18 31));
}

/* 细网格叠加：亮色用深线、暗色用白线 */
.login::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(15, 23, 42, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(15, 23, 42, 0.05) 1px, transparent 1px);
  background-size: var(--xf-tech-grid-size) var(--xf-tech-grid-size);
  pointer-events: none;
}

html.dark .login::before {
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.05) 1px, transparent 1px);
}

.login__grid {
  position: relative;
  z-index: 0;
  width: min(1160px, 100%);
  height: min(720px, calc(100vh - 80px));
  height: min(720px, calc(100dvh - 80px));
  border: 1px solid rgba(15, 23, 42, 0.1);
  background-image:
    linear-gradient(rgba(15, 23, 42, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(15, 23, 42, 0.05) 1px, transparent 1px);
  background-size: 32px 32px;
  border-radius: 24px;
  opacity: 0.7;
}

html.dark .login__grid {
  border-color: rgba(255, 255, 255, 0.14);
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.06) 1px, transparent 1px);
}

.login__panel {
  position: absolute;
  z-index: 1;
  display: grid;
  grid-template-columns: minmax(320px, 1.1fr) minmax(360px, 420px);
  gap: 36px;
  align-items: center;
  width: min(1080px, calc(100% - 48px));
  padding: 48px;
  background: var(--xf-bg-glass-strong);
  background-image: var(--xf-gradient-tech);
  border: 1px solid var(--xf-border-color);
  border-radius: 20px;
  box-shadow: var(--xf-shadow-xl);
  backdrop-filter: blur(8px);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

.login-brand {
  padding-right: 12px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.1s;
}

.login-brand__tag {
  display: inline-flex;
  align-items: center;
  height: 32px;
  padding: 0 14px;
  border-radius: 999px;
  background: var(--xf-primary-alpha-8);
  color: var(--xf-primary-strong);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  font-weight: 700;
  letter-spacing: var(--xf-tracking-wide);
}

.login-brand__title {
  margin: 18px 0 12px;
  font-family: var(--xf-font-display);
  font-size: 40px;
  font-weight: 700;
  line-height: 1.2;
  color: var(--xf-gray-900);
  letter-spacing: var(--xf-tracking-tight);
}

.login-brand__subtitle {
  max-width: 520px;
  margin: 0;
  font-size: 15px;
  line-height: 1.8;
  color: var(--xf-text-secondary);
}

.login-brand__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 28px;
}

.login-brand__meta span {
  display: inline-flex;
  align-items: center;
  height: 36px;
  padding: 0 16px;
  /* Apple/Pinguo：小型标签一律药丸形（与 login-brand__tag 同形） */
  border-radius: 999px;
  background: var(--xf-bg-glass-strong);
  border: 1px solid var(--xf-border-color);
  color: var(--xf-text-regular);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-base);
  font-weight: 500;
  letter-spacing: var(--xf-tracking-wide);
}

.login-card {
  position: relative;
  width: 100%;
  padding: 36px 32px 28px;
  background: var(--xf-bg-glass-strong);
  border: 1px solid var(--xf-border-color);
  border-top: 4px solid var(--xf-primary);
  border-radius: 16px;
  box-shadow: var(--xf-shadow-xl);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.2s;
}

.login-card__header {
  display: flex;
  align-items: center;
  gap: 14px;
  /* 窄卡下标题块可收缩，偏好控件不被挤出导致标题换行 */
  min-width: 0;
  /* 文案较长的语言（英文等）标题 + 两枚药丸可能超过卡宽：
     允许折行，药丸掉落到下一行右对齐，而不是溢出卡片右边框 */
  flex-wrap: wrap;
  row-gap: 10px;
  margin-bottom: 24px;
}

.login-card__title {
  white-space: nowrap;
  margin: 0 0 4px;
  font-family: var(--xf-font-display);
  font-size: 26px;
  font-weight: 700;
  color: var(--xf-gray-900);
}

.login-card__subtitle {
  margin: 0;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
}

/* 偏好控件（AuthPrefs 组件）贴 header 右缘，与标题块弹性分配空间。
   按钮外观与 ≤560px 小屏降级全部由组件自带，此处只负责定位 */
.login-card__lang {
  margin-left: auto;
  flex-shrink: 0;
}

.login-card__tip {
  margin: 2px 0 18px;
  padding: 10px 12px;
  border-left: 3px solid var(--xf-primary);
  background: var(--xf-primary-alpha-8);
  color: var(--xf-primary-deep);
  font-size: var(--xf-font-size-sm);
}

.login-card__captcha {
  display: flex;
  gap: 10px;
  width: 100%;
  align-items: center;
}

.login-card__captcha .el-input {
  flex: 1;
}

.login-card__captcha-img {
  flex-shrink: 0;
  width: 120px;
  height: 48px;
  border-radius: 10px;
  border: 1px solid var(--xf-border-color);
  /* 验证码占位底色走变量：写死 #f0f2f5 在暗色下是一块浅灰方块 */
  background: var(--xf-gray-100);
  cursor: pointer;
  user-select: none;
  transition: border-color 0.2s ease;
}

.login-card__captcha-img:hover {
  border-color: var(--xf-primary);
}

.login-card__captcha-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}

.login-card__actions {
  margin: 8px 0 0;
}

.login-card__footer {
  padding-top: 10px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-500);
  text-align: center;
}

.login-card__footer a {
  margin-left: 6px;
  color: var(--xf-primary);
  font-weight: 600;
}

.login-card__copyright {
  margin-top: var(--xf-spacing-md);
  color: var(--xf-text-muted);
}

:deep(.el-form-item) {
  margin-bottom: 18px;
}

:deep(.el-form-item__error) {
  color: var(--xf-danger);
}

:deep(.el-input__wrapper) {
  min-height: 48px;
  border-radius: 10px;
  box-shadow: 0 0 0 1px var(--xf-border-color) inset;
  background: var(--xf-gray-50);
}

:deep(.el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px var(--xf-border-color-strong) inset;
}

:deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px var(--xf-primary) inset;
}

:deep(.liquid-glass-buttons .glass-btn--primary) {
  border-radius: 10px;
  background: var(--xf-gradient-primary);
  border: 1px solid var(--xf-primary-alpha-45);
  box-shadow: var(--xf-shadow-primary);
  backdrop-filter: none;
  -webkit-backdrop-filter: none;
}

:deep(.liquid-glass-buttons .glass-btn--primary:hover) {
  background: var(--xf-gradient-primary-hover);
  transform: translateY(-1px);
}

:deep(.liquid-glass-buttons .glass-btn--primary::before) {
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.18), transparent);
}

/* 中间宽度区段（961px–1200px）：双列布局可用宽度被压缩，
   品牌区 3 个 meta 标签（约 456px）会超出品牌列（约 424px）导致第三个折行，
   收紧 meta 标签与面板内边距，保证一行放下；同时降低标题字号给英文文案留余量 */
@media (min-width: 961px) and (max-width: 1200px) {
  .login__panel {
    padding: 40px;
    gap: 28px;
  }

  .login-brand__title {
    font-size: 34px;
  }

  .login-brand__meta {
    gap: 10px;
  }

  .login-brand__meta span {
    padding: 0 12px;
    font-size: 13px;
    white-space: nowrap;
  }
}

@media (max-width: 960px) {
  .login__grid {
    display: none;
  }

  .login__panel {
    position: relative;
    grid-template-columns: 1fr;
    gap: 28px;
    width: min(560px, 100%);
    padding: 28px;
  }

  .login-brand {
    padding-right: 0;
  }

  .login-brand__title {
    font-size: 30px;
  }
}

@media (max-width: 640px) {
  .login {
    padding: 16px;
  }

  .login__panel {
    width: 100%;
    padding: 20px;
    border-radius: 16px;
  }

  .login-card {
    padding: 24px 20px;
  }

  .login-card__footer {
    font-size: var(--xf-font-size-xs);
  }

  .login-brand__meta {
    gap: 10px;
  }
}

/* ===== Apple 风格打磨（fluid interfaces：按压即时反馈 / 顺滑过渡 / 材质层次 / 无障碍降级） ===== */

/* 1) 按压即时反馈：反馈落在按下瞬间，而非松开（pointer-down） */
.login-card:active,
:deep(.liquid-glass-buttons .glass-btn--primary):active,
:deep(.liquid-glass-buttons .glass-btn):active {
  transform: scale(0.98);
  transition: transform 100ms ease-out;
}

/* 验证码图同样给按压反馈 */
.login-card__captcha-img:active {
  transform: scale(0.97);
  transition: transform 100ms ease-out;
}

/* 2) hover 过渡改为更顺滑的曲线（尊重可中断性，避免生硬跳变） */
.login-card,
.login-brand__meta span,
.login-card__captcha-img {
  transition:
    transform 100ms ease-out,
    box-shadow 240ms cubic-bezier(0.32, 0.72, 0, 1),
    border-color 200ms ease;
  will-change: transform;
}

/* 主按钮 hover 的上浮用弹簧感曲线，回落即按压缩放接管 */
:deep(.liquid-glass-buttons .glass-btn--primary),
:deep(.liquid-glass-buttons .glass-btn) {
  transition:
    transform 300ms cubic-bezier(0.32, 0.72, 0, 1),
    background 200ms ease,
    box-shadow 240ms cubic-bezier(0.32, 0.72, 0, 1);
}

/* 3) 输入框聚焦：柔和外发光（focus 即时、无延迟），材质层次更清晰 */
:deep(.el-input__wrapper) {
  transition: box-shadow 180ms cubic-bezier(0.32, 0.72, 0, 1);
}
:deep(.el-input__wrapper.is-focus) {
  box-shadow:
    0 0 0 1px var(--xf-primary) inset,
    0 0 0 4px var(--xf-primary-alpha-8);
}

/* 4) 卡片材质：更大的表面用更强的模糊与更深的阴影（尺寸暗示厚度） */
.login__panel {
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-top-color: rgba(255, 255, 255, 0.4); /* 顶缘亮线 = 光照在材质上 */
}
.login-card {
  backdrop-filter: blur(16px) saturate(160%);
  -webkit-backdrop-filter: blur(16px) saturate(160%);
}

/* 5) 入场动效：blur+scale 材质化到来，而非单纯透明度淡入 */
@keyframes material-enter {
  from {
    opacity: 0;
    transform: translateY(12px) scale(0.985);
    filter: blur(6px);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
    filter: blur(0);
  }
}
.login__panel {
  animation: material-enter 0.5s cubic-bezier(0.32, 0.72, 0, 1) both;
}

/* ===== 暗色适配 =====
   新背景是深红混合渐变（主题无关，亮暗一致），无需暗色覆盖。
   唯一例外是品牌标签 chip：亮色下是「红字红底」，暗色玻璃面板上
   深红文字（--xf-primary-strong）对比度不足，翻为白玻璃 */
html.dark .login-brand__tag {
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.18);
  color: rgba(255, 255, 255, 0.92);
}
/* 6) 无障碍降级 */
@media (prefers-reduced-motion: reduce) {
  .login__panel,
  .login-card,
  .login-brand {
    animation: none !important;
    transition: opacity 200ms ease !important;
    transform: none !important;
  }
  .login-card:active,
  :deep(.glass-btn):active {
    transform: none !important;
  }
}
@media (prefers-reduced-transparency: reduce) {
  .login__panel,
  .login-card {
    background: var(--xf-gray-50);
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
  }
}
</style>
