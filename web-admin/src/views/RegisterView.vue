<template>
  <div ref="registerRootRef" class="register">
    <!-- 装饰层单独成层、自行裁切：白色细网格叠加在深红混合渐变（.register 自身背景）上，
         替代原先整屏的品牌红渐变——注册是一次性冷启动动作，
         高饱和红铺满全屏会把「危险/告警」的语义误加到中性表单上。
         裁切必须由本层承担，绝不能挂到 .register 上：注册表单比登录页高得多
         （三步 + 口令强度条 + 信息核对），整页 overflow:hidden 会在 768px
         高的屏上把顶部永久裁掉，且顶部溢出在滚动容器里不可达 -->
    <div class="register__decor" aria-hidden="true" />
    <div class="register__panel">
      <section class="register-brand">
        <span class="register-brand__tag">{{ $t('register.brandTag') }}</span>
        <h1 class="register-brand__title">
          <ScrambleText :text="$t('register.brandTitle')" />
        </h1>
        <p class="register-brand__subtitle">
          {{ $t('register.brandSubtitle') }}
        </p>
        <!-- 左栏步骤条是全页唯一的进度指示：右侧卡片只渲染当前步，
             用户需要一个「还剩几步」的锚点，否则分步反而制造焦虑。
             aria-current 让读屏软件也能播报当前步（原先的进度语义挂在
             卡片顶部那条重复的进度条上，随进度条一并移除后在此补齐） -->
        <ol class="register-steps">
          <li
            v-for="(s, i) in steps"
            :key="s.key"
            class="register-steps__item"
            :class="{
              'is-active': i === activeStep,
              'is-done': i < activeStep,
            }"
            :aria-current="i === activeStep ? 'step' : undefined"
          >
            <span class="register-steps__index">
              <el-icon v-if="i < activeStep"><Check /></el-icon>
              <template v-else>{{ i + 1 }}</template>
            </span>
            <span class="register-steps__text">
              <span class="register-steps__title">{{ s.title }}</span>
              <span class="register-steps__desc">{{ s.desc }}</span>
            </span>
          </li>
        </ol>
      </section>

      <div class="register-card">
        <div class="register-card__header">
          <div class="register-card__heading">
            <h2 class="register-card__title">
              {{ steps[activeStep].title }}
            </h2>
            <p class="register-card__subtitle">
              {{ steps[activeStep].desc }}
            </p>
          </div>
          <!-- 主题 + 语言偏好控件抽为共享组件 AuthPrefs：
               此前登录页与注册页各自实现了一遍且类名不同，还出现「注册有主题切换、
               登录没有」的功能不对称。抽离后两页由构造保证一致，
               小屏降级规则也只在组件内维护一处 -->
          <AuthPrefs class="register-card__prefs" />
        </div>

        <el-form
          ref="registerFormRef"
          :model="registerForm"
          :rules="rules"
          label-position="top"
          size="large"
          :validate-on-rule-change="false"
          @keyup.enter="onEnter"
        >
          <!-- 步骤容器：三步内容高度不同（第 1 步比第 3 步高约 130px），
               直接切换会让卡片瞬间跳高/跳矮。高度由 ResizeObserver 跟踪当前步实测值，
               过渡期间才裁切溢出，避免把 el-form-item 的错误文案长期裁掉 -->
          <div
            class="register-card__steps"
            :class="{ 'is-stepping': isStepping }"
            :style="stepsWrapStyle"
          >
            <!-- ===== 第 1 步：账号凭据 ===== -->
            <div
              v-show="activeStep === 0"
              :ref="(el) => setPanel(0, el)"
              class="register-step"
              :class="stepDirClass"
            >
              <p class="register-card__hint">
                {{ $t('register.accountHint') }}
              </p>
              <div class="field-grid">
                <el-form-item :label="$t('auth.username')" prop="username">
                  <el-input
                    id="username"
                    v-model="registerForm.username"
                    name="username"
                    :placeholder="$t('validation.usernameRequired')"
                    :prefix-icon="User"
                    maxlength="30"
                    clearable
                    autocomplete="username"
                  />
                </el-form-item>
                <el-form-item :label="$t('auth.email')" prop="email">
                  <el-input
                    id="email"
                    v-model="registerForm.email"
                    name="email"
                    :placeholder="$t('register.emailPlaceholder')"
                    :prefix-icon="Message"
                    maxlength="254"
                    clearable
                    autocomplete="email"
                  />
                </el-form-item>
              </div>
              <div class="field-grid">
                <el-form-item :label="$t('auth.password')" prop="password">
                  <el-input
                    id="password"
                    v-model="registerForm.password"
                    name="password"
                    type="password"
                    :placeholder="$t('validation.passwordRequired')"
                    :prefix-icon="Lock"
                    maxlength="64"
                    show-password
                    autocomplete="new-password"
                  />
                </el-form-item>
                <el-form-item :label="$t('auth.confirmPassword')" prop="confirmPassword">
                  <el-input
                    id="confirmPassword"
                    v-model="registerForm.confirmPassword"
                    name="confirmPassword"
                    type="password"
                    :placeholder="$t('register.confirmPwdPlaceholder')"
                    :prefix-icon="Lock"
                    maxlength="64"
                    show-password
                    autocomplete="new-password"
                  />
                </el-form-item>
              </div>

              <!-- 口令强度实时条（D-2 拆为 PasswordStrengthMeter 组件）：
                 判据复用 evaluatePasswordRules，与提交时的校验同源 -->
              <PasswordStrengthMeter :password="registerForm.password" />
            </div>
            <!-- ===== 第 2 步：身份信息（后端全部 optional） ===== -->
            <div
              v-show="activeStep === 1"
              :ref="(el) => setPanel(1, el)"
              class="register-step"
              :class="stepDirClass"
            >
              <p class="register-card__hint">
                {{ $t('register.profileHint') }}
              </p>
              <div class="field-grid">
                <el-form-item prop="realName">
                  <template #label>
                    <span class="field-label">
                      {{ $t('auth.realName') }}
                      <em class="field-label__optional">{{ $t('register.optionalTag') }}</em>
                    </span>
                  </template>
                  <el-input
                    id="realName"
                    v-model="registerForm.realName"
                    name="realName"
                    :placeholder="$t('validation.realNameRequired')"
                    :prefix-icon="UserFilled"
                    maxlength="50"
                    clearable
                    autocomplete="name"
                  />
                </el-form-item>
                <el-form-item prop="phone">
                  <template #label>
                    <span class="field-label">
                      {{ $t('auth.phone') }}
                      <em class="field-label__optional">{{ $t('register.optionalTag') }}</em>
                    </span>
                  </template>
                  <el-input
                    id="phone"
                    v-model="registerForm.phone"
                    name="phone"
                    :placeholder="$t('register.phonePlaceholder')"
                    :prefix-icon="Phone"
                    maxlength="20"
                    clearable
                    autocomplete="tel"
                  />
                </el-form-item>
              </div>
              <el-form-item prop="department">
                <template #label>
                  <span class="field-label">
                    {{ $t('auth.department') }}
                    <em class="field-label__optional">{{ $t('register.optionalTag') }}</em>
                  </span>
                </template>
                <el-input
                  id="department"
                  v-model="registerForm.department"
                  name="department"
                  :placeholder="$t('register.departmentPlaceholder')"
                  :prefix-icon="OfficeBuilding"
                  maxlength="100"
                  clearable
                  autocomplete="organization"
                />
              </el-form-item>
            </div>

            <!-- ===== 第 3 步：人机校验 + 信息核对 ===== -->
            <div
              v-show="activeStep === 2"
              :ref="(el) => setPanel(2, el)"
              class="register-step"
              :class="stepDirClass"
            >
              <p class="register-card__hint">
                {{ $t('register.confirmHint') }}
              </p>
              <!-- 验证码状态查询失败：注册验证码默认开启，不能因为「查不到」就跳过；
                   若服务端确实要求验证码，用户会在提交时被拒绝且没有填写入口。 -->
              <el-alert
                v-if="captchaStatus === 'error'"
                :title="$t('login.captchaStatusFailed')"
                type="warning"
                :closable="false"
                show-icon
                class="register-card__captcha-error"
              >
                <template #default>
                  <button
                    type="button"
                    class="glass-btn glass-btn--default glass-btn--sm"
                    @click="loadCaptchaStatus"
                  >
                    {{ $t('common.retry') }}
                  </button>
                </template>
              </el-alert>
              <el-form-item
                v-if="captchaEnabled"
                :label="$t('register.captchaTitle')"
                prop="captchaText"
              >
                <div class="register-card__captcha">
                  <el-input
                    id="captcha"
                    v-model="registerForm.captchaText"
                    name="captcha"
                    :placeholder="$t('auth.captcha')"
                    :prefix-icon="Key"
                    maxlength="4"
                    clearable
                    autocomplete="off"
                  />
                  <img
                    v-if="captchaImg"
                    :src="captchaImg"
                    class="register-card__captcha-img"
                    :alt="$t('auth.captcha')"
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
                    class="register-card__captcha-img register-card__captcha-placeholder"
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

              <!-- 一-7：隐私告知同意是本步的**必填**项（后端 privacyConsent 必须布尔 true），
                   不是装饰性的勾选框；勾选前可点开完整告知，文案与 CONSENT_SCOPES 的 notice 项一致 -->
              <el-form-item prop="privacyConsent" class="register-card__consent">
                <el-checkbox id="privacyConsent" v-model="registerForm.privacyConsent">
                  {{ $t('register.privacyConsentLabel') }}
                </el-checkbox>
                <button
                  type="button"
                  class="register-card__consent-open"
                  @click="privacyNoticeVisible = true"
                >
                  {{ $t('register.privacyConsentOpen') }}
                </button>
              </el-form-item>

              <!-- 信息核对（D-2 拆为 RegisterSummary 组件，列表项由父级传入） -->
              <RegisterSummary :items="summaryItems" />
            </div>
          </div>
        </el-form>

        <div class="register-card__actions">
          <!-- 与登录页共用同一枚液态玻璃按钮组件：两个认证页的操作区观感必须一致，
               否则从登录跳到注册像是换了另一个产品。
               该组件不支持 disabled，故 loading 态按登录页的做法整体换成占位按钮 -->
          <LiquidGlassButtons
            v-if="!loading"
            :buttons="actionButtons"
            :height="50"
            @press="onAction"
          />
          <button
            v-else
            type="button"
            class="glass-btn glass-btn--primary is-loading"
            style="width: 100%; height: 50px"
            disabled
          >
            {{ $t('register.submitting') }}
          </button>
        </div>

        <div class="register-card__footer">
          <button type="button" class="register-card__reset" @click="resetForm">
            {{ $t('common.reset') }}
          </button>
          <router-link to="/login">
            {{ $t('register.hasAccount') }}
          </router-link>
        </div>
      </div>
    </div>
    <!-- 隐私告知全文：告知内容必须**可读**才谈得上明示同意，故与勾选框同屏可达。
         版本号由后端同意记录同一常量决定（services/consentService.PRIVACY_NOTICE_VERSION），
         界面不另抄一份日期，避免"告知已改版而界面还显示旧版" -->
    <el-dialog
      v-model="privacyNoticeVisible"
      :title="$t('register.privacyNoticeTitle', { version: PRIVACY_NOTICE_VERSION })"
      width="560px"
      align-center
    >
      <p class="privacy-notice__intro">{{ $t('register.privacyNoticeIntro') }}</p>
      <h4 class="privacy-notice__heading">{{ $t('register.privacyNoticeScopeTitle') }}</h4>
      <ul class="privacy-notice__list">
        <li v-for="key in privacyNoticeScopes" :key="key">
          {{ $t(`register.privacyNoticeScopes.${key}`) }}
        </li>
      </ul>
      <p class="privacy-notice__para">{{ $t('register.privacyNoticeRetention') }}</p>
      <p class="privacy-notice__para">{{ $t('register.privacyNoticeRights') }}</p>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--primary glass-btn--sm"
          @click="acceptPrivacyNotice"
        >
          {{ $t('register.privacyNoticeClose') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, nextTick } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElNotification } from 'element-plus/es/components/notification/index.mjs'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import { haptic } from '@/utils/haptic'
import { encryptPassword } from '@/utils/loginCipher'
import { encryptionErrorMessage } from '@/utils/encryptionError'
import { passwordStrengthRule } from '@/utils/password'
import LiquidGlassButtons from '@/components/LiquidGlassButtons.vue'
import AuthPrefs from '@/components/AuthPrefs.vue'
import ScrambleText from '@/components/ScrambleText.vue'
import { usePointerGradient } from '@/composables/usePointerGradient'
// D-2：强度条与信息核对拆为子组件，步骤切换动效拆为组合式函数
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import RegisterSummary from '@/components/RegisterSummary.vue'
import { PRIVACY_NOTICE_VERSION, PRIVACY_NOTICE_SCOPES } from '@/utils/privacyNotice'
import { useStepTransition } from '@/composables/useStepTransition'
import {
  User,
  Message,
  Lock,
  UserFilled,
  Phone,
  OfficeBuilding,
  Key,
  Check,
} from '@element-plus/icons-vue'

const { t } = useI18n()
const router = useRouter()

// 鼠标追踪渐变：指针位置写入 .register 的 --posX/--posY，驱动装饰层光斑跟随
const registerRootRef = ref(null)
usePointerGradient(registerRootRef)

const privacyNoticeVisible = ref(false)
const loading = ref(false)
// 提交重入锁：与 loading 分开，**同步**置位。loading 要等整表异步校验通过才置位，
// 连点时后面的点击早已越过 loading 判断（实测同一 tick 三次点击发出 3 个注册请求，
// 第 2/3 次会因用户名重复而失败，用户先看到「注册成功」再连吃两个错误提示）。
const submitting = ref(false)
// 分步「下一步」的重入锁：与 submitting 同一理由，但服务另一条路径。validateStep
// 内部 await validateField，校验窗口内的连点会各自读到同一个 activeStep，恢复后两次
// 都 +1 => 0->2 直接落到确认步，用户没填身份步骤就注册了（实测复现）。
const stepping = ref(false)
const registerFormRef = ref(null)
const activeStep = ref(0)

const registerForm = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  realName: '',
  phone: '',
  department: '',
  captchaText: '',
  privacyConsent: false,
})

const steps = computed(() => [
  { key: 'account', title: t('register.stepAccount'), desc: t('register.stepAccountDesc') },
  { key: 'profile', title: t('register.stepProfile'), desc: t('register.stepProfileDesc') },
  { key: 'confirm', title: t('register.stepConfirm'), desc: t('register.stepConfirmDesc') },
])

// 各步骤所辖字段：nextStep 只校验当前步，避免「第 1 步就报第 3 步验证码没填」；一-7 的同意勾选恒校验
const STEP_FIELDS = [
  ['username', 'email', 'password', 'confirmPassword'],
  ['realName', 'phone', 'department'],
  ['privacyConsent', 'captchaText'],
]

// 口令逐条规则与强度分档已随强度条迁入 PasswordStrengthMeter 组件（D-2），
// 该组件与提交校验共用 evaluatePasswordRules 判据，保持同源

/** 告知范围清单来自 utils/privacyNotice（与后端 CONSENT_SCOPES 的 notice 项对拍），不在此手抄 */
const privacyNoticeScopes = PRIVACY_NOTICE_SCOPES

/** 告知弹窗的「我已阅读」只关闭弹窗，**不代勾**：同意必须由用户自己在勾选框上作出 */
const acceptPrivacyNotice = () => {
  privacyNoticeVisible.value = false
}

const summaryItems = computed(() => [
  { label: t('auth.username'), value: registerForm.username },
  { label: t('auth.email'), value: registerForm.email },
  { label: t('auth.realName'), value: registerForm.realName },
  { label: t('auth.phone'), value: registerForm.phone },
  { label: t('auth.department'), value: registerForm.department },
])

const rules = computed(() => ({
  username: [
    { required: true, message: t('validation.usernameRequired'), trigger: 'blur' },
    { min: 3, max: 30, message: t('validation.usernameLen'), trigger: 'blur' },
    { pattern: /^[a-zA-Z0-9_]+$/, message: t('validation.usernamePattern'), trigger: 'blur' },
  ],
  email: [
    { required: true, message: t('validation.emailRequired'), trigger: 'blur' },
    { type: 'email', message: t('validation.emailInvalid'), trigger: 'blur' },
  ],
  password: [
    { required: true, message: t('validation.passwordRequired'), trigger: 'blur' },
    passwordStrengthRule(t('validation.passwordMin')),
  ],
  confirmPassword: [
    { required: true, message: t('validation.confirmRequired'), trigger: 'blur' },
    {
      validator: (rule, value, callback) => {
        if (value !== registerForm.password) {
          callback(new Error(t('validation.confirmMismatch')))
        } else {
          callback()
        }
      },
      trigger: ['blur', 'change'],
    },
  ],
  // realName / phone / department 后端均为 optional，此处不设 required，
  // 只保留格式约束（手机号）——写 required:false + message 只会让界面看起来像必填
  phone: [{ pattern: /^1[3-9]\d{9}$/, message: t('validation.phonePattern'), trigger: 'blur' }],
  // 一-7：必须是布尔 true（后端 .custom(v => v === true) 同口径）。用 validator 而非
  // required:true —— el-checkbox 的 false 会被 required 判成「有值」，勾选框形同虚设。
  privacyConsent: [
    {
      validator: (rule, value, callback) => {
        value === true ? callback() : callback(new Error(t('register.privacyConsentRequired')))
      },
      trigger: 'change',
    },
  ],
  captchaText: [
    { required: true, message: t('validation.captchaRequired'), trigger: 'blur' },
    { len: 4, message: t('validation.captchaLen'), trigger: 'blur' },
  ],
}))

// 改密码后重新校验确认框：此前 confirmPassword 只在自身 blur 时比对，
// 用户先填确认再回头改密码时，界面仍显示「已通过」，直到提交才报不一致
watch(
  () => registerForm.password,
  () => {
    if (!registerForm.confirmPassword) return
    registerFormRef.value?.validateField('confirmPassword').catch(() => {})
  }
)

// 图形验证码：注册接口默认强制要求（REGISTER_CAPTCHA_ENABLED），
// captchaId 随注册请求提交，图片以 data URI 内联渲染
const captchaEnabled = ref(false)
const captchaId = ref('')
const captchaImg = ref('')
// 验证码状态：loading / ready / error。error 时既不假定开启（没有图可填）
// 也不假定关闭（注册验证码默认开启）——必须先重试拿到确定答案才能提交。
const captchaStatus = ref('loading')
let captchaStatusPromise = null

const loadCaptcha = async () => {
  // 先清空再拉取（与 LoginView.loadCaptcha 同口径）：验证码是一次性消费，失败的刷新
  // 若不清空，会留着上一次已被提交消费掉的旧 captchaId + 旧图，用户对着陈旧图重填、
  // captchaId 仍是消费过的那个 → 每次提交都失败且毫无提示 = 静默锁死。清空后失败态
  // 落到「点击重试」占位图，可自愈。getCaptcha 走 apiClient，网络失败拦截器已统一提示。
  captchaId.value = ''
  captchaImg.value = ''
  try {
    const { data: resp } = await api.auth.getCaptcha()
    if (resp.success && resp.data?.captchaId) {
      captchaId.value = resp.data.captchaId
      captchaImg.value = `data:image/svg+xml;utf8,${encodeURIComponent(resp.data.svg)}`
    }
  } catch (_) {
    // 保持清空态：渲染占位图「点击重试」，而非停在已消费的陈旧验证码
  }
}

const loadCaptchaStatus = async () => {
  if (captchaStatusPromise) return captchaStatusPromise
  captchaStatus.value = 'loading'
  captchaStatusPromise = (async () => {
    try {
      const { data: resp } = await api.auth.getCaptchaStatus()
      captchaEnabled.value = !!resp.data?.registerCaptchaEnabled
      captchaStatus.value = 'ready'
      // 等图片就绪再返回：提交前的兜底重试拿到 ready 后应能直接带上 captchaId
      if (captchaEnabled.value) await loadCaptcha()
      return true
    } catch (_) {
      // 不能默认关闭：注册验证码默认开启，跳过校验的提交只会被后端拒绝
      captchaEnabled.value = false
      captchaStatus.value = 'error'
      return false
    } finally {
      captchaStatusPromise = null
    }
  })()
  return captchaStatusPromise
}

onMounted(() => {
  loadCaptchaStatus()

  // 面板高度观察已迁入 useStepTransition（D-2），此处只负责启动
  startObserving()
})

/** 只校验当前步骤字段；未开启验证码时第 3 步无待校验字段，直接放行 */
const validateStep = async (index) => {
  // captchaText 仅开启验证码时校验；privacyConsent 恒校验（同意是注册前提，不随开关变化）
  const fields = STEP_FIELDS[index].filter((f) => f !== 'captchaText' || captchaEnabled.value)
  if (fields.length === 0) return true
  try {
    await registerFormRef.value.validateField(fields)
    return true
  } catch (_) {
    return false
  }
}

/* ===== 步骤切换动效（D-2 拆入 composables/useStepTransition.js）=====
   方向感知 + 面板高度实测 + 过渡期裁切，与表单数据无关的纯视图状态机 */
const {
  stepDirection,
  stepDirClass,
  setPanel,
  stepsWrapStyle,
  isStepping,
  beginStepTransition,
  startObserving,
} = useStepTransition(activeStep)

const nextStep = async () => {
  // 锁必须在 await 之前同步置位，否则拦不住校验窗口内的连点（同 submitting）
  if (stepping.value) return
  stepping.value = true
  try {
    if (!(await validateStep(activeStep.value))) {
      ElMessage.warning(t('register.stepIncomplete'))
      return
    }
    if (activeStep.value < steps.value.length - 1) {
      stepDirection.value = 'forward'
      activeStep.value += 1
      beginStepTransition()
    }
  } finally {
    stepping.value = false
  }
}

const prevStep = () => {
  if (activeStep.value > 0) {
    stepDirection.value = 'back'
    activeStep.value -= 1
    beginStepTransition()
  }
}

/** 回车：非末步等价于「下一步」，末步才提交——避免中途误触发注册请求 */
const onEnter = () => {
  if (submitting.value) return
  if (activeStep.value < steps.value.length - 1) nextStep()
  else onRegister()
}

/**
 * 操作区按钮组：第 1 步只有「下一步」，其后追加「上一步」。
 * 末步的主按钮文案切换为「提交注册」，与 onEnter 的分支口径保持一致。
 */
const actionButtons = computed(() => {
  const list = []
  if (activeStep.value > 0) {
    list.push({ id: 'prev', label: t('register.prev'), type: 'default' })
  }
  const isLast = activeStep.value >= steps.value.length - 1
  list.push({
    id: 'submit',
    label: isLast ? t('register.submit') : t('register.next'),
    type: 'primary',
  })
  return list
})

/** 统一接收 LiquidGlassButtons 的 press 事件，按 id 与当前步派发 */
const onAction = (id) => {
  if (id === 'prev') {
    prevStep()
    return
  }
  if (activeStep.value < steps.value.length - 1) nextStep()
  else onRegister()
}

const onRegister = async () => {
  // 重入防护必须同步生效：按钮的 loading 占位要等异步校验通过后才挂上，
  // 校验窗口内的连点拦不住（见 submitting 声明处的实测说明）
  if (submitting.value) return
  submitting.value = true
  haptic(10)
  try {
    // 验证码配置未知时先重试查询：拿到确定答案、且表单项按最新开关渲染后再整表校验，
    // 否则「刚查到验证码开启」这一次的校验会漏掉尚未挂载的验证码字段
    if (captchaStatus.value !== 'ready') {
      const ok = await loadCaptchaStatus()
      if (!ok) {
        ElMessage.error(t('login.captchaStatusFailed'))
        return
      }
      await nextTick()
    }
    // 提交前整表校验：分步校验只覆盖走过的步骤，用户可能通过回退跳过某步。
    // 单独一层 try：它的 reject 不能落进下面「任何失败都换验证码」的分支——
    // 整表校验失败与请求失败是两件事，前者该保留用户已填对的验证码
    // （LoginView.vue 同一修法：validate() 包内层 catch 后 return，不碰验证码）
    try {
      await registerFormRef.value.validate()
    } catch (_) {
      return
    }

    loading.value = true

    // 开启验证码但图片尚未就绪：本次提交必然缺 captchaId，拦下并指向占位图重试
    if (captchaEnabled.value && !captchaId.value) {
      ElMessage.warning(t('login.captchaLoading'))
      return
    }

    // 口令密文轨（FE-H1）：加密不可用（返回 null / 抛错）一律阻断提交，
    // 不存在明文回退轨；「可用但失败」提示重试（用户重试成本为零）
    const payload = {
      username: registerForm.username,
      email: registerForm.email,
      realName: registerForm.realName,
      phone: registerForm.phone,
      department: registerForm.department,
      // 一-7：明示同意，后端校验 v === true；缺省或非布尔会被 400 拒绝
      privacyConsent: registerForm.privacyConsent,
    }
    let enc
    try {
      enc = await encryptPassword(registerForm.password, 'REGISTER')
    } catch (e) {
      console.warn('[loginCipher] 口令加密失败，已阻断提交：', e?.message)
      // 文案统一走共享 helper（P2 收敛）：指纹不符/非安全上下文/通用失败三分支
      ElMessage.error(encryptionErrorMessage(t, e))
      return
    }
    // H（G2 统一口径）：null = dev 非安全上下文加密不可用。与 ReportView 的导出
    // 二次验证、UserView 建号同口径——报错中止，不再回退明文轨上行口令。
    if (!enc) {
      ElMessage.error(t('login.insecureContext'))
      return
    }
    payload.encPassword = enc

    // 仅开启验证码时携带校验字段
    if (captchaEnabled.value) {
      payload.captchaId = captchaId.value
      payload.captchaText = registerForm.captchaText.trim()
    }

    // 调用后端注册接口
    const response = await api.auth.register(payload)

    if (response.data.success) {
      ElNotification({
        title: t('register.successTitle'),
        message: t('register.successMsg'),
        type: 'success',
      })

      // 跳转到登录页面
      router.push('/login')
    } else {
      ElMessage.error(response.data.message || t('register.failed'))
      // 验证码一次性消费：失败后换新
      if (captchaEnabled.value) {
        registerForm.captchaText = ''
        loadCaptcha()
      }
    }
  } catch (error) {
    // 错误已在 axios 拦截器中处理
    // 验证码一次性消费：任何失败尝试后都必须换新
    if (captchaEnabled.value) {
      registerForm.captchaText = ''
      loadCaptcha()
    }
  } finally {
    loading.value = false
    // 校验不通过 / 加密失败 / 请求失败 / 成功，都必须解锁：否则提交按钮永久卡死
    submitting.value = false
  }
}

const resetForm = () => {
  // ref 可能尚未挂载（对话框/过渡期触发重置）：判空防解引用崩溃
  registerFormRef.value?.resetFields()
  stepDirection.value = 'back'
  activeStep.value = 0
  beginStepTransition()
  if (captchaEnabled.value) loadCaptcha()
}
</script>

<style scoped src="./RegisterView.css"></style>
