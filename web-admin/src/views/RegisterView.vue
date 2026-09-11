<template>
  <div class="register">
    <!-- 装饰层单独成层、自行裁切：底色渐变 + 细网格 + 光斑（aurora），
         替代原先整屏的品牌红渐变——注册是一次性冷启动动作，
         高饱和红铺满全屏会把「危险/告警」的语义误加到中性表单上。
         裁切必须由本层承担，绝不能挂到 .register 上：注册表单比登录页高得多
         （三步 + 口令强度条 + 信息核对），整页 overflow:hidden 会在 768px
         高的屏上把顶部永久裁掉，且顶部溢出在滚动容器里不可达 -->
    <div class="register__decor" aria-hidden="true">
      <div class="register__aurora" />
    </div>
    <div class="register__panel">
      <section class="register-brand">
        <span class="register-brand__tag">{{ $t('register.brandTag') }}</span>
        <h1 class="register-brand__title">
          {{ $t('register.brandTitle') }}
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
                    @click="loadCaptcha"
                  />
                  <div
                    v-else
                    class="register-card__captcha-img register-card__captcha-placeholder"
                    @click="loadCaptcha"
                  >
                    {{ $t('login.captchaLoading') }}
                  </div>
                </div>
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
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElNotification } from 'element-plus/es/components/notification/index.mjs'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import { encryptPassword } from '@/utils/loginCipher'
import { passwordStrengthRule } from '@/utils/password'
import LiquidGlassButtons from '@/components/LiquidGlassButtons.vue'
import AuthPrefs from '@/components/AuthPrefs.vue'
// D-2：强度条与信息核对拆为子组件，步骤切换动效拆为组合式函数
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'
import RegisterSummary from '@/components/RegisterSummary.vue'
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

const loading = ref(false)
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
})

const steps = computed(() => [
  { key: 'account', title: t('register.stepAccount'), desc: t('register.stepAccountDesc') },
  { key: 'profile', title: t('register.stepProfile'), desc: t('register.stepProfileDesc') },
  { key: 'confirm', title: t('register.stepConfirm'), desc: t('register.stepConfirmDesc') },
])

// 各步骤所辖字段：nextStep 只校验当前步，避免「第 1 步就报第 3 步验证码没填」
const STEP_FIELDS = [
  ['username', 'email', 'password', 'confirmPassword'],
  ['realName', 'phone', 'department'],
  ['captchaText'],
]

// 口令逐条规则与强度分档已随强度条迁入 PasswordStrengthMeter 组件（D-2），
// 该组件与提交校验共用 evaluatePasswordRules 判据，保持同源

const summaryItems = computed(() => [
  { label: t('auth.username'), value: registerForm.username },
  { label: t('auth.email'), value: registerForm.email },
  { label: t('auth.realName'), value: registerForm.realName },
  { label: t('auth.phone'), value: registerForm.phone },
  { label: t('auth.department'), value: registerForm.department },
])

const rules = {
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
  captchaText: [
    { required: true, message: t('validation.captchaRequired'), trigger: 'blur' },
    { len: 4, message: t('validation.captchaLen'), trigger: 'blur' },
  ],
}

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

const loadCaptcha = async () => {
  try {
    const { data: resp } = await api.auth.getCaptcha()
    if (resp.success && resp.data?.captchaId) {
      captchaId.value = resp.data.captchaId
      captchaImg.value = `data:image/svg+xml;utf8,${encodeURIComponent(resp.data.svg)}`
    }
  } catch (_) {
    // 验证码加载失败时用户可点击占位区重试
  }
}

const loadCaptchaStatus = async () => {
  try {
    const { data: resp } = await api.auth.getCaptchaStatus()
    captchaEnabled.value = !!resp.data?.registerCaptchaEnabled
    if (captchaEnabled.value) {
      loadCaptcha()
    }
  } catch (_) {
    // 状态查询失败按默认关闭处理
    captchaEnabled.value = false
  }
}

onMounted(() => {
  loadCaptchaStatus()

  // 面板高度观察已迁入 useStepTransition（D-2），此处只负责启动
  startObserving()
})

/** 只校验当前步骤字段；未开启验证码时第 3 步无待校验字段，直接放行 */
const validateStep = async (index) => {
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
  if (!(await validateStep(activeStep.value))) {
    ElMessage.warning(t('register.stepIncomplete'))
    return
  }
  if (activeStep.value < steps.value.length - 1) {
    stepDirection.value = 'forward'
    activeStep.value += 1
    beginStepTransition()
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
  if (loading.value) return
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
  if (loading.value) return
  try {
    // 提交前整表校验：分步校验只覆盖走过的步骤，用户可能通过回退跳过某步
    await registerFormRef.value.validate()

    loading.value = true

    // 口令密文轨（FE-H1）：null 仅限 WebCrypto 不可用（设计内降级）；
    // 「可用但失败」抛错时阻断提交并提示重试，不静默明文上行
    const payload = {
      username: registerForm.username,
      email: registerForm.email,
      realName: registerForm.realName,
      phone: registerForm.phone,
      department: registerForm.department,
    }
    let enc
    try {
      enc = await encryptPassword(registerForm.password)
    } catch (e) {
      console.warn('[loginCipher] 口令加密失败，已阻断提交：', e?.message)
      ElMessage.error(t('login.encryptionFailed'))
      return
    }
    if (enc) payload.encPassword = enc
    else payload.password = registerForm.password

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
  }
}

const resetForm = () => {
  registerFormRef.value.resetFields()
  stepDirection.value = 'back'
  activeStep.value = 0
  beginStepTransition()
  if (captchaEnabled.value) loadCaptcha()
}
</script>

<style scoped>
/* ===== 背景 =====
   原实现是 135deg 的 primary-light → primary-deep 全屏铺红，注册表单本身
   是中性录入场景，满屏高饱和红既刺眼又与「告警」语义冲突。改为与登录页同
   一套浅色底 + 极淡网格，另叠两枚品牌色光斑维持视觉归属。 */
/* ===== 布局容器 =====
   垂直居中改用面板自身的 margin-block:auto，而非容器的 align-items:center。
   内容放得下时两者观感一致，内容超高时行为相反——这正是此前「多端适配」失效的
   根因：align-items:center 会让内容向上下同时溢出，而顶部溢出在滚动容器里
   不可达（注册表单比登录页高得多：三步 + 口令强度条 + 信息核对，在 768px 高的
   笔记本上必然溢出）。auto 外边距在没有剩余空间时归零，内容回到顶部且完整可滚动。 */
.register {
  position: relative;
  display: flex;
  justify-content: center;
  min-height: 100vh;
  min-height: 100dvh;
  padding: 40px 24px;
  /* 刘海屏 / 圆角屏安全区：横屏时避免内容贴住听筒或 home 指示条。
     max() 保证无安全区的普通桌面仍是设计稿的 40/24 */
  padding-top: max(40px, env(safe-area-inset-top));
  padding-right: max(24px, env(safe-area-inset-right));
  padding-bottom: max(40px, env(safe-area-inset-bottom));
  padding-left: max(24px, env(safe-area-inset-left));
  background: linear-gradient(180deg, var(--xf-gray-50) 0%, var(--xf-gray-100) 100%);
  /* 不再设 overflow:hidden —— 裁切职责下放给 .register__decor。
     整页裁切会把超高的注册表单永久切掉顶部且无法滚动 */
}

/* 装饰层：只负责铺底与裁切，不参与滚动、不参与命中测试 */
.register__decor {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
}

.register__decor::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: var(--xf-tech-grid);
  background-size: var(--xf-tech-grid-size) var(--xf-tech-grid-size);
}

/* 两枚柔和光斑：右上品牌红、左下石板灰，radial-gradient 边缘完全透明，
   不产生硬边；inset:-20% 让模糊后的边缘溢出装饰层被裁掉，避免露出直边 */
.register__aurora {
  position: absolute;
  inset: -20%;
  background-image:
    radial-gradient(38% 38% at 78% 12%, var(--xf-primary-alpha-12) 0%, transparent 100%),
    radial-gradient(42% 42% at 12% 88%, var(--xf-info-alpha-15) 0%, transparent 100%);
  filter: blur(6px);
}

.register__panel {
  position: relative;
  z-index: 1;
  /* 有余量时垂直居中，无余量时归零并回到顶部（内容完整可滚动） */
  margin-block: auto;
  display: grid;
  grid-template-columns: minmax(280px, 0.9fr) minmax(400px, 520px);
  gap: 48px;
  align-items: center;
  width: min(1080px, 100%);
  /* 关键「去框」修复：不再设背景/边框/阴影/backdrop-filter。
     此前面板是玻璃材质、卡片也是玻璃——Apple 明确反对
     "在半透明材质上叠半透明材质"——且各自带边框，
     视觉上变成「框里套框」的过期仪表盘语言。
     现在面板退为纯布局容器：品牌文字与表单卡片各自直接坐在页面背景上，
     层级只靠卡片自身的 border + shadow + 间距制造，描边不再竞争 */
  padding: 0;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

/* ===== 左栏：品牌 + 步骤条 ===== */
.register-brand {
  padding-top: 6px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.1s;
}

.register-brand__tag {
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

.register-brand__title {
  margin: 18px 0 12px;
  font-family: var(--xf-font-display);
  font-size: 34px;
  font-weight: 700;
  line-height: 1.25;
  color: var(--xf-gray-900);
  letter-spacing: var(--xf-tracking-tight);
}

.register-brand__subtitle {
  margin: 0;
  font-size: 14px;
  line-height: 1.8;
  color: var(--xf-text-secondary);
}

.register-steps {
  list-style: none;
  margin: 32px 0 0;
  padding: 0;
}

.register-steps__item {
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding-bottom: 26px;
}

/* 竖向连接线：最后一项不画，否则线会拖到卡片外 */
.register-steps__item:not(:last-child)::before {
  content: '';
  position: absolute;
  left: 15px;
  top: 32px;
  bottom: 6px;
  width: 2px;
  background: var(--xf-border-color);
}

.register-steps__item.is-done::before {
  background: var(--xf-primary-alpha-45);
}

.register-steps__index {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  border: 1px solid var(--xf-border-color-strong);
  /* gray-50 而非 #fff：暗色下需要跟随翻转，否则圆点变成一排白点 */
  background: var(--xf-gray-50);
  color: var(--xf-gray-500);
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-sm);
  font-weight: 700;
  transition:
    background 0.25s var(--xf-ease-glass),
    color 0.25s,
    border-color 0.25s;
}

.register-steps__item.is-active .register-steps__index {
  background: var(--xf-gradient-primary);
  border-color: transparent;
  color: #fff;
  box-shadow: var(--xf-shadow-primary);
}

.register-steps__item.is-done .register-steps__index {
  background: var(--xf-primary-alpha-12);
  border-color: var(--xf-primary-alpha-45);
  color: var(--xf-primary-strong);
}

.register-steps__text {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding-top: 4px;
}

.register-steps__title {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-base);
  font-weight: 600;
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
}

.register-steps__item.is-active .register-steps__title,
.register-steps__item.is-done .register-steps__title {
  color: var(--xf-gray-900);
}

.register-steps__desc {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}

/* ===== 右栏：表单卡片 ===== */
.register-card {
  position: relative;
  padding: 32px 30px 26px;
  /* 用 gray-50 而非硬编码 #fff：暗色模式下 gray-50 翻为 #0f172a，
     写死白底会在 html.dark 下变成一块刺眼的白板 */
  background: var(--xf-gray-50);
  border: 1px solid var(--xf-border-color);
  /* 去掉此前的 4px 红色顶部实色条——Apple 早就不用"色块强调头部"做层级，
     改由 padding + shadow + 内容自身排版制造。品牌色留给真正的主操作 */
  border-radius: 16px;
  box-shadow: var(--xf-shadow-lg);
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.2s;
}

.register-card__header {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 18px;
}

.register-card__heading {
  min-width: 0;
}

.register-card__title {
  margin: 0 0 4px;
  font-family: var(--xf-font-display);
  font-size: 22px;
  font-weight: 700;
  color: var(--xf-gray-900);
  /* 22px 已属展示字号，需负字距收紧（字号越大字距应越紧） */
  letter-spacing: var(--xf-tracking-tight);
}

.register-card__subtitle {
  margin: 0;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
}

/* 偏好控件（AuthPrefs 组件）贴 header 右缘，与标题块弹性分配空间。
   按钮外观与小屏降级（≤560px 收成纯图标）全部由组件自带，此处只负责定位 */
.register-card__prefs {
  margin-left: auto;
  flex-shrink: 0;
}

/* 卡片顶部原本还有一条细进度条，已移除：它与左栏步骤列表在指示同一件事，
   桌面端两处同时可见即冗余。原注释称「窄屏时它是唯一进度线索」并不成立——
   步骤列表窄屏照样渲染，只是由竖排改为横排。
   进度语义改由 <ol> 的 aria-current="step" 承载，读屏软件同样可播报。 */

/* ===== 步骤切换 =====
   三步内容高度不一致，容器高度跟随当前步做过渡；
   只在切换瞬间裁切溢出（.is-stepping），过渡结束即恢复 visible——
   若长期 overflow:hidden，el-form-item 的错误文案会被裁掉 */
.register-card__steps {
  position: relative;
  overflow: visible;
  transition: height 0.36s var(--xf-ease-glass);
}

.register-card__steps.is-stepping {
  overflow: hidden;
}

/* 方向性入场：前进自右、后退自左。
   v-show 由 display:none → block 时 CSS 动画会自动重新播放，
   因此无需 <Transition> 包裹——用 v-if 会让未挂载的字段从 el-form 注销，
   onRegister 的整表校验就会退化成只校验末步（丢失「回退跳步」的安全网） */
.register-step.is-fwd {
  animation: step-in-fwd 0.32s var(--xf-ease-glass) both;
}

.register-step.is-back {
  animation: step-in-back 0.32s var(--xf-ease-glass) both;
}

@keyframes step-in-fwd {
  from {
    opacity: 0;
    transform: translate3d(18px, 0, 0);
  }
  to {
    opacity: 1;
    transform: translate3d(0, 0, 0);
  }
}

@keyframes step-in-back {
  from {
    opacity: 0;
    transform: translate3d(-18px, 0, 0);
  }
  to {
    opacity: 1;
    transform: translate3d(0, 0, 0);
  }
}

/* 步骤说明文字：直接以次级文本呈现，不装进灰底圆角块。
   此前每步顶部都是一块 gray-100 盒子，与下方的口令块、核对块用同一套
   「描边 + 底色」手法，三层嵌套糊成一团、层级尽失。
   Apple 的做法是用留白与字色区分主次：说明性文字走次级灰 + 舒适行距，
   把「画框」留给真正需要成为独立材质的表面。 */
.register-card__hint {
  margin: 0 0 20px;
  color: var(--xf-text-secondary);
  font-size: var(--xf-font-size-sm);
  line-height: 1.65;
}

/* 两列网格：窄屏由 media query 收成单列 */
.field-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 16px;
}

/* 「选填」标记：后端 realName/phone/department 均为 optional，
   原实现在 rules 里给它们写了 message，界面看上去像必填 */
.field-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

/* 「选填」标记只是一句补充语义，不是一枚控件：
   去掉灰底胶囊，用次级灰的小字承载。三个可选字段各挂一枚药丸，
   叠在已经很多边框的表单上只会制造噪点 */
.field-label__optional {
  color: var(--xf-gray-500);
  font-size: 11px;
  font-style: normal;
  font-weight: 500;
  letter-spacing: var(--xf-tracking-wide);
}

/* 口令强度区样式已随组件迁入 PasswordStrengthMeter.vue（D-2） */

/* 信息核对区样式已随组件迁入 RegisterSummary.vue（D-2） */

/* ===== 操作区 ===== */
.register-card__actions {
  margin-top: 4px;
}

/* 主按钮与登录页完全同一套观感：品牌渐变 + 投影 + 悬停微抬。
   两个认证页的操作区必须一致，否则跨页像换了产品 */
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

/* 「上一步」按内容收缩并设下限，主按钮吃掉剩余空间。
   组件内 .glass-btn 默认 flex:1 等宽，会让次要动作抢走主动作的视觉重心 */
:deep(.liquid-glass-buttons .glass-btn--default) {
  flex: 0 0 auto;
  min-width: 96px;
}

.register-card__footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--xf-border-color);
  font-size: var(--xf-font-size-sm);
}

.register-card__footer a {
  color: var(--xf-primary);
  font-weight: 600;
}

.register-card__reset {
  padding: 0;
  border: none;
  background: none;
  color: var(--xf-gray-500);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  cursor: pointer;
  transition:
    color 0.2s,
    opacity 0.12s ease-out;
}

.register-card__reset:hover {
  color: var(--xf-gray-800);
}

.register-card__reset:active {
  opacity: 0.6;
}

/* ===== 验证码 ===== */
.register-card__captcha {
  display: flex;
  gap: 10px;
  width: 100%;
  align-items: center;
}

.register-card__captcha .el-input {
  flex: 1;
}

.register-card__captcha-img {
  flex-shrink: 0;
  width: 120px;
  height: 48px;
  border-radius: 10px;
  border: 1px solid var(--xf-border-color);
  background: var(--xf-gray-100);
  cursor: pointer;
  user-select: none;
  transition:
    border-color 0.2s ease,
    transform 0.12s ease-out;
}

.register-card__captcha-img:hover {
  border-color: var(--xf-primary);
}

/* 可点击刷新：按压即下沉，暗示这是一枚按钮而非装饰图 */
.register-card__captcha-img:active {
  transform: scale(0.96);
}

.register-card__captcha-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}

/* ===== 表单控件：与登录页同一套输入框观感 ===== */
:deep(.el-form-item) {
  margin-bottom: 18px;
}

:deep(.el-form-item__label) {
  padding-bottom: 6px;
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-700);
  letter-spacing: var(--xf-tracking-wide);
}

:deep(.el-form-item__error) {
  color: var(--xf-danger);
}

:deep(.el-input__wrapper) {
  min-height: 44px;
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

/* ==========================================================================
   多端适配
   断点按「布局形态真正改变的位置」划分，而不是照抄某个设备宽度：
   - 1000px  左右分栏塌成上下堆叠（卡片列最小 400px，再窄就放不下两栏）
   - 640px   字段两列网格收成单列（每格已不足 150px）
   - 560px   卡片头部偏好按钮收成纯图标（关键修复，见下）
   - 480/380 小屏机型收紧间距、字号与验证码图
   - max-height 700px  横屏手机与 768p 笔记本，纵向留白让位给内容
   ========================================================================== */

/* 中间宽度区段（1001px–1200px）：双列布局被压缩，品牌 meta 标签折行的收紧处理 */
@media (min-width: 1001px) and (max-width: 1200px) {
  .login-brand__meta {
    gap: 10px;
  }

  .login-brand__meta span {
    padding: 0 12px;
    font-size: 13px;
    white-space: nowrap;
  }
}

@media (max-width: 1000px) {
  .register__panel {
    grid-template-columns: 1fr;
    gap: 28px;
    width: min(560px, 100%);
    padding: 28px;
  }

  .register-brand__title {
    font-size: 28px;
  }

  /* 左栏折到上方后，竖排步骤条会占掉大半屏高——改横向排布 */
  .register-steps {
    display: flex;
    gap: 10px;
    margin-top: 22px;
  }

  .register-steps__item {
    flex: 1;
    flex-direction: column;
    gap: 8px;
    padding-bottom: 0;
  }

  .register-steps__item:not(:last-child)::before {
    left: 32px;
    top: 15px;
    right: -10px;
    bottom: auto;
    width: auto;
    height: 2px;
  }

  /* 横向排布下每格容不下描述文案 */
  .register-steps__desc {
    display: none;
  }
}

@media (max-width: 640px) {
  .register {
    padding: 16px;
    padding-top: max(16px, env(safe-area-inset-top));
    padding-right: max(16px, env(safe-area-inset-right));
    padding-bottom: max(16px, env(safe-area-inset-bottom));
    padding-left: max(16px, env(safe-area-inset-left));
  }

  .register__panel {
    width: 100%;
    padding: 20px;
  }

  .register-card {
    padding: 22px 18px;
  }

  /* 单列：两列网格在此宽度下每格不足 150px，输入框内容会被挤压 */
  .field-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 480px) {
  .register-card {
    padding: 20px 16px;
  }

  .register-card__title {
    font-size: 20px;
  }

  .register-brand__title {
    font-size: 24px;
  }

  /* 验证码图缩窄：120px 在此宽度下会把输入框挤到不足 90px */
  .register-card__captcha-img {
    width: 104px;
    height: 44px;
  }
}

@media (max-width: 380px) {
  .register__panel {
    padding: 16px;
  }

  .register-card {
    padding: 18px 14px;
  }

  .register-card__captcha-img {
    width: 92px;
  }

  /* 三段步骤在此宽度下互相挤压，收紧字号与间距而非隐藏标题
     （隐藏会让进度指示退化为三个无意义的圆点） */
  .register-steps {
    gap: 6px;
    margin-top: 18px;
  }

  .register-steps__title {
    font-size: 11px;
  }
}

/* 矮视口：横屏手机与 768px 高的笔记本。
   注册表单本身较高（三步 + 强度条 + 核对区），纵向留白必须让位给内容，
   否则整页被推出屏幕——配合 .register__panel 的 margin-block:auto，
   内容超高时回到顶部且完整可滚动 */
@media (max-height: 700px) {
  .register {
    padding-top: max(20px, env(safe-area-inset-top));
    padding-bottom: max(20px, env(safe-area-inset-bottom));
  }

  .register__panel {
    padding: 24px;
  }

  .register-brand {
    padding-top: 0;
  }

  .register-brand__title {
    margin: 12px 0 8px;
  }

  .register-steps {
    margin-top: 18px;
  }

  .register-steps__item {
    padding-bottom: 18px;
  }
}

/* ===== 暗色适配 =====
   绝大多数样式已走 --xf-* 变量，dark.css 覆盖变量后自动跟随；
   下面三处是变量翻转仍不成立、必须显式覆盖的：
   1. 提示条：前景写的是 primary-deep（深红），暗色底上等于不可读
   2. 光斑：亮色下的低透明度色斑在深底上几乎看不见，需提亮
   3. 主渐变按钮/logo 的白字在暗色下保持不变（无需覆盖，此处仅备注）
   选择器写成 html.dark .x —— scoped 编译后为 html.dark .x[data-v-*]，
   元素本就在本组件内，无需 :global（:global 只用于 teleport 出去的下拉菜单）。 */
html.dark .register__aurora {
  background-image:
    radial-gradient(38% 38% at 78% 12%, var(--xf-primary-alpha-25) 0%, transparent 100%),
    radial-gradient(42% 42% at 12% 88%, var(--xf-info-alpha-30) 0%, transparent 100%);
}

/* summary 暗色覆盖已随 RegisterSummary.vue 迁走（D-2） */

/* ===== 减少动态效果 =====
   global.css 的降级规则只覆盖 .glass-btn/.glass-card/.glass-segmented，
   本页自有的入场动画、步骤位移与高度过渡不在其中，必须就地降级。
   降级不等于没有反馈：位移换成短促交叉淡入，状态变化依然可见。 */
@media (prefers-reduced-motion: reduce) {
  .register__panel,
  .register-brand,
  .register-card {
    animation: none;
  }

  .register-card__steps {
    transition: none;
  }

  .register-step.is-fwd,
  .register-step.is-back {
    animation: step-fade 0.18s ease both;
  }

  /* .pwd-meter__fill 的降级已随组件迁入 PasswordStrengthMeter.vue（D-2） */
  .register-steps__index {
    transition: none;
  }

  /* 触摸/鼠标按压不再缩放，避免前庭不适
     （AuthPrefs 内的按钮降级由组件自行处理） */
  .register-card__captcha-img:active {
    transform: none;
  }

  .register-card__captcha-img,
  .register-card__reset {
    transition: none;
  }

  .register-card__reset:active {
    opacity: 1;
  }
}

@keyframes step-fade {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
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
