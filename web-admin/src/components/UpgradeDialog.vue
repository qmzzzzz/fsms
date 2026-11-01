<template>
  <el-dialog
    v-model="visible"
    :title="t('about.upgrade.dialogTitle')"
    width="min(640px, calc(100vw - 32px))"
    append-to-body
    destroy-on-close
    :close-on-click-modal="false"
    :close-on-press-escape="!submitting"
    :show-close="!submitting"
    :before-close="beforeClose"
    @closed="reset"
  >
    <!-- 进度态：任务一旦存在（本次提交成功、409 领养或在途任务），弹窗只读展示进度 -->
    <div
      v-if="job"
      class="upgrade-progress"
      data-testid="upgrade-progress"
      role="status"
      aria-live="polite"
    >
      <div class="upgrade-progress-head">
        <span class="upgrade-progress-title">{{ t('about.upgrade.progressTitle') }}</span>
        <el-tag size="small" :type="stateTagType(job.state)">{{ stateLabel(job.state) }}</el-tag>
      </div>
      <p v-if="outcomeLabel(job.outcome)" class="upgrade-outcome">
        {{ outcomeLabel(job.outcome) }}
      </p>
      <p v-if="job.message" class="upgrade-message">{{ job.message }}</p>
      <p v-else-if="job.state === 'queued'" class="upgrade-hint">
        {{ t('about.upgrade.waitingAgent') }}
      </p>
      <p v-if="pollError" class="upgrade-field-error" role="alert" data-testid="upgrade-poll-error">
        {{ pollError }}
      </p>
      <p v-if="job.message || job.steps.length" class="upgrade-field-hint">
        {{ t('about.upgrade.serverTextNote') }}
      </p>

      <el-descriptions :column="2" border size="small" class="upgrade-job-meta">
        <el-descriptions-item :label="t('about.upgrade.jobId')" :span="2">
          <span class="upgrade-mono">{{ job.id }}</span>
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.imageLabel')" :span="2">
          <span class="upgrade-mono upgrade-wrap">{{ job.image || '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.modeLabel')">
          {{ modeLabel(job.mode) }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.currentColor')">
          {{ colorLabel(job.activeColor || currentColor) }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.targetColor')">
          <!-- 202/queued 的任务常无 targetColor：回退到概览推导出的目标色 -->
          {{ colorLabel(job.targetColor || targetColor) }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.requestedBy')">
          {{ job.requestedBy?.username || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="t('about.upgrade.requestedAt')">
          {{ formatTime(job.requestedAt) }}
        </el-descriptions-item>
        <el-descriptions-item
          v-if="job.finishedAt"
          :label="t('about.upgrade.finishedAt')"
          :span="2"
        >
          {{ formatTime(job.finishedAt) }}
        </el-descriptions-item>
      </el-descriptions>

      <h4 class="upgrade-steps-title">{{ t('about.upgrade.steps') }}</h4>
      <ul v-if="job.steps.length" class="upgrade-steps">
        <li v-for="(step, index) in job.steps" :key="index" class="upgrade-step">
          <span class="upgrade-step-time">{{ formatTime(step.at) }}</span>
          <span class="upgrade-step-name">{{ stepLabel(step.name) }}</span>
          <span v-if="step.detail" class="upgrade-step-detail">{{ step.detail }}</span>
        </li>
      </ul>
      <p v-else class="upgrade-hint">{{ t('about.upgrade.noSteps') }}</p>
    </div>

    <!-- 表单态 -->
    <template v-else>
      <el-alert type="warning" :closable="false" show-icon :title="t('about.upgrade.warning')" />
      <div v-if="!ready" class="upgrade-blocked" data-testid="upgrade-blocked">
        <h4>{{ t('about.upgrade.notReady') }}</h4>
        <ul>
          <li v-for="(reason, index) in reasons" :key="index">
            {{ upgradeReason(reason.text, reason.code) }}
          </li>
        </ul>
      </div>
      <div v-if="targetColor" class="upgrade-target">
        <span>
          {{ t('about.upgrade.currentColor') }}:
          <strong>{{ colorLabel(currentColor) }}</strong>
        </span>
        <span class="upgrade-arrow">→</span>
        <span>
          {{ t('about.upgrade.targetColor') }}:
          <strong>{{ colorLabel(targetColor) }}</strong>
        </span>
      </div>
      <el-form label-position="top" @submit.prevent>
        <el-form-item :label="t('about.upgrade.sourceLabel')">
          <el-radio-group
            v-model="source"
            class="upgrade-source"
            data-testid="upgrade-source"
            :disabled="submitting"
          >
            <el-radio value="registry">{{ t('about.upgrade.sourceRegistry') }}</el-radio>
            <el-radio value="offline" :disabled="offlineBundles.length === 0">
              {{ t('about.upgrade.sourceOffline') }}
            </el-radio>
          </el-radio-group>
          <!-- 禁用态也要能看见处置动作：提示放在来源行内，不依赖先切到离线 -->
          <div v-if="offlineBundles.length === 0" class="upgrade-field-hint">
            {{ t('about.upgrade.offlineNone') }}
          </div>
        </el-form-item>
        <el-form-item
          :label="
            source === 'offline'
              ? t('about.upgrade.offlineBundleLabel')
              : t('about.upgrade.imageLabel')
          "
        >
          <!-- 离线来源：候选来自代理心跳公布的包摘要（应用只「点名」，导入与校验都在宿主） -->
          <el-select
            v-if="source === 'offline'"
            v-model="selectedBundle"
            class="upgrade-bundle-select"
            data-testid="upgrade-bundle-select"
            filterable
            :placeholder="t('about.upgrade.offlineBundlePlaceholder')"
            :no-data-text="t('about.upgrade.offlineBundleEmpty')"
            :aria-invalid="imageError ? 'true' : 'false'"
            aria-describedby="upgrade-image-hint upgrade-image-error"
          >
            <el-option
              v-for="bundle in offlineBundles"
              :key="bundle.ref"
              :value="bundle.ref"
              :label="bundleOptionLabel(bundle)"
            >
              <span class="upgrade-bundle-version">{{ bundle.version || bundle.dirName }}</span>
              <span class="upgrade-bundle-ref">{{ bundle.ref }}</span>
            </el-option>
          </el-select>
          <el-input
            v-else
            v-model="image"
            class="upgrade-image-input"
            maxlength="512"
            clearable
            :placeholder="t('about.upgrade.imagePlaceholder')"
            :aria-invalid="imageError ? 'true' : 'false'"
            aria-describedby="upgrade-image-hint upgrade-image-error"
            @keydown.enter.prevent="submit"
          />
          <div id="upgrade-image-hint" class="upgrade-field-hint">
            {{
              source === 'offline' ? t('about.upgrade.offlineHint') : t('about.upgrade.imageHint')
            }}
          </div>
          <div v-if="imageError" id="upgrade-image-error" class="upgrade-field-error" role="alert">
            {{ imageError }}
          </div>
        </el-form-item>
        <el-form-item :label="t('about.upgrade.credential')">
          <el-input
            v-if="credentialMode === 'password'"
            v-model="password"
            class="upgrade-password-input"
            type="password"
            show-password
            autocomplete="current-password"
            :placeholder="t('about.upgrade.passwordPlaceholder')"
            @keydown.enter.prevent="submit"
          />
          <el-input
            v-else
            v-model="mfaCode"
            class="upgrade-mfa-input"
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
            :placeholder="t('about.upgrade.mfaPlaceholder')"
            @keydown.enter.prevent="submit"
          />
          <button
            type="button"
            class="glass-btn glass-btn--link upgrade-mode-toggle"
            :disabled="submitting"
            @click="toggleMode"
          >
            {{
              credentialMode === 'mfa' ? t('about.upgrade.usePassword') : t('about.upgrade.useMfa')
            }}
          </button>
        </el-form-item>
      </el-form>
    </template>

    <template #footer>
      <button
        type="button"
        class="glass-btn glass-btn--default"
        :disabled="submitting"
        @click="visible = false"
      >
        {{ job ? t('about.upgrade.close') : t('common.cancel') }}
      </button>
      <button
        v-if="!job"
        type="button"
        class="glass-btn glass-btn--primary"
        data-testid="upgrade-submit"
        :disabled="submitting || !canSubmit"
        :aria-busy="submitting ? 'true' : 'false'"
        @click="submit"
      >
        {{ submitting ? t('about.upgrade.submitting') : t('about.upgrade.submit') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, watch, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSystemLabels } from '@/i18n/systemLabels'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api, isHandledApiError, isCanceledError } from '@/utils/api'
import { encryptPassword } from '@/utils/loginCipher'
import { formatTime } from '@/utils/datetime'
import { isPageHidden } from '@/utils/versionWatcher'

/**
 * 一键热升级弹窗（AboutView 唯一入口）
 *
 * 只负责三件事：收集 digest 钉扎镜像 + 二次验证凭据、提交队列请求、按任务 ID
 * 轮询进度。真正的执行在宿主代理（应用容器没有 docker socket），所以这里的
 * 「成功」只代表请求已入队——进度必须以代理写回的状态为准，不能在本弹窗里
 * 自行宣布升级完成。
 *
 * 轮询节律 3s：页面隐藏时不发（与版本探测同纪律）；任务进入终态立即停，
 * 避免升级结束后仍长期占用一个轮询客户端。
 */
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  overview: { type: Object, default: null },
  // 页面可见性判据可注入（测试无需改写全局 document），默认走全仓统一实现
  isHidden: { type: Function, default: null },
})
const emit = defineEmits(['update:modelValue', 'started', 'completed'])

const { t } = useI18n()

const POLL_MS = 3000
// 失败重试的退避上限：升级可能持续几分钟，封顶 1 分钟仍能及时看到进度，
// 又不至于把「切流瞬间的 502」打成 3s 一次的常驻压力（P2-5）
const POLL_MAX_MS = 60 * 1000
const IMAGE_RE = /^[^\s@]+@sha256:[0-9a-f]{64}$/
const JOB_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const TERMINAL_STATES = new Set(['succeeded', 'failed'])
const STATE_TAG_TYPES = {
  queued: 'info',
  running: 'warning',
  succeeded: 'success',
  failed: 'danger',
  unknown: 'info',
}
const OPPOSITE_COLOR = { blue: 'green', green: 'blue' }

const visible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const job = ref(null)
const image = ref('')
// 镜像来源：registry = 手输 digest（在线仓库）；offline = 从代理心跳公布的包里选。
// 切换来源不改对方已填的值——两边都可能填了一半，互相覆盖只会制造「我以为填了 A」。
const source = ref('registry')
const selectedBundle = ref('')
const imageError = ref('')
const credentialMode = ref('password')
const password = ref('')
const mfaCode = ref('')
/**
 * 提交中（busy）。
 *
 * 它同时是「关闭闸门」与「状态复位闸门」：置位发生在第一个 await 之前（P1-1），
 * 关闭被 :before-close / show-close / 底部按钮统一挡住（P1-2）。
 */
const submitting = ref(false)
/** 轮询进入终态时的展示文案（4xx / 响应形状异常）；轮询静默，不能只弹 toast（P2-5） */
const pollError = ref('')

/**
 * 状态代号：每次 reset / 关闭 / 卸载 +1。
 *
 * 所有异步链（加密、提交、轮询）在 await 之后都核对它——代号变了说明弹窗已经
 * 关闭或状态已被清空，这条链就不再有权改动任何状态（P1-2/P1-3）。
 */
let stateEpoch = 0
/** 组件卸载标记：卸载后回来的响应一律丢弃（P1-2） */
let disposed = false

/** 页面是否不可见：默认走全仓统一判据（P2-6） */
const isHidden = () => (typeof props.isHidden === 'function' ? props.isHidden() : isPageHidden())

const currentColor = computed(() => {
  const color = props.overview?.server?.color
  return typeof color === 'string' ? color : ''
})
const targetColor = computed(() => OPPOSITE_COLOR[currentColor.value] || '')
// overview 缺失时不禁用：读取概况失败不应连带阻断升级入口，服务端仍会给出具体错误码
const { upgradeReason } = useSystemLabels()
const ready = computed(() => props.overview?.upgrade?.ready !== false)
// 与 reasons 同序的稳定原因码：英文界面据此本地化，中文界面继续用后端原文
const reasons = computed(() => {
  const list = props.overview?.upgrade?.reasons
  const codes = props.overview?.upgrade?.reasonCodes
  if (!Array.isArray(list)) return []
  return list.map((text, index) => ({
    text: typeof text === 'string' ? text : String(text ?? ''),
    code: Array.isArray(codes) && typeof codes[index] === 'string' ? codes[index] : '',
  }))
})

// 代理心跳公布的离线包候选：只是「自称通过校验的候选」，导入与摘要比对都在宿主执行时做
const offlineBundles = computed(() => {
  const list = props.overview?.upgrade?.bundles?.available
  if (!Array.isArray(list)) return []
  return list.filter((bundle) => bundle && typeof bundle.ref === 'string')
})

const bundleOptionLabel = (bundle) =>
  (bundle && (bundle.version || bundle.dirName)) || bundle?.ref || ''
const modeLabel = (mode) =>
  mode === 'offline' ? t('about.upgrade.sourceOffline') : t('about.upgrade.sourceRegistry')

const canSubmit = computed(() => {
  // 就绪条件未满足时不提交：后端必然拒绝，让用户先按提示联系运维修配置
  if (!ready.value) return false
  // 离线来源看选中的包，在线来源看手输的引用——两边互不代替
  const target = source.value === 'offline' ? selectedBundle.value.trim() : image.value.trim()
  if (!target) return false
  return credentialMode.value === 'mfa' ? /^\d{6}$/.test(mfaCode.value.trim()) : !!password.value
})

const stateLabel = (state) => {
  const key = `about.upgrade.state.${state || 'unknown'}`
  const text = t(key)
  return text === key ? t('about.upgrade.state.unknown') : text
}
const stateTagType = (state) => STATE_TAG_TYPES[state] || 'info'
const colorLabel = (color) => {
  if (color === 'blue') return t('about.upgrade.colorBlue')
  if (color === 'green') return t('about.upgrade.colorGreen')
  return t('about.upgrade.colorUnknown')
}
const stepLabel = (name) => {
  const key = `about.upgrade.stepNames.${name || ''}`
  const text = t(key)
  return text === key ? String(name || '') : text
}

/**
 * 结果码 → 文案。后端 outcome 是稳定标识（success / rolled_back …），
 * message / step.detail 则是代理写回的中文**原文**——原文只标注来源，
 * 不当作翻译结果（P2-11）。未知码直接回退显示码本身，避免丢失信息。
 */
const outcomeLabel = (outcome) => {
  const code = typeof outcome === 'string' ? outcome.trim() : ''
  if (!code) return ''
  const key = `about.upgrade.outcome.${code}`
  const text = t(key)
  return text === key ? code : text
}

/**
 * 后端任务形状归一化：缺字段/类型漂移时渲染 '-' 而不是 undefined/崩溃。
 *
 * 返回 boolean（P2-4）：没有有效任务 ID 时**不得**当作领养成功——原实现静默
 * return，调用方照样 emit('started') + startPolling，于是每 3s 打一发注定
 * 无结果的轮询，而且这个 interval 永远没有清除条件。
 */
const adoptJob = (raw) => {
  if (!raw || typeof raw !== 'object') return false
  const id = typeof raw.id === 'string' ? raw.id : ''
  if (!id) return false
  job.value = {
    id,
    state: STATE_TAG_TYPES[raw.state] ? raw.state : 'unknown',
    image: typeof raw.image === 'string' ? raw.image : '',
    mode: raw.mode === 'offline' ? 'offline' : 'registry',
    message: typeof raw.message === 'string' ? raw.message : '',
    outcome: typeof raw.outcome === 'string' ? raw.outcome : '',
    activeColor: typeof raw.activeColor === 'string' ? raw.activeColor : '',
    targetColor: typeof raw.targetColor === 'string' ? raw.targetColor : '',
    requestedAt: raw.requestedAt || null,
    startedAt: raw.startedAt || null,
    finishedAt: raw.finishedAt || null,
    requestedBy:
      raw.requestedBy && typeof raw.requestedBy === 'object'
        ? {
            userId: typeof raw.requestedBy.userId === 'string' ? raw.requestedBy.userId : '',
            username: typeof raw.requestedBy.username === 'string' ? raw.requestedBy.username : '',
          }
        : null,
    steps: Array.isArray(raw.steps)
      ? raw.steps
          .filter((step) => step && typeof step === 'object')
          .map((step) => ({
            name: typeof step.name === 'string' ? step.name : '',
            detail: typeof step.detail === 'string' ? step.detail : '',
            at: step.at || null,
          }))
      : [],
  }
  return true
}

let pollTimer = null
let pollCtrl = null
let polling = false
/** 轮询请求令牌：只有最后一次发出的请求有权改状态 / 排下一次（P1-3） */
let pollToken = 0
/** 连续失败次数：决定指数退避的倍数 */
let pollFailures = 0

/** 中止在途轮询请求：弹窗关闭 / 切换任务 / 换目标后，旧响应不得回填（P1-3） */
const abortPollRequest = () => {
  if (pollCtrl) {
    try {
      pollCtrl.abort()
    } catch (_) {
      // abort 失败不应阻断关闭流程
    }
    pollCtrl = null
  }
}

const stopPolling = () => {
  if (pollTimer !== null) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
  // 令牌 +1：在途请求回来后自行失效（它已被 abort，这里只是双保险）
  pollToken += 1
  polling = false
  pollFailures = 0
  abortPollRequest()
}

const runPoll = () => {
  pollTimer = null
  pollJob()
}

/** 指数退避：第一次失败 6s、其后 12/24/48s…封顶 POLL_MAX_MS（P2-5） */
const nextBackoffMs = () => Math.min(POLL_MS * 2 ** pollFailures, POLL_MAX_MS)

/** 排下一次轮询（单选：永远只有一个定时器） */
const schedulePoll = (delayMs) => {
  if (pollTimer !== null) clearTimeout(pollTimer)
  pollTimer = setTimeout(runPoll, delayMs)
}

const retryLater = () => {
  pollFailures += 1
  schedulePoll(nextBackoffMs())
}

const pollJob = async () => {
  const targetId = job.value?.id
  if (!targetId || polling) return
  // 页面隐藏时不发请求（与版本探测同纪律），但**节律必须保住**：
  // 隐藏期间直接停表的话，用户切回来就再也不会刷新了（setInterval 版本没这个坑）。
  // 下个周期到达时若已可见，自然补上一发。
  if (isHidden()) {
    schedulePoll(POLL_MS)
    return
  }

  polling = true
  const token = (pollToken += 1)
  const epoch = stateEpoch
  abortPollRequest()
  const ctrl = typeof AbortController === 'function' ? new AbortController() : null
  pollCtrl = ctrl
  // 只有「同一次提交、同一个任务、同一条轮询链」的响应才有权改状态
  const stillCurrent = () => !disposed && epoch === stateEpoch && job.value?.id === targetId

  try {
    const config = { silentErrors: true }
    if (ctrl) config.signal = ctrl.signal
    const { data: resp } = await api.security.getUpgradeJob(targetId, config)
    if (!stillCurrent() || token !== pollToken) return

    if (!resp?.success) {
      // HTTP 200 但 success:false：业务层失败，按可重试失败处理（不改状态）
      if (resp?.errors?.errorCode === 'UPGRADE_JOB_NOT_FOUND') {
        pollError.value = t('about.upgrade.jobGone')
        stopPolling()
        return
      }
      retryLater()
      return
    }

    if (!adoptJob(resp.data?.job)) {
      // 形状异常：继续轮询只会一直拿到同样的坏响应，停表并把原因摆出来
      pollError.value = t('about.upgrade.badResponse')
      stopPolling()
      return
    }
    pollFailures = 0
    if (TERMINAL_STATES.has(job.value.state)) {
      stopPolling()
      emit('completed', job.value)
      return
    }
    schedulePoll(POLL_MS)
  } catch (e) {
    if (!stillCurrent() || token !== pollToken || isCanceledError(e)) return
    const status = Number(e?.response?.status || 0)
    if (status >= 400 && status < 500) {
      // 4xx 进终态（原实现只认 404）：404＝任务状态文件已被清理，
      // 其余 4xx＝这个查询不会再成功，不停表只会每 3s 拿一次同样的拒绝
      pollError.value = t(status === 404 ? 'about.upgrade.jobGone' : 'about.upgrade.pollRejected')
      stopPolling()
      return
    }
    // 5xx / 网络错误：切流瞬间最可能发生的形态，必须留着重试——但要退避
    retryLater()
  } finally {
    if (token === pollToken) polling = false
  }
}

const startPolling = () => {
  stopPolling()
  pollJob()
}

const toggleMode = () => {
  credentialMode.value = credentialMode.value === 'mfa' ? 'password' : 'mfa'
  password.value = ''
  mfaCode.value = ''
}

const submit = async () => {
  if (submitting.value || !canSubmit.value) return
  imageError.value = ''
  const mode = source.value === 'offline' ? 'offline' : 'registry'
  const value = (mode === 'offline' ? selectedBundle.value : image.value).trim()
  if (!IMAGE_RE.test(value)) {
    imageError.value =
      mode === 'offline' ? t('about.upgrade.offlineBundleInvalid') : t('about.upgrade.imageInvalid')
    return
  }

  // P1-1：置位必须发生在**第一个 await 之前**。原实现把 submitting 放在
  // encryptPassword 之后，而加密本身是 async —— 连点 / 回车能在加密窗口里
  // 并行跑进第二次 submit，于是两次 triggerUpgrade 一起发出去。
  submitting.value = true
  const epoch = (stateEpoch += 1)
  const stillCurrent = () => !disposed && epoch === stateEpoch

  try {
    let credential
    if (credentialMode.value === 'mfa') {
      credential = { mfaCode: mfaCode.value.trim() }
    } else {
      try {
        const enc = await encryptPassword(password.value, 'PASSWORD_CURRENT')
        if (!stillCurrent()) return
        credential = enc ? { encCurrentPassword: enc } : { currentPassword: password.value }
      } catch (e) {
        if (!stillCurrent()) return
        ElMessage.error(
          e?.code === 'PUBLIC_KEY_PIN_MISMATCH'
            ? t('login.publicKeyPinMismatch')
            : e?.code === 'INSECURE_CONTEXT'
              ? t('login.insecureContext')
              : t('login.encryptionFailed')
        )
        return
      }
    }

    // 提交（POST）刻意不带 signal：写请求一旦被取消，前端以为「没发生」而
    // 服务端可能已入队，这种错位比多一次点击危险得多（同 api.js P3-42 口径）。
    // 关窗失代后由 stillCurrent() 丢弃响应即可。
    const { data: resp } = await api.security.triggerUpgrade({
      image: value,
      mode,
      ...credential,
    })
    if (!stillCurrent()) return
    if (resp?.success && resp.data?.job) {
      if (adoptJob(resp.data.job)) {
        emit('started', job.value)
        startPolling()
      } else {
        // P2-4：响应里没有有效任务 ID 时不得开始在飞轮询
        ElMessage.error(t('about.upgrade.badResponse'))
      }
      return
    }
    ElMessage.error(resp?.message || t('messages.requestFailed'))
  } catch (e) {
    if (!stillCurrent()) return
    // 409 的响应带 jobId：领养在途任务并直接看进度，而不是让用户对着
    // 「已有任务进行中」的提示干等（他也无从知道那个任务在哪看）。
    const conflictId = e?.response?.data?.errors?.jobId
    if (e?.response?.status === 409 && JOB_ID_RE.test(String(conflictId || ''))) {
      if (adoptJob({ id: conflictId, state: 'queued' })) {
        emit('started', job.value)
        startPolling()
      } else {
        ElMessage.error(t('about.upgrade.badResponse'))
      }
    } else if (!isHandledApiError(e)) {
      ElMessage.error(t('messages.requestFailed'))
    }
  } finally {
    // 只有「当前这一次提交」有权复位：关窗 / reset 之后，旧请求不得改动新状态
    if (epoch === stateEpoch) {
      submitting.value = false
      password.value = ''
      mfaCode.value = ''
    }
  }
}

/**
 * 关闭前拦截（P1-2）。
 *
 * 提交窗口里不允许关闭：关闭会 reset（清掉 submitting），但已发出的请求
 * 回来时若继续 adoptJob + startPolling，定时器就失去了宿主——升级在跑，
 * 进度却无处可看，用户只能刷新页面。提交窗口很短，堵住比失去进度划算。
 */
const beforeClose = (done) => {
  if (submitting.value) return
  done()
}

/**
 * 关闭即中止在途请求、停轮询并清空凭据；任务本身继续在宿主侧执行，
 * 不受弹窗开关影响。
 *
 * 代号 +1 是这里的核心：所有在途的 await 链（加密 / 提交 / 轮询）就此失去
 * 改动状态的资格，响应回来也不会再 adoptJob（P1-2/P1-3）。
 */
const reset = () => {
  stateEpoch += 1
  stopPolling()
  pollError.value = ''
  job.value = null
  image.value = ''
  source.value = 'registry'
  selectedBundle.value = ''
  imageError.value = ''
  credentialMode.value = 'password'
  password.value = ''
  mfaCode.value = ''
  submitting.value = false
}

watch(
  () => props.modelValue,
  (open) => {
    if (!open) {
      // 关闭 = 停轮询 + 中止在途请求（任务在宿主侧继续，界面不再空转）
      stateEpoch += 1
      stopPolling()
      return
    }
    const active = props.overview?.upgrade?.activeJob
    if (active && !job.value && adoptJob(active)) startPolling()
  },
  { immediate: true }
)

// 弹窗打开期间另一管理员已入队任务：切到进度态，避免本表单提交后撞 409
watch(
  () => props.overview?.upgrade?.activeJob,
  (active) => {
    if (props.modelValue && !job.value && active && adoptJob(active)) startPolling()
  }
)

onUnmounted(() => {
  // 卸载即弃代 + 停轮询：卸载后回来的响应不得再回填状态（P1-2）
  disposed = true
  stateEpoch += 1
  stopPolling()
})
</script>

<style scoped>
.upgrade-progress-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.upgrade-progress-title {
  font-family: var(--xf-font-display);
  font-weight: 600;
  color: var(--xf-gray-800);
}

.upgrade-outcome {
  margin: 8px 0 4px;
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-800);
}

.upgrade-message {
  margin: 0 0 12px;
  color: var(--xf-gray-700);
  font-size: var(--xf-font-size-sm);
  line-height: 1.6;
  word-break: break-word;
}

.upgrade-hint {
  margin: 8px 0;
  color: var(--xf-text-secondary);
  font-size: var(--xf-font-size-xs);
  line-height: 1.6;
}

.upgrade-job-meta {
  margin-top: 8px;
}

.upgrade-mono {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
}

.upgrade-wrap {
  word-break: break-all;
}

.upgrade-steps-title {
  margin: 18px 0 8px;
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-800);
}

.upgrade-steps {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 220px;
  overflow-y: auto;
  border-left: 2px solid var(--xf-border-color);
}

.upgrade-step {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
  padding: 6px 0 6px 12px;
  position: relative;
  font-size: var(--xf-font-size-xs);
}

.upgrade-step::before {
  content: '';
  position: absolute;
  left: -5px;
  top: 12px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--xf-primary);
}

.upgrade-step-time {
  flex: 0 0 auto;
  font-family: var(--xf-font-mono);
  color: var(--xf-gray-500);
}

.upgrade-step-name {
  flex: 0 0 auto;
  font-weight: 600;
  color: var(--xf-gray-800);
}

.upgrade-step-detail {
  flex: 1 1 100%;
  color: var(--xf-gray-600);
  word-break: break-word;
}

.upgrade-blocked {
  margin-top: 14px;
  padding: 12px 14px;
  border-radius: var(--xf-radius-sm);
  background: var(--xf-gray-50);
  border: 1px solid var(--xf-border-color);
}

.upgrade-blocked h4 {
  margin: 0 0 6px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-danger);
}

.upgrade-blocked ul {
  margin: 0;
  padding-left: 18px;
  color: var(--xf-gray-700);
  font-size: var(--xf-font-size-xs);
  line-height: 1.7;
}

.upgrade-target {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 14px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-700);
}

.upgrade-arrow {
  color: var(--xf-text-secondary);
}

.upgrade-field-hint {
  margin-top: 4px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  line-height: 1.5;
}

.upgrade-field-error {
  margin-top: 4px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-danger);
}

.upgrade-mode-toggle {
  margin-top: 4px;
}

.upgrade-source {
  flex-wrap: wrap;
}

.upgrade-bundle-select {
  width: 100%;
}

.upgrade-bundle-version {
  font-weight: 600;
  margin-right: 10px;
}

.upgrade-bundle-ref {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  word-break: break-all;
}
</style>
