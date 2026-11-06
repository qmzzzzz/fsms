<template>
  <!-- MFA 两步验证（I-06）。D-2 自 ProfileView 拆出：
       状态查询、注册/启用/关闭/恢复码再生成、二维码渲染、复制降级
       全部内聚在本组件，视图层不再感知 MFA 细节 -->
  <el-card shadow="never" class="profile-block">
    <template #header>
      <span class="card-header">{{ t('profile.mfaTitle') }}</span>
    </template>

    <!-- 状态未知（查询失败）：不得按「未开启」展示——真实已开启时用户会看不到
         关闭入口，真实未开启时用户可能重复登记。显式错误 + 重试，并锁住写入口。 -->
    <template v-if="mfa.status === 'loading'">
      <el-skeleton :rows="2" animated />
    </template>
    <template v-else-if="mfa.status === 'error'">
      <el-alert
        :title="t('profile.mfaStatusError')"
        type="error"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            @click="loadMfaStatus"
          >
            {{ t('profile.mfaStatusRetry') }}
          </button>
        </template>
      </el-alert>
    </template>

    <!-- 已开启：提供关闭入口（动态口令 / 备用恢复码二选一） -->
    <template v-else-if="mfa.enabled">
      <el-alert
        :title="t('profile.mfaOn')"
        type="success"
        :closable="false"
        style="margin-bottom: 16px"
      />
      <!-- 备用恢复码余量提醒 -->
      <el-alert
        v-if="mfa.recoveryRemaining !== null && mfa.recoveryRemaining <= 3"
        :title="t('profile.recoveryLow', { count: mfa.recoveryRemaining })"
        type="warning"
        :closable="false"
        style="margin-bottom: 16px"
      />
      <el-form label-width="100px" class="profile-form" @submit.prevent>
        <el-form-item
          :label="mfa.disableMode === 'recovery' ? t('profile.mfaRecoveryCode') : t('auth.mfaCode')"
        >
          <el-input
            v-model="mfa.disableCode"
            :placeholder="
              mfa.disableMode === 'recovery'
                ? t('profile.mfaRecoveryPlaceholder')
                : t('profile.mfaDisablePlaceholder')
            "
            :maxlength="mfa.disableMode === 'recovery' ? 9 : 6"
            :inputmode="mfa.disableMode === 'recovery' ? 'text' : 'numeric'"
            style="width: 220px"
            @keydown.enter.prevent="enterSubmit($event, disableMfa)"
          />
        </el-form-item>
        <el-form-item>
          <button
            type="button"
            class="glass-btn glass-btn--danger"
            :disabled="mfa.busy"
            @click="disableMfa"
          >
            {{ t('profile.mfaDisable') }}
          </button>
          <button
            type="button"
            class="glass-btn glass-btn--link mfa-mode-toggle"
            :disabled="mfa.busy"
            @click="toggleDisableMode"
          >
            {{
              mfa.disableMode === 'recovery'
                ? t('profile.mfaUseTotp')
                : t('profile.mfaUseRecoveryCode')
            }}
          </button>
        </el-form-item>
      </el-form>
      <!-- 重新生成备用恢复码（旧码作废） -->
      <el-divider class="profile-form" />
      <el-form label-width="100px" class="profile-form" @submit.prevent>
        <el-form-item :label="t('auth.mfaCode')">
          <el-input
            v-model="mfa.regenCode"
            :placeholder="t('profile.recoveryRegenPlaceholder')"
            maxlength="6"
            inputmode="numeric"
            style="width: 200px"
            @keydown.enter.prevent="enterSubmit($event, regenerateCodes)"
          />
        </el-form-item>
        <el-form-item>
          <button
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="mfa.busy"
            @click="regenerateCodes"
          >
            {{ t('profile.recoveryRegenerate') }}
          </button>
        </el-form-item>
      </el-form>
    </template>

    <!-- 未开启：两步流程（生成密钥 → 认证器添加 → 输码确认） -->
    <template v-else>
      <el-alert
        :title="t('profile.mfaIntro')"
        type="info"
        :closable="false"
        style="margin-bottom: 16px"
      />
      <template v-if="!mfa.secret">
        <!-- 登记密钥要能绑定认证器，必须当面验证密码：仅有被劫持的会话不足以
             把攻击者自己的认证器绑进账号（M-05）。密码同时用于下一步 enable 复检。 -->
        <el-form label-width="100px" class="profile-form" @submit.prevent>
          <el-form-item :label="t('auth.currentPassword')">
            <el-input
              v-model="mfa.enrollPassword"
              type="password"
              show-password
              :placeholder="t('profile.mfaPasswordPlaceholder')"
              style="width: 260px"
              @keydown.enter.prevent="enterSubmit($event, enrollMfa)"
            />
          </el-form-item>
          <el-form-item>
            <button
              type="button"
              class="glass-btn glass-btn--primary"
              :disabled="mfa.busy"
              @click="enrollMfa"
            >
              {{ t('profile.mfaStart') }}
            </button>
          </el-form-item>
        </el-form>
      </template>
      <template v-else>
        <el-form label-width="100px" class="profile-form" @submit.prevent>
          <!-- 二维码：用户扫描认证器添加账户 -->
          <el-form-item :label="t('profile.mfaQrcode')">
            <canvas ref="qrcodeCanvas" width="200" height="200" class="mfa-qrcode" />
          </el-form-item>
          <el-form-item :label="t('profile.mfaSecret')">
            <div class="mfa-copy-row">
              <code class="mfa-secret">{{ mfa.secret }}</code>
              <button
                type="button"
                class="glass-btn glass-btn--default glass-btn--sm mfa-copy-btn"
                @click="copyMfaText(mfa.secret)"
              >
                {{ t('common.copy') }}
              </button>
            </div>
          </el-form-item>
          <el-form-item :label="t('profile.mfaManualUri')">
            <div class="mfa-copy-row">
              <span class="mfa-uri" :title="mfa.otpauthUri">{{ mfa.otpauthUri }}</span>
              <button
                type="button"
                class="glass-btn glass-btn--default glass-btn--sm mfa-copy-btn"
                @click="copyMfaText(mfa.otpauthUri)"
              >
                {{ t('common.copy') }}
              </button>
            </div>
          </el-form-item>
          <el-form-item :label="t('auth.mfaCode')">
            <el-input
              v-model="mfa.confirmCode"
              :placeholder="t('profile.mfaCodePlaceholder')"
              maxlength="6"
              inputmode="numeric"
              style="width: 200px"
              @keydown.enter.prevent="enterSubmit($event, enableMfa)"
            />
          </el-form-item>
          <el-form-item>
            <button
              type="button"
              class="glass-btn glass-btn--primary"
              :disabled="mfa.busy"
              @click="enableMfa"
            >
              {{ t('profile.mfaEnable') }}
            </button>
          </el-form-item>
        </el-form>
      </template>
    </template>
  </el-card>

  <!-- 备用恢复码对话框：明文仅展示一次，强制引导保存 -->
  <el-dialog
    v-model="mfa.showRecoveryDialog"
    :title="t('profile.recoveryDialogTitle')"
    width="420px"
    :close-on-click-modal="false"
    :show-close="false"
    :before-close="handleRecoveryDialogClose"
    append-to-body
    destroy-on-close
    @closed="clearRecoveryCodes"
  >
    <el-alert
      :title="t('profile.recoveryDialogWarning')"
      type="warning"
      :closable="false"
      style="margin-bottom: 12px"
    />
    <div class="recovery-codes">
      <code v-for="code in mfa.recoveryCodes" :key="code" class="recovery-code">{{ code }}</code>
    </div>
    <template #footer>
      <button type="button" class="glass-btn glass-btn--default" @click="copyAllRecoveryCodes">
        {{ t('common.copy') }}
      </button>
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        @click="mfa.showRecoveryDialog = false"
      >
        {{ t('profile.recoverySaved') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api } from '@/utils/api'
import { encryptPassword } from '@/utils/loginCipher'
import { enterSubmit } from '@/utils/enterSubmit'
import QRCode from 'qrcode'

const { t } = useI18n()

// MFA 两步验证状态（I-06）
const mfa = reactive({
  // loading / ready / error：查询失败时不能把「未知」折叠成「未开启」——
  // 真实已开启的用户会因此看不到关闭入口，真实未开启的用户会被诱导重复登记。
  status: 'loading',
  enabled: false,
  secret: '',
  otpauthUri: '',
  confirmCode: '',
  disableCode: '',
  // totp / recovery：关闭入口支持第二因子的两种形态（后端 mfaDisable 接受
  // mfaCode 或 recoveryCode，设备丢失时只能用恢复码关闭）。
  disableMode: 'totp',
  regenCode: '',
  // 登记/开启共用的当前密码：仅在内存中停留到 enable 成功或组件卸载
  enrollPassword: '',
  busy: false,
  recoveryCodes: [],
  showRecoveryDialog: false,
  recoveryRemaining: null,
})

const qrcodeCanvas = ref(null)

/** 将 otpauth URI 渲染为画布二维码 */
const renderQrcode = async () => {
  await nextTick()
  if (!qrcodeCanvas.value || !mfa.otpauthUri) return
  try {
    await QRCode.toCanvas(qrcodeCanvas.value, mfa.otpauthUri, {
      width: 200,
      margin: 1,
      color: { dark: '#1a1a2e', light: '#ffffff' },
    })
  } catch (_) {
    // 二维码渲染失败不影响手动输入
  }
}

const loadMfaStatus = async () => {
  mfa.status = 'loading'
  try {
    const { data: resp } = await api.auth.getMfaStatus()
    // HTTP 2xx 不等于业务成功：success:false 时 data 可能缺失或过期，
    // 按「未开启」继续渲染会诱导重复登记 / 藏掉关闭入口。
    if (resp?.success !== true) {
      mfa.status = 'error'
      return
    }
    mfa.enabled = !!resp.data?.enabled
    mfa.recoveryRemaining = resp.data?.recoveryCodesRemaining ?? null
    mfa.status = 'ready'
  } catch (_) {
    // 错误已由拦截器提示；此处保留「未知」状态并给出重试入口，
    // 不把查询失败当成「未开启」继续渲染开启流程。
    mfa.status = 'error'
  }
}

const toggleDisableMode = () => {
  mfa.disableMode = mfa.disableMode === 'recovery' ? 'totp' : 'recovery'
  mfa.disableCode = ''
}

/** 口令加密失败时的可执行文案（与 ChangePasswordCard 同口径） */
const encryptionErrorMessage = (e) => {
  if (e?.code === 'PUBLIC_KEY_PIN_MISMATCH') return t('login.publicKeyPinMismatch')
  if (e?.code === 'INSECURE_CONTEXT') return t('login.insecureContext')
  return t('login.encryptionFailed')
}

/**
 * 构造当前口令凭据：只走密文轨。加密失败（含 dev 非安全上下文返回 null）一律
 * 抛给调用方阻断提交，不得静默明文上行——G2 统一口径：明文回退轨已删，
 * null 按生产同款 INSECURE_CONTEXT 语义抛出，调用方 catch 统一提示。
 */
const buildPasswordCredential = async (password) => {
  const enc = await encryptPassword(password, 'PASSWORD_CURRENT')
  if (!enc) {
    const err = new Error('WebCrypto 不可用，已拒绝以明文提交口令')
    err.code = 'INSECURE_CONTEXT'
    throw err
  }
  return { encCurrentPassword: enc }
}

const enrollMfa = async () => {
  // 重入防护必须同步置位：按钮 :disabled="mfa.busy" 只挡点击，挡不住 Enter 提交
  // （keydown.enter 直接调用提交函数）。长按回车的自动重复会在请求在途时重复提交
  // ——本轮实测 enable 路径 4 次 keydown 发出 4 个 POST /auth/mfa/enable。
  // 四个端点（enroll/enable/disable/recovery-codes）都是「重新生成并覆盖」的
  // 非幂等语义，重复提交会让服务端状态与用户所见不一致，故四个入口统一拦截。
  if (mfa.busy) return
  if (!mfa.enrollPassword) {
    ElMessage.warning(t('profile.mfaPasswordRequired'))
    return
  }
  mfa.busy = true
  try {
    // 当前口令走密文轨（PASSWORD_CURRENT 用途）：加密失败就阻断，绝不静默明文上行
    let credential
    try {
      credential = await buildPasswordCredential(mfa.enrollPassword)
    } catch (e) {
      console.warn('[loginCipher] MFA 登记口令加密失败，已阻断提交：', e?.message)
      ElMessage.error(encryptionErrorMessage(e))
      return
    }
    const { data: resp } = await api.auth.mfaEnroll(credential)
    if (resp.success && resp.data?.secret) {
      mfa.secret = resp.data.secret
      mfa.otpauthUri = resp.data.otpauthUri || ''
      renderQrcode()
      ElMessage.info(t('profile.mfaEnrolledTip'))
    }
  } catch (_) {
    // 错误已在拦截器处理
  } finally {
    mfa.busy = false
  }
}

// 快捷复制 MFA 密钥 / 手动录入 URI：
// 优先 Clipboard API（localhost 与 HTTPS 为 secure context），
// 局域网 IP 访问 dev 等非安全上下文时降级 textarea + execCommand
const copyMfaText = async (text) => {
  if (!text) return
  let ok = false
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      ok = true
    }
  } catch (_) {
    /* 走降级 */
  }
  if (!ok) {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try {
      ok = document.execCommand('copy')
    } catch (_) {
      ok = false
    }
    document.body.removeChild(ta)
  }
  if (ok) {
    ElMessage.success(t('common.copied'))
  } else {
    ElMessage.warning(t('common.copyFailed'))
  }
}

const enableMfa = async () => {
  const code = mfa.confirmCode.trim()
  if (!/^\d{6}$/.test(code)) {
    ElMessage.warning(t('profile.mfaCodeInvalid'))
    return
  }
  // enroll 已验过一次密码；enable 是真正改变安全状态的一步，服务端要求复检。
  // 这里复用同一份内存口令，用户无需重复输入。
  if (!mfa.enrollPassword) {
    ElMessage.warning(t('profile.mfaPasswordRequired'))
    return
  }
  // 重入防护必须同步置位：按钮 :disabled="mfa.busy" 只挡点击，挡不住 Enter 提交
  // （keydown.enter 直接调用提交函数）。长按回车的自动重复会在请求在途时重复提交
  // ——本轮实测 enable 路径 4 次 keydown 发出 4 个 POST /auth/mfa/enable。
  // 四个端点（enroll/enable/disable/recovery-codes）都是「重新生成并覆盖」的
  // 非幂等语义，重复提交会让服务端状态与用户所见不一致，故四个入口统一拦截。
  if (mfa.busy) return
  mfa.busy = true
  try {
    let credential
    try {
      credential = await buildPasswordCredential(mfa.enrollPassword)
    } catch (e) {
      console.warn('[loginCipher] MFA 开启口令加密失败，已阻断提交：', e?.message)
      ElMessage.error(encryptionErrorMessage(e))
      return
    }
    const { data: resp } = await api.auth.mfaEnable({
      mfaCode: code,
      ...credential,
    })
    // 只有 success:true 才能改本地状态：否则会把「服务端拒绝」显示成
    // 已开启并清掉密钥/口令，用户既回不去也开不了。
    if (resp?.success !== true) {
      ElMessage.error(resp?.message || t('common.failed'))
      return
    }
    mfa.enabled = true
    mfa.secret = ''
    mfa.otpauthUri = ''
    mfa.confirmCode = ''
    mfa.enrollPassword = ''
    // 备用恢复码：明文仅本次响应返回一次，强制弹窗引导保存
    if (Array.isArray(resp.data?.recoveryCodes) && resp.data.recoveryCodes.length) {
      mfa.recoveryCodes = resp.data.recoveryCodes
      mfa.showRecoveryDialog = true
      mfa.recoveryRemaining = resp.data.recoveryCodes.length
    } else {
      // 已开启但本次未返回恢复码（异常场景）：提示并将可用余量归零，避免残留旧计数
      ElMessage.warning(t('profile.recoveryMissingWarn'))
      mfa.recoveryRemaining = 0
    }
    ElMessage.success(t('profile.mfaEnabledOk'))
  } catch (_) {
    // 错误已在拦截器处理
  } finally {
    mfa.busy = false
  }
}

/** 重新生成备用恢复码（需当前动态口令；旧码作废） */
const regenerateCodes = async () => {
  const code = mfa.regenCode.trim()
  if (!/^\d{6}$/.test(code)) {
    ElMessage.warning(t('profile.mfaCodeInvalid'))
    return
  }
  // 重入防护必须同步置位：按钮 :disabled="mfa.busy" 只挡点击，挡不住 Enter 提交
  // （keydown.enter 直接调用提交函数）。长按回车的自动重复会在请求在途时重复提交
  // ——本轮实测 enable 路径 4 次 keydown 发出 4 个 POST /auth/mfa/enable。
  // 四个端点（enroll/enable/disable/recovery-codes）都是「重新生成并覆盖」的
  // 非幂等语义，重复提交会让服务端状态与用户所见不一致，故四个入口统一拦截。
  if (mfa.busy) return
  mfa.busy = true
  try {
    const { data: resp } = await api.auth.regenerateRecoveryCodes({ mfaCode: code })
    if (resp?.success !== true) {
      ElMessage.error(resp?.message || t('common.failed'))
      return
    }
    // 与 enableMfa 同口径：响应未携带恢复码时视为异常，不弹空弹窗误导用户
    const codes = resp.data?.recoveryCodes || []
    if (!codes.length) {
      ElMessage.error(t('profile.recoveryEmptyError'))
      return
    }
    mfa.recoveryCodes = codes
    mfa.showRecoveryDialog = true
    mfa.regenCode = ''
    mfa.recoveryRemaining = codes.length
    ElMessage.success(t('profile.recoveryRegenerated'))
  } catch (_) {
    // 错误已在拦截器处理
  } finally {
    mfa.busy = false
  }
}

const copyAllRecoveryCodes = () => {
  copyMfaText(mfa.recoveryCodes.join('\n'))
}

// destroy-on-close 只清 DOM；reactive 数组也要在关闭后清掉，
// 否则明文恢复码在组件生命周期内一直可被 XSS/DevTools 读取。
const clearRecoveryCodes = () => {
  mfa.recoveryCodes = []
}

// 恢复码对话框防误关：明文仅展示一次，ESC 等系统关闭入口先二次确认，确认后才放行
const handleRecoveryDialogClose = async (done) => {
  try {
    await ElMessageBox.confirm(t('profile.recoveryCloseConfirm'), t('messages.confirmTitle'), {
      type: 'warning',
    })
    done()
  } catch (_) {
    // 用户取消：保持对话框打开继续保存
  }
}

/** 恢复码归一：大小写不敏感、忽略空白，缺省连字符时补上（后端只接受 XXXX-XXXX） */
const normalizeRecoveryCode = (raw) => {
  const compact = raw.replace(/\s/g, '').toUpperCase()
  return /^[A-HJ-KM-NP-Z2-9]{8}$/.test(compact)
    ? `${compact.slice(0, 4)}-${compact.slice(4)}`
    : compact
}

const disableMfa = async () => {
  // 第二因子二选一：动态口令或备用恢复码（设备丢失时只有恢复码可用）
  const raw = mfa.disableCode.trim()
  let payload
  if (mfa.disableMode === 'recovery') {
    const recoveryCode = normalizeRecoveryCode(raw)
    if (!/^[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}$/.test(recoveryCode)) {
      ElMessage.warning(t('profile.mfaRecoveryInvalid'))
      return
    }
    payload = { recoveryCode }
  } else {
    if (!/^\d{6}$/.test(raw)) {
      ElMessage.warning(t('profile.mfaCodeInvalid'))
      return
    }
    payload = { mfaCode: raw }
  }
  // 重入防护必须同步置位：按钮 :disabled="mfa.busy" 只挡点击，挡不住 Enter 提交
  // （keydown.enter 直接调用提交函数）。长按回车的自动重复会在请求在途时重复提交
  // ——本轮实测 enable 路径 4 次 keydown 发出 4 个 POST /auth/mfa/enable。
  // 四个端点（enroll/enable/disable/recovery-codes）都是「重新生成并覆盖」的
  // 非幂等语义，重复提交会让服务端状态与用户所见不一致，故四个入口统一拦截。
  if (mfa.busy) return
  mfa.busy = true
  try {
    const { data: resp } = await api.auth.mfaDisable(payload)
    if (resp?.success !== true) {
      ElMessage.error(resp?.message || t('common.failed'))
      return
    }
    mfa.enabled = false
    mfa.status = 'ready'
    mfa.disableCode = ''
    mfa.disableMode = 'totp'
    mfa.recoveryRemaining = 0
    ElMessage.success(t('profile.mfaDisabledOk'))
  } catch (_) {
    // 错误已在拦截器处理
  } finally {
    mfa.busy = false
  }
}

onMounted(() => {
  loadMfaStatus()
})

// 组件卸载时擦除瞬态密钥材料：TOTP secret / otpauth URI / 一次性恢复码只在"配置 MFA"
// 这一段时间内需要可见。它们都是纯前端内存态、本不落 storage，但 ProfileView 长时间停留
// 或被 keep-alive 复用时，明文恢复码/密钥会一直挂在 reactive state 里（DevTools/异常快照
// 可读）。与 LoginView 登录后立即清空 password 字段同一卫生口径。
onUnmounted(() => {
  mfa.secret = ''
  mfa.otpauthUri = ''
  mfa.recoveryCodes = []
  mfa.confirmCode = ''
  mfa.disableCode = ''
  mfa.disableMode = 'totp'
  mfa.regenCode = ''
  mfa.enrollPassword = ''
  mfa.showRecoveryDialog = false
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

/* MFA 密钥与 otpauth URI 展示（I-06）：等宽字体便于人工比对录入 */
.mfa-copy-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  width: 100%;
}
.mfa-copy-row .mfa-secret,
.mfa-copy-row .mfa-uri {
  flex: 1;
  min-width: 0;
}
.mfa-copy-btn {
  flex-shrink: 0;
}

.mfa-mode-toggle {
  margin-left: 12px;
}

/* 备用恢复码网格：两列等宽，等宽字体便于抄录核对 */
.recovery-codes {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.recovery-code {
  font-family: var(--xf-font-display, monospace);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 1px;
  text-align: center;
  padding: 8px 6px;
  border-radius: 8px;
  background: rgba(128, 128, 128, 0.12);
}

/* 原 ProfileView 中 .mfa-secret/.mfa-uri 各有两处定义，此处按级联合并结果保留 */
.mfa-secret {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-sm);
  font-weight: 700;
  letter-spacing: 1px;
  background: var(--xf-gray-100);
  border-radius: 6px;
  padding: 6px 12px;
  word-break: break-all;
  max-width: 360px;
  display: inline-block;
}

.mfa-uri {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  word-break: break-all;
  max-width: 360px;
  display: inline-block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mfa-qrcode {
  border: 1px solid var(--xf-border-color);
  border-radius: 10px;
  background: #fff;
}
</style>
