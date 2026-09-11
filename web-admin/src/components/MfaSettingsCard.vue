<template>
  <!-- MFA 两步验证（I-06）。D-2 自 ProfileView 拆出：
       状态查询、注册/启用/关闭/恢复码再生成、二维码渲染、复制降级
       全部内聚在本组件，视图层不再感知 MFA 细节 -->
  <el-card shadow="never" class="profile-block">
    <template #header>
      <span class="card-header">{{ t('profile.mfaTitle') }}</span>
    </template>

    <!-- 已开启：仅提供关闭入口 -->
    <template v-if="mfa.enabled">
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
        <el-form-item :label="t('auth.mfaCode')">
          <el-input
            v-model="mfa.disableCode"
            :placeholder="t('profile.mfaDisablePlaceholder')"
            maxlength="6"
            inputmode="numeric"
            style="width: 200px"
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
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="mfa.busy"
          @click="enrollMfa"
        >
          {{ t('profile.mfaStart') }}
        </button>
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
import { ref, reactive, onMounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api } from '@/utils/api'
import { enterSubmit } from '@/utils/enterSubmit'
import QRCode from 'qrcode'

const { t } = useI18n()

// MFA 两步验证状态（I-06）
const mfa = reactive({
  enabled: false,
  secret: '',
  otpauthUri: '',
  confirmCode: '',
  disableCode: '',
  regenCode: '',
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
  try {
    const { data: resp } = await api.auth.getMfaStatus()
    mfa.enabled = !!resp.data?.enabled
    mfa.recoveryRemaining = resp.data?.recoveryCodesRemaining ?? null
  } catch (_) {
    // 状态查询失败按未开启展示，不影响页面其余功能
  }
}

const enrollMfa = async () => {
  mfa.busy = true
  try {
    const { data: resp } = await api.auth.mfaEnroll()
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
  mfa.busy = true
  try {
    const { data: resp } = await api.auth.mfaEnable({ mfaCode: code })
    mfa.enabled = true
    mfa.secret = ''
    mfa.otpauthUri = ''
    mfa.confirmCode = ''
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
  mfa.busy = true
  try {
    const { data: resp } = await api.auth.regenerateRecoveryCodes({ mfaCode: code })
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

const disableMfa = async () => {
  const code = mfa.disableCode.trim()
  if (!/^\d{6}$/.test(code)) {
    ElMessage.warning(t('profile.mfaCodeInvalid'))
    return
  }
  mfa.busy = true
  try {
    await api.auth.mfaDisable({ mfaCode: code })
    mfa.enabled = false
    mfa.disableCode = ''
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
