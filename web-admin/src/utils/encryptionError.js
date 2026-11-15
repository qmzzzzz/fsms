/**
 * 口令加密失败的用户文案（G2 统一口径，i18n 键收敛）
 *
 * encryptPassword（见 loginCipher.js）的失败语义只有三种用户可感知形态：
 *   - PUBLIC_KEY_PIN_MISMATCH：公钥指纹与构建期钉扎不符——主动 MITM 或服务端
 *     轮换密钥后前端包未随之重建，与「网络抖动、重试即可」不是一回事，文案须可执行；
 *   - INSECURE_CONTEXT：非安全上下文（HTTPS）下 WebCrypto 不可用，须提示启用 HTTPS；
 *   - 其余（公钥网络故障/算法异常/用途键非法）：提示重试后重新提交。
 *
 * 此前这段三元/if 链在 ChangePasswordCard、MfaSettingsCard、ReauthDialog、
 * UpgradeDialog、LoginView、RegisterView、ReportView、UserView（两处）各自复制，
 * 新增失败码时漏改任何一处就会出现口径漂移——收敛到这里单一事实来源。
 *
 * @param {(key: string, named?: unknown) => string} t vue-i18n 的翻译函数（组件内
 *   已由 useI18n() 取得，这里不再依赖组件上下文，便于单测直调）
 * @param {unknown} error encryptPassword 抛出的错误（可为 null/undefined，兜底通用文案）
 * @returns {string} 已翻译的错误文案
 */
export function encryptionErrorMessage(t, error) {
  if (error?.code === 'PUBLIC_KEY_PIN_MISMATCH') return t('login.publicKeyPinMismatch')
  if (error?.code === 'INSECURE_CONTEXT') return t('login.insecureContext')
  return t('login.encryptionFailed')
}
