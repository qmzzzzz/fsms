/**
 * 审计读取票据（内存态）
 *
 * 由 POST /api/security/reauth 换取，5 分钟有效、绑定当前账号与会话。
 * 只存内存：不写 localStorage/sessionStorage（票据是 bearer 凭据，
 * 持久化会让"关闭标签页"不再等于失效）。刷新页面后需重新验证。
 */

let entry = null

/** @param {{ticket: string, expiresIn: number}} issued */
export function storeReauthTicket(ticket, expiresIn) {
  if (!ticket || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    entry = null
    return
  }
  entry = { ticket, expiresAt: Date.now() + expiresIn * 1000 }
}

/** @returns {string|null} 未签发或已过期返回 null */
export function getReauthTicket() {
  if (!entry) return null
  if (Date.now() >= entry.expiresAt) {
    entry = null
    return null
  }
  return entry.ticket
}

export function clearReauthTicket() {
  entry = null
}
