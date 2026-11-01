/**
 * 审计读取的二次验证：客户端**不持有任何凭据**（2026-10-31，审计一-3）
 *
 * 原实现把 POST /security/reauth 换来的票据存在内存里，随每个受保护读取发出去。
 * 票据是 bearer 凭据：内存里躺着一张"5 分钟内可重放"的东西，一旦被读走（XSS、
 * 崩溃转储、调试器）就等于整个窗口的审计读取权。
 *
 * 改造后 step-up 的结果落在**服务端**（models/ReauthGrant，按 access token 的 sid
 * 绑定、5 分钟、TTL 清理）：窗口内读取端点直接放行，客户端手里没有任何凭据可泄漏；
 * 窗口过期后服务端回 401 REAUTH_TICKET_REQUIRED，页面重新弹框即可。
 *
 * 本文件只剩一个"刚验证过"的**本地时间戳**，用途单一：避免用户刚输完口令、页面
 * 重放首屏那几条读取时又立刻弹框（重放与弹框之间的竞态）。它不是凭据——丢了、
 * 被改了都不产生任何权限，最坏只是多弹一次框。
 */

let verifiedAt = null

/** 记录"本页刚完成过一次二次验证"（仅用于抑制紧随其后的重复弹框） */
export function markReauthVerified() {
  verifiedAt = Date.now()
}

/** 本页是否刚验证过（3 秒窗口，够覆盖首屏重放；不是授权判据） */
export function justReauthVerified() {
  return Boolean(verifiedAt) && Date.now() - verifiedAt < 3000
}

/** 清掉本地标记（登出、窗口被服务端拒绝时调用） */
export function clearReauthTicket() {
  verifiedAt = null
}
