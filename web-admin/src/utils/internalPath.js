/**
 * 站内跳转目标校验（P3-11）：仅接受以 / 开头且非 // 的路径。
 * 拒绝协议相对地址（//host 会被浏览器按当前协议解析到第三方域）与
 * 绝对 URL；非法值一律回落 fallback（默认 /dashboard）。
 *
 * P2（2026-11-17 审计 §3.2）：补充拒绝含反斜杠的形态。WHATWG URL 在特殊协议
 * （http/https 等）下把 `\` 视同 `/`，`/\evil.com` 会被解析成 //evil.com——
 * 一旦返回值被用于 location.href / window.open / 锚点 href 即开放重定向。
 * 当前唯一消费方 LoginView 走 router.push（不可跨域），故属纵深防御；
 * 但校验器不应依赖「调用方恰好安全」。内部路由路径本就不应含反斜杠，
 * 因此对以 / 开头的值只要含 `\` 一律回落（同时覆盖 `/\evil.com`、`/\`、
 * `/a\b` 等全部变体，无需逐形态枚举）。
 */
export const safeInternalPath = (value, fallback = '/dashboard') => {
  if (typeof value !== 'string') return fallback
  if (!value.startsWith('/') || value.startsWith('//')) return fallback
  if (value.includes('\\')) return fallback
  return value
}
