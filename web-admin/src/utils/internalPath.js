/**
 * 站内跳转目标校验（P3-11）：仅接受以 / 开头且非 // 的路径。
 * 拒绝协议相对地址（//host 会被浏览器按当前协议解析到第三方域）与
 * 绝对 URL；非法值一律回落 fallback（默认 /dashboard）。
 */
export const safeInternalPath = (value, fallback = '/dashboard') => {
  if (typeof value !== 'string') return fallback
  if (!value.startsWith('/') || value.startsWith('//')) return fallback
  return value
}
