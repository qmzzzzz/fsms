/**
 * 统一的本地日期/时间格式化工具（前端复审 O-3 抽取，单一事实来源）
 * 口径：本地时区、hour12=false；避免 toISOString 的 UTC 日期在东八区 0-8 点错位一天
 */
export const localDateStr = (d = new Date()) => {
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

export const formatTime = (v) => {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return '-'
  const hh = String(d.getHours()).padStart(2, '0')
  const mi = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${localDateStr(d)} ${hh}:${mi}:${ss}`
}

/**
 * ISO/时间戳 → 本地墙钟串「YYYY-MM-DD HH:mm:ss」，与 el-date-picker 的
 * value-format 同构（可直接用于回填，不会把 UTC 小时当字面小时）。
 *
 * 为什么需要它：picker 的 value-format 被声明为本地格式串时，它只做**字符串解析**，
 * 不做时区换算——直接把 "2026-10-01T01:00:00.000Z" 塞进去，界面会显示 01:00，
 * 而真实本地时间是 09:00（东八区）；用户原样保存后提交回 2026-09-30T17:00:00.000Z，
 * 每次「打开-保存」平移一个时区偏移（实测复现）。
 *
 * @param {string|number|Date} v
 * @returns {string} 无法解析时返回空串（picker 显示为空，交由必填校验拦截）
 */
export const toLocalWallClock = (v) => {
  if (!v) return ''
  const d = v instanceof Date ? v : new Date(v)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n) => String(n).padStart(2, '0')
  return `${localDateStr(d)} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
