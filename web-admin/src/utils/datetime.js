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
